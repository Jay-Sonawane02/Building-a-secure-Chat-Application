#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#include "../common/cert_utils.h"
#include "../common/crypto_channel.h"
#include "../common/framing.h"
#include "../common/handshake.h"

static const int DEFAULT_PORT = 5000;
static const char *SERVER_CERT_PATH = "server.crt";
static const char *SERVER_KEY_PATH = "server.key";

struct ClientInfo {
    int fd;
    std::vector<uint8_t> key;
    uint64_t send_counter = 0;
};

static std::map<std::string, ClientInfo> g_clients;
static std::mutex g_clients_mutex;

static std::string timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}
static void log(const std::string &msg) {
    std::cout << "[" << timestamp() << "] " << msg << std::endl;
}

static bool register_client(const std::string &username, int fd,
                             const std::vector<uint8_t> &key) {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    if (g_clients.count(username)) return false;
    g_clients[username] = ClientInfo{fd, key, 0};
    return true;
}
static void unregister_client(const std::string &username) {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    g_clients.erase(username);
}
static bool relay_to(const std::string &target_username, const std::string &plaintext) {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    auto it = g_clients.find(target_username);
    if (it == g_clients.end()) return false;
    return channel::send_encrypted(it->second.fd, it->second.key,
                                    channel::SERVER_TO_CLIENT,
                                    it->second.send_counter, plaintext);
}
static std::string who_list() {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    std::ostringstream oss;
    oss << "WHOLIST";
    for (auto &kv : g_clients) oss << " " << kv.first;
    return oss.str();
}

static void handle_client(int fd, std::string peer_addr, const cert::X509Ptr &server_cert,
                           const cert::PKeyPtr &server_key) {
    LineReader reader{fd, ""};

    if (!send_line(fd, "CERT " + cert::cert_to_wire(server_cert))) {
        close(fd);
        return;
    }

    std::string nonce_line;
    if (!reader.recv_line(nonce_line) || nonce_line.rfind("NONCE ", 0) != 0) {
        log("Client " + peer_addr + " did not send a nonce challenge (unexpected)");
        close(fd);
        return;
    }
    std::vector<uint8_t> nonce_bytes = base64::decode(nonce_line.substr(6));
    std::vector<uint8_t> signature = cert::sign_challenge(server_key, nonce_bytes);
    if (!send_line(fd, "PROOF " + base64::encode(signature))) {
        close(fd);
        return;
    }

    handshake::Result hs;
    try {
        hs = handshake::do_handshake_speak_first(fd, reader, "server<-" + peer_addr);
    } catch (const std::exception &e) {
        log("Handshake failed with " + peer_addr + ": " + e.what());
        close(fd);
        return;
    }
    uint64_t send_counter = 0;

    std::string username;
    auto rr = channel::recv_encrypted(reader, hs.key, username);
    if (rr != channel::RecvResult::OK || username.empty()) {
        close(fd);
        return;
    }
    if (!register_client(username, fd, hs.key)) {
        channel::send_encrypted(fd, hs.key, channel::SERVER_TO_CLIENT, send_counter,
                                 "ERR username_taken");
        close(fd);
        log("Rejected duplicate username '" + username + "' from " + peer_addr);
        return;
    }
    channel::send_encrypted(fd, hs.key, channel::SERVER_TO_CLIENT, send_counter, "OK");
    log("Client connected: " + username + " (" + peer_addr + ") fingerprint=" +
        hs.fingerprint + " [cert+PoP verified by client before this handshake]");

    std::string line;
    while (true) {
        auto res = channel::recv_encrypted(reader, hs.key, line);
        if (res == channel::RecvResult::DISCONNECTED) break;
        if (res == channel::RecvResult::TAMPER_DETECTED) {
            log("[TAMPER DETECTED] rejected corrupted message from " + username);
            continue;
        }
        if (res == channel::RecvResult::MALFORMED) continue;
        if (line.empty()) continue;

        if (line == "/quit") {
            log("[CMD] " + username + " -> /quit");
            break;
        }
        if (line == "/who") {
            log("[CMD] " + username + " -> /who");
            std::lock_guard<std::mutex> lock(g_clients_mutex);
            auto it = g_clients.find(username);
            if (it != g_clients.end()) {
                channel::send_encrypted(fd, hs.key, channel::SERVER_TO_CLIENT,
                                         it->second.send_counter, who_list());
            }
            continue;
        }
        if (line[0] == '@') {
            size_t space = line.find(' ');
            if (space == std::string::npos) {
                channel::send_encrypted(fd, hs.key, channel::SERVER_TO_CLIENT,
                                         send_counter, "ERR malformed_message");
                continue;
            }
            std::string target = line.substr(1, space - 1);
            std::string message = line.substr(space + 1);
            log("[RELAY] " + username + " -> " + target + ": " + message);
            if (!relay_to(target, "MSG " + username + " " + message)) {
                std::lock_guard<std::mutex> lock(g_clients_mutex);
                auto it = g_clients.find(username);
                if (it != g_clients.end()) {
                    channel::send_encrypted(fd, hs.key, channel::SERVER_TO_CLIENT,
                                             it->second.send_counter,
                                             "ERR user_not_found " + target);
                }
            }
            continue;
        }
        std::lock_guard<std::mutex> lock(g_clients_mutex);
        auto it = g_clients.find(username);
        if (it != g_clients.end()) {
            channel::send_encrypted(fd, hs.key, channel::SERVER_TO_CLIENT,
                                     it->second.send_counter, "ERR unknown_command");
        }
    }

    unregister_client(username);
    close(fd);
    log("Client disconnected: " + username);
}

int main(int argc, char *argv[]) {
    int port = argc > 1 ? std::atoi(argv[1]) : DEFAULT_PORT;

    cert::X509Ptr server_cert;
    cert::PKeyPtr server_key;
    try {
        server_cert = cert::load_cert_from_file(SERVER_CERT_PATH);
        server_key = cert::load_private_key_from_file(SERVER_KEY_PATH);
    } catch (const std::exception &e) {
        std::cerr << "Failed to load server certificate/key: " << e.what() << "\n";
        std::cerr << "Run setup_ca.sh first to generate " << SERVER_CERT_PATH
                  << " and " << SERVER_KEY_PATH << ".\n";
        return 1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    listen(listen_fd, 8);
    log("Phase 3 chat server (PKI + DH + AES-GCM) listening on port " +
        std::to_string(port));

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        std::string peer = std::string(ip) + ":" + std::to_string(ntohs(client_addr.sin_port));
        std::thread(handle_client, client_fd, peer, std::cref(server_cert),
                    std::cref(server_key))
            .detach();
    }
    return 0;
}

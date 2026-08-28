// Phase 2 - Client-Server Confidentiality via Diffie-Hellman
//
// Same relay logic as Phase 1, but every connection now starts with an
// independent DH handshake (server speaks first, sending its DH public
// value before anything else -- no plaintext chat data ever crosses the
// wire). C1<->S and C2<->S each get their OWN handshake with fresh random
// exponents; there is no shared secret between C1 and C2 at this phase.
//
// After the handshake, everything -- including the username
// registration line -- is AES-GCM encrypted. The server can still read
// every message's plaintext internally (Phase 2 only protects the network
// link, not the server itself; that's Phase 4's job), and relays between
// clients by decrypting with the sender's key and re-encrypting with the
// recipient's key, since each client has an independent session key.
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

#include "../common/crypto_channel.h"
#include "../common/framing.h"
#include "../common/handshake.h"

static const int DEFAULT_PORT = 5000;

struct ClientInfo {
    int fd;
    std::vector<uint8_t> key;   // this client's session key with the server
    uint64_t send_counter = 0;  // server->client nonce counter for this link
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

// Sends `plaintext` to `target_username`, encrypted under THAT client's own
// session key (not the sender's) -- each link is independently keyed.
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

static void handle_client(int fd, std::string peer_addr) {
    LineReader reader{fd, ""};

    // --- DH handshake: server speaks first ---
    handshake::Result hs;
    try {
        hs = handshake::do_handshake_speak_first(fd, reader, "server<-" + peer_addr);
    } catch (const std::exception &e) {
        log("Handshake failed with " + peer_addr + ": " + e.what());
        close(fd);
        return;
    }
    uint64_t send_counter = 0;  // this connection's server->client counter

    // --- encrypted registration: first encrypted line is the username ---
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
        hs.fingerprint);

    std::string line;
    while (true) {
        auto res = channel::recv_encrypted(reader, hs.key, line);
        if (res == channel::RecvResult::DISCONNECTED) break;
        if (res == channel::RecvResult::TAMPER_DETECTED) {
            // This is the tamper-detection path in live operation: a
            // corrupted/tampered ciphertext fails the GCM tag check and we
            // simply drop it rather than processing garbage. See
            // tamper_test.cpp for a controlled, isolated demonstration.
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
            {
                std::lock_guard<std::mutex> lock(g_clients_mutex);
                auto it = g_clients.find(username);
                if (it != g_clients.end()) {
                    channel::send_encrypted(fd, hs.key, channel::SERVER_TO_CLIENT,
                                             it->second.send_counter, who_list());
                }
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

            // Verification point: the server can still read this in full,
            // since it decrypted the sender's link independently -- this is
            // expected/documented Phase 2 behaviour (link security, not
            // end-to-end). Phase 4 is what hides this from the server.
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

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
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
    if (listen(listen_fd, 8) < 0) {
        perror("listen");
        return 1;
    }

    log("Phase 2 chat server (DH + AES-GCM) listening on port " + std::to_string(port));

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        std::string peer = std::string(ip) + ":" + std::to_string(ntohs(client_addr.sin_port));
        std::thread(handle_client, client_fd, peer).detach();
    }

    close(listen_fd);
    return 0;
}

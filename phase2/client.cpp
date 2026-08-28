// Phase 2 - Client-Server Confidentiality via Diffie-Hellman (client side)
//
// Connects, performs a DH handshake (listens for the server's public value
// first, then replies with its own -- see common/handshake.h), derives the
// AES key, prints the verification fingerprint, then sends its username as
// the FIRST encrypted line (registration is protected too, per spec 3.1).
// Everything after that -- commands and chat -- is AES-GCM encrypted.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "../common/crypto_channel.h"
#include "../common/framing.h"
#include "../common/handshake.h"

static std::atomic<bool> g_running{true};

static void receiver_loop(LineReader *reader, std::vector<uint8_t> key) {
    std::string line;
    while (g_running) {
        auto res = channel::recv_encrypted(*reader, key, line);
        if (res == channel::RecvResult::DISCONNECTED) break;
        if (res == channel::RecvResult::TAMPER_DETECTED) {
            std::cout << "\n[SECURITY] Received message failed authentication "
                         "(tampering detected) -- discarded.\n> "
                      << std::flush;
            continue;
        }
        if (res == channel::RecvResult::MALFORMED) continue;

        if (line.rfind("MSG ", 0) == 0) {
            std::string rest = line.substr(4);
            size_t space = rest.find(' ');
            std::string sender = space == std::string::npos ? rest : rest.substr(0, space);
            std::string message = space == std::string::npos ? "" : rest.substr(space + 1);
            std::cout << "\n[" << sender << "]: " << message << "\n> " << std::flush;
        } else if (line.rfind("WHOLIST", 0) == 0) {
            std::cout << "\nOnline users:" << line.substr(7) << "\n> " << std::flush;
        } else if (line.rfind("ERR", 0) == 0) {
            std::cout << "\n[server error] " << line.substr(4) << "\n> " << std::flush;
        } else if (line == "OK") {
            // registration ack, nothing to print
        } else {
            std::cout << "\n[server] " << line << "\n> " << std::flush;
        }
    }
    if (g_running) {
        std::cout << "\nDisconnected from server.\n";
        g_running = false;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> [username]\n";
        return 1;
    }
    std::string server_ip = argv[1];
    int port = std::atoi(argv[2]);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP: " << server_ip << "\n";
        return 1;
    }
    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    LineReader reader{fd, ""};
    handshake::Result hs;
    try {
        hs = handshake::do_handshake_listen_first(fd, reader, "client");
    } catch (const std::exception &e) {
        std::cerr << "DH handshake failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "Verify this fingerprint matches the server's log for your "
                 "connection: "
              << hs.fingerprint << "\n";

    std::string username;
    if (argc > 3) {
        username = argv[3];
    } else {
        std::cout << "Choose a username: ";
        std::getline(std::cin, username);
    }

    uint64_t send_counter = 0;
    if (!channel::send_encrypted(fd, hs.key, channel::CLIENT_TO_SERVER, send_counter,
                                  username)) {
        std::cerr << "Failed to send username.\n";
        return 1;
    }

    std::string ack;
    auto ack_res = channel::recv_encrypted(reader, hs.key, ack);
    if (ack_res != channel::RecvResult::OK) {
        std::cerr << "Server closed the connection during registration.\n";
        return 1;
    }
    if (ack != "OK") {
        std::cerr << "Registration failed: " << ack << "\n";
        return 1;
    }
    std::cout << "Connected as '" << username
              << "' (encrypted). Commands: @user msg | /chat user | /who | /quit\n";

    // NOTE: this thread is joined (not detached) before main() returns --
    // it holds a pointer to `reader`, a stack-local object. Detaching here
    // would risk the receiver thread still using `reader` after main's
    // stack frame is gone the moment the user quits. See the join() +
    // shutdown() sequence at the bottom of main() for how we cleanly
    // unblock it first.
    std::thread receiver(receiver_loop, &reader, hs.key);

    std::string current_peer;
    std::string line;
    std::cout << "> " << std::flush;
    while (g_running && std::getline(std::cin, line)) {
        if (line.empty()) {
            std::cout << "> " << std::flush;
            continue;
        }
        if (line == "/quit") {
            channel::send_encrypted(fd, hs.key, channel::CLIENT_TO_SERVER, send_counter,
                                     "/quit");
            g_running = false;
            break;
        }
        if (line == "/who") {
            channel::send_encrypted(fd, hs.key, channel::CLIENT_TO_SERVER, send_counter,
                                     "/who");
            std::cout << "> " << std::flush;
            continue;
        }
        if (line.rfind("/chat ", 0) == 0) {
            current_peer = line.substr(6);
            std::cout << "Now chatting with '" << current_peer << "'\n> " << std::flush;
            continue;
        }
        if (line[0] == '@') {
            size_t space = line.find(' ');
            if (space == std::string::npos) {
                std::cout << "Usage: @username message\n> " << std::flush;
                continue;
            }
            current_peer = line.substr(1, space - 1);
            channel::send_encrypted(fd, hs.key, channel::CLIENT_TO_SERVER, send_counter,
                                     line);
            std::cout << "> " << std::flush;
            continue;
        }
        if (current_peer.empty()) {
            std::cout << "No chat partner selected. Use /chat username or "
                         "@username message\n> "
                      << std::flush;
            continue;
        }
        channel::send_encrypted(fd, hs.key, channel::CLIENT_TO_SERVER, send_counter,
                                 "@" + current_peer + " " + line);
        std::cout << "> " << std::flush;
    }

    // Unblock the receiver thread's pending recv() call, then wait for it
    // to fully exit before this stack frame (and `reader`) goes away.
    g_running = false;
    shutdown(fd, SHUT_RDWR);
    receiver.join();
    close(fd);
    return 0;
}

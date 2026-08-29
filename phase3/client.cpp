// Phase 3 - Server Authentication via PKI (client side)
//
// Before any DH exchange: receive the server's certificate, validate it
// against our trusted ca.crt (signature chain, validity period, identity),
// then challenge the server to prove it holds the matching private key.
// If ANY check fails, we abort immediately -- no nonce sent, no DH public
// value sent, no username, nothing -- per spec 4.1's explicit requirement.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "../common/cert_utils.h"
#include "../common/crypto_channel.h"
#include "../common/framing.h"
#include "../common/handshake.h"

static const char *TRUSTED_CA_PATH = "ca.crt";
static const char *EXPECTED_SERVER_CN = "chatserver.local";

static std::atomic<bool> g_running{true};

// 16 random bytes for the proof-of-possession challenge nonce. Reuses
// BN_rand (already an approved primitive via bn.h, same as the DH module)
// rather than pulling in a separate RNG header.
static std::vector<uint8_t> random_nonce(int num_bytes) {
    BIGNUM *r = BN_new();
    BN_rand(r, num_bytes * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    std::vector<uint8_t> out(num_bytes);
    BN_bn2binpad(r, out.data(), num_bytes);
    BN_free(r);
    return out;
}

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
            // registration ack
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

    cert::X509Ptr ca_cert;
    try {
        ca_cert = cert::load_cert_from_file(TRUSTED_CA_PATH);
    } catch (const std::exception &e) {
        std::cerr << "Cannot load trusted CA certificate: " << e.what() << "\n";
        std::cerr << "You need a local copy of ca.crt (from setup_ca.sh) before "
                     "connecting.\n";
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
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

    // --- Step 1: receive and validate the server's certificate ---
    std::string cert_line;
    if (!reader.recv_line(cert_line) || cert_line.rfind("CERT ", 0) != 0) {
        std::cerr << "ABORT: server did not present a certificate as the first "
                     "message. Refusing to proceed.\n";
        close(fd);
        return 1;
    }
    cert::X509Ptr server_cert;
    try {
        server_cert = cert::cert_from_wire(cert_line.substr(5));
    } catch (const std::exception &e) {
        std::cerr << "ABORT: could not parse the server's certificate (" << e.what()
                  << "). Refusing to proceed.\n";
        close(fd);
        return 1;
    }

    auto validation = cert::validate_certificate(server_cert, ca_cert, EXPECTED_SERVER_CN);
    if (!validation.ok) {
        std::cerr << "ABORT: certificate validation FAILED -- " << validation.reason
                  << "\n";
        std::cerr << "No nonce, no DH public value, no password, and no username "
                     "were sent. Connection closed immediately.\n";
        close(fd);  // no further data sent, per spec 4.1
        return 1;
    }
    std::cout << "Certificate validated: CN=" << cert::get_common_name(server_cert)
              << ", signed by trusted CA, within validity period.\n";

    // --- Step 2: proof of possession -- challenge the server ---
    std::vector<uint8_t> nonce = random_nonce(16);
    if (!send_line(fd, "NONCE " + base64::encode(nonce))) {
        std::cerr << "Failed to send proof-of-possession challenge.\n";
        close(fd);
        return 1;
    }
    std::string proof_line;
    if (!reader.recv_line(proof_line) || proof_line.rfind("PROOF ", 0) != 0) {
        std::cerr << "ABORT: server did not respond to the proof-of-possession "
                     "challenge. Refusing to proceed.\n";
        close(fd);
        return 1;
    }
    std::vector<uint8_t> signature = base64::decode(proof_line.substr(6));
    if (!cert::verify_challenge(server_cert, nonce, signature)) {
        std::cerr << "ABORT: proof-of-possession FAILED -- the signature does not "
                     "verify against the certificate's public key. This server "
                     "(or attacker) holds the certificate file but NOT the "
                     "matching private key. Refusing to proceed.\n";
        close(fd);
        return 1;
    }
    std::cout << "Proof-of-possession verified: server controls the private key "
                 "matching its certificate.\n";

    // --- From here on, identical to Phase 2 ---
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
    if (ack_res != channel::RecvResult::OK || ack != "OK") {
        std::cerr << "Registration failed.\n";
        return 1;
    }
    std::cout << "Connected as '" << username
              << "' (authenticated + encrypted). Commands: @user msg | /chat user "
                 "| /who | /quit\n";

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

    g_running = false;
    shutdown(fd, SHUT_RDWR);
    receiver.join();
    close(fd);
    return 0;
}

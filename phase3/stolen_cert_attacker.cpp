#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

#include "../common/cert_utils.h"
#include "../common/framing.h"

static const char *STOLEN_CERT_PATH = "server.crt";
static const char *WRONG_KEY_PATH = "wrong_key.key";

static std::string timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}
static void log(const std::string &msg) {
    std::cout << "[" << timestamp() << "] " << msg << std::endl;
}

int main(int argc, char *argv[]) {
    int port = argc > 1 ? std::atoi(argv[1]) : 5000;

    cert::X509Ptr stolen_cert;
    cert::PKeyPtr wrong_key;
    try {
        stolen_cert = cert::load_cert_from_file(STOLEN_CERT_PATH);
        wrong_key = cert::load_private_key_from_file(WRONG_KEY_PATH);
    } catch (const std::exception &e) {
        std::cerr << "Failed to load " << STOLEN_CERT_PATH << "/" << WRONG_KEY_PATH
                  << ": " << e.what() << "\n";
        return 1;
    }
    log("Loaded a COPY of the genuine server.crt (this will pass certificate "
        "validation) and a WRONG private key that does NOT match it (this will "
        "fail proof-of-possession).");

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
    listen(listen_fd, 4);
    log("Stolen-cert attacker listening on port " + std::to_string(port) +
        ". Point a client at THIS machine to run the test.");

    while (true) {
        sockaddr_in victim_addr{};
        socklen_t victim_len = sizeof(victim_addr);
        int victim_fd = accept(listen_fd, (sockaddr *)&victim_addr, &victim_len);
        if (victim_fd < 0) continue;
        log("Client connected -- presenting the stolen (but genuine) certificate.");

        LineReader reader{victim_fd, ""};
        if (!send_line(victim_fd, "CERT " + cert::cert_to_wire(stolen_cert))) {
            close(victim_fd);
            continue;
        }

        std::string nonce_line;
        if (!reader.recv_line(nonce_line) || nonce_line.rfind("NONCE ", 0) != 0) {
            log("Client disconnected before sending a nonce -- unexpected, since "
                "the genuine cert should pass validation.");
            close(victim_fd);
            continue;
        }
        log("Client accepted the certificate and sent a proof-of-possession "
            "challenge, as expected (the cert itself really is valid).");

        std::vector<uint8_t> nonce = base64::decode(nonce_line.substr(6));
        std::vector<uint8_t> bogus_signature = cert::sign_challenge(wrong_key, nonce);
        send_line(victim_fd, "PROOF " + base64::encode(bogus_signature));
        log("Sent a signature produced with the WRONG private key. The client "
            "should now detect that this signature does not verify against the "
            "certificate's actual public key, and abort.");

        std::string next_line;
        if (!reader.recv_line(next_line)) {
            log("*** CLIENT DISCONNECTED after the bad signature. Proof-of-"
                "possession correctly rejected the stolen cert + wrong key "
                "combination. ***");
        } else {
            log("Unexpected: client sent '" + next_line +
                "' after receiving a bogus signature -- check verify_challenge() "
                "in the client.");
        }

        close(victim_fd);
        log("Session ended.");
    }
    return 0;
}

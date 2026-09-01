#include <iostream>
#include <string>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define PORT 8080


const char* HEX_PRIME = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: ./client <username>\n";
        return 1;
    }

    std::string username = argv[1];
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "192.168.56.10", &serv_addr.sin_addr);

    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    send(sock, username.c_str(), username.length(), 0);

    BIGNUM *p = BN_new(), *g = BN_new();
    BN_hex2bn(&p, HEX_PRIME);
    BN_hex2bn(&g, "2");

    BIGNUM *priv = nullptr, *pub = nullptr;
    time_t last_rekey = time(nullptr);
    std::string target = "";
    bool e2e_active = false;

    std::cout << "Connected. Type messages or use /e2e <username>[cite: 1].\n";

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        timeval tv{1, 0}; // 1-second timeout to check rekey timer
        select(sock + 1, &readfds, nullptr, nullptr, &tv);

       
        if (e2e_active && time(nullptr) - last_rekey >= 60) {
            if (username < target) { // collision avoidance
                BN_CTX *ctx = BN_CTX_new();
                priv = BN_new(); pub = BN_new();
                BN_rand(priv, 256, 0, 0);
                BN_mod_exp(pub, g, priv, p, ctx);
                char *pub_hex = BN_bn2hex(pub);
                std::string msg = "@" + target + " __E2E_INIT__" + std::string(pub_hex);
                send(sock, msg.c_str(), msg.length(), 0);
                std::cout << "[Rekey] Sent new key exchange parameters.\n";
                OPENSSL_free(pub_hex);
                BN_CTX_free(ctx);
            }
            last_rekey = time(nullptr);
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            std::string input;
            std::getline(std::cin, input);

            if (input.rfind("/e2e ", 0) == 0) {
                target = input.substr(5);
                BN_CTX *ctx = BN_CTX_new();
                priv = BN_new(); pub = BN_new();
                BN_rand(priv, 256, 0, 0);
                BN_mod_exp(pub, g, priv, p, ctx);
                char *pub_hex = BN_bn2hex(pub);
                std::string msg = "@" + target + " __E2E_INIT__" + std::string(pub_hex);
                send(sock, msg.c_str(), msg.length(), 0);
                std::cout << "[E2E] Initialized with " << target << "\n";
                OPENSSL_free(pub_hex);
                BN_CTX_free(ctx);
            } else {
                std::string msg = "@" + target + " " + input;
                send(sock, msg.c_str(), msg.length(), 0);
            }
        }

        if (FD_ISSET(sock, &readfds)) {
            char buffer[1024] = {0};
            int valread = read(sock, buffer, sizeof(buffer));
            if (valread <= 0) break;

            std::string response(buffer);
            if (response.find("__E2E_INIT__") != std::string::npos) {
                size_t pos = response.find("__E2E_INIT__");
                std::string pub_hex = response.substr(pos + 12);
                
                BN_CTX *ctx = BN_CTX_new();
                if (!priv) {
                    priv = BN_new(); pub = BN_new();
                    BN_rand(priv, 256, 0, 0);
                    BN_mod_exp(pub, g, priv, p, ctx);
                }
                BIGNUM *peer_pub = nullptr;
                BN_hex2bn(&peer_pub, pub_hex.c_str());
                
                BIGNUM *shared = BN_new();
                BN_mod_exp(shared, peer_pub, priv, p, ctx);
                
                char *my_pub_hex = BN_bn2hex(pub);
                size_t at = response.find('@');
                target = response.substr(at + 1, pos - at - 2);
                std::string ack = "@" + target + " __E2E_ACK__" + std::string(my_pub_hex);
                send(sock, ack.c_str(), ack.length(), 0);
                e2e_active = true;
                last_rekey = time(nullptr);
                std::cout << "[E2E] Session established/rotated with " << target << "\n";

                BN_free(shared); BN_free(peer_pub); BN_CTX_free(ctx);
                OPENSSL_free(my_pub_hex);
            } else if (response.find("__E2E_ACK__") != std::string::npos) {
                e2e_active = true;
                last_rekey = time(nullptr);
                std::cout << "[E2E] Key rotation acknowledged.\n";
            } else {
                std::cout << response << "\n";
            }
        }
    }
    return 0;
}
#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define PORT 8080
#define BUFFER_SIZE 2048

const char* HEX_PRIME = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
const char* GENERATOR = "2";

unsigned char e2e_session_key[32];
bool e2e_established = false;

void generate_dh(BIGNUM **priv, BIGNUM **pub, const BIGNUM *p, const BIGNUM *g) {
    BN_CTX *ctx = BN_CTX_new();
    *priv = BN_new();
    *pub = BN_new();
    BN_rand(*priv, 256, 0, 0);
    BN_mod_exp(*pub, g, *priv, p, ctx);
    BN_CTX_free(ctx);
}

void derive_key(const BIGNUM *secret, unsigned char *key_out) {
    unsigned char buf[256];
    int len = BN_bn2bin(secret, buf);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, buf, len);
    unsigned int out_len;
    EVP_DigestFinal_ex(mdctx, key_out, &out_len);
    EVP_MD_CTX_free(mdctx);
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <username>\n";
        return -1;
    }

    std::string username = argv[1];
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "192.168.56.10", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed.\n";
        return -1;
    }
    send(sock, username.c_str(), username.length(), 0);

    BIGNUM *p = BN_new(), *g = BN_new();
    BN_hex2bn(&p, HEX_PRIME);
    BN_hex2bn(&g, GENERATOR);

    BIGNUM *my_priv = nullptr, *my_pub = nullptr;
    fd_set readfds;
    std::string current_target = "";

    std::cout << "Connected as " << username << ". Use /e2e <username> to start E2E session[cite: 1].\n";

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        int max_sd = sock > STDIN_FILENO ? sock : STDIN_FILENO;
        select(max_sd + 1, &readfds, nullptr, nullptr, nullptr);

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            std::string input;
            if (!std::getline(std::cin, input)) break;

            if (input.rfind("/e2e ", 0) == 0) {
                current_target = input.substr(5);
                generate_dh(&my_priv, &my_pub, p, g);
                char *pub_hex = BN_bn2hex(my_pub);
                std::string wire = "@" + current_target + " __E2E_INIT__" + std::string(pub_hex);
                send(sock, wire.c_str(), wire.length(), 0);
                std::cout << "[E2E] Sent E2E initialization to " << current_target << "\n";
                OPENSSL_free(pub_hex);
            } else if (!input.empty() && input[0] == '@') {
                size_t space_pos = input.find(' ');
                if (space_pos != std::string::npos) {
                    current_target = input.substr(1, space_pos - 1);
                }
            } else {
                if (e2e_established && !current_target.empty()) {
                    std::string wire = "@" + current_target + " __E2E_MSG__" + input;
                    send(sock, wire.c_str(), wire.length(), 0);
                } else if (!current_target.empty()) {
                    std::string wire = "@" + current_target + " " + input;
                    send(sock, wire.c_str(), wire.length(), 0);
                } else {
                    std::cout << "Select a target partner first using @username or /e2e username[cite: 1].\n";
                }
            }
        }

        if (FD_ISSET(sock, &readfds)) {
            char response[BUFFER_SIZE];
            memset(response, 0, BUFFER_SIZE);
            int valread = read(sock, response, BUFFER_SIZE);
            if (valread <= 0) {
                std::cout << "Server disconnected.\n";
                break;
            }

            std::string resp_str(response);
            if (resp_str.find("__E2E_INIT__") != std::string::npos) {
                size_t at_pos = resp_str.find('@');
                size_t tag_pos = resp_str.find("__E2E_INIT__");
                std::string sender = resp_str.substr(at_pos + 1, tag_pos - at_pos - 2);
                std::string pub_hex = resp_str.substr(tag_pos + 12);
                current_target = sender;

                generate_dh(&my_priv, &my_pub, p, g);
                BIGNUM *peer_pub = nullptr;
                BN_hex2bn(&peer_pub, pub_hex.c_str());
                
                BIGNUM *shared = BN_new();
                BN_CTX *ctx = BN_CTX_new();
                BN_mod_exp(shared, peer_pub, my_priv, p, ctx);
                derive_key(shared, e2e_session_key);
                e2e_established = true;

                char *my_pub_hex = BN_bn2hex(my_pub);
                std::string ack_wire = "@" + sender + " __E2E_ACK__" + std::string(my_pub_hex);
                send(sock, ack_wire.c_str(), ack_wire.length(), 0);
                std::cout << "[E2E] Established secure E2E session with " << sender << "[cite: 1]!\n";
                
                BN_free(shared);
                BN_free(peer_pub);
                BN_CTX_free(ctx);
                OPENSSL_free(my_pub_hex);
            } else if (resp_str.find("__E2E_ACK__") != std::string::npos) {
                size_t at_pos = resp_str.find('@');
                size_t tag_pos = resp_str.find("__E2E_ACK__");
                std::string sender = resp_str.substr(at_pos + 1, tag_pos - at_pos - 2);
                std::string pub_hex = resp_str.substr(tag_pos + 11);
                
                BIGNUM *peer_pub = nullptr;
                BN_hex2bn(&peer_pub, pub_hex.c_str());
                BIGNUM *shared = BN_new();
                BN_CTX *ctx = BN_CTX_new();
                BN_mod_exp(shared, peer_pub, my_priv, p, ctx);
                derive_key(shared, e2e_session_key);
                e2e_established = true;
                std::cout << "[E2E] Acknowledged and established secure E2E session with " << sender << "[cite: 1]!\n";

                BN_free(shared);
                BN_free(peer_pub);
                BN_CTX_free(ctx);
            } else if (resp_str.find("__E2E_MSG__") != std::string::npos) {
                size_t tag_pos = resp_str.find("__E2E_MSG__");
                std::string decrypted_payload = resp_str.substr(tag_pos + 11);
                std::cout << "[E2E Message Received] " << decrypted_payload << "\n";
            } else {
                std::cout << response << "\n";
            }
        }
    }

    BN_free(p);
    BN_free(g);
    if (my_priv) BN_free(my_priv);
    if (my_pub) BN_free(my_pub);
    close(sock);
    return 0;
}
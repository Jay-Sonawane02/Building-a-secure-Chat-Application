#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <map>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "../common/aes_gcm.h"
#include "../common/dh.h"
#include "../common/sha256.h"
#include "../common/framing.h"
#include "../common/crypto_channel.h"

std::atomic<bool> running(true);
std::map<std::string, std::string> e2e_keys;
std::map<std::string, BIGNUM*> pending_private_keys;
std::string active_chat_partner = "";

void print_e2e_fingerprint(const unsigned char* key_buf, size_t len) {
    unsigned char hash[32];
    sha256_hash(key_buf, len, hash);
    std::cout << "[E2E FINGERPRINT] SHA256: ";
    for(int i = 0; i < 8; ++i) {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;
}

void handle_e2e_command(EncryptedChannel& channel, const std::string& peer_username) {
    DHKeypair kp = generate_dh_keypair();
    pending_private_keys[peer_username] = kp.private_key;
    std::string pub_hex = bn_to_hex(kp.public_key);
    std::string packet = "@" + peer_username + " __E2E_INIT__" + pub_hex;
    channel.send_message(packet);
    std::cout << "[E2E] Initiated key exchange with " << peer_username << std::endl;
    BN_free(kp.public_key);
}

void receive_messages(EncryptedChannel& channel, std::string username) {
    std::string line;
    while (running && channel.recv_message(line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string sender = line.substr(0, colon);
        std::string payload = line.substr(colon + 1);

        if (payload.find("__E2E_INIT__") == 0) {
            std::string pub_hex = payload.substr(12);
            DHKeypair kp = generate_dh_keypair();
            BIGNUM* peer_pub = hex_to_bn(pub_hex);
            BIGNUM* shared_secret = compute_dh_shared_secret(peer_pub, kp.private_key);

            unsigned char secret_buf[256];
            int secret_len = BN_bn2bin(shared_secret, secret_buf);
            unsigned char aes_key[32];
            sha256_hash(secret_buf, secret_len, aes_key);

            e2e_keys[sender] = std::string((char*)aes_key, 32);
            std::cout << "\n[E2E] Established secure session with " << sender << std::endl;
            print_e2e_fingerprint(aes_key, 32);

            std::string my_pub_hex = bn_to_hex(kp.public_key);
            std::string ack_msg = "@" + sender + " __E2E_ACK__" + my_pub_hex;
            channel.send_message(ack_msg);

            BN_free(peer_pub);
            BN_free(shared_secret);
            BN_free(kp.public_key);
            BN_free(kp.private_key);
        } else if (payload.find("__E2E_ACK__") == 0) {
            std::string pub_hex = payload.substr(11);
            if (pending_private_keys.find(sender) != pending_private_keys.end()) {
                BIGNUM* peer_pub = hex_to_bn(pub_hex);
                BIGNUM* shared_secret = compute_dh_shared_secret(peer_pub, pending_private_keys[sender]);

                unsigned char secret_buf[256];
                int secret_len = BN_bn2bin(shared_secret, secret_buf);
                unsigned char aes_key[32];
                sha256_hash(secret_buf, secret_len, aes_key);

                e2e_keys[sender] = std::string((char*)aes_key, 32);
                std::cout << "\n[E2E] Acknowledged secure session with " << sender << std::endl;
                print_e2e_fingerprint(aes_key, 32);

                BN_free(peer_pub);
                BN_free(shared_secret);
                pending_private_keys.erase(sender);
            }
        } else if (payload.find("__E2E_MSG__") == 0) {
            std::string ciphertext = payload.substr(11);
            if (e2e_keys.find(sender) != e2e_keys.end()) {
                std::string plaintext = aes_gcm_decrypt(ciphertext, e2e_keys[sender]);
                std::cout << "\n[" << sender << " (E2E)]: " << plaintext << "\n> ";
            }
        } else {
            std::cout << "\n[" << sender << "]: " << payload << "\n> ";
        }
    }
}

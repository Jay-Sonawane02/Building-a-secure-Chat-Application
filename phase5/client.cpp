#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <map>
#include <chrono>
#include <mutex>
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
std::mutex key_mutex;
int rekey_counter = 0;

void print_rotation_fingerprint(const std::string& partner, const std::string& key_str) {
    unsigned char hash[32];
    sha256_hash((unsigned char*)key_str.data(), key_str.size(), hash);
    auto now = std::chrono::system_clock::now();
    std::time_t time_now = std::chrono::system_clock::to_time_t(now);
    
    std::cout << "\n[REKEY TIMESTAMP] " << std::ctime(&time_now);
    std::cout << "[REKEY FINGERPRINT] Partner: " << partner << " | SHA256: ";
    for(int i = 0; i < 8; ++i) {
        printf("%02x", hash[i]);
    }
    std::cout << "\n> ";
}

void automatic_rekey_worker(EncryptedChannel& channel, std::string username, std::string partner) {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        if (partner.empty()) continue;

        if (username < partner) {
            std::lock_guard<std::mutex> lock(key_mutex);
            rekey_counter++;

            DHKeypair kp = generate_dh_keypair();
            std::string pub_hex = bn_to_hex(kp.public_key);
            std::string rekey_packet = "@" + partner + " __E2E_INIT__" + pub_hex;
            channel.send_message(rekey_packet);

            // Temporarily store pending private key for handshake completion
            // Update active key upon receiving ACK
            BN_free(kp.public_key);
            BN_free(kp.private_key);
        }
    }
}

void secure_zero_memory(std::string& key) {
    if (!key.empty()) {
        OPENSSL_cleanse(&key[0], key.size());
        key.clear();
    }
}

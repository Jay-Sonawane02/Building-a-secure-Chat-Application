// Phase 2 - AES-GCM Tamper Detection Demonstration (spec 3.2)
//
// This is a self-contained, isolated demonstration of the property the
// live chat already enforces on every message (see crypto_channel.h's
// recv_encrypted, which returns TAMPER_DETECTED and discards the message
// rather than processing it): flipping a single bit anywhere in an
// AES-GCM ciphertext or its authentication tag causes decryption to fail
// loudly, rather than silently producing corrupted plaintext.
//
// Run with no arguments for a quick self-check; run with a message string
// to encrypt/tamper/decrypt that specific message instead.
#include <iostream>
#include <random>
#include <string>

#include "../common/aes_gcm.h"

static std::string to_hex(const std::vector<uint8_t> &v) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (uint8_t b : v) {
        out += digits[(b >> 4) & 0xF];
        out += digits[b & 0xF];
    }
    return out;
}

int main(int argc, char *argv[]) {
    std::string plaintext =
        argc > 1 ? argv[1] : "This is a confidential Phase 2 test message.";

    // A random key/nonce is fine for this isolated demo -- the point being
    // demonstrated is GCM's tamper detection, not a live session's key
    // material (which is never printed anywhere in the real app).
    std::vector<uint8_t> key(aesgcm::KEY_LEN);
    std::vector<uint8_t> nonce(aesgcm::NONCE_LEN);
    std::random_device rd;
    for (auto &b : key) b = static_cast<uint8_t>(rd());
    for (auto &b : nonce) b = static_cast<uint8_t>(rd());

    std::cout << "=== Phase 2 AES-GCM Tamper Detection Test ===\n\n";
    std::cout << "Plaintext:  \"" << plaintext << "\"\n";

    auto ciphertext = aesgcm::encrypt(key.data(), nonce.data(), plaintext);
    std::cout << "Ciphertext+tag (hex): " << to_hex(ciphertext) << "\n\n";

    // --- Baseline: decrypt the UNMODIFIED ciphertext, should succeed ---
    std::string recovered;
    bool ok = aesgcm::decrypt(key.data(), nonce.data(), ciphertext, recovered);
    std::cout << "[1] Decrypting UNMODIFIED ciphertext...\n";
    if (ok) {
        std::cout << "    SUCCESS. Recovered plaintext: \"" << recovered << "\"\n\n";
    } else {
        std::cout << "    UNEXPECTED FAILURE (this should not happen)\n\n";
        return 1;
    }

    // --- Tamper: flip a single bit somewhere in the ciphertext body ---
    auto tampered = ciphertext;
    size_t flip_index = tampered.size() / 2;  // somewhere in the middle
    uint8_t original_byte = tampered[flip_index];
    tampered[flip_index] ^= 0x01;  // flip the lowest bit of one byte
    std::cout << "[2] Flipping one bit at byte offset " << flip_index
              << " (0x" << std::hex << (int)original_byte << " -> 0x"
              << (int)tampered[flip_index] << std::dec << ")\n";
    std::cout << "    Tampered ciphertext+tag (hex): " << to_hex(tampered) << "\n\n";

    // --- Attempt to decrypt the tampered ciphertext ---
    std::string tampered_result;
    bool tampered_ok =
        aesgcm::decrypt(key.data(), nonce.data(), tampered, tampered_result);
    std::cout << "[3] Attempting to decrypt TAMPERED ciphertext...\n";
    if (!tampered_ok) {
        std::cout << "    REJECTED as expected: GCM authentication tag mismatch.\n"
                   << "    No plaintext was produced -- this is the tamper-\n"
                   << "    detection property AES-GCM provides over plain AES.\n";
    } else {
        std::cout << "    UNEXPECTED: tampered ciphertext was accepted! ("
                   << "recovered garbage: \"" << tampered_result << "\")\n"
                   << "    This should never happen with correct GCM usage.\n";
        return 1;
    }

    std::cout << "\n=== Test complete: tamper detection working correctly ===\n";
    return 0;
}

// SHA-256 via OpenSSL's EVP digest API (<openssl/evp.h> is an allowed
// primitive). Used for two distinct purposes in Phase 2:
//   1. Deriving the AES key from the raw DH shared secret (key = SHA256(secret))
//   2. Computing a printable "fingerprint" of that key (fingerprint =
//      SHA256(key)) so we can display proof both sides agree WITHOUT ever
//      printing the raw secret or the key itself, per the spec's
//      verification requirement.
#pragma once

#include <openssl/evp.h>

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sha256 {

constexpr size_t DIGEST_LEN = 32;

inline std::vector<uint8_t> hash(const uint8_t *data, size_t len) {
    std::vector<uint8_t> out(DIGEST_LEN);
    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, out.data(), &out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA-256 hashing failed");
    }
    EVP_MD_CTX_free(ctx);
    out.resize(out_len);
    return out;
}

inline std::vector<uint8_t> hash(const std::vector<uint8_t> &data) {
    return hash(data.data(), data.size());
}

inline std::string to_hex(const std::vector<uint8_t> &bytes) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out += digits[(b >> 4) & 0xF];
        out += digits[b & 0xF];
    }
    return out;
}

}  // namespace sha256

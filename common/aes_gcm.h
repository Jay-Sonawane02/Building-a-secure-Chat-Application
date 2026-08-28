// AES-256-GCM authenticated encryption, built on OpenSSL's EVP API
// (<openssl/evp.h> is an explicitly allowed primitive per the assignment).
//
// AES-GCM gives confidentiality AND integrity in one primitive: tampering
// with the ciphertext causes the authentication tag check to fail, so
// decrypt() returns false rather than silently producing corrupted output.
// This is the property the Phase 2 tamper-detection test demonstrates.
#pragma once

#include <openssl/evp.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace aesgcm {

constexpr size_t KEY_LEN = 32;    // AES-256
constexpr size_t NONCE_LEN = 12;  // standard GCM nonce size
constexpr size_t TAG_LEN = 16;    // standard GCM tag size

// Encrypts `plaintext` under `key` (32 bytes) and `nonce` (12 bytes).
// Returns ciphertext with the 16-byte auth tag appended at the end.
// Caller must guarantee (key, nonce) is never reused -- see crypto_channel.h
// for how nonces are constructed to guarantee this across the session.
inline std::vector<uint8_t> encrypt(const uint8_t *key, const uint8_t *nonce,
                                     const std::string &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> out(plaintext.size() + TAG_LEN);
    int len = 0, out_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM encrypt init failed");
    }

    if (EVP_EncryptUpdate(ctx, out.data(), &len,
                           reinterpret_cast<const uint8_t *>(plaintext.data()),
                           static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM encrypt update failed");
    }
    out_len = len;

    if (EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM encrypt final failed");
    }
    out_len += len;

    // Fetch and append the 16-byte authentication tag.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
                             out.data() + out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM get tag failed");
    }
    out_len += TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    out.resize(out_len);
    return out;
}

// Decrypts `ciphertext_and_tag` (ciphertext with 16-byte tag appended) under
// `key`/`nonce`. Returns true and fills `plaintext_out` on success; returns
// false (WITHOUT producing any output) if the authentication tag does not
// match -- i.e. if the ciphertext was tampered with in transit.
inline bool decrypt(const uint8_t *key, const uint8_t *nonce,
                     const std::vector<uint8_t> &ciphertext_and_tag,
                     std::string &plaintext_out) {
    if (ciphertext_and_tag.size() < TAG_LEN) return false;
    size_t ct_len = ciphertext_and_tag.size() - TAG_LEN;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    std::vector<uint8_t> out(ct_len);
    int len = 0, out_len = 0;
    bool ok = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) {
        ok = false;
    }

    if (ok && EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext_and_tag.data(),
                                 static_cast<int>(ct_len)) != 1) {
        ok = false;
    }
    out_len = len;

    // Tell OpenSSL the expected tag value (the last 16 bytes we received).
    if (ok) {
        std::vector<uint8_t> tag(ciphertext_and_tag.begin() + ct_len,
                                  ciphertext_and_tag.end());
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag.data()) != 1) {
            ok = false;
        }
    }

    // EVP_DecryptFinal_ex returns <= 0 if the computed tag doesn't match the
    // one we were given -- THIS is the tamper-detection check in action.
    if (ok && EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len) != 1) {
        ok = false;
    } else if (ok) {
        out_len += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    out.resize(out_len);
    plaintext_out.assign(reinterpret_cast<char *>(out.data()), out.size());
    return true;
}

}  // namespace aesgcm

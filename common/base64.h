// Minimal base64 codec. Used purely so binary AES-GCM ciphertext (nonce +
// ciphertext + tag) can travel over our newline-delimited text framing as
// one clean line, same as Phase 1's framing scheme. Not a cryptographic
// operation -- just an encoding, like hex.
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace base64 {

inline std::string encode(const std::vector<uint8_t> &data) {
    static const char *table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += table[n & 0x3F];
        i += 3;
    }
    size_t rem = data.size() - i;
    if (rem == 1) {
        uint32_t n = data[i] << 16;
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += "=";
    }
    return out;
}

inline int decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;  // '=' padding or invalid
}

inline std::vector<uint8_t> decode(const std::string &s) {
    std::vector<uint8_t> out;
    out.reserve((s.size() / 4) * 3);

    int vals[4];
    size_t vi = 0;
    for (char c : s) {
        if (c == '=' || c == '\r' || c == '\n') continue;
        int v = decode_char(c);
        if (v < 0) throw std::runtime_error("invalid base64 character");
        vals[vi++] = v;
        if (vi == 4) {
            uint32_t n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
            out.push_back((n >> 16) & 0xFF);
            out.push_back((n >> 8) & 0xFF);
            out.push_back(n & 0xFF);
            vi = 0;
        }
    }
    if (vi == 2) {
        uint32_t n = (vals[0] << 18) | (vals[1] << 12);
        out.push_back((n >> 16) & 0xFF);
    } else if (vi == 3) {
        uint32_t n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6);
        out.push_back((n >> 16) & 0xFF);
        out.push_back((n >> 8) & 0xFF);
    }
    return out;
}

}  // namespace base64

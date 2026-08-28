// Ties together framing + base64 + AES-GCM into "send an encrypted line" /
// "receive and decrypt a line", used identically by the server, client, and
// (for the MITM demonstration) Mallory's proxy.
//
// NONCE CONSTRUCTION -- this is the part that's easy to get subtly wrong:
// A single DH exchange produces ONE shared key, used for traffic in BOTH
// directions on that link. If both sides independently started a
// message-counter at 0, the very first message from each side would reuse
// nonce=0 under the SAME key -- a catastrophic AES-GCM nonce-reuse bug.
// We avoid this by construction: each side tags its own outgoing nonces
// with a fixed 1-byte role marker (CLIENT_TO_SERVER vs SERVER_TO_CLIENT)
// that the other side never uses, so the two directions can never collide
// no matter what each side's counter value is. The nonce is sent inline
// with every message, so the receiver doesn't need to track counters at
// all -- it just decrypts with whatever nonce arrived.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "aes_gcm.h"
#include "base64.h"
#include "framing.h"

namespace channel {

enum Direction : uint8_t { CLIENT_TO_SERVER = 0x01, SERVER_TO_CLIENT = 0x02 };

inline std::vector<uint8_t> make_nonce(Direction dir, uint64_t counter) {
    std::vector<uint8_t> nonce(aesgcm::NONCE_LEN, 0);
    nonce[0] = static_cast<uint8_t>(dir);
    for (int i = 0; i < 8; ++i) {
        nonce[1 + i] = static_cast<uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
    }
    // bytes 9,10,11 stay zero -- 12 bytes total
    return nonce;
}

// Encrypts `plaintext` and sends it as one line. `counter` is the caller's
// own per-direction send counter; it is incremented on every call so the
// same nonce is never reused for this (key, direction) pair.
inline bool send_encrypted(int fd, const std::vector<uint8_t> &key, Direction dir,
                            uint64_t &counter, const std::string &plaintext) {
    std::vector<uint8_t> nonce = make_nonce(dir, counter++);
    std::vector<uint8_t> ct = aesgcm::encrypt(key.data(), nonce.data(), plaintext);

    std::vector<uint8_t> wire;
    wire.reserve(nonce.size() + ct.size());
    wire.insert(wire.end(), nonce.begin(), nonce.end());
    wire.insert(wire.end(), ct.begin(), ct.end());

    return send_line(fd, base64::encode(wire));
}

enum class RecvResult { OK, DISCONNECTED, TAMPER_DETECTED, MALFORMED };

// Receives one line, base64-decodes it, splits off the embedded nonce, and
// decrypts. Returns TAMPER_DETECTED (not a crash, not corrupted output) if
// the GCM authentication tag doesn't verify -- this is the tamper-detection
// property required by spec 3.2.
inline RecvResult recv_encrypted(LineReader &reader, const std::vector<uint8_t> &key,
                                  std::string &plaintext_out) {
    std::string line;
    if (!reader.recv_line(line)) return RecvResult::DISCONNECTED;

    std::vector<uint8_t> wire;
    try {
        wire = base64::decode(line);
    } catch (...) {
        return RecvResult::MALFORMED;
    }
    if (wire.size() < aesgcm::NONCE_LEN + aesgcm::TAG_LEN) return RecvResult::MALFORMED;

    std::vector<uint8_t> nonce(wire.begin(), wire.begin() + aesgcm::NONCE_LEN);
    std::vector<uint8_t> ct(wire.begin() + aesgcm::NONCE_LEN, wire.end());

    if (!aesgcm::decrypt(key.data(), nonce.data(), ct, plaintext_out)) {
        return RecvResult::TAMPER_DETECTED;
    }
    return RecvResult::OK;
}

}  // namespace channel

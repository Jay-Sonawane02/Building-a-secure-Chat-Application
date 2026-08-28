// Orchestrates one DH handshake over an already-connected socket, then
// derives the AES key and prints the verification fingerprint. Used
// identically whether you're the "server side" or "client side" of a given
// link -- Mallory's proxy reuses both roles (server-side towards the
// victim, client-side towards the real server) to pull off the MITM.
#pragma once

#include <openssl/bn.h>

#include <iostream>
#include <vector>

#include "dh.h"
#include "framing.h"
#include "sha256.h"

namespace handshake {

struct Result {
    std::vector<uint8_t> key;  // 32-byte AES-256 key = SHA256(shared secret)
    std::string fingerprint;   // hex(SHA256(key)) -- safe to print/compare
};

inline std::string compute_fingerprint(const std::vector<uint8_t> &key) {
    return sha256::to_hex(sha256::hash(key));
}

// NOTE: both functions take the caller's LineReader BY REFERENCE and keep
// using it afterward for the encrypted phase, rather than creating a local
// one that would go out of scope here. If the peer's handshake reply ever
// arrives in the same TCP segment as data that follows it, that trailing
// data would otherwise sit trapped in a reader object we throw away the
// moment this function returns -- silently losing the start of the
// encrypted stream. Sharing one LineReader for the connection's whole
// lifetime avoids that class of bug entirely.

// Whichever side sends its DH public value FIRST. In our protocol the
// server always speaks first (mirrors it presenting a certificate first in
// Phase 3), so this is used by server.cpp and, for the victim-facing side
// of the proxy, by mallory_proxy.cpp.
inline Result do_handshake_speak_first(int fd, LineReader &reader,
                                        const std::string &role_label) {
    BN_CTX *ctx = BN_CTX_new();
    dh::BNPtr p, g;
    dh::load_group(p, g);
    dh::Keypair mine = dh::generate_keypair(p, g, ctx);

    if (!send_line(fd, "DHPUB " + dh::pub_to_hex(mine.pub))) {
        BN_CTX_free(ctx);
        throw std::runtime_error("failed to send DH public value");
    }

    std::string line;
    if (!reader.recv_line(line) || line.rfind("DHPUB ", 0) != 0) {
        BN_CTX_free(ctx);
        throw std::runtime_error("did not receive peer's DH public value");
    }
    dh::BNPtr peer_pub = dh::hex_to_pub(line.substr(6));

    std::vector<uint8_t> secret = dh::compute_shared_secret(peer_pub, mine.priv, p, ctx);
    BN_CTX_free(ctx);

    Result r;
    r.key = sha256::hash(secret);
    r.fingerprint = compute_fingerprint(r.key);
    std::cout << "[" << role_label << "] DH handshake complete. Key fingerprint: "
              << r.fingerprint << std::endl;
    return r;
}

// Whichever side RECEIVES the peer's DH public value first, then replies
// with its own. Used by client.cpp, and by mallory_proxy.cpp for its
// outbound leg towards the real server.
inline Result do_handshake_listen_first(int fd, LineReader &reader,
                                         const std::string &role_label) {
    BN_CTX *ctx = BN_CTX_new();
    dh::BNPtr p, g;
    dh::load_group(p, g);
    dh::Keypair mine = dh::generate_keypair(p, g, ctx);

    std::string line;
    if (!reader.recv_line(line) || line.rfind("DHPUB ", 0) != 0) {
        BN_CTX_free(ctx);
        throw std::runtime_error("did not receive peer's DH public value");
    }
    dh::BNPtr peer_pub = dh::hex_to_pub(line.substr(6));

    if (!send_line(fd, "DHPUB " + dh::pub_to_hex(mine.pub))) {
        BN_CTX_free(ctx);
        throw std::runtime_error("failed to send DH public value");
    }

    std::vector<uint8_t> secret = dh::compute_shared_secret(peer_pub, mine.priv, p, ctx);
    BN_CTX_free(ctx);

    Result r;
    r.key = sha256::hash(secret);
    r.fingerprint = compute_fingerprint(r.key);
    std::cout << "[" << role_label << "] DH handshake complete. Key fingerprint: "
              << r.fingerprint << std::endl;
    return r;
}

}  // namespace handshake

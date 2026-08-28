// Diffie-Hellman key exchange, built from BIGNUM primitives.
//
// Per the assignment's allowed-tools list and TA clarification: functions
// with "DH" or "Diffie-Hellman" in their name (DH_generate_key,
// DH_compute_key, EVP_PKEY_derive used for DH, anything from
// <openssl/dh.h>) are NOT allowed, since those run the whole exchange for
// you. BN_mod_exp IS allowed -- it's a generic big-integer primitive, not
// DH-specific. This file implements the actual DH *protocol logic*
// ourselves (exponent generation, exchange sequencing, shared-secret
// derivation) using BN_mod_exp as the underlying arithmetic tool, which is
// exactly what the assignment expects.
#pragma once

#include <openssl/bn.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "dh_params.h"

namespace dh {

// RAII wrapper so we don't have to manually BN_free() everywhere.
struct BNDeleter {
    void operator()(BIGNUM *b) const { BN_free(b); }
};
using BNPtr = std::unique_ptr<BIGNUM, BNDeleter>;

struct Keypair {
    BNPtr priv;  // random private exponent
    BNPtr pub;   // g^priv mod p
};

// Loads the standard, published RFC 3526 Group 14 (p, g) -- never generated
// ourselves, per spec.
inline void load_group(BNPtr &p, BNPtr &g) {
    BIGNUM *p_raw = nullptr, *g_raw = nullptr;
    if (BN_hex2bn(&p_raw, dhparams::P_HEX) == 0 ||
        BN_hex2bn(&g_raw, dhparams::G_HEX) == 0) {
        throw std::runtime_error("failed to parse DH group parameters");
    }
    p.reset(p_raw);
    g.reset(g_raw);
}

// Generates a fresh private exponent and computes the corresponding public
// value pub = g^priv mod p. A fresh keypair must be generated per
// connection (C1<->S and C2<->S each get their own, independent exchange).
inline Keypair generate_keypair(const BNPtr &p, const BNPtr &g, BN_CTX *ctx) {
    Keypair kp;

    // Private exponent: random value in roughly [1, p-1]. 256 random bits
    // gives ~128-bit security margin against discrete-log attacks -- more
    // than enough entropy for a 2048-bit group per RFC 3526's own guidance.
    BIGNUM *priv = BN_new();
    if (!priv || BN_rand(priv, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1) {
        throw std::runtime_error("failed to generate DH private exponent");
    }
    kp.priv.reset(priv);

    BIGNUM *pub = BN_new();
    if (!pub) throw std::runtime_error("BN_new failed");
    // pub = g^priv mod p -- the one generic bignum primitive the assignment
    // permits us to use directly for the modular exponentiation itself.
    if (BN_mod_exp(pub, g.get(), kp.priv.get(), p.get(), ctx) != 1) {
        BN_free(pub);
        throw std::runtime_error("BN_mod_exp failed while computing public value");
    }
    kp.pub.reset(pub);

    return kp;
}

// Computes the shared secret: peer_pub^my_priv mod p. Both sides compute
// this independently and arrive at the identical value g^(ab) mod p.
// Returns the raw secret as a FIXED-LENGTH byte string (zero-padded to the
// byte size of p via BN_bn2binpad) -- this matters because BN_bn2bin alone
// can silently drop leading zero bytes, which would make the two sides'
// "raw secret" byte strings different lengths in the rare case the shared
// value happens to start with a zero byte, breaking the hash-based key
// derivation. Padding to a fixed width avoids that class of bug entirely.
inline std::vector<uint8_t> compute_shared_secret(const BNPtr &peer_pub,
                                                   const BNPtr &my_priv,
                                                   const BNPtr &p, BN_CTX *ctx) {
    BIGNUM *shared = BN_new();
    if (!shared) throw std::runtime_error("BN_new failed");
    if (BN_mod_exp(shared, peer_pub.get(), my_priv.get(), p.get(), ctx) != 1) {
        BN_free(shared);
        throw std::runtime_error("BN_mod_exp failed while computing shared secret");
    }

    int width = BN_num_bytes(p.get());
    std::vector<uint8_t> out(width);
    if (BN_bn2binpad(shared, out.data(), width) < 0) {
        BN_free(shared);
        throw std::runtime_error("BN_bn2binpad failed");
    }
    BN_free(shared);
    return out;
}

// Hex encode/decode for putting a BIGNUM public value on the wire as plain
// text (public values are not secret -- they're transmitted openly in every
// real DH exchange, including this one).
inline std::string pub_to_hex(const BNPtr &pub) {
    char *hex = BN_bn2hex(pub.get());
    std::string s(hex);
    OPENSSL_free(hex);
    return s;
}

inline BNPtr hex_to_pub(const std::string &hex) {
    BIGNUM *b = nullptr;
    if (BN_hex2bn(&b, hex.c_str()) == 0) {
        throw std::runtime_error("failed to parse peer's DH public value");
    }
    return BNPtr(b);
}

}  // namespace dh

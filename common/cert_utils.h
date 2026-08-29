// X.509 certificate loading, chain validation, and proof-of-possession
// signing/verification, using OpenSSL's <openssl/x509.h> and <openssl/evp.h>
// (both explicitly allowed primitives). No TLS/SSL library involved -- this
// is us doing the certificate exchange and validation logic ourselves, per
// spec 4.1.
#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ctime>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "base64.h"

namespace cert {

struct X509Deleter {
    void operator()(X509 *c) const { X509_free(c); }
};
struct PKeyDeleter {
    void operator()(EVP_PKEY *k) const { EVP_PKEY_free(k); }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyDeleter>;

// --- Loading from disk (server loads its own cert+key; client loads ca.crt) ---

inline X509Ptr load_cert_from_file(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) throw std::runtime_error("cannot open certificate file: " + path);
    X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!cert) throw std::runtime_error("failed to parse certificate: " + path);
    return X509Ptr(cert);
}

inline PKeyPtr load_private_key_from_file(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp) throw std::runtime_error("cannot open private key file: " + path);
    EVP_PKEY *key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!key) throw std::runtime_error("failed to parse private key: " + path);
    return PKeyPtr(key);
}

// --- Putting a certificate on the wire (DER bytes, base64-encoded as one line) ---

inline std::string cert_to_wire(const X509Ptr &cert) {
    uint8_t *der = nullptr;
    int len = i2d_X509(cert.get(), &der);
    if (len < 0) throw std::runtime_error("i2d_X509 failed");
    std::vector<uint8_t> bytes(der, der + len);
    OPENSSL_free(der);
    return base64::encode(bytes);
}

inline X509Ptr cert_from_wire(const std::string &b64) {
    std::vector<uint8_t> der = base64::decode(b64);
    const uint8_t *p = der.data();
    X509 *cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (!cert) throw std::runtime_error("failed to parse certificate from wire");
    return X509Ptr(cert);
}

// --- Validation (spec 4.1: signature, validity period, identity) ---

// Checks the cert's signature was produced by ca_cert's key pair. For a
// single self-signed root CA (no intermediates), this is sufficient chain
// validation -- X509_verify checks the signature over the cert's contents
// using the CA's public key.
inline bool signature_chains_to_ca(const X509Ptr &cert, const X509Ptr &ca_cert) {
    EVP_PKEY *ca_pubkey = X509_get_pubkey(ca_cert.get());
    if (!ca_pubkey) return false;
    int result = X509_verify(cert.get(), ca_pubkey);
    EVP_PKEY_free(ca_pubkey);
    return result == 1;
}

inline bool validity_period_ok(const X509Ptr &cert) {
    // X509_cmp_current_time returns <0 if the given time is in the past
    // (relative to now), >0 if in the future, 0 on error.
    int not_before = X509_cmp_current_time(X509_get0_notBefore(cert.get()));
    int not_after = X509_cmp_current_time(X509_get0_notAfter(cert.get()));
    // notBefore must be in the past (<0), notAfter must be in the future (>0).
    return not_before < 0 && not_after > 0;
}

inline std::string get_common_name(const X509Ptr &cert) {
    X509_NAME *name = X509_get_subject_name(cert.get());
    if (!name) return "";
    char buf[256] = {0};
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf) - 1);
    if (len < 0) return "";
    return std::string(buf);
}

struct ValidationResult {
    bool ok = false;
    std::string reason;  // filled in on failure, for logging/report evidence
};

// Runs all three required checks IN ORDER, stopping at the first failure --
// per spec 4.1, if validation fails for ANY reason the client must abort
// immediately and must not proceed to DH or send anything further. The
// caller is responsible for actually stopping (this function only reports).
inline ValidationResult validate_certificate(const X509Ptr &cert, const X509Ptr &ca_cert,
                                              const std::string &expected_cn) {
    if (!signature_chains_to_ca(cert, ca_cert)) {
        return {false, "signature does not chain to the trusted CA"};
    }
    if (!validity_period_ok(cert)) {
        return {false, "certificate is expired or not yet valid"};
    }
    std::string cn = get_common_name(cert);
    if (cn != expected_cn) {
        return {false, "certificate identifies '" + cn + "', expected '" + expected_cn + "'"};
    }
    return {true, "all checks passed"};
}

// --- Proof of possession: sign/verify a challenge value with RSA-SHA256 ---
// Ties "presents a valid certificate" to "controls the matching private key
// on THIS live connection" -- a copied .crt file alone cannot pass this.

inline std::vector<uint8_t> sign_challenge(const PKeyPtr &priv, const std::vector<uint8_t> &data) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, priv.get()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSignInit failed");
    }
    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, nullptr, &sig_len, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSign (length query) failed");
    }
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(ctx, sig.data(), &sig_len, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSign failed");
    }
    sig.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    return sig;
}

// Verifies `signature` over `data` using the PUBLIC KEY EMBEDDED IN THE
// ALREADY-VALIDATED CERTIFICATE -- this is what ties the live connection to
// the specific identity the certificate vouched for.
inline bool verify_challenge(const X509Ptr &cert, const std::vector<uint8_t> &data,
                              const std::vector<uint8_t> &signature) {
    EVP_PKEY *pub = X509_get_pubkey(cert.get());
    if (!pub) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pub);
        return false;
    }
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pub) == 1) {
        ok = EVP_DigestVerify(ctx, signature.data(), signature.size(), data.data(),
                               data.size()) == 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pub);
    return ok;
}

}  // namespace cert

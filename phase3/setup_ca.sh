#!/bin/bash
# Phase 3 - CA and certificate setup (spec 4.1, 4.3)
#
# Run this ONCE, on the Server VM (the CA is hosted here per spec 1.2.1:
# "CA can be hosted on the Server VM"). It produces:
#   ca.key, ca.crt        -- your Certificate Authority (ca.key is SECRET,
#                            never copy it anywhere; ca.crt is PUBLIC and
#                            gets distributed to Client1/Client2/Mallory so
#                            they can validate against it)
#   server.key, server.crt -- the real, CA-signed server identity
#   wrong_key.key          -- a DIFFERENT private key, used only by
#                            stolen_cert_attacker.cpp to demonstrate that a
#                            copied cert file without the matching private
#                            key fails proof-of-possession (spec 4.2)
#   mallory.key, mallory.crt -- a SELF-signed cert (NOT signed by ca.key),
#                            used only by mallory_proxy.cpp to demonstrate
#                            that Mallory cannot forge a certificate that
#                            passes chain validation (spec 4.2)
set -e

EXPECTED_CN="chatserver.local"

echo "=== 1. Certificate Authority: private key + self-signed root cert ==="
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.crt \
    -subj "/CN=MyChatCA"

echo ""
echo "=== 2. Server key pair + CSR ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=${EXPECTED_CN}"

echo ""
echo "=== 3. CA signs the server's CSR -> genuine server certificate ==="
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256

echo ""
echo "=== 4. [Attacker material] A DIFFERENT private key, for the ==="
echo "===    stolen-cert-without-key test (spec 4.2)              ==="
openssl genrsa -out wrong_key.key 2048

echo ""
echo "=== 5. [Attacker material] Mallory's SELF-signed cert, NOT   ==="
echo "===    signed by the real CA, for the MITM re-attempt        ==="
echo "===    (spec 4.2). Same CN to be maximally deceptive.        ==="
openssl req -x509 -newkey rsa:2048 -nodes -keyout mallory.key -out mallory.crt \
    -days 365 -subj "/CN=${EXPECTED_CN}"

echo ""
echo "=== Done. Files produced in $(pwd): ==="
ls -la ca.key ca.crt server.key server.csr server.crt wrong_key.key mallory.key mallory.crt

echo ""
echo "NEXT STEP: copy ca.crt (ONLY ca.crt, never ca.key) to Client1 and"
echo "Client2 so they have a trusted copy to validate against."
echo "Copy mallory.crt + mallory.key to the Mallory VM for the MITM re-test."
echo "Copy server.crt + wrong_key.key to wherever you run stolen_cert_attacker."

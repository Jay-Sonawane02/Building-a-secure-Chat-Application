# Phase 2 — Client-Server Confidentiality via Diffie-Hellman

Each client independently establishes an AES-256-GCM session key with the
server via a hand-implemented Diffie-Hellman exchange (RFC 3526 Group 14,
2048-bit). All traffic after the handshake — including username
registration — is encrypted. Includes a MITM proxy that demonstrates why DH
alone doesn't authenticate who you're talking to.

## Files

- `../common/dh_params.h` — RFC 3526 Group 14 (p, g), verified against the RFC text
- `../common/dh.h` — DH keypair generation and shared-secret computation (uses `BN_mod_exp` directly — see note below)
- `../common/aes_gcm.h` — AES-256-GCM encrypt/decrypt via OpenSSL EVP
- `../common/base64.h` — self-contained base64 codec (carries binary ciphertext over the line-based framing)
- `../common/sha256.h` — SHA-256 hashing (key derivation + fingerprints)
- `../common/handshake.h` — orchestrates one DH handshake + key/fingerprint derivation
- `../common/crypto_channel.h` — encrypt-and-send / receive-and-decrypt, with nonce construction
- `../common/framing.h` — newline-delimited line framing (same scheme as Phase 1)
- `server.cpp`, `client.cpp` — the chat app itself
- `tamper_test.cpp` — standalone AES-GCM tamper-detection demonstration
- `mallory_proxy.cpp` — the MITM attack proxy


## Build (on every VM: Server, Client1, Client2, Mallory)

```bash
g++ -std=c++17 -pthread -Wall -Wextra -o server server.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o client client.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o tamper_test tamper_test.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o mallory_proxy mallory_proxy.cpp -lssl -lcrypto
```

## Run — normal operation (Server = 192.168.56.10, C1 = .11, C2 = .12)

On Server:
```bash
./server 5000
```
On Client1:
```bash
./client 192.168.56.10 5000 alice
```
On Client2:
```bash
./client 192.168.56.10 5000 bob
```

Each client prints a fingerprint right after connecting, e.g.:
```
Verify this fingerprint matches the server's log for your connection: 9f74c3ef...
```
Cross-check that value against the server's own log line for that
connection (`[server<-<ip:port>] DH handshake complete. Key fingerprint:
...`) — **spec 3.2 requires showing these match**. 

## Verification 1 — Wireshark re-capture (spec 3.2)

Repeat the exact same tcpdump/Wireshark process from Phase 1, on the same
port. This time, "Follow → TCP Stream" should show only random-looking
base64 ciphertext — no readable usernames or message text. 

## Verification 2 — Tamper detection test (spec 3.2)

```bash
./tamper_test
```
This is a self-contained demo: encrypts a message, flips one bit of the
resulting ciphertext, and shows decryption is rejected (GCM tag mismatch)
rather than producing corrupted output. You can also pass your own message:
```bash
./tamper_test "some other test string"
```

## Verification 3 — MITM attack (spec 3.3, run on Mallory VM = 192.168.56.13)

**Setup:** one client (the "victim") gets manually pointed at Mallory
instead of the real server. The other client connects normally.

On Mallory (`192.168.56.13`):
```bash
./mallory_proxy 5000 192.168.56.10 5000
```
(listens on port 5000, forwards to the real server at `192.168.56.10:5000`)

On Client2 (`bob`, normal — connects directly to the real server):
```bash
./client 192.168.56.10 5000 bob
```

On Client1 (`alice`, the **victim** — pointed at Mallory's IP instead):
```bash
./client 192.168.56.13 5000 alice
```

Then from alice's prompt: `@bob top secret message`

**What you'll see:**
- Alice's client prints a fingerprint that matches exactly what Mallory's
  log shows as the "victim-facing fingerprint" — from alice's point of
  view, everything looks like a normal, correctly-verified handshake.
- The real server's log shows a *different* fingerprint for "alice" — the
  one Mallory generated for its own connection to the server.
- Mallory's log shows lines like:
  ```
  [CAPTURED victim->server] alice
  [CAPTURED victim->server] @bob top secret message
  ```
  — full plaintext, despite both endpoints believing they have a secure,
  authenticated connection.
- Bob still receives the message correctly (`[alice]: top secret
  message`) — the attack is fully transparent; nothing breaks or looks
  wrong on either legitimate side.




- **Nonce construction**: since one DH exchange produces a single key used
  bidirectionally, nonces are tagged with a 1-byte role marker
  (client→server vs server→client) to guarantee the two directions can
  never collide on the same (key, nonce) pair, even though each side's
  message counter independently starts at 0.

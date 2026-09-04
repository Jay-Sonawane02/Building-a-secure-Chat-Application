# Phase 4 — End-to-End Encryption Between Clients

C1 and C2 establish a shared key directly with each other, invisible to
the server, triggered by `/e2e username`. This sits as an additional inner
layer on top of the Phase 3 client-server encrypted channel — the server's
routing logic is completely unchanged.

## Files

- `server.cpp` — **byte-for-byte identical to `phase3/server.cpp`**. This is intentional and is the point being demonstrated: the server never needs to understand E2E tags.
- `client.cpp` — Phase 3's client (cert validation, PoP, client-server DH) with the E2E layer added on top.

## Setup

Uses the same `ca.crt`/`server.crt`/`server.key` from `phase3/setup_ca.sh` — copy those over, or re-run the script here.

## Build

```bash
g++ -std=c++17 -pthread -Wall -Wextra -o server server.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o client client.cpp -lssl -lcrypto
```

## Run

```bash
./server 5000                              # Server VM
./client 192.168.56.10 5000 alice          # Client1
./client 192.168.56.10 5000 bob            # Client2
```

## Using E2E

```
/e2e bob            <- initiates a key exchange with bob, sets bob as current peer
hello securely      <- once the session is established, plain messages to
                        the current peer are automatically E2E-encrypted
```

You can still talk to a peer you haven't run `/e2e` with — those messages
fall back to plain Phase 2/3-style client-server encryption (server can
read them), exactly as before.

## Verification (spec 5.2)

**1. Fingerprint matching, independent of the server.** Both clients print
`[E2E] Session established/acknowledged with <peer>. Fingerprint: ...`
right after the exchange completes. Cross-check both sides show the
identical value. Note this fingerprint is computed entirely between C1 and
C2 — the server's own DH fingerprint (client-server link) is a completely
different, unrelated value.

**2. Server-blindness, before vs after.** Send one message to a peer
*before* running `/e2e`, then run `/e2e`, then send another message. The
server's log will show:
```
[RELAY] alice -> bob: before e2e, server can read this        <- fully readable
[RELAY] alice -> bob: __E2E_INIT__<hex>                        <- public DH value, not secret
[RELAY] bob -> alice: __E2E_ACK__<hex>                         <- public DH value, not secret
[RELAY] alice -> bob: __E2E_MSG__<base64 ciphertext>           <- OPAQUE, server cannot read this
```
Screenshot this single log — it contains both the "before" and "after"
states side by side already.

**3. Functional correctness.** Confirm the receiving client actually
displays the decrypted message: `[alice (E2E)]: <message>`.

## Design notes for the report

- **Wire tags** (exact strings, spec 1.4): `__E2E_INIT__`, `__E2E_ACK__`,
  `__E2E_MSG__`. These are just the *payload* of an ordinary
  `@username`-addressed message sent through the existing encrypted
  client-server channel — the server's relay code (`@target` → look up
  `target` → forward payload) never needed to change at all.
- **Double encryption / layering**: an E2E message is `AES-GCM_e2e(plaintext)`,
  tagged with `__E2E_MSG__`, and that whole string is then encrypted AGAIN
  via `channel::send_encrypted()` under the client-server key before
  hitting the socket. Two independent AEAD layers, two independent keys.
- **Nonce safety for the E2E layer**: the same problem as Phase 2's
  client-server link applies here — one DH exchange produces a single key
  used by both directions. Since both usernames are known to both sides,
  each side deterministically assigns itself a direction byte by comparing
  usernames (lexicographically smaller = `0x01`, larger = `0x02`) — both
  sides compute this the same way independently, so the two directions
  can never collide on a nonce.
- **Why the server can still see `__E2E_INIT__`/`__E2E_ACK__` in the
  clear**: these carry DH *public* values, which are not secret in any DH
  exchange — an eavesdropper (or the server) seeing them doesn't help
  derive the shared secret (discrete log problem). Only `__E2E_MSG__`
  needs to be opaque, since that's where the actual content lives.

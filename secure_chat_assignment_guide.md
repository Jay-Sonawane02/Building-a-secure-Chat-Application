# CS6008 Secure Chat Assignment — Complete Phase Guide

A working reference for all 5 phases: what to build, how to build it, what tools/libraries to use, and exactly what your report needs for each phase.

---

## Before Phase 1: One-time setup

**VMs (do this first, everything else depends on it):**
- 4 VMs on the same virtual network (VirtualBox/VMware "Internal Network" or "Host-only" mode works well): `Server`, `Client1`, `Client2`, `Mallory`.
- All Ubuntu/Debian-based is easiest for consistent package availability.
- Verify connectivity: `ping` between every pair of VMs before writing any code. Note down each VM's IP — you'll need a topology diagram for the report anyway, so record it now.

**Toolchain to install on every VM:**
```bash
sudo apt update
sudo apt install build-essential g++ libssl-dev wireshark tcpdump git openssl
```
- `libssl-dev` → gives you OpenSSL's `BN_*` (bignum), `EVP_*` (AES-GCM, SHA-256), and `X509_*` (cert parsing) headers/libs — these are the *only* OpenSSL pieces you're allowed to touch.
- `wireshark` → GUI capture (needs `sudo usermod -aG wireshark $USER` + relogin, or just run tcpdump and open the .pcap in Wireshark on your host).
- `git` → init a repo in your assignment root now, on day 1, before writing a line of code.

**Repo structure (set this up immediately):**
```
secure-chat-assignment/
├── .git/
├── phase1/   (server.cpp, client.cpp, README.md)
├── phase2/
├── phase3/
├── phase4/
├── phase5/
├── common/        ← shared code you reuse across phases (framing, DH, AES-GCM wrappers)
└── report.pdf
```
Commit after Phase 1 works, again after the Phase 2 MITM works, again after Phase 3 defeats it, etc. Don't batch commits at the end — the TA checks commit history/timestamps.

---

## Phase 1 — Baseline Chat (No Security)

### What it is
A TCP server that two clients connect to simultaneously. It's a pure relay — whatever C1 sends to C2 (or vice versa), the server just forwards, reading and understanding every byte. This phase is intentionally insecure — you're establishing the "bad" baseline that every later phase measurably improves on.

### Basics to know beforehand
- **TCP vs UDP:** TCP gives a reliable, ordered, connection-oriented byte *stream* — no built-in concept of "messages." This is why framing is a real design decision, not busywork: without it, `recv()` might hand you half a message, or two messages glued together, especially under load.
- **Client-server vs peer-to-peer:** the architecture here is client-server (Phase 4 layers a peer-to-peer key exchange *on top*, but bytes still physically flow through the server).
- **Blocking I/O and concurrency:** a naive server that calls `recv()` on one client blocks while waiting, and can't service a second client simultaneously unless you use threads (one per connection) or a multiplexed event loop (`select`/`poll`/`epoll`). Understand *why* this matters — you'll extend this same server through all 5 phases.

### How to build it
1. **Framing first.** TCP has no message boundaries — decide now and reuse everywhere. Simplest: newline-delimited text lines (works fine since chat is text). Every send appends `\n`; every receive buffers until it sees `\n`.
2. **Server design:** thread-per-client (easiest to reason about in C++) or `select()`/`poll()` in one thread. Maintain `std::map<std::string username, int socket_fd>`.
3. **Client registration:** first thing a client sends after connecting is its username (e.g. a `/login username` line or just a raw username line) — design this yourself and document it.
4. **Command parsing on the client**, per §1.3 of the spec:
   - `@username message` → send to `username`, set as `current_peer`
   - `/chat username` → just set `current_peer`, no send
   - `/who` → ask server for online users, server replies with the list
   - `/quit` → clean disconnect, close socket, exit
   - Anything else → treat as plain message to `current_peer`
5. **Server relay logic:** on receiving `@user:message` (however you encode the target), look up `user` in the map, forward to that socket. Log every relayed message to stdout (you need this for verification).

### Tools/libraries
- Pure POSIX sockets: `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `send()`, `recv()`.
- Nothing cryptographic yet.

### Report — what to include
- Protocol description: your framing scheme, how you define a "complete" message, how the server would route messages if more than 2 clients connected (even though only 2 are required, the spec asks you to reason about it).
- Server log screenshot showing it reads every relayed message in the clear.
- Wireshark screenshot: capture on the VM's interface (`eth0` or equivalent) filtered to your chat port, "Follow → TCP Stream," showing plaintext chat content.
- Brief VM topology note/diagram (IPs + roles) — spec asks for this alongside every phase's screenshots, so set the format now and reuse it.

---

## Phase 2 — Client↔Server Confidentiality via Diffie–Hellman

### What it is
Each client independently establishes a shared AES key with the server via hand-rolled DH, then all traffic on that link is AES-GCM encrypted. You then build a MITM proxy to prove DH alone (no authentication) is breakable.

Two separable pieces: the **key exchange** and the **encryption**. DH works like this: use a standard, published `(p, g)` pair (never generate your own prime). Each side picks a private random exponent (`a` for client, `b` for server), computes its public value (`A = g^a mod p`, `B = g^b mod p`), the public values are exchanged in the clear, and each side computes the same shared secret two ways: `B^a mod p = A^b mod p = g^(ab) mod p`. An eavesdropper who only sees `A`, `B`, `p`, `g` can't feasibly recover `a`, `b`, or the shared secret (discrete log problem) — but critically, DH *alone* proves nothing about who's on the other end, only that both sides agree on a secret. That gap is exactly what the MITM task below exploits.

### Basics to know beforehand
- **The discrete logarithm problem:** DH's security rests on: given `p`, `g`, and `A = g^a mod p`, it's computationally infeasible to recover `a`. Modular exponentiation is easy to compute forward but hard to invert — that asymmetry is the whole foundation. You should be able to state this in one sentence for your report.
- **Why "modular"?** Without the `mod p`, `g^a` would grow astronomically large. The modulus keeps values bounded inside a finite group while preserving the one-way property.
- **Symmetric vs asymmetric crypto:** DH produces a *shared secret* used for symmetric encryption (AES) — same key both directions, fast. This is distinct from asymmetric crypto (RSA, used in Phase 3 for certs/signatures) where you have separate public/private keys. Know which phase uses which and why.
- **Hash functions:** SHA-256 is one-way and deterministic — same input always gives the same output, but you can't reverse it. That's exactly what's needed to turn a DH secret into a key: deterministic (both sides derive the same key) but not reversible.
- **AEAD (Authenticated Encryption with Associated Data):** AES-GCM isn't just "AES but fancier" — it gives confidentiality (can't read it) *and* integrity/authenticity (can't modify it undetected) in one primitive. Plain AES (e.g. CBC mode) only gives confidentiality — an attacker could flip ciphertext bits and you'd decrypt to corrupted-but-*accepted* plaintext. GCM produces an authentication tag; tampering breaks the tag check, so decryption fails loudly instead of silently. This is the concept the Phase 2 tamper-test is designed to demonstrate.
- **Nonce/IV reuse:** reusing a nonce with the same key in GCM catastrophically breaks the security guarantees (can even leak the authentication key). Understand this before writing the encryption loop, not after a bug report.

### How to build it

**DH from scratch:**
1. Use a standard RFC 3526 MODP group (e.g. Group 14, 2048-bit) — hardcode the published `p` (hex string) and `g` (usually 2) as constants. Do not generate your own prime.
2. Represent big numbers with OpenSSL's `BIGNUM`/`BN_*` API — this is allowed as a low-level primitive.
3. Implement modular exponentiation yourself: square-and-multiply over `BN_mod_mul`/`BN_mod_sqr` (or `BN_mul`+`BN_mod`), looping over the bits of the exponent. **Do not call `BN_mod_exp`** — that's the library doing the modexp for you, which the spec disallows.
4. Each side: generate private random exponent (`BN_rand`), compute public value `= g^private mod p` via your modexp, exchange public values over the (still plaintext at this point) socket, then each computes `shared = peer_public^my_private mod p`.
5. **Hash it:** `SHA256(shared_secret_bytes)` → this becomes your AES-256-GCM key. Use `EVP_sha256()` via the EVP API. Never use the raw BIGNUM bytes directly as the AES key.
   - **Why hash it (put this reasoning in your report):** the raw DH output `g^(ab) mod p` isn't uniformly distributed over the AES key space — it's a number with mathematical structure (it will never land on certain values, and its bit distribution isn't ideal for a symmetric key). Hashing it with SHA-256 collapses it into a uniformly-distributed, fixed-length key. This is standard practice — essentially a stripped-down key-derivation-function (KDF) step.

**AES-GCM:**
- Use OpenSSL's EVP AEAD interface: `EVP_EncryptInit_ex`/`EVP_EncryptUpdate`/`EVP_EncryptFinal_ex` with `EVP_aes_256_gcm()`, plus `EVP_CIPHER_CTX_ctrl` to get/set the GCM tag.
- Each message needs a unique nonce (12 bytes is standard for GCM) — a per-message counter is simplest and safest (never reuse nonce+key).
- Wire format per message: `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`, then apply your Phase 1 framing on top of that blob (e.g. base64-encode it so it's still a clean text line, or switch to length-prefixed binary framing — either works, just document which).

**Independent exchanges:** C1↔S and C2↔S must be two separate DH runs with separate private exponents — don't reuse one exchange for both.

### Tools/libraries
- OpenSSL `BN_*` (bignum arithmetic — building block for your own modexp)
- OpenSSL `EVP_*` (AES-256-GCM, SHA-256)
- Your own DH/modexp code — this is the graded deliverable, not a library call

### Verification tasks (build these into the code, not just manually)
1. Print `SHA256(shared_secret)` truncated/hex-encoded as a "fingerprint" on both client and server — never print the raw secret or the AES key. Show they match.
2. Wireshark capture again on the same setup — content should now be unreadable.
3. Tamper test: grab a captured ciphertext (or flip a byte programmatically), feed it to the decrypt function, show `EVP_DecryptFinal_ex` returns failure (GCM tag mismatch) rather than producing garbage plaintext.

### The MITM attack you build
1. A standalone proxy program (`mitm_proxy.cpp`), run on the Mallory VM.
2. Manually configure the victim client to connect to Mallory's IP:port instead of the real server's.
3. Mallory accepts the client connection and performs DH **as if it were the server** (its own keypair, computes a shared secret with the real client).
4. Mallory separately opens a connection to the real server and performs DH **as if it were the client** (a second, independent shared secret).
5. On every message: decrypt with the client-side secret, log/print the plaintext, re-encrypt with the server-side secret and forward (and vice versa for server→client traffic).
6. Both client and server complete their handshake successfully and believe they're talking directly and securely to each other — neither has any way to know Mallory is in the middle, because nothing in the Phase 2 protocol ever checks *identity*, only that "someone" completed a valid DH exchange.

**Why the victim can't easily tell:** the client-side fingerprint check *correctly* matches what "the server" (actually Mallory) computed — because Mallory really did run a legitimate DH exchange with the client, it just also ran a second one with the real server. There's no cryptographic anomaly to detect from inside the protocol; the only way to catch this is out-of-band verification (e.g. reading the fingerprint aloud over a separate trusted channel like a phone call), which essentially nobody does in normal usage. This is precisely the motivation for Phase 3.

### Report — what to include
- DH implementation walkthrough + why you hash the shared secret before using it as a key (raw DH output isn't uniformly distributed over the key space; hashing gives you a well-distributed, fixed-length key — standard KDF practice).
- Fingerprint match evidence (both sides' printed output, side by side).
- Wireshark before/after screenshots (Phase 1 plaintext vs Phase 2 ciphertext).
- Tamper-detection test: show the byte-flip input and the resulting decryption failure/error.
- MITM section: proxy source code, logs showing captured plaintext, and — importantly — a written explanation of **what observable evidence (if any) would tip off the victim**, and why an ordinary user wouldn't notice (there's no identity check yet, so the client-side fingerprint *correctly* matches what "the server" — actually Mallory — computed; nothing looks wrong without out-of-band verification).

---

## Phase 3 — Server Authentication via PKI

### What it is
You fix exactly the gap Phase 2's MITM exploited: prove the server is who it claims to be, before doing DH at all. A cert alone proves an identity was *vouched for by the CA at some point in the past* — it doesn't prove that whoever is on the live connection right now actually controls the matching private key (they could have just copied the `.crt` file). Proof-of-possession is what ties "presents a valid cert" to "is the real entity on this specific connection, right now."

### Basics to know beforehand
- **The core problem PKI solves:** DH tells you "I share a secret with whoever's on the other end," never "who that is." PKI adds an *identity* layer on top.
- **Digital signatures:** RSA signing uses the *private* key to produce a signature over some data; anyone with the *public* key can verify it. Unlike encryption (secrecy), a signature's purpose is authenticity/non-repudiation — proof that "the holder of this private key produced/approved this data."
- **What a certificate actually is:** a data structure binding a public key to an identity (CN, org, etc.), digitally signed by a CA. Validating a cert really means checking: "did a CA I trust vouch for the binding between this public key and this identity?"
- **Chain of trust:** you trust the CA's root cert directly (you installed `ca.crt` yourself, out of band, before any of this runs). Everything else — the server cert — is trusted *transitively*, because the CA signed it. This is why the client needs its own local copy of `ca.crt` ahead of time; there's no bootstrapping trust from nothing.
- **Certificate ≠ live authentication:** this is the conceptual crux of Phase 3. Possessing a valid cert file proves nothing about *who's on the socket right now* — someone could have copied the file. Proof-of-possession (signing a fresh, connection-specific value with the private key) is what binds the cert to the live connection. This distinction is explicitly named in the assignment's learning objectives, so know it cold.

### How to build it

**1. Set up your CA (command-line OpenSSL, not code):**
```bash
# CA key + self-signed root cert
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/CN=MyChatCA"

# Server keypair + CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=chatserver.local"   # ← clients validate against this exact CN

# CA signs the server's CSR → server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256
```
Distribute `ca.crt` to both client VMs (this is the "trusted copy" they validate against). Server keeps `server.crt` + `server.key`.

**2. Protocol change — before DH:**
- Server sends `server.crt` (raw DER or PEM bytes) to the connecting client, as the very first thing after TCP connect.
- Client loads its local `ca.crt`, and validates the received cert using OpenSSL's `X509_*` / `X509_STORE_*` verification API (`X509_STORE_add_cert`, `X509_verify_cert`, or lower-level `X509_verify` against the CA's public key) — this is allowed since it's cert parsing/validation, not the TLS handshake itself.
- Checks required, in order, abort on first failure:
  - Signature chains to the trusted CA (`X509_verify`)
  - Validity period not expired (`X509_cmp_current_time` on notBefore/notAfter)
  - CN matches expected server identity (`X509_NAME_get_text_by_NID`)
- On any failure: close the connection immediately. No password, no DH public value sent, nothing.

**3. Proof-of-possession:**
- After cert validation passes, client sends a fresh random nonce (or use the DH public value once exchanged).
- Server signs it with `server.key` using `EVP_DigestSign` (RSA-SHA256 signature).
- Client verifies that signature using the **public key embedded in the cert it already validated** (`X509_get_pubkey` → `EVP_DigestVerify`).
- This proves the entity on *this specific connection* holds the private key — not just a copy of the cert file.

**4. Then proceed with Phase 2's DH + AES-GCM exactly as before**, now sitting on top of an authenticated channel.

### Tools/libraries
- OpenSSL CLI for CA/cert issuance (one-time setup, not runtime code)
- OpenSSL `X509_*` for parsing/validating certs at runtime
- OpenSSL `EVP_DigestSign`/`EVP_DigestVerify` for proof-of-possession signatures
- `openssl s_client -connect <server>:<port> -showcerts` — spec explicitly says use this to verify your cert setup manually

### Attack re-tests
1. **Re-run the Phase 2 MITM proxy** against this protocol. Mallory has no CA private key, so it can't produce a cert that validates. Client should abort at the cert-check step, before DH. Same Mallory VM/network position as Phase 2 (redo the ARP-spoof/redirect setup if you did the fully transparent variant). Screenshot the rejection, and explicitly contrast against the Phase 2 log where the same setup succeeded.
2. **Stolen-cert-only test:** copy `server.crt` to an attacker script that does *not* have `server.key`. Have it attempt proof-of-possession — it can't produce a valid signature over the nonce, client should reject. Show this log too.

### Report — what to include
- All OpenSSL CLI commands used to build the CA and issue the cert (copy-pasteable).
- Client/server code changes for cert exchange, validation, and proof-of-possession.
- Phase 2 MITM re-attempt: failure logs/screenshots, explicit "this worked in Phase 2, fails here because Mallory can't produce a CA-signed cert" statement.
- Stolen-cert-without-key test: attempt + rejection evidence.
- VM topology reminder (same format as before).

---

## Phase 4 — End-to-End Encryption Between Clients

### What it is
C1 and C2 derive a key directly with each other — the server relays bytes but can't read or derive the key. This layer sits *inside* the Phase 3 client-server encrypted channel (double encryption). The server MAY still see routing metadata (who's messaging whom, since it needs that to deliver), but must never be able to derive the C1↔C2 key or decrypt the content — that separation, enforced purely by tagging opaque payloads rather than changing the server's logic, is the actual design challenge of this phase.

### Basics to know beforehand
- **What "end-to-end" actually means:** encryption where only the two endpoints (not any intermediary, however trusted) can read the content. The server here is a "trusted-for-delivery, untrusted-for-content" relay — a common real-world pattern (e.g. Signal's servers route messages but can't read them).
- **Layered/nested encryption:** you're not replacing the Phase 3 client-server encryption, you're wrapping a second independent encrypted blob inside it. Phase 3 protects the *link* (C1↔S, S↔C2 individually); Phase 4 protects the *content* end-to-end regardless of what the server does with it. Both exist simultaneously for different threat models — link security stops a network eavesdropper between C1 and S; E2E stops even a *malicious server* from reading content.
- **Protocol multiplexing via tagging:** since handshake data and chat data travel over the same logical channel (`@username` routing), you need an application-level way to distinguish "this is a key-exchange control message" from "this is user content" without changing the transport layer. This is a standard real-world pattern (think HTTP headers vs. body, or MIME types) — recognizing that makes the tag scheme a normal protocol design tool, not a strange assignment quirk.

### How to build it

1. **Trigger:** `/e2e username` command on the client. Reuse your Phase 2 DH module (same MODP group, same modexp code) — no need to reinvent it.
2. **Wire tagging** (exact strings required by spec, don't rename):
   - `__E2E_INIT__<data>` — C1 → C2 (via server): C1's DH public value.
   - `__E2E_ACK__<data>` — C2 → C1 (via server): C2's DH public value, completing the exchange.
   - `__E2E_MSG__<data>` — actual chat content, encrypted under the derived C1↔C2 key.
3. **How this rides through the server unchanged:** these tagged strings are just the *payload* of an ordinary `@username` message. The server still does exactly what it did in Phase 1–3: look up `username`, forward the payload. It never parses the tag — it's opaque to the server. This is why the spec insists server routing code doesn't need to change.
4. **On the receiving client**, before displaying anything, check the payload prefix:
   - Starts with `__E2E_INIT__` → feed `<data>` into your DH state machine, respond with `__E2E_ACK__<my_public_value>`. Never show this to the user as chat.
   - Starts with `__E2E_ACK__` → feed into DH state machine, complete key derivation. Never show as chat.
   - Starts with `__E2E_MSG__` → AES-GCM decrypt `<data>` with the derived E2E key, display as chat. Never treat as a handshake step.
5. **Layering:** the tagged string (`__E2E_MSG__<ciphertext>` etc.) is exactly what gets passed down into your existing Phase 3 client→server AES-GCM encryption before hitting the socket. So a chat message is: `AES-GCM_serverlink( "__E2E_MSG__" + AES-GCM_e2e(plaintext) )`. Two independent AEAD layers, two independent keys.

### Tools/libraries
- Your existing DH module (Phase 2) and AES-GCM wrapper (Phase 2) — reused, not rewritten.
- No new libraries needed.

### Verification tasks
1. Print E2E key fingerprint independently on C1 and C2, show they match — and note in your report that the server logs show no DH exponents ever crossing it in a form it could use.
2. Instrument server-side logging (same log you built in Phase 1/2/3): capture what the server sees *before* `/e2e` is triggered (readable-after-decryption chat, same as Phase 2/3) vs. *after* (opaque `__E2E_MSG__<blob>` — server can route by username but the payload means nothing to it). Screenshot both, side by side.
3. Functional test: C1 sends a message post-handshake, confirm C2 decrypts and displays it correctly.

### Report — what to include
- Source code for the E2E key exchange and message wrapping/tagging logic.
- Fingerprint-match evidence (both clients, independently computed).
- Server log excerpt: pre-E2E (readable) vs post-E2E (opaque), clearly contrasted.
- Short note confirming the server's routing logic required zero changes — this demonstrates you understood the design constraint, not just the mechanics.

---

## Phase 5 — Forward Secrecy

### What it is
Auto-rotate the C1↔C2 E2E key every 60 seconds so that a future key compromise doesn't retroactively expose the whole conversation history — only the traffic from that one 60-second window. In Phase 4, if the single static session key is ever compromised (even after the fact), every past message encrypted under it becomes retroactively readable, assuming an attacker logged the ciphertext along the way. Forward secrecy closes that: because each time window uses a fresh, independent key that's destroyed after use, a leak of "the current key" doesn't unlock anything from before or after that window.

### Basics to know beforehand
- **What forward secrecy actually guarantees:** *past* session keys are not derivable from a *future* compromised key or long-term secret. It's specifically about protecting history, not about making the current moment more secure than Phase 4 already made it.
- **Why periodic re-keying achieves this:** each new key comes from a fresh DH exchange with fresh random exponents — it's not derived *from* the old key. If it were, compromising one key could let an attacker work backward or forward through a chain. Independence between successive keys is the property that matters, not just "the key changes."
- **Key lifecycle management:** generate → use → *actively destroy*. If an old key just sits unused in memory, it's still recoverable if an attacker later gets memory access — forward secrecy in the strict sense requires actually erasing it (zeroing the buffer), not just no longer referencing it.
- **Race conditions in distributed protocols:** two independent clocks (C1's timer, C2's timer) will never fire in perfect sync — that's a basic distributed-systems reality, not a bug to "fix" so much as something to design around. That's why the spec wants a justified strategy (e.g. asymmetric roles) rather than one specific correct answer.

### How to build it

1. **Timer:** on each client, a 60-second timer (thread with `sleep`/`nanosleep`, or a `timerfd` if you want it integrated into an event loop) triggers a rekey.
2. **Rekey = a fresh DH exchange**, reusing your Phase 4 machinery: run a new `__E2E_INIT__`/`__E2E_ACK__` round, derive a brand-new shared secret, hash it into a new AES key, **and explicitly zero out/discard the old key** (e.g. `memset` the old key buffer to 0, or otherwise ensure it's not reachable/reusable) once the new key is confirmed active on both sides.
3. **Collision avoidance (both sides' timers can fire near-simultaneously):** pick one clear strategy and justify it in the report. Simplest and safe: **asymmetric roles** — e.g., whichever peer has the lexicographically smaller username is always the one who initiates rekeys (sends `__E2E_INIT__` on its timer); the other peer never initiates on its own timer, it only ever responds with `__E2E_ACK__`. This structurally prevents the race — there's only ever one initiator.
   - Alternative if you want it fancier: tag each key with an incrementing epoch number, and if both sides somehow propose simultaneously, the side with (say) the higher proposed epoch/timestamp wins and the other discards its proposal. More complex — only do this if the simple role-based approach feels too easy for your report.
4. **Continuity across rotation:** tag each `__E2E_MSG__` with the epoch/key-version it was encrypted under (e.g. `__E2E_MSG__<epoch>:<ciphertext>`), so a message that was in flight during a rotation can still be decrypted with the correct (possibly just-retired) key on the receiving end — keep the *previous* key around briefly (a few seconds grace window) purely for draining in-flight messages, then discard it too.

### Tools/libraries
- Same DH + AES-GCM code as Phase 2/4, run repeatedly on a timer.
- POSIX timer/thread facilities (`std::thread` + `std::this_thread::sleep_for`, or `timerfd_create` if using an event loop).

### Verification tasks
1. Log fingerprint + timestamp on both clients at every rotation. Run the session long enough to capture at least 2 rotations. Show: (a) fingerprint changes each time, (b) both clients' logs show matching fingerprints after each rotation completes.
2. Send a chat message immediately after a rotation fires, confirm correct decryption on the receiving end (rotation didn't break the live session).

### Report — what to include
- Source for the rekey timer and your chosen collision-avoidance strategy, with justification for why you picked it over alternatives.
- Fingerprint + timestamp logs from both clients across ≥2 rotations.
- The post-rotation message delivery test (log/screenshot).
- **Written explanation (this is explicitly graded):** in your own words, what an attacker who compromises a single key can and cannot do. E.g.: compromising the key active during minute 5 exposes only traffic from that ~60-second window; it does not expose earlier or later traffic, because each window used an independent, now-discarded key. Contrast explicitly with Phase 4 alone, where one static session key for the whole conversation means a single compromise exposes everything, past and future, until the session ends.

---

## Report — full checklist across all phases

Your report is one PDF covering all 5 phases plus an LLM-prompt appendix. Suggested structure per phase (repeat this shape 5 times):

1. Implementation summary (design decisions: framing, threading model, etc.)
2. Verification results (fingerprints, Wireshark screenshots, logs) — as specified per phase above
3. Attack results where applicable (Phase 2, 3) — code + evidence + explanation
4. VM topology note/diagram (IPs + roles) alongside each phase's screenshots, so the TA can correlate captures to your network layout
5. Appendix: every LLM prompt you used, in full

---

## Suggested day-by-day pacing (14 days)

| Days | Focus |
|---|---|
| 1–2 | VM setup, networking verified, repo initialized, Phase 1 complete + committed |
| 3–5 | Phase 2: DH from scratch, AES-GCM, verification, MITM proxy |
| 6–8 | Phase 3: CA/PKI, cert validation, proof-of-possession, MITM re-test |
| 9–10 | Phase 4: E2E tagging scheme, layered encryption, server-blindness verification |
| 11–12 | Phase 5: rekey timer, collision handling, rotation verification |
| 13–14 | Report writing, screenshots, final Wireshark captures, buffer for bugs |

Build in slack — Phase 2's modexp-from-scratch and Phase 3's cert/PoP logic are usually where people lose the most time to subtle bugs (endianness in your DH byte encoding, nonce reuse in GCM, cert chain validation edge cases).

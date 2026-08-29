# Secure Chat Assignment — Handoff Guide (Phases 4, 5, and Report)

You're picking this up partway through. Jay has fully built, tested, and
evidenced **Phases 1–3** across a real 4-VM network. Your job is **Phase
4, Phase 5, and the final report**. This document takes you from "nothing
installed" to "ready to start coding Phase 4."

Read this top to bottom once before doing anything — it'll save you time.

---

## Part 0 — What is this assignment, in one paragraph

You're building a chat app in C++ over TCP sockets, hardened in 5
incremental phases: (1) plaintext relay, (2) Diffie-Hellman key exchange +
AES-GCM encryption between each client and the server, (3) PKI/certificates
so the server can prove its identity, (4) end-to-end encryption directly
between the two clients (invisible to the server), (5) automatic key
rotation every 60 seconds for forward secrecy. Phases 2 and 3 also require
you to build a MITM attack against your own earlier phase, to prove the
new security property actually works. Everything runs across 4 separate
Ubuntu VMs (Server, Client1, Client2, and an attacker VM called Mallory),
not on one machine via localhost.

---

## Part 1 — One-time computer setup

You'll need this even if Jay already has his own VMs running — you need
your **own** copies on your own machine to actually write and test Phase
4/5 code yourself.

### 1.1 Install VirtualBox

Download and install **Oracle VirtualBox** from virtualbox.org. Standard
installer, no special options needed.

### 1.2 Download Ubuntu Server

Go to **https://releases.ubuntu.com/noble/** and download
`ubuntu-24.04.x-live-server-amd64.iso` (the **Server** image, not
Desktop — no GUI needed, much lighter on resources since you're running 4
VMs at once). "AMD64" here just means "64-bit x86" — it works fine on
Intel processors too, that naming is historical.

If your PC is Windows: check that virtualization (Intel VT-x / AMD-V) is
enabled in your BIOS, and if you're on Windows 10/11 Pro, make sure
Hyper-V/WSL2 isn't conflicting with VirtualBox (disable them under "Turn
Windows features on or off" if VMs run very slowly or won't start).

### 1.3 Create a Host-only Network

In VirtualBox: **Tools → Network** (or **File → Host Network Manager** in
older versions) → **Host-only Networks** tab → there's usually already one
called `VirtualBox Host-Only Ethernet Adapter` at `192.168.56.1/24` with
DHCP enabled. If not, click **Create** to add one. This is the private
network all 4 of your VMs will share so they can talk to each other.

### 1.4 Create 4 VMs

Create one VM named `Server`, with:
- Linux / Ubuntu (64-bit), pointed at your downloaded ISO
- ~2048 MB RAM, 1-2 CPUs, ~20GB disk
- **Two network adapters**: Adapter 1 = NAT (for internet/`apt install`), Adapter 2 = Host-only Adapter (the one from step 1.3)

Boot it, walk through the Ubuntu Server installer (defaults are fine
everywhere), **say YES when asked to install OpenSSH server** (this
matters a lot — you'll need it constantly), pick a simple
username/password you'll remember.

Once it boots and you can log in, **shut it down** (`sudo shutdown now`),
then **clone it 3 times** (right-click → Clone, check "Reinitialize MAC
address", Full Clone) and name the clones `Client1`, `Client2`, `Mallory`.

### 1.5 Fix hostnames and set static IPs (important — don't skip)

On EACH of the 4 VMs, fix the hostname (clones all inherit "server" as
their hostname otherwise):
```bash
sudo hostnamectl set-hostname client1   # (or client2, mallory — skip on Server)
sudo reboot
```

Then, on EACH VM, give it a fixed IP (DHCP can hand out duplicate IPs
across VMs that aren't all running at once — static IPs avoid this
entirely and match the topology Jay already documented):
```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```
Replace the contents with (swap the IP per VM):
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses: [192.168.56.10/24]
```
Save (Ctrl+O, Enter, Ctrl+X), then:
```bash
sudo netplan apply
```

**Use this exact IP assignment (matches Jay's setup and his report evidence):**

| VM | IP |
|---|---|
| Server | `192.168.56.10` |
| Client1 | `192.168.56.11` |
| Client2 | `192.168.56.12` |
| Mallory | `192.168.56.13` |

Verify from the Server VM:
```bash
ping -c 3 192.168.56.11
ping -c 3 192.168.56.12
ping -c 3 192.168.56.13
```
All three should show 0% packet loss before you move on.

### 1.6 Install the toolchain (on all 4 VMs)

```bash
sudo apt update
sudo apt install -y build-essential g++ libssl-dev wireshark tcpdump git openssl
```
Say **Yes** if asked about non-superuser packet capture during the
wireshark install.

### 1.7 Install Wireshark on your actual Windows/Mac machine too

Download from **wireshark.org** — you'll pull `.pcap` capture files off the
VMs and open them here, since the GUI is much nicer on your host than
inside a VM.

### 1.8 A critical workflow note that will save you hours of confusion

There are **two completely different places you'll type commands**:

- **A Windows PowerShell / Mac Terminal window** — used ONLY for `ssh
  jay@192.168.56.X` (to log into a VM) and `scp` (to copy files between
  your computer and a VM).
- **A VM's own terminal** (you'll see a prompt like `jay@server:~$`) —
  used for EVERYTHING else: compiling, running the chat app, editing
  files with `nano`, git commands, etc.

**Never run `scp`/`ssh` from inside a prompt that already says
`jay@something:~$`** — that means you're already inside a VM, and those
commands would try to act *from* that VM, not *to* it. This mistake alone
cost a lot of back-and-forth during Phases 1–3.

Once SSH is confirmed working (`ssh jay@192.168.56.10` from PowerShell
should log you in), copy-paste into terminals works normally in SSH
sessions — much easier than the VirtualBox GUI window, where clipboard
sharing doesn't work by default.

---

## Part 2 — Getting the existing code onto your VMs

Jay will send you (or you'll pull from a shared git repo) these folders:
```
common/   -- 8 shared header files used by every phase
phase1/   -- done, don't touch
phase2/   -- done, don't touch
phase3/   -- done, don't touch
phase4/   -- YOUR job (currently empty or just has this guide)
phase5/   -- YOUR job
```

**Important: `common/` and each `phaseN/` folder must sit as SIBLINGS** —
e.g. `~/common/` and `~/phase4/` in the same parent directory — because the
code uses `#include "../common/xyz.h"` paths. If you nest them wrong,
you'll get "file not found" compile errors.

Copy the whole project onto **all 4 VMs** (Server, Client1, Client2, and
Mallory each need a full copy) via `scp` from PowerShell, e.g.:
```powershell
scp -r common phase1 phase2 phase3 phase4 phase5 jay@192.168.56.10:~/
```
(repeat for `.11`, `.12`, `.13`)

**Sanity check before writing any new code:** compile and run Phase 3
first, exactly as Jay already verified it, to confirm your VM setup is
correct. See `phase3/README.md` for exact commands. If Phase 3 doesn't
work on your VMs, Phase 4 won't either — fix that first.

---

## Part 3 — What's already done (Phases 1–3), so you understand what you're building on

### The shared `common/` modules (you'll reuse most of these directly)

- **`dh.h` / `dh_params.h`** — hand-rolled Diffie-Hellman using RFC 3526
  Group 14 (2048-bit). Uses `BN_mod_exp` directly (per TA clarification:
  this is allowed since it's a generic bignum primitive, not a DH-specific
  function — only `DH_generate_key`/`DH_compute_key`/`<openssl/dh.h>` are
  banned).
- **`aes_gcm.h`** — AES-256-GCM encrypt/decrypt via OpenSSL EVP.
- **`sha256.h`** — used both to derive the AES key from the raw DH secret
  (`key = SHA256(shared_secret)`) and to compute a printable "fingerprint"
  (`fingerprint = SHA256(key)`) for verification without ever printing the
  actual key.
- **`base64.h`** — self-contained codec, carries binary ciphertext as text
  lines over the newline-delimited framing.
- **`framing.h`** — `LineReader`/`send_line`: newline-delimited message
  framing over raw TCP sockets. Every phase uses this same scheme.
- **`crypto_channel.h`** — `send_encrypted()` / `recv_encrypted()`, plus
  the nonce-construction scheme: nonces are tagged with a 1-byte direction
  marker (`CLIENT_TO_SERVER` / `SERVER_TO_CLIENT`) so the two directions of
  one bidirectional key can never reuse the same nonce, even though each
  side's counter independently starts at 0.
- **`handshake.h`** — orchestrates one full DH handshake
  (`do_handshake_speak_first` / `do_handshake_listen_first`) and prints the
  fingerprint. **You will very likely reuse this directly for Phase 4's
  client-to-client key exchange** — just run it peer-to-peer instead of
  client-server.
- **`cert_utils.h`** (Phase 3 only) — X.509 loading, chain/validity/CN
  validation, and proof-of-possession signing/verification.

### Phase 1 — Baseline (done)
Plain TCP relay, no encryption. Newline-delimited framing. Server logs
every message in plaintext — verified with Wireshark showing readable
chat content in the raw capture.

### Phase 2 — DH + AES-GCM (done)
Each client does an independent DH handshake with the server (server
speaks first). Username registration and all chat happens encrypted.
Verified: fingerprint matching, Wireshark showing only ciphertext, a
standalone tamper-detection test (`tamper_test.cpp`), and a **working
MITM attack** (`mallory_proxy.cpp`) that captures plaintext by performing
two independent DH exchanges — proving DH alone doesn't authenticate
identity.

### Phase 3 — PKI/Certificates (done)
Before any DH exchange: server presents a CA-signed certificate
(`CN=chatserver.local`), client validates it (signature chain to CA,
validity period, identity match), then proof-of-possession (client sends a
nonce, server signs it, client verifies against the cert's public key).
**This defeats the exact Phase 2 MITM attack** — Mallory can't forge a
CA-signed cert, so the client aborts before any DH exchange happens.
Also demonstrated: a stolen genuine cert without the matching key passes
certificate validation but fails proof-of-possession.

**The wire protocol by the end of Phase 3, per connection, in order:**
```
1. Server sends its certificate           (plaintext, but not secret)
2. Client validates it (abort if any check fails, nothing further sent)
3. Client sends a random nonce
4. Server signs it, sends the signature
5. Client verifies (abort if it fails)
6. DH handshake (server speaks first)
7. Everything from here on is AES-GCM encrypted:
   client sends username, server ACKs, then normal chat commands
```

---

## Part 4 — Your job: Phase 4

### What it needs to do (spec summary)
C1 and C2 establish a shared key **directly with each other**, invisible
to the server, triggered by the exact command `/e2e username`. The
server must keep routing by username without any code changes — it just
sees opaque tagged strings. Use these EXACT wire tags (spec requires this,
don't rename them):
```
__E2E_INIT__<data>   -- C1's DH public value, sent to C2 via the server
__E2E_ACK__<data>    -- C2's DH public value, completing the exchange
__E2E_MSG__<data>    -- actual chat content, encrypted under the E2E key
```

### How to build it (reusing what's already there)

1. **Start from Phase 3's `client.cpp`/`server.cpp`** — copy them into
   `phase4/` as your starting point, don't rewrite from scratch.
2. **The server needs zero crypto-aware changes.** It already just does
   `@username <payload>` → look up `username` → forward `<payload>`. A
   `__E2E_INIT__...` string is just another opaque payload as far as the
   server's relay logic is concerned. Don't touch the server's routing.
3. **On the client**, add the `/e2e username` command: when triggered,
   generate a DH keypair (reuse `dh::generate_keypair()` from
   `common/dh.h`) and send `@username __E2E_INIT__<hex of your DH public value>`
   through the existing (already-encrypted) client-server channel.
4. **On the receiving client**, before treating an incoming `MSG sender
   <payload>` as chat text, check the payload's prefix:
   - `__E2E_INIT__` → feed the data into your own DH computation, reply
     with `@sender __E2E_ACK__<your DH public value>`. Never display this
     to the user as chat.
   - `__E2E_ACK__` → complete your own DH computation, derive the E2E key
     (`SHA256(shared_secret)`, exactly like `handshake.h` already does).
     Never display as chat.
   - `__E2E_MSG__` → AES-GCM decrypt the payload using the E2E key
     (reuse `aesgcm::decrypt()` from `common/aes_gcm.h`), display as chat.
     Never treat as a handshake step.
5. **Layering**: once the E2E session exists, an outgoing chat message
   becomes: encrypt with the E2E key → prefix with `__E2E_MSG__` → that
   whole string is what gets sent as the "message" over the existing
   Phase 3 client-server encrypted channel (so it's double-encrypted: E2E
   layer inside, client-server layer outside).

### Verification you need to produce
- Fingerprint of the E2E key, computed independently on C1 and C2, shown
  to match — **without the server ever being involved** in computing it.
- Server-side log evidence: before `/e2e` is triggered, the server can
  still read chat content (Phase 2/3 behavior). After `/e2e` completes,
  the server's log should show only the opaque `__E2E_MSG__<ciphertext>`
  string — it can route by username but the content means nothing to it.
  Screenshot both states side by side.
- Functional test: C1 sends a message post-handshake, C2 correctly
  decrypts and displays it.

---

## Part 5 — Your job: Phase 5 (after Phase 4 works)

### What it needs to do
Auto-rotate the C1↔C2 E2E key every 60 seconds, so a future key
compromise only exposes that ~60-second window of traffic, not the whole
conversation.

### Key design decision you must make and justify in the report
Both clients' 60-second timers will never fire in perfect sync. Pick ONE
clear strategy:
- **Simplest (recommended)**: asymmetric roles — whichever peer has the
  lexicographically smaller username always initiates rekeys on its timer
  (sends a new `__E2E_INIT__`); the other peer never initiates on its own
  timer, only ever responds with `__E2E_ACK__`. This structurally prevents
  any race, since there's only ever one initiator.
- Alternative (more complex, optional): tag each key with an incrementing
  epoch number; if both sides somehow propose at once, whichever has the
  higher epoch/timestamp wins.

### Implementation notes
- Reuse the exact same `__E2E_INIT__`/`__E2E_ACK__` machinery from Phase
  4 — a rekey is just running that handshake again.
- **Actually destroy the old key** once the new one is confirmed
  (`memset`/zero the buffer) — don't just stop referencing it.
- Tag each `__E2E_MSG__` with a small epoch/version number (e.g.
  `__E2E_MSG__<epoch>:<ciphertext>`) so a message that was in flight
  during a rotation can still be decrypted with the correct (possibly
  just-retired) key — keep the previous key around for a few seconds
  purely to drain in-flight messages, then discard it too.

### Verification you need to produce
- Fingerprint + timestamp logged on both clients at every rotation, across
  at least 2 rotations, showing the fingerprint changes each time and both
  sides agree after each rotation.
- A message sent immediately after a rotation still decrypts correctly.
- **Written explanation (explicitly graded)**: in your own words, what an
  attacker who compromises one key can and cannot do — e.g. compromising
  the key active during minute 5 only exposes that ~60-second window, not
  earlier or later traffic, because each window used an independent,
  now-discarded key. Contrast explicitly with Phase 4 alone, where one
  static session key means a single compromise exposes the entire
  conversation.

---

## Part 6 — The report

One PDF, covering all 5 phases (Jay can supply his own writeup notes/
screenshots for Phases 1–3 — ask him for these rather than re-deriving
them). Structure, repeated per phase:
1. Implementation summary (design decisions)
2. Verification results (fingerprints, Wireshark screenshots, logs)
3. Attack results where applicable (Phases 2, 3) — code + evidence + explanation
4. VM topology note (the IP table above, reused every phase)
5. **Appendix: every LLM prompt used, in full** — this is a mandatory
   deliverable per the assignment spec, not optional. Keep a running log
   of prompts as you go so you're not reconstructing it at the end.

---

## Quick reference — command cheat sheet

```bash
# Compile any phase's server/client:
g++ -std=c++17 -pthread -Wall -Wextra -o server server.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o client client.cpp -lssl -lcrypto

# Run:
./server 5000                              # on Server VM
./client 192.168.56.10 5000 alice          # on Client1
./client 192.168.56.10 5000 bob            # on Client2

# Wireshark capture (on Server VM, in a second SSH session):
sudo tcpdump -i enp0s8 -w /tmp/capture.pcap port 5000
# ... generate some traffic, then Ctrl+C ...
# From PowerShell, pull it to your machine:
scp jay@192.168.56.10:/tmp/capture.pcap "C:\wherever\capture.pcap"
```

If you get stuck, the exact same troubleshooting patterns from Phases 1–3
apply: check you're running `scp`/`ssh` from PowerShell (not inside a VM),
check `common/` and `phaseN/` are sibling folders, and check all 4 VMs can
still `ping` each other before debugging anything else.

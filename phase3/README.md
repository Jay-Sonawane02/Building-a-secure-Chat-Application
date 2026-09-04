# Phase 3 — Server Authentication via PKI

Fixes the exact gap Phase 2's MITM exploited: before any DH exchange, the
server presents a CA-signed certificate, which the client validates
(signature chain, validity period, identity) and then challenges with a
proof-of-possession nonce. Includes a re-run of the Phase 2 MITM attack
(now defeated) and a separate stolen-certificate test.

## Files

- `setup_ca.sh` — one-time OpenSSL CLI script: creates the CA, the genuine server cert, and the attacker test materials
- `../common/cert_utils.h` — X.509 loading, chain/validity/CN validation, proof-of-possession sign/verify
- `server.cpp`, `client.cpp` — Phase 2's chat app with cert exchange + PoP prepended before DH
- `mallory_proxy_phase3.cpp` — re-attempt of the Phase 2 MITM attack; now fails
- `stolen_cert_attacker.cpp` — separate test: genuine cert file, wrong private key

## Step 1 — Set up the CA (run ONCE, on the Server VM)

```bash
cd phase3
chmod +x setup_ca.sh
./setup_ca.sh
```

This produces 8 files. **Only `ca.crt` and `mallory.crt`/`mallory.key` and
`server.crt`/`wrong_key.key` ever leave the Server VM** — `ca.key` and
`server.key` are secrets that stay put:

| File | Secret? | Goes where |
|---|---|---|
| `ca.key` | **YES — never copy anywhere** | stays on Server VM only |
| `ca.crt` | No (public root cert) | copy to Client1, Client2 |
| `server.key` | **YES — never copy anywhere** | stays on Server VM only |
| `server.crt` | No | stays on Server VM (server presents it over the wire — clients receive it live, they don't need a local copy) |
| `mallory.crt` + `mallory.key` | attacker test material | copy to Mallory VM |
| `server.crt` (copy) + `wrong_key.key` | attacker test material | copy anywhere you'll run `stolen_cert_attacker` |

```bash
# From your Windows PowerShell, after generating on Server:
scp jay@192.168.56.10:~/phase3/ca.crt "D:\Network Security\A1\phase3\"
scp "D:\Network Security\A1\phase3\ca.crt" jay@192.168.56.11:~/phase3/
scp "D:\Network Security\A1\phase3\ca.crt" jay@192.168.56.12:~/phase3/

scp jay@192.168.56.10:~/phase3/mallory.crt jay@192.168.56.10:~/phase3/mallory.key "D:\Network Security\A1\phase3\"
scp "D:\Network Security\A1\phase3\mallory.crt" "D:\Network Security\A1\phase3\mallory.key" jay@192.168.56.13:~/phase3/
```

## Step 2 — Build (on every VM)

```bash
g++ -std=c++17 -pthread -Wall -Wextra -o server server.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o client client.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o mallory_proxy_phase3 mallory_proxy_phase3.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o stolen_cert_attacker stolen_cert_attacker.cpp -lssl -lcrypto
```

## Step 3 — Verify the legitimate flow (spec 4.2)

On Server (needs `server.crt` + `server.key` in the same folder, from setup_ca.sh):
```bash
./server 5000
```
On Client1/Client2 (each needs `ca.crt` in the same folder):
```bash
./client 192.168.56.10 5000 alice
```

You should see, in order:
```
Certificate validated: CN=chatserver.local, signed by trusted CA, within validity period.
Proof-of-possession verified: server controls the private key matching its certificate.
[client] DH handshake complete. Key fingerprint: ...
Connected as 'alice' (authenticated + encrypted). ...
```
Cross-check the fingerprint against the server's log, exactly as in Phase 2.

## Step 4 — Re-run the MITM attack (spec 4.2, the core deliverable)

On Mallory (needs `mallory.crt` + `mallory.key`):
```bash
./mallory_proxy_phase3 5000
```

On Client1 (the victim — point at Mallory, exactly like Phase 2):
```bash
./client 192.168.56.13 5000 alice
```

**Expected result — the attack now fails:**
```
ABORT: certificate validation FAILED -- signature does not chain to the trusted CA
No nonce, no DH public value, no password, and no username were sent. Connection closed immediately.
```
Mallory's log shows:
```
Sent our self-signed certificate to the victim. Waiting to see if they proceed...
*** VICTIM DISCONNECTED WITHOUT SENDING ANYTHING FURTHER. ***
```

## Step 5 — Stolen certificate without the private key (spec 4.2, separate test)

This is a distinct scenario from the MITM: an attacker who has a copy of
the *real, genuine* `server.crt` (e.g. read off the Server VM's disk) but
not `server.key`.

On any VM (needs a copy of the genuine `server.crt` + `wrong_key.key` from setup_ca.sh):
```bash
./stolen_cert_attacker 5000
```
On a client, point at it:
```bash
./client <stolen_cert_attacker's IP> 5000 alice
```

**Expected result:**
```
Certificate validated: CN=chatserver.local, signed by trusted CA, within validity period.
ABORT: proof-of-possession FAILED -- the signature does not verify against the certificate's public key. This server (or attacker) holds the certificate file but NOT the matching private key. Refusing to proceed.
```

Note the certificate validation line **succeeds** this time — the cert
really is genuine. It's specifically the proof-of-possession step that
catches this attack, which is exactly the point: a certificate alone only
proves an identity was vouched for at some point in the past; it does not
prove who currently controls the matching private key on this live
connection.

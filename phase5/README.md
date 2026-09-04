# Phase 5 — Forward Secrecy

Extends Phase 4's E2E session with automatic key rotation every 60
seconds, so a future key compromise only exposes the traffic from that one
~60-second window, not the whole conversation.

## Files

- `server.cpp` — byte-for-byte identical to Phase 3/4's server. Still no changes needed.
- `client.cpp` — Phase 4's client with a rekey timer, epoch tagging, collision avoidance, and active key destruction added.

## Build

```bash
g++ -std=c++17 -pthread -Wall -Wextra -o server server.cpp -lssl -lcrypto
g++ -std=c++17 -pthread -Wall -Wextra -o client client.cpp -lssl -lcrypto
```
(Reuses the same `ca.crt`/`server.crt`/`server.key` from Phase 3/4.)

## Run

```bash
./server 5000
./client 192.168.56.10 5000 alice
./client 192.168.56.10 5000 bob
```

## Commands

- `/e2e username` — same as Phase 4, starts the first exchange (epoch 0)
- `/rekey username` — **new, documented per spec 1.3's allowance for extra
  Phase 5 commands.** Forces an immediate rotation instead of waiting the
  full 60 seconds, so you can demonstrate multiple rotations quickly.
  Only works if your username sorts lexicographically before your peer's
  — see "Collision avoidance" below for why.
- Everything else (`@user`, `/chat`, `/who`, `/quit`) unchanged.

## Design decision: collision avoidance (spec 6.1)

Both clients' 60-second timers will never fire in perfect sync. **Chosen
approach: asymmetric roles.** Whichever username is lexicographically
smaller always initiates rekeys (on its timer, or via `/rekey`); the other
peer never initiates on its own timer, it only ever responds with
`__E2E_ACK__`. Since there is structurally only ever one initiator for a
given pair, there is no race to resolve — both sides independently compute
the same "who initiates" answer just by comparing the two (fixed, already
known) usernames.

*Why this over an epoch/timestamp "highest proposal wins" scheme*: that
alternative adds real complexity (detecting simultaneous proposals,
picking a winner, discarding the loser's in-flight exchange) to solve a
problem the asymmetric-roles approach avoids by construction. Given the
usernames are fixed for the session's lifetime, there's no scenario where
the two sides could disagree about who's the initiator.

## Epoch tagging (how messages survive a rotation)

Every wire message now carries an epoch number:
```
__E2E_INIT__<epoch>:<hex pub>
__E2E_ACK__<epoch>:<hex pub>
__E2E_MSG__<epoch>:<base64 nonce+ciphertext+tag>
```
Each session keeps its **current** key/epoch plus the **one previous**
key/epoch. A message tagged with the previous epoch can still be
decrypted — covering the case where a message was in flight right as a
rotation completed. Anything older than that has already been actively
destroyed (`OPENSSL_cleanse`) and is unrecoverable — which is the actual
point of forward secrecy, not an oversight.

## Verification (spec 6.2)

**1. Fingerprint + timestamp across ≥2 rotations.** Use `/rekey` twice in
a row (after `/e2e`) and confirm both clients' logs show:
```
[HH:MM:SS] [E2E] Session with <peer> now at epoch N. Fingerprint: <hex>
```
with the **same fingerprint on both sides** at each epoch, and a
**different fingerprint at each new epoch**.

**2. Post-rotation message delivery.** Send a message immediately after a
rotation completes; confirm it's displayed correctly on the other side,
tagged with the epoch it was encrypted under: `[sender (E2E, epoch N)]: ...`

**3. Written explanation (explicitly graded) — see below.**

## What forward secrecy actually buys you (required explanation)

**In Phase 4 alone**, C1 and C2 use one static E2E session key for the
entire conversation. If an attacker later compromises that single key —
say, by seizing a device or exploiting a bug — and they had been logging
the encrypted traffic all along, they can now decrypt **every message from
the entire session, past and future**, because it was all protected by the
same unchanging key.

**With Phase 5's rotation**, each ~60-second window uses a fresh key
derived from a brand-new DH exchange, independent of every previous key
(not derived *from* the old key — a fresh random exponent each time). Once
a window ends, that window's key is actively zeroed out of memory.

Concretely: if an attacker compromises the key that was active during,
say, minute 5 of a conversation, they can decrypt only the traffic sent
during that ~60-second window. They **cannot** decrypt:
- Earlier traffic (minutes 0–4), because those windows' keys were
  independently derived and have already been destroyed — there is no
  mathematical path from the minute-5 key back to an earlier key.
- Later traffic (minute 6 onward), *unless* they also compromise each
  subsequent key individually — a single compromise doesn't give them a
  way to predict or derive future keys either, since those come from
  fresh, independent DH exchanges the attacker wasn't part of.

**What forward secrecy does *not* protect against**: it doesn't stop an
attacker who has *ongoing, continuous* access to a compromised endpoint
(e.g., malware actively running in memory during every rotation) from
capturing each new key as it's generated — forward secrecy is specifically
about limiting the blast radius of a single, later, point-in-time
compromise of previously-discarded key material, not about making an
actively-controlled endpoint secure.

This is the concrete contrast with Phase 4: one static key there means one
compromise = the whole conversation. Here, one compromise = one ~60-second
window, and the size of that window is a direct, tunable security/latency
tradeoff (shorter rotation interval = smaller exposure window per
compromise, at the cost of more frequent DH exchanges).

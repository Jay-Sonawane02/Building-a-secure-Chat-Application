# Phase 1 — Baseline Chat Application (No Security)

A plaintext TCP relay chat server + client. The server can read every
message it relays — this is intentional; Phase 2 fixes it.

## Build

```bash
g++ -std=c++17 -pthread -Wall -Wextra -o server server.cpp
g++ -std=c++17 -pthread -Wall -Wextra -o client client.cpp
```

No external dependencies — pure POSIX sockets.

## Run (across VMs)

On the **Server VM**:
```bash
./server 5000
```
(5000 is the default port if you omit the argument.)

On **Client VM 1**:
```bash
./client <server_ip> 5000 alice
```

On **Client VM 2**:
```bash
./client <server_ip> 5000 bob
```

(The username can also be omitted from the command line — the client will
prompt for it interactively.)

## Using the client

Once connected, type at the `>` prompt:

| Input | Behaviour |
|---|---|
| `@bob hello there` | Sends "hello there" to `bob`, and sets `bob` as your current chat partner |
| `/chat bob` | Switches your current chat partner to `bob`, sends nothing |
| `hello again` | (plain text) sent to whichever partner is currently selected |
| `/who` | Lists all currently connected usernames |
| `/quit` | Cleanly disconnects and exits |

## Protocol summary 

- **Framing:** newline-delimited text lines. TCP has no message boundaries,
  so every logical message is one `\n`-terminated line; a message is
  "complete" once a `\n` has been read off the socket. Both client and
  server buffer partial reads until a full line is available
  (`recv_line()`/`LineReader`).
- **Registration:** the first line a client ever sends is its username. The
  server stores it in a `map<username, socket_fd>`.
- **Wire format**, client → server:
  - `<username>` (first line only)
  - `@<username> <message>` — chat message
  - `/who` — request online user list
  - `/quit` — disconnect
- **Wire format**, server → client:
  - `OK` / `ERR <reason>`
  - `MSG <sender> <message>` — an incoming chat message
  - `WHOLIST <user1> <user2> ...`
- **Routing beyond 2 clients:** the server's routing is a plain username
  lookup (`map<string, int>`), not hardcoded to exactly two participants.
  If a third, fourth, etc. client connected and registered a unique
  username, `@username` addressing would route to them identically with
  zero protocol changes — the two-client limit in this phase is a *scope*
  constraint from the spec, not a structural one in the code.

## Required verification (spec §2.2)

**1. Server-side plaintext logging.** The server prints every relayed
message to stdout, e.g.:
```
[17:53:12] [RELAY] alice -> bob: hello bob, this is alice testing phase1
```
Run the server with output redirected to a log file (`./server 5000 |
tee server.log`) and include a snippet in the report showing full message
content.

**2. Wireshark capture.**
1. On the Server VM, start a capture on the interface used for the chat
   traffic (e.g. `eth0`), filtered to the chat port:
   ```
   tcp.port == 5000
   ```
2. From a Client VM, connect and exchange a few messages.
3. In Wireshark, right-click a packet in the stream → **Follow → TCP
   Stream**. The chat text (username registration, `@bob ...` messages,
   `WHOLIST`, etc.) will be fully readable in the reassembled stream.
4. Screenshot this for the report — this is the "plaintext" baseline that
   Phase 2's capture will visibly contrast against (ciphertext instead of
   readable text).


- No message persistence — if a target user isn't currently online,
  the sender gets `ERR user_not_found <target>` and the message is dropped
  (not queued).
- Single listening thread accepts connections; one thread per connected
  client handles that client's traffic (`std::thread` per `accept()`).

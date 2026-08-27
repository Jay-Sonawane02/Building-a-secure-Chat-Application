// Phase 1 - Baseline Chat Server (No Security)
//
// A pure TCP relay: whatever C1 sends addressed to C2 (or vice versa) is
// forwarded byte-for-byte, in plaintext. The server understands and logs
// every message it relays -- this is the intentional, documented weakness
// that later phases fix.
//
// ---------------------------------------------------------------------------
// WIRE PROTOCOL (server <-> client), all lines newline-terminated ('\n'):
//
//   Framing: TCP is a byte stream with no message boundaries, so every
//   logical message is a single newline-delimited text line. A message is
//   "complete" once a '\n' has been seen; anything after it belongs to the
//   next message. This is why every read goes through recv_line(), which
//   buffers partial reads until a full line is available.
//
//   Client -> Server:
//     <username>                  (first line only, registers the connection)
//     @<username> <message text>  (chat message addressed to <username>)
//     /who                        (request online user list)
//     /quit                       (clean disconnect)
//
//   Server -> Client:
//     OK                                   (registration accepted)
//     ERR <reason>                         (registration/relay error)
//     MSG <sender> <message text>          (an incoming chat message)
//     WHOLIST <user1> <user2> ...          (response to /who)
//
// Routing (documented per the report requirement in 2.3): the server keeps
// a single map<username, socket_fd>. If more than two clients connected,
// the exact same @username lookup already generalizes -- routing is not
// hardcoded to "the other client", it looks up whichever username was
// named, so N clients would work identically without protocol changes.
// ---------------------------------------------------------------------------

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

static const int DEFAULT_PORT = 5000;

// username -> socket fd, shared across all client-handler threads
static std::map<std::string, int> g_clients;
static std::mutex g_clients_mutex;

// ---- logging -----------------------------------------------------------
static std::string timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}

static void log(const std::string &msg) {
    std::cout << "[" << timestamp() << "] " << msg << std::endl;
}

// ---- line-based framing over a raw TCP socket ---------------------------
// Each client-handler thread owns one of these buffers; recv_line blocks
// until it has assembled one full newline-terminated line (handles both
// partial reads and multiple-lines-in-one-recv()).
struct LineReader {
    int fd;
    std::string buf;

    // Returns false on disconnect/error, true with `out` populated on success.
    bool recv_line(std::string &out) {
        size_t pos;
        while ((pos = buf.find('\n')) == std::string::npos) {
            char chunk[4096];
            ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) return false;  // peer closed or error
            buf.append(chunk, n);
        }
        out = buf.substr(0, pos);
        // strip a trailing '\r' in case a client sends CRLF
        if (!out.empty() && out.back() == '\r') out.pop_back();
        buf.erase(0, pos + 1);
        return true;
    }
};

static bool send_line(int fd, const std::string &line) {
    std::string out = line + "\n";
    size_t total = 0;
    while (total < out.size()) {
        ssize_t n = send(fd, out.data() + total, out.size() - total, 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

// ---- client registry helpers --------------------------------------------
static bool register_client(const std::string &username, int fd) {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    if (g_clients.count(username)) return false;
    g_clients[username] = fd;
    return true;
}

static void unregister_client(const std::string &username) {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    g_clients.erase(username);
}

// Looks up target's fd; returns -1 if not online.
static int lookup_fd(const std::string &username) {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    auto it = g_clients.find(username);
    return it == g_clients.end() ? -1 : it->second;
}

static std::string who_list() {
    std::lock_guard<std::mutex> lock(g_clients_mutex);
    std::ostringstream oss;
    oss << "WHOLIST";
    for (auto &kv : g_clients) oss << " " << kv.first;
    return oss.str();
}

// ---- per-client thread ----------------------------------------------------
static void handle_client(int fd, std::string peer_addr) {
    LineReader reader{fd, ""};
    std::string username;

    // First line on the wire is always the username.
    if (!reader.recv_line(username) || username.empty()) {
        close(fd);
        return;
    }
    if (!register_client(username, fd)) {
        send_line(fd, "ERR username_taken");
        close(fd);
        log("Rejected duplicate username '" + username + "' from " + peer_addr);
        return;
    }
    send_line(fd, "OK");
    log("Client connected: " + username + " (" + peer_addr + ")");

    std::string line;
    while (reader.recv_line(line)) {
        if (line.empty()) continue;

        if (line == "/quit") {
            log("[CMD] " + username + " -> /quit");
            break;
        }

        if (line == "/who") {
            log("[CMD] " + username + " -> /who");
            send_line(fd, who_list());
            continue;
        }

        if (line[0] == '@') {
            // Format: @target message text...
            size_t space = line.find(' ');
            if (space == std::string::npos) {
                send_line(fd, "ERR malformed_message");
                continue;
            }
            std::string target = line.substr(1, space - 1);
            std::string message = line.substr(space + 1);

            // This is the verification point required by 2.2: the server
            // logs the full plaintext content of every relayed message.
            log("[RELAY] " + username + " -> " + target + ": " + message);

            int target_fd = lookup_fd(target);
            if (target_fd < 0) {
                send_line(fd, "ERR user_not_found " + target);
                continue;
            }
            if (!send_line(target_fd, "MSG " + username + " " + message)) {
                send_line(fd, "ERR delivery_failed " + target);
            }
            continue;
        }

        // Anything else is not a recognized wire command from this client.
        send_line(fd, "ERR unknown_command");
    }

    unregister_client(username);
    close(fd);
    log("Client disconnected: " + username);
}

int main(int argc, char *argv[]) {
    int port = argc > 1 ? std::atoi(argv[1]) : DEFAULT_PORT;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  // listen on all interfaces
    addr.sin_port = htons(port);

    if (bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, 8) < 0) {
        perror("listen");
        return 1;
    }

    log("Phase 1 chat server listening on port " + std::to_string(port));

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        std::string peer = std::string(ip) + ":" + std::to_string(ntohs(client_addr.sin_port));

        std::thread(handle_client, client_fd, peer).detach();
    }

    close(listen_fd);
    return 0;
}

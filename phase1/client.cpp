#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

struct LineReader {
    int fd;
    std::string buf;

    bool recv_line(std::string &out) {
        size_t pos;
        while ((pos = buf.find('\n')) == std::string::npos) {
            char chunk[4096];
            ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) return false;
            buf.append(chunk, n);
        }
        out = buf.substr(0, pos);
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

static std::atomic<bool> g_running{true};

// Background thread: prints whatever the server sends, as it arrives.
static void receiver_loop(int fd) {
    LineReader reader{fd, ""};
    std::string line;
    while (g_running && reader.recv_line(line)) {
        if (line.rfind("MSG ", 0) == 0) {
            // MSG <sender> <message text>
            std::string rest = line.substr(4);
            size_t space = rest.find(' ');
            std::string sender = space == std::string::npos ? rest : rest.substr(0, space);
            std::string message = space == std::string::npos ? "" : rest.substr(space + 1);
            std::cout << "\n[" << sender << "]: " << message << "\n> " << std::flush;
        } else if (line.rfind("WHOLIST", 0) == 0) {
            std::cout << "\nOnline users:" << line.substr(7) << "\n> " << std::flush;
        } else if (line.rfind("ERR", 0) == 0) {
            std::cout << "\n[server error] " << line.substr(4) << "\n> " << std::flush;
        } else if (line == "OK") {
        } else {
            std::cout << "\n[server] " << line << "\n> " << std::flush;
        }
    }
    if (g_running) {
        std::cout << "\nDisconnected from server.\n";
        g_running = false;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> [username]\n";
        return 1;
    }
    std::string server_ip = argv[1];
    int port = std::atoi(argv[2]);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid server IP: " << server_ip << "\n";
        return 1;
    }

    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    std::string username;
    if (argc > 3) {
        username = argv[3];
    } else {
        std::cout << "Choose a username: ";
        std::getline(std::cin, username);
    }

    if (!send_line(fd, username)) {
        std::cerr << "Failed to send username.\n";
        return 1;
    }

    LineReader startup_reader{fd, ""};
    std::string ack;
    if (!startup_reader.recv_line(ack)) {
        std::cerr << "Server closed the connection during registration.\n";
        return 1;
    }
    if (ack != "OK") {
        std::cerr << "Registration failed: " << ack << "\n";
        return 1;
    }
    std::cout << "Connected as '" << username << "'. Commands: @user msg | /chat user | /who | /quit\n";

    std::thread receiver(receiver_loop, fd);

    receiver.detach();

    std::string current_peer;
    std::string line;
    std::cout << "> " << std::flush;
    while (g_running && std::getline(std::cin, line)) {
        if (line.empty()) {
            std::cout << "> " << std::flush;
            continue;
        }

        if (line == "/quit") {
            send_line(fd, "/quit");
            g_running = false;
            break;
        }

        if (line == "/who") {
            send_line(fd, "/who");
            std::cout << "> " << std::flush;
            continue;
        }

        if (line.rfind("/chat ", 0) == 0) {
            current_peer = line.substr(6);
            std::cout << "Now chatting with '" << current_peer << "'\n> " << std::flush;
            continue;
        }

        if (line[0] == '@') {
            size_t space = line.find(' ');
            if (space == std::string::npos) {
                std::cout << "Usage: @username message\n> " << std::flush;
                continue;
            }
            current_peer = line.substr(1, space - 1);
            send_line(fd, line);
            std::cout << "> " << std::flush;
            continue;
        }

        if (current_peer.empty()) {
            std::cout << "No chat partner selected. Use /chat username or @username message\n> "
                       << std::flush;
            continue;
        }
        send_line(fd, "@" + current_peer + " " + line);
        std::cout << "> " << std::flush;
    }

    close(fd);
    return 0;
}

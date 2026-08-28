// Line-based framing over a raw TCP socket -- identical scheme to Phase 1.
// Every logical message (handshake value or, from Phase 2 on, an encrypted
// blob) is one newline-terminated line.
#pragma once

#include <sys/socket.h>
#include <unistd.h>

#include <string>

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

inline bool send_line(int fd, const std::string &line) {
    std::string out = line + "\n";
    size_t total = 0;
    while (total < out.size()) {
        ssize_t n = send(fd, out.data() + total, out.size() - total, 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

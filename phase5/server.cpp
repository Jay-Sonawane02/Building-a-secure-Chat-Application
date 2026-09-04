#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 2);
    std::cout << "Server running on port " << PORT << "\n";

    int client_sockets[2];
    std::string client_names[2];

    for (int i = 0; i < 2; i++) {
        client_sockets[i] = accept(server_fd, nullptr, nullptr);
        char buf[256] = {0};
        read(client_sockets[i], buf, sizeof(buf));
        client_names[i] = std::string(buf);
        std::cout << "Client connected: " << client_names[i] << "\n";
    }

    fd_set readfds;
    while (true) {
        FD_ZERO(&readfds);
        int max_sd = client_sockets[0] > client_sockets[1] ? client_sockets[0] : client_sockets[1];
        FD_SET(client_sockets[0], &readfds);
        FD_SET(client_sockets[1], &readfds);

        select(max_sd + 1, &readfds, nullptr, nullptr, nullptr);

        for (int i = 0; i < 2; i++) {
            if (FD_ISSET(client_sockets[i], &readfds)) {
                char buffer[1024] = {0};
                int valread = read(client_sockets[i], buffer, sizeof(buffer));
                if (valread <= 0) {
                    close(client_sockets[i]);
                    return 0;
                }
                std::cout << "[Relay] " << client_names[i] << ": " << buffer << "\n";
                
                // Forward message to the other client
                int target_idx = 1 - i;
                std::string msg = "@" + client_names[i] + " " + std::string(buffer);
                send(client_sockets[target_idx], msg.c_str(), msg.length(), 0);
            }
        }
    }
    return 0;
}
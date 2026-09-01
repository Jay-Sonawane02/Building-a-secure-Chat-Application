#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define MAX_CLIENTS 2
#define BUFFER_SIZE 2048

struct Client {
    int socket;
    std::string username;
};

Client clients[MAX_CLIENTS];
int client_count = 0;

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    std::cout << "Phase 4 Relay Server listening on port " << PORT << "...\n";

    while (client_count < MAX_CLIENTS) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        memset(buffer, 0, BUFFER_SIZE);
        read(new_socket, buffer, BUFFER_SIZE);
        buffer[strcspn(buffer, "\r\n")] = 0;

        clients[client_count].socket = new_socket;
        clients[client_count].username = std::string(buffer);
        std::cout << "[SERVER LOG] Client registered: " << clients[client_count].username << "\n";
        client_count++;
    }

    fd_set readfds;
    while (true) {
        FD_ZERO(&readfds);
        int max_sd = 0;
        for (int i = 0; i < client_count; i++) {
            FD_SET(clients[i].socket, &readfds);
            if (clients[i].socket > max_sd) max_sd = clients[i].socket;
        }

        select(max_sd + 1, &readfds, nullptr, nullptr, nullptr);

        for (int i = 0; i < client_count; i++) {
            if (FD_ISSET(clients[i].socket, &readfds)) {
                memset(buffer, 0, BUFFER_SIZE);
                int valread = read(clients[i].socket, buffer, BUFFER_SIZE);
                if (valread <= 0) {
                    close(clients[i].socket);
                    exit(0);
                }
                buffer[valread] = '\0';
                
                std::cout << "[SERVER LOG Relay] From " << clients[i].username << ": " << buffer << "\n";

                if (buffer[0] == '@') {
                    std::string msg_str(buffer);
                    size_t space_pos = msg_str.find(' ');
                    if (space_pos != std::string::npos) {
                        std::string target = msg_str.substr(1, space_pos - 1);
                        std::string payload = msg_str.substr(space_pos + 1);
                        
                        for (int j = 0; j < client_count; j++) {
                            if (clients[j].username == target) {
                                std::string rel_msg = "@" + clients[i].username + " " + payload;
                                send(clients[j].socket, rel_msg.c_str(), rel_msg.length(), 0);
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
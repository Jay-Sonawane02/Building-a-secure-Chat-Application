#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>  
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include "../common/aes_gcm.h"
#include "../common/base64.h"
#include "../common/cert_utils.h"
#include "../common/crypto_channel.h"
#include "../common/dh.h"
#include "../common/framing.h"
#include "../common/handshake.h"
#include "../common/sha256.h"

static const char *TRUSTED_CA_PATH = "ca.crt";
static const char *EXPECTED_SERVER_CN = "chatserver.local";
static const int REKEY_INTERVAL_SECONDS = 60;

static std::atomic<bool> g_running{true};

static std::string now_str() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}

struct E2ESession {
    uint32_t current_epoch = 0;
    std::vector<uint8_t> current_key;
    uint64_t send_counter = 0;

    bool has_previous = false;
    uint32_t previous_epoch = 0;
    std::vector<uint8_t> previous_key;

    uint8_t my_direction;
    std::chrono::steady_clock::time_point last_rotation;
};

struct PendingRekey {
    uint32_t epoch;
    dh::BNPtr priv;
};

static std::mutex g_e2e_mutex;
static std::map<std::string, E2ESession> g_e2e_sessions;
static std::map<std::string, PendingRekey> g_pending;  

static std::mutex g_channel_mutex;
static std::string g_username;
static dh::BNPtr g_dh_p, g_dh_g;
static BN_CTX *g_dh_ctx = nullptr;
static int g_fd = -1;
static std::vector<uint8_t> g_server_key;
static uint64_t g_server_send_counter = 0;

static uint8_t direction_for(const std::string &me, const std::string &peer) {
    return me < peer ? 0x01 : 0x02;
}
static bool i_am_initiator(const std::string &me, const std::string &peer) {
    return me < peer;  // collision-avoidance rule, see file header
}

static std::vector<uint8_t> e2e_nonce(uint8_t dir, uint64_t counter) {
    std::vector<uint8_t> nonce(aesgcm::NONCE_LEN, 0);
    nonce[0] = dir;
    for (int i = 0; i < 8; ++i) nonce[1 + i] = static_cast<uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
    return nonce;
}

static bool send_to_server_locked(const std::string &plaintext) {
    std::lock_guard<std::mutex> lock(g_channel_mutex);
    return channel::send_encrypted(g_fd, g_server_key, channel::CLIENT_TO_SERVER,
                                    g_server_send_counter, plaintext);
}
.
static void destroy_key(std::vector<uint8_t> &key) {
    if (!key.empty()) {
        OPENSSL_cleanse(key.data(), key.size());
        key.clear();
    }
}

static void initiate_e2e(const std::string &target, uint32_t proposed_epoch) {
    dh::Keypair kp = dh::generate_keypair(g_dh_p, g_dh_g, g_dh_ctx);
    std::string payload = "__E2E_INIT__" + std::to_string(proposed_epoch) + ":" +
                           dh::pub_to_hex(kp.pub);
    {
        std::lock_guard<std::mutex> lock(g_e2e_mutex);
        g_pending[target] = PendingRekey{proposed_epoch, std::move(kp.priv)};
    }
    send_to_server_locked("@" + target + " " + payload);
}

static void rekey_timer_loop() {
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::vector<std::pair<std::string, uint32_t>> due;
        {
            std::lock_guard<std::mutex> lock(g_e2e_mutex);
            auto elapsed_now = std::chrono::steady_clock::now();
            for (auto &kv : g_e2e_sessions) {
                const std::string &peer = kv.first;
                E2ESession &s = kv.second;
                if (!i_am_initiator(g_username, peer)) continue;  // not our role
                auto elapsed =
                    std::chrono::duration_cast<std::chrono::seconds>(elapsed_now - s.last_rotation)
                        .count();
                if (elapsed >= REKEY_INTERVAL_SECONDS) {
                    due.push_back({peer, s.current_epoch + 1});
                    s.last_rotation = elapsed_now;  // reset so we don't re-fire every second
                }
            }
        }
        for (auto &p : due) {
            initiate_e2e(p.first, p.second);
            std::cout << "\n[REKEY] Timer fired -- proposing epoch " << p.second << " with "
                      << p.first << "\n> " << std::flush;
        }
    }
}

static void receiver_loop(LineReader *reader) {
    std::string line;
    while (g_running) {
        auto res = channel::recv_encrypted(*reader, g_server_key, line);
        if (res == channel::RecvResult::DISCONNECTED) break;
        if (res == channel::RecvResult::TAMPER_DETECTED) {
            std::cout << "\n[SECURITY] Client-server message failed authentication -- "
                         "discarded.\n> "
                      << std::flush;
            continue;
        }
        if (res == channel::RecvResult::MALFORMED) continue;

        if (line.rfind("MSG ", 0) == 0) {
            std::string rest = line.substr(4);
            size_t space = rest.find(' ');
            std::string sender = space == std::string::npos ? rest : rest.substr(0, space);
            std::string payload = space == std::string::npos ? "" : rest.substr(space + 1);

            if (payload.rfind("__E2E_INIT__", 0) == 0) {
                std::string rest2 = payload.substr(12);
                size_t colon = rest2.find(':');
                if (colon == std::string::npos) continue;
                uint32_t epoch = static_cast<uint32_t>(std::stoul(rest2.substr(0, colon)));
                std::string peer_hex = rest2.substr(colon + 1);
                try {
                    dh::BNPtr peer_pub = dh::hex_to_pub(peer_hex);
                    dh::Keypair kp = dh::generate_keypair(g_dh_p, g_dh_g, g_dh_ctx);
                    std::vector<uint8_t> secret =
                        dh::compute_shared_secret(peer_pub, kp.priv, g_dh_p, g_dh_ctx);
                    std::vector<uint8_t> key = sha256::hash(secret);
                    std::string fingerprint = sha256::to_hex(sha256::hash(key));

                    {
                        std::lock_guard<std::mutex> lock(g_e2e_mutex);
                        E2ESession &s = g_e2e_sessions[sender];
                        if (!s.current_key.empty()) {
                            destroy_key(s.previous_key);  // drop anything older than "previous"
                            s.previous_key = std::move(s.current_key);
                            s.previous_epoch = s.current_epoch;
                            s.has_previous = true;
                        }
                        s.current_key = key;
                        s.current_epoch = epoch;
                        s.send_counter = 0;
                        s.my_direction = direction_for(g_username, sender);
                        s.last_rotation = std::chrono::steady_clock::now();
                    }
                    std::cout << "\n[" << now_str() << "] [E2E] Session with " << sender
                              << " now at epoch " << epoch << ". Fingerprint: " << fingerprint
                              << "\n> " << std::flush;

                    std::string ack = "__E2E_ACK__" + std::to_string(epoch) + ":" +
                                       dh::pub_to_hex(kp.pub);
                    send_to_server_locked("@" + sender + " " + ack);
                } catch (const std::exception &e) {
                    std::cout << "\n[E2E] Failed to process INIT: " << e.what() << "\n> "
                              << std::flush;
                }
                continue;
            }

            if (payload.rfind("__E2E_ACK__", 0) == 0) {
                std::string rest2 = payload.substr(11);
                size_t colon = rest2.find(':');
                if (colon == std::string::npos) continue;
                uint32_t epoch = static_cast<uint32_t>(std::stoul(rest2.substr(0, colon)));
                std::string peer_hex = rest2.substr(colon + 1);

                std::lock_guard<std::mutex> lock(g_e2e_mutex);
                auto it = g_pending.find(sender);
                if (it == g_pending.end() || it->second.epoch != epoch) {
                    std::cout << "\n[E2E] Unexpected/stale ACK from " << sender
                              << " -- ignored.\n> " << std::flush;
                    continue;
                }
                try {
                    dh::BNPtr peer_pub = dh::hex_to_pub(peer_hex);
                    std::vector<uint8_t> secret =
                        dh::compute_shared_secret(peer_pub, it->second.priv, g_dh_p, g_dh_ctx);
                    std::vector<uint8_t> key = sha256::hash(secret);
                    std::string fingerprint = sha256::to_hex(sha256::hash(key));

                    E2ESession &s = g_e2e_sessions[sender];
                    if (!s.current_key.empty()) {
                        destroy_key(s.previous_key);
                        s.previous_key = std::move(s.current_key);
                        s.previous_epoch = s.current_epoch;
                        s.has_previous = true;
                    }
                    s.current_key = key;
                    s.current_epoch = epoch;
                    s.send_counter = 0;
                    s.my_direction = direction_for(g_username, sender);
                    s.last_rotation = std::chrono::steady_clock::now();
                    g_pending.erase(it);

                    std::cout << "\n[" << now_str() << "] [E2E] Session with " << sender
                              << " now at epoch " << epoch << ". Fingerprint: " << fingerprint
                              << "\n> " << std::flush;
                } catch (const std::exception &e) {
                    std::cout << "\n[E2E] Failed to process ACK: " << e.what() << "\n> "
                              << std::flush;
                }
                continue;
            }

            if (payload.rfind("__E2E_MSG__", 0) == 0) {
                std::string rest2 = payload.substr(11);
                size_t colon = rest2.find(':');
                if (colon == std::string::npos) continue;
                uint32_t epoch = static_cast<uint32_t>(std::stoul(rest2.substr(0, colon)));
                std::string blob_b64 = rest2.substr(colon + 1);

                std::lock_guard<std::mutex> lock(g_e2e_mutex);
                auto it = g_e2e_sessions.find(sender);
                if (it == g_e2e_sessions.end()) {
                    std::cout << "\n[E2E] Message from " << sender
                              << " but no session exists.\n> " << std::flush;
                    continue;
                }
                const uint8_t *key_ptr = nullptr;
                if (epoch == it->second.current_epoch) {
                    key_ptr = it->second.current_key.data();
                } else if (it->second.has_previous && epoch == it->second.previous_epoch) {
                    key_ptr = it->second.previous_key.data();  // grace-period decrypt
                } else {
                    std::cout << "\n[E2E] Message from " << sender << " uses epoch " << epoch
                              << ", which has been discarded -- cannot decrypt (this is "
                                 "forward secrecy working as intended).\n> "
                              << std::flush;
                    continue;
                }
                try {
                    std::vector<uint8_t> wire = base64::decode(blob_b64);
                    if (wire.size() < aesgcm::NONCE_LEN + aesgcm::TAG_LEN) continue;
                    std::vector<uint8_t> nonce(wire.begin(), wire.begin() + aesgcm::NONCE_LEN);
                    std::vector<uint8_t> ct(wire.begin() + aesgcm::NONCE_LEN, wire.end());
                    std::string plaintext;
                    if (aesgcm::decrypt(key_ptr, nonce.data(), ct, plaintext)) {
                        std::cout << "\n[" << sender << " (E2E, epoch " << epoch
                                  << ")]: " << plaintext << "\n> " << std::flush;
                    } else {
                        std::cout << "\n[SECURITY] E2E message from " << sender
                                  << " failed authentication.\n> " << std::flush;
                    }
                } catch (const std::exception &e) {
                    std::cout << "\n[E2E] Error decoding message: " << e.what() << "\n> "
                              << std::flush;
                }
                continue;
            }

            std::cout << "\n[" << sender << "]: " << payload << "\n> " << std::flush;
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

    cert::X509Ptr ca_cert;
    try {
        ca_cert = cert::load_cert_from_file(TRUSTED_CA_PATH);
    } catch (const std::exception &e) {
        std::cerr << "Cannot load trusted CA certificate: " << e.what() << "\n";
        return 1;
    }

    g_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);
    if (connect(g_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
    LineReader reader{g_fd, ""};

    std::string cert_line;
    if (!reader.recv_line(cert_line) || cert_line.rfind("CERT ", 0) != 0) {
        std::cerr << "ABORT: server did not present a certificate.\n";
        close(g_fd);
        return 1;
    }
    cert::X509Ptr server_cert;
    try {
        server_cert = cert::cert_from_wire(cert_line.substr(5));
    } catch (const std::exception &e) {
        std::cerr << "ABORT: could not parse server certificate (" << e.what() << ").\n";
        close(g_fd);
        return 1;
    }
    auto validation = cert::validate_certificate(server_cert, ca_cert, EXPECTED_SERVER_CN);
    if (!validation.ok) {
        std::cerr << "ABORT: certificate validation FAILED -- " << validation.reason << "\n";
        close(g_fd);
        return 1;
    }
    std::cout << "Certificate validated: CN=" << cert::get_common_name(server_cert) << "\n";

    std::vector<uint8_t> nonce(16);
    {
        BIGNUM *r = BN_new();
        BN_rand(r, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_bn2binpad(r, nonce.data(), 16);
        BN_free(r);
    }
    send_line(g_fd, "NONCE " + base64::encode(nonce));
    std::string proof_line;
    if (!reader.recv_line(proof_line) || proof_line.rfind("PROOF ", 0) != 0) {
        std::cerr << "ABORT: server did not respond to proof-of-possession challenge.\n";
        close(g_fd);
        return 1;
    }
    std::vector<uint8_t> signature = base64::decode(proof_line.substr(6));
    if (!cert::verify_challenge(server_cert, nonce, signature)) {
        std::cerr << "ABORT: proof-of-possession FAILED.\n";
        close(g_fd);
        return 1;
    }
    std::cout << "Proof-of-possession verified.\n";

    handshake::Result hs;
    try {
        hs = handshake::do_handshake_listen_first(g_fd, reader, "client");
    } catch (const std::exception &e) {
        std::cerr << "DH handshake failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "Client-server fingerprint: " << hs.fingerprint << "\n";
    g_server_key = hs.key;

    std::string username;
    if (argc > 3) {
        username = argv[3];
    } else {
        std::cout << "Choose a username: ";
        std::getline(std::cin, username);
    }
    g_username = username;

    if (!send_to_server_locked(username)) {
        std::cerr << "Failed to send username.\n";
        return 1;
    }
    std::string ack;
    auto ack_res = channel::recv_encrypted(reader, g_server_key, ack);
    if (ack_res != channel::RecvResult::OK || ack != "OK") {
        std::cerr << "Registration failed.\n";
        return 1;
    }
    std::cout << "Connected as '" << username
              << "'. Commands: @user msg | /chat user | /e2e user | /rekey user | /who | "
                 "/quit\n";
    std::cout << "(/rekey forces an immediate rotation for testing, instead of waiting "
              << REKEY_INTERVAL_SECONDS << "s -- only works if your username sorts before "
              << "your peer's, since that side is the designated initiator.)\n";

    dh::load_group(g_dh_p, g_dh_g);
    g_dh_ctx = BN_CTX_new();

    std::thread receiver(receiver_loop, &reader);
    std::thread rekey_thread(rekey_timer_loop);

    std::string current_peer;
    std::string line;
    std::cout << "> " << std::flush;
    while (g_running && std::getline(std::cin, line)) {
        if (line.empty()) {
            std::cout << "> " << std::flush;
            continue;
        }
        if (line == "/quit") {
            send_to_server_locked("/quit");
            g_running = false;
            break;
        }
        if (line == "/who") {
            send_to_server_locked("/who");
            std::cout << "> " << std::flush;
            continue;
        }
        if (line.rfind("/chat ", 0) == 0) {
            current_peer = line.substr(6);
            std::cout << "Now chatting with '" << current_peer << "'\n> " << std::flush;
            continue;
        }
        if (line.rfind("/e2e ", 0) == 0) {
            std::string target = line.substr(5);
            current_peer = target;
            initiate_e2e(target, 0);
            std::cout << "[E2E] Initiated key exchange with " << target << "\n> "
                       << std::flush;
            continue;
        }
        if (line.rfind("/rekey ", 0) == 0) {
            std::string target = line.substr(7);
            if (!i_am_initiator(g_username, target)) {
                std::cout << "[REKEY] Only " << (g_username < target ? g_username : target)
                          << " (the lexicographically smaller username) can initiate a "
                             "rekey with this peer -- that's the collision-avoidance rule. "
                             "Ask them to run /rekey instead.\n> "
                          << std::flush;
                continue;
            }
            uint32_t next_epoch = 0;
            bool have_session = false;
            {
                std::lock_guard<std::mutex> lock(g_e2e_mutex);
                auto it = g_e2e_sessions.find(target);
                if (it != g_e2e_sessions.end()) {
                    have_session = true;
                    next_epoch = it->second.current_epoch + 1;
                    it->second.last_rotation = std::chrono::steady_clock::now();
                }
            }  // lock released here, BEFORE the network call below
            if (!have_session) {
                std::cout << "[REKEY] No active E2E session with " << target
                          << " -- run /e2e first.\n> " << std::flush;
                continue;
            }
            initiate_e2e(target, next_epoch);
            std::cout << "[REKEY] Forced immediate rotation to epoch " << next_epoch
                      << " with " << target << " (test command)\n> " << std::flush;
            continue;
        }
        if (line[0] == '@') {
            size_t space = line.find(' ');
            if (space == std::string::npos) {
                std::cout << "Usage: @username message\n> " << std::flush;
                continue;
            }
            current_peer = line.substr(1, space - 1);
            std::string message = line.substr(space + 1);
            std::lock_guard<std::mutex> lock(g_e2e_mutex);
            auto it = g_e2e_sessions.find(current_peer);
            if (it != g_e2e_sessions.end()) {
                std::vector<uint8_t> n = e2e_nonce(it->second.my_direction,
                                                    it->second.send_counter++);
                std::vector<uint8_t> ct =
                    aesgcm::encrypt(it->second.current_key.data(), n.data(), message);
                std::vector<uint8_t> wire;
                wire.insert(wire.end(), n.begin(), n.end());
                wire.insert(wire.end(), ct.begin(), ct.end());
                std::string payload = "__E2E_MSG__" + std::to_string(it->second.current_epoch) +
                                       ":" + base64::encode(wire);
                send_to_server_locked("@" + current_peer + " " + payload);
            } else {
                send_to_server_locked(line);
            }
            std::cout << "> " << std::flush;
            continue;
        }
        if (current_peer.empty()) {
            std::cout << "No chat partner selected.\n> " << std::flush;
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(g_e2e_mutex);
            auto it = g_e2e_sessions.find(current_peer);
            if (it != g_e2e_sessions.end()) {
                std::vector<uint8_t> n = e2e_nonce(it->second.my_direction,
                                                    it->second.send_counter++);
                std::vector<uint8_t> ct =
                    aesgcm::encrypt(it->second.current_key.data(), n.data(), line);
                std::vector<uint8_t> wire;
                wire.insert(wire.end(), n.begin(), n.end());
                wire.insert(wire.end(), ct.begin(), ct.end());
                std::string payload = "__E2E_MSG__" + std::to_string(it->second.current_epoch) +
                                       ":" + base64::encode(wire);
                send_to_server_locked("@" + current_peer + " " + payload);
            } else {
                send_to_server_locked("@" + current_peer + " " + line);
            }
        }
        std::cout << "> " << std::flush;
    }

    g_running = false;
    shutdown(g_fd, SHUT_RDWR);
    receiver.join();
    rekey_thread.join();
    if (g_dh_ctx) BN_CTX_free(g_dh_ctx);
    close(g_fd);
    return 0;
}

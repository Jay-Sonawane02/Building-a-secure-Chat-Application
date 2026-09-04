// Phase 4 - End-to-End Encryption Between Clients
//
// Everything through certificate validation, proof-of-possession, and the
// client-server DH handshake is IDENTICAL to Phase 3 -- see that file for
// those comments. This file adds exactly one new layer on top: a second,
// independent DH exchange directly between two clients, triggered by
// `/e2e username`, using the required wire tags so the server's relay
// logic never needs to change.
//
// WIRE TAGS (spec 1.4, exact strings required):
//   __E2E_INIT__<hex DH pub>   -- sent as the payload of an ordinary
//                                 @username message through the existing
//                                 encrypted client-server channel
//   __E2E_ACK__<hex DH pub>    -- same, completes the E2E exchange
//   __E2E_MSG__<base64 blob>   -- base64(nonce || AES-GCM ciphertext+tag),
//                                 the actual chat content once the E2E
//                                 session exists
//
// LAYERING: an E2E chat message is encrypted TWICE -- once under the E2E
// key (this file), and the resulting tagged string is then encrypted AGAIN
// under the client-server key via the existing channel::send_encrypted()
// call, exactly like any other outgoing line. The server only ever sees
// (and can only ever decrypt down to) the outer layer -- the payload
// "__E2E_MSG__<blob>" is opaque to it.
//
// NONCE SAFETY FOR THE E2E LAYER: same problem as the client-server link
// in Phase 2 -- one DH exchange produces a single key used by BOTH
// directions. Since usernames are known to both sides, each side
// deterministically assigns itself a direction byte by comparing usernames
// (lexicographically smaller = 0x01, larger = 0x02) -- both sides compute
// this the same way independently, so the two directions can never
// collide on a nonce, exactly like the CLIENT_TO_SERVER/SERVER_TO_CLIENT
// split in common/crypto_channel.h.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
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

static std::atomic<bool> g_running{true};

// ---- E2E session state (per peer username) --------------------------
struct E2ESession {
    std::vector<uint8_t> key;  // 32-byte AES key = SHA256(E2E shared secret)
    uint64_t send_counter = 0;
    uint8_t my_direction;  // 0x01 or 0x02, see nonce-safety note above
};

static std::mutex g_e2e_mutex;                          // guards both maps below
static std::map<std::string, E2ESession> g_e2e_sessions;  // established sessions
static std::map<std::string, dh::BNPtr> g_pending_priv;   // our priv key while awaiting an ACK

// The client-server channel is shared between the main thread (typing)
// and the receiver thread (which auto-sends __E2E_ACK__ replies), so both
// the socket writes AND the shared send_counter need a single lock.
static std::mutex g_channel_mutex;

static std::string g_username;  // set once, after registration
static dh::BNPtr g_dh_p, g_dh_g;
static BN_CTX *g_dh_ctx = nullptr;

static uint8_t direction_for(const std::string &me, const std::string &peer) {
    return me < peer ? 0x01 : 0x02;
}

// Same nonce construction as common/crypto_channel.h's make_nonce(), just
// for the E2E layer's own independent key/counter space.
static std::vector<uint8_t> e2e_nonce(uint8_t dir, uint64_t counter) {
    std::vector<uint8_t> nonce(aesgcm::NONCE_LEN, 0);
    nonce[0] = dir;
    for (int i = 0; i < 8; ++i) nonce[1 + i] = static_cast<uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
    return nonce;
}

static bool send_channel_locked(int fd, const std::vector<uint8_t> &key,
                                 uint64_t &counter, const std::string &plaintext) {
    std::lock_guard<std::mutex> lock(g_channel_mutex);
    return channel::send_encrypted(fd, key, channel::CLIENT_TO_SERVER, counter, plaintext);
}

// ---- receiver thread ---------------------------------------------------
static void receiver_loop(int fd, LineReader *reader, std::vector<uint8_t> server_key,
                           uint64_t *server_send_counter) {
    std::string line;
    while (g_running) {
        auto res = channel::recv_encrypted(*reader, server_key, line);
        if (res == channel::RecvResult::DISCONNECTED) break;
        if (res == channel::RecvResult::TAMPER_DETECTED) {
            std::cout << "\n[SECURITY] Message failed authentication on the "
                         "client-server link (tampering detected) -- discarded.\n> "
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
                std::string peer_hex = payload.substr(12);
                try {
                    dh::BNPtr peer_pub = dh::hex_to_pub(peer_hex);
                    dh::Keypair kp = dh::generate_keypair(g_dh_p, g_dh_g, g_dh_ctx);
                    std::vector<uint8_t> secret =
                        dh::compute_shared_secret(peer_pub, kp.priv, g_dh_p, g_dh_ctx);
                    std::vector<uint8_t> key = sha256::hash(secret);
                    std::string fingerprint = sha256::to_hex(sha256::hash(key));

                    std::string ack_payload = "__E2E_ACK__" + dh::pub_to_hex(kp.pub);
                    {
                        std::lock_guard<std::mutex> lock(g_e2e_mutex);
                        g_e2e_sessions[sender] =
                            E2ESession{key, 0, direction_for(g_username, sender)};
                    }
                    send_channel_locked(fd, server_key, *server_send_counter,
                                        "@" + sender + " " + ack_payload);
                    std::cout << "\n[E2E] Session established with " << sender
                              << ". Fingerprint: " << fingerprint << "\n> " << std::flush;
                } catch (const std::exception &e) {
                    std::cout << "\n[E2E] Failed to process INIT from " << sender << ": "
                              << e.what() << "\n> " << std::flush;
                }
                continue;
            }

            if (payload.rfind("__E2E_ACK__", 0) == 0) {
                std::string peer_hex = payload.substr(11);
                std::lock_guard<std::mutex> lock(g_e2e_mutex);
                auto it = g_pending_priv.find(sender);
                if (it == g_pending_priv.end()) {
                    std::cout << "\n[E2E] Unexpected ACK from " << sender
                              << " (no pending exchange) -- ignored.\n> " << std::flush;
                    continue;
                }
                try {
                    dh::BNPtr peer_pub = dh::hex_to_pub(peer_hex);
                    std::vector<uint8_t> secret =
                        dh::compute_shared_secret(peer_pub, it->second, g_dh_p, g_dh_ctx);
                    std::vector<uint8_t> key = sha256::hash(secret);
                    std::string fingerprint = sha256::to_hex(sha256::hash(key));
                    g_e2e_sessions[sender] =
                        E2ESession{key, 0, direction_for(g_username, sender)};
                    g_pending_priv.erase(it);
                    std::cout << "\n[E2E] Session acknowledged with " << sender
                              << ". Fingerprint: " << fingerprint << "\n> " << std::flush;
                } catch (const std::exception &e) {
                    std::cout << "\n[E2E] Failed to process ACK from " << sender << ": "
                              << e.what() << "\n> " << std::flush;
                }
                continue;
            }

            if (payload.rfind("__E2E_MSG__", 0) == 0) {
                std::string blob_b64 = payload.substr(11);
                std::lock_guard<std::mutex> lock(g_e2e_mutex);
                auto it = g_e2e_sessions.find(sender);
                if (it == g_e2e_sessions.end()) {
                    std::cout << "\n[E2E] Received an E2E message from " << sender
                              << " but no session exists -- discarded.\n> " << std::flush;
                    continue;
                }
                try {
                    std::vector<uint8_t> wire = base64::decode(blob_b64);
                    if (wire.size() < aesgcm::NONCE_LEN + aesgcm::TAG_LEN) {
                        std::cout << "\n[E2E] Malformed message from " << sender
                                  << ".\n> " << std::flush;
                        continue;
                    }
                    std::vector<uint8_t> nonce(wire.begin(), wire.begin() + aesgcm::NONCE_LEN);
                    std::vector<uint8_t> ct(wire.begin() + aesgcm::NONCE_LEN, wire.end());
                    std::string plaintext;
                    if (aesgcm::decrypt(it->second.key.data(), nonce.data(), ct, plaintext)) {
                        std::cout << "\n[" << sender << " (E2E)]: " << plaintext << "\n> "
                                  << std::flush;
                    } else {
                        std::cout << "\n[SECURITY] E2E message from " << sender
                                  << " failed authentication (tampering detected) -- "
                                     "discarded.\n> "
                                  << std::flush;
                    }
                } catch (const std::exception &e) {
                    std::cout << "\n[E2E] Error decoding message from " << sender << ": "
                              << e.what() << "\n> " << std::flush;
                }
                continue;
            }

            // Not an E2E-tagged payload -- ordinary Phase 2/3-style plaintext
            // chat, which the SERVER can still read (this is expected before
            // an E2E session exists, or for peers you haven't run /e2e with).
            std::cout << "\n[" << sender << "]: " << payload << "\n> " << std::flush;
        } else if (line.rfind("WHOLIST", 0) == 0) {
            std::cout << "\nOnline users:" << line.substr(7) << "\n> " << std::flush;
        } else if (line.rfind("ERR", 0) == 0) {
            std::cout << "\n[server error] " << line.substr(4) << "\n> " << std::flush;
        } else if (line == "OK") {
            // registration ack
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

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);
    if (connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
    LineReader reader{fd, ""};

    // --- Certificate validation + proof-of-possession (identical to Phase 3) ---
    std::string cert_line;
    if (!reader.recv_line(cert_line) || cert_line.rfind("CERT ", 0) != 0) {
        std::cerr << "ABORT: server did not present a certificate. Refusing to proceed.\n";
        close(fd);
        return 1;
    }
    cert::X509Ptr server_cert;
    try {
        server_cert = cert::cert_from_wire(cert_line.substr(5));
    } catch (const std::exception &e) {
        std::cerr << "ABORT: could not parse server certificate (" << e.what() << ").\n";
        close(fd);
        return 1;
    }
    auto validation = cert::validate_certificate(server_cert, ca_cert, EXPECTED_SERVER_CN);
    if (!validation.ok) {
        std::cerr << "ABORT: certificate validation FAILED -- " << validation.reason << "\n";
        close(fd);
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
    send_line(fd, "NONCE " + base64::encode(nonce));
    std::string proof_line;
    if (!reader.recv_line(proof_line) || proof_line.rfind("PROOF ", 0) != 0) {
        std::cerr << "ABORT: server did not respond to proof-of-possession challenge.\n";
        close(fd);
        return 1;
    }
    std::vector<uint8_t> signature = base64::decode(proof_line.substr(6));
    if (!cert::verify_challenge(server_cert, nonce, signature)) {
        std::cerr << "ABORT: proof-of-possession FAILED.\n";
        close(fd);
        return 1;
    }
    std::cout << "Proof-of-possession verified.\n";

    // --- Client-server DH handshake (identical to Phase 2/3) ---
    handshake::Result hs;
    try {
        hs = handshake::do_handshake_listen_first(fd, reader, "client");
    } catch (const std::exception &e) {
        std::cerr << "DH handshake failed: " << e.what() << "\n";
        return 1;
    }
    std::cout << "Client-server fingerprint: " << hs.fingerprint << "\n";

    std::string username;
    if (argc > 3) {
        username = argv[3];
    } else {
        std::cout << "Choose a username: ";
        std::getline(std::cin, username);
    }
    g_username = username;

    uint64_t server_send_counter = 0;
    if (!send_channel_locked(fd, hs.key, server_send_counter, username)) {
        std::cerr << "Failed to send username.\n";
        return 1;
    }
    std::string ack;
    auto ack_res = channel::recv_encrypted(reader, hs.key, ack);
    if (ack_res != channel::RecvResult::OK || ack != "OK") {
        std::cerr << "Registration failed.\n";
        return 1;
    }
    std::cout << "Connected as '" << username
              << "'. Commands: @user msg | /chat user | /e2e user | /who | /quit\n";

    // Load the DH group ONCE for all E2E exchanges this session.
    dh::load_group(g_dh_p, g_dh_g);
    g_dh_ctx = BN_CTX_new();

    std::thread receiver(receiver_loop, fd, &reader, hs.key, &server_send_counter);

    std::string current_peer;
    std::string line;
    std::cout << "> " << std::flush;
    while (g_running && std::getline(std::cin, line)) {
        if (line.empty()) {
            std::cout << "> " << std::flush;
            continue;
        }
        if (line == "/quit") {
            send_channel_locked(fd, hs.key, server_send_counter, "/quit");
            g_running = false;
            break;
        }
        if (line == "/who") {
            send_channel_locked(fd, hs.key, server_send_counter, "/who");
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
            try {
                dh::Keypair kp = dh::generate_keypair(g_dh_p, g_dh_g, g_dh_ctx);
                std::string init_payload = "__E2E_INIT__" + dh::pub_to_hex(kp.pub);
                {
                    std::lock_guard<std::mutex> lock(g_e2e_mutex);
                    g_pending_priv[target] = std::move(kp.priv);
                }
                send_channel_locked(fd, hs.key, server_send_counter,
                                     "@" + target + " " + init_payload);
                std::cout << "[E2E] Initiated key exchange with " << target << "\n> "
                          << std::flush;
            } catch (const std::exception &e) {
                std::cout << "[E2E] Failed to initiate: " << e.what() << "\n> " << std::flush;
            }
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
            // Route through the E2E layer if a session with this peer
            // exists, otherwise fall back to plain Phase 2/3-style chat.
            std::lock_guard<std::mutex> lock(g_e2e_mutex);
            auto it = g_e2e_sessions.find(current_peer);
            if (it != g_e2e_sessions.end()) {
                std::vector<uint8_t> n = e2e_nonce(it->second.my_direction,
                                                    it->second.send_counter++);
                std::vector<uint8_t> ct = aesgcm::encrypt(it->second.key.data(), n.data(), message);
                std::vector<uint8_t> wire;
                wire.insert(wire.end(), n.begin(), n.end());
                wire.insert(wire.end(), ct.begin(), ct.end());
                std::string payload = "__E2E_MSG__" + base64::encode(wire);
                send_channel_locked(fd, hs.key, server_send_counter,
                                     "@" + current_peer + " " + payload);
            } else {
                send_channel_locked(fd, hs.key, server_send_counter, line);
            }
            std::cout << "> " << std::flush;
            continue;
        }
        if (current_peer.empty()) {
            std::cout << "No chat partner selected. Use /chat, /e2e, or @username.\n> "
                      << std::flush;
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(g_e2e_mutex);
            auto it = g_e2e_sessions.find(current_peer);
            if (it != g_e2e_sessions.end()) {
                std::vector<uint8_t> n = e2e_nonce(it->second.my_direction,
                                                    it->second.send_counter++);
                std::vector<uint8_t> ct = aesgcm::encrypt(it->second.key.data(), n.data(), line);
                std::vector<uint8_t> wire;
                wire.insert(wire.end(), n.begin(), n.end());
                wire.insert(wire.end(), ct.begin(), ct.end());
                std::string payload = "__E2E_MSG__" + base64::encode(wire);
                send_channel_locked(fd, hs.key, server_send_counter,
                                     "@" + current_peer + " " + payload);
            } else {
                send_channel_locked(fd, hs.key, server_send_counter,
                                     "@" + current_peer + " " + line);
            }
        }
        std::cout << "> " << std::flush;
    }

    g_running = false;
    shutdown(fd, SHUT_RDWR);
    receiver.join();
    if (g_dh_ctx) BN_CTX_free(g_dh_ctx);
    close(fd);
    return 0;
}

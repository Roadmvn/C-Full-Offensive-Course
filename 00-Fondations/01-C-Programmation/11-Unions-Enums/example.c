/*
 * Module 12 : Unions et Énumérations
 *
 * Description : Démonstration complète des unions et enums avec applications offensives
 * Compilation : gcc -o example example.c
 * Exécution  : ./example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// DEMO 1 : Union de base - partage mémoire
// ============================================================================

union BasicUnion {
    int i;
    float f;
    char str[20];
};

void demo_basic_union(void) {
    printf("=== DEMO 1 : Union de base ===\n\n");

    union BasicUnion u;

    // Taille = plus grand membre
    printf("Taille union : %lu bytes\n", sizeof(u));
    printf("Taille int   : %lu bytes\n", sizeof(u.i));
    printf("Taille float : %lu bytes\n", sizeof(u.f));
    printf("Taille str   : %lu bytes\n\n", sizeof(u.str));

    // Utiliser comme int
    u.i = 42;
    printf("Après u.i = 42:\n");
    printf("  u.i = %d\n", u.i);
    printf("  u.f = %f (garbage)\n\n", u.f);

    // Utiliser comme float (écrase i)
    u.f = 3.14f;
    printf("Après u.f = 3.14:\n");
    printf("  u.f = %f\n", u.f);
    printf("  u.i = %d (garbage)\n\n", u.i);

    // Utiliser comme string (écrase tout)
    strcpy(u.str, "Hello");
    printf("Après u.str = \"Hello\":\n");
    printf("  u.str = \"%s\"\n", u.str);
    printf("  u.i = %d (garbage)\n\n", u.i);
}

// ============================================================================
// DEMO 2 : Type Punning - voir les bits
// ============================================================================

typedef union {
    float f;
    uint32_t bits;
    uint8_t bytes[4];
} FloatBits;

void demo_type_punning(void) {
    printf("=== DEMO 2 : Type Punning ===\n\n");

    FloatBits fb;
    fb.f = 3.14159f;

    printf("Float: %f\n", fb.f);
    printf("Bits:  0x%08X\n", fb.bits);
    printf("Bytes: ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", fb.bytes[i]);
    }
    printf("(little-endian)\n\n");

    // Modifier les bits directement
    fb.bits = 0x40490FDB;  // Pi en IEEE 754
    printf("Après fb.bits = 0x40490FDB:\n");
    printf("Float: %f (Pi!)\n\n", fb.f);
}

// ============================================================================
// DEMO 3 : IEEE 754 décomposition
// ============================================================================

typedef union {
    float f;
    struct {
        uint32_t mantissa : 23;
        uint32_t exponent : 8;
        uint32_t sign : 1;
    } parts;
} IEEE754Float;

void demo_ieee754(void) {
    printf("=== DEMO 3 : IEEE 754 Float ===\n\n");

    IEEE754Float num;

    float values[] = {1.0f, -1.0f, 3.14159f, 0.5f, 2.0f};
    int count = sizeof(values) / sizeof(values[0]);

    printf("%-12s %-6s %-10s %-10s\n", "Value", "Sign", "Exponent", "Mantissa");
    printf("─────────────────────────────────────────\n");

    for (int i = 0; i < count; i++) {
        num.f = values[i];
        printf("%-12f %-6u %-10u 0x%06X\n",
               num.f, num.parts.sign,
               num.parts.exponent, num.parts.mantissa);
    }
    printf("\n");
}

// ============================================================================
// DEMO 4 : Enum de base
// ============================================================================

enum Color {
    RED,
    GREEN,
    BLUE
};

void demo_basic_enum(void) {
    printf("=== DEMO 4 : Enum de base ===\n\n");

    printf("RED   = %d\n", RED);
    printf("GREEN = %d\n", GREEN);
    printf("BLUE  = %d\n\n", BLUE);

    enum Color c = GREEN;
    printf("Color c = GREEN = %d\n\n", c);
}

// ============================================================================
// DEMO 5 : Enum avec valeurs personnalisées
// ============================================================================

typedef enum {
    HTTP_OK = 200,
    HTTP_CREATED = 201,
    HTTP_BAD_REQUEST = 400,
    HTTP_UNAUTHORIZED = 401,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_SERVER_ERROR = 500
} HttpStatus;

const char *http_status_string(HttpStatus s) {
    switch (s) {
        case HTTP_OK:           return "OK";
        case HTTP_CREATED:      return "Created";
        case HTTP_BAD_REQUEST:  return "Bad Request";
        case HTTP_UNAUTHORIZED: return "Unauthorized";
        case HTTP_FORBIDDEN:    return "Forbidden";
        case HTTP_NOT_FOUND:    return "Not Found";
        case HTTP_SERVER_ERROR: return "Internal Server Error";
        default:                return "Unknown";
    }
}

void demo_http_status(void) {
    printf("=== DEMO 5 : HTTP Status Codes ===\n\n");

    HttpStatus codes[] = {HTTP_OK, HTTP_NOT_FOUND, HTTP_SERVER_ERROR};
    int count = sizeof(codes) / sizeof(codes[0]);

    for (int i = 0; i < count; i++) {
        printf("%d %s\n", codes[i], http_status_string(codes[i]));
    }
    printf("\n");
}

// ============================================================================
// DEMO 6 : Enum comme flags (bitwise)
// ============================================================================

typedef enum {
    PERM_NONE    = 0,
    PERM_READ    = 1 << 0,  // 0001
    PERM_WRITE   = 1 << 1,  // 0010
    PERM_EXECUTE = 1 << 2,  // 0100
    PERM_DELETE  = 1 << 3   // 1000
} Permission;

void print_permissions(Permission p) {
    printf("Permissions: ");
    if (p == PERM_NONE) {
        printf("NONE");
    } else {
        if (p & PERM_READ)    printf("R");
        if (p & PERM_WRITE)   printf("W");
        if (p & PERM_EXECUTE) printf("X");
        if (p & PERM_DELETE)  printf("D");
    }
    printf(" (0x%X)\n", p);
}

void demo_enum_flags(void) {
    printf("=== DEMO 6 : Enum Flags ===\n\n");

    Permission user = PERM_READ | PERM_WRITE;
    printf("User: ");
    print_permissions(user);

    Permission admin = PERM_READ | PERM_WRITE | PERM_EXECUTE | PERM_DELETE;
    printf("Admin: ");
    print_permissions(admin);

    // Test de flag
    if (user & PERM_READ) {
        printf("User can read\n");
    }
    if (!(user & PERM_DELETE)) {
        printf("User cannot delete\n");
    }

    // Ajouter un flag
    user |= PERM_EXECUTE;
    printf("After adding EXECUTE: ");
    print_permissions(user);

    // Retirer un flag
    user &= ~PERM_WRITE;
    printf("After removing WRITE: ");
    print_permissions(user);

    printf("\n");
}

// ============================================================================
// DEMO 7 : Tagged Union (Variant Type)
// ============================================================================

typedef enum {
    VAR_INT,
    VAR_FLOAT,
    VAR_STRING,
    VAR_BOOL
} VariantType;

typedef struct {
    VariantType type;
    union {
        int i;
        float f;
        char str[32];
        int b;
    } value;
} Variant;

void print_variant(const Variant *v) {
    switch (v->type) {
        case VAR_INT:
            printf("Int: %d\n", v->value.i);
            break;
        case VAR_FLOAT:
            printf("Float: %f\n", v->value.f);
            break;
        case VAR_STRING:
            printf("String: \"%s\"\n", v->value.str);
            break;
        case VAR_BOOL:
            printf("Bool: %s\n", v->value.b ? "true" : "false");
            break;
    }
}

void demo_tagged_union(void) {
    printf("=== DEMO 7 : Tagged Union ===\n\n");

    Variant vars[4];

    vars[0].type = VAR_INT;
    vars[0].value.i = 42;

    vars[1].type = VAR_FLOAT;
    vars[1].value.f = 3.14159f;

    vars[2].type = VAR_STRING;
    strcpy(vars[2].value.str, "Hello World");

    vars[3].type = VAR_BOOL;
    vars[3].value.b = 1;

    printf("Variants:\n");
    for (int i = 0; i < 4; i++) {
        printf("  [%d] ", i);
        print_variant(&vars[i]);
    }
    printf("\n");
}

// ============================================================================
// DEMO 8 : Application offensive - État d'implant
// ============================================================================

typedef enum {
    STATE_INIT,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_EXECUTING,
    STATE_SLEEPING,
    STATE_ERROR,
    STATE_DEAD
} ImplantState;

const char *state_name(ImplantState s) {
    const char *names[] = {
        "INIT", "CONNECTING", "CONNECTED",
        "EXECUTING", "SLEEPING", "ERROR", "DEAD"
    };
    return (s >= 0 && s <= STATE_DEAD) ? names[s] : "UNKNOWN";
}

typedef struct {
    char id[16];
    ImplantState state;
    int error_code;
} Implant;

void implant_transition(Implant *imp, ImplantState new_state) {
    printf("[%s] %s -> %s\n",
           imp->id, state_name(imp->state), state_name(new_state));
    imp->state = new_state;
}

void demo_implant_state(void) {
    printf("=== DEMO 8 : État d'implant ===\n\n");

    Implant imp = {"IMP-001", STATE_INIT, 0};

    implant_transition(&imp, STATE_CONNECTING);
    implant_transition(&imp, STATE_CONNECTED);
    implant_transition(&imp, STATE_EXECUTING);
    implant_transition(&imp, STATE_SLEEPING);
    implant_transition(&imp, STATE_CONNECTED);
    printf("\n");
}

// ============================================================================
// DEMO 9 : Application offensive - Commandes C2
// ============================================================================

typedef enum {
    CMD_NOP       = 0x00,
    CMD_SHELL     = 0x01,
    CMD_DOWNLOAD  = 0x02,
    CMD_UPLOAD    = 0x03,
    CMD_SLEEP     = 0x04,
    CMD_EXIT      = 0xFF
} CommandType;

typedef struct {
    CommandType type;
    uint32_t id;
    union {
        struct {
            char command[256];
        } shell;
        struct {
            char url[256];
            char path[256];
        } download;
        struct {
            char path[256];
        } upload;
        struct {
            int seconds;
            int jitter;
        } sleep;
    } args;
} C2Command;

void execute_c2_command(const C2Command *cmd) {
    printf("[CMD 0x%02X] ", cmd->type);

    switch (cmd->type) {
        case CMD_NOP:
            printf("NOP\n");
            break;
        case CMD_SHELL:
            printf("SHELL: %s\n", cmd->args.shell.command);
            break;
        case CMD_DOWNLOAD:
            printf("DOWNLOAD: %s -> %s\n",
                   cmd->args.download.url,
                   cmd->args.download.path);
            break;
        case CMD_UPLOAD:
            printf("UPLOAD: %s\n", cmd->args.upload.path);
            break;
        case CMD_SLEEP:
            printf("SLEEP: %ds (±%d%%)\n",
                   cmd->args.sleep.seconds,
                   cmd->args.sleep.jitter);
            break;
        case CMD_EXIT:
            printf("EXIT\n");
            break;
        default:
            printf("UNKNOWN\n");
    }
}

void demo_c2_commands(void) {
    printf("=== DEMO 9 : Commandes C2 ===\n\n");

    C2Command cmds[4];

    // Shell command
    cmds[0].type = CMD_SHELL;
    cmds[0].id = 1;
    strcpy(cmds[0].args.shell.command, "whoami");

    // Download command
    cmds[1].type = CMD_DOWNLOAD;
    cmds[1].id = 2;
    strcpy(cmds[1].args.download.url, "http://evil.com/payload.exe");
    strcpy(cmds[1].args.download.path, "/tmp/payload.exe");

    // Sleep command
    cmds[2].type = CMD_SLEEP;
    cmds[2].id = 3;
    cmds[2].args.sleep.seconds = 60;
    cmds[2].args.sleep.jitter = 20;

    // Exit command
    cmds[3].type = CMD_EXIT;
    cmds[3].id = 4;

    for (int i = 0; i < 4; i++) {
        execute_c2_command(&cmds[i]);
    }
    printf("\n");
}

// ============================================================================
// DEMO 10 : Application offensive - Parsing IP
// ============================================================================

typedef union {
    uint32_t addr;
    uint8_t octets[4];
} IPv4Addr;

void demo_ip_parsing(void) {
    printf("=== DEMO 10 : Parsing IP ===\n\n");

    IPv4Addr ip;

    // Construire à partir d'octets
    ip.octets[0] = 192;
    ip.octets[1] = 168;
    ip.octets[2] = 1;
    ip.octets[3] = 100;

    printf("IP construite: %u.%u.%u.%u\n",
           ip.octets[0], ip.octets[1],
           ip.octets[2], ip.octets[3]);
    printf("Valeur 32-bit: 0x%08X\n\n", ip.addr);

    // Parser depuis une valeur 32-bit
    ip.addr = 0x0A000001;  // 10.0.0.1 (network order)
    printf("IP depuis 0x0A000001:\n");
    printf("  Network order: %u.%u.%u.%u\n",
           ip.octets[0], ip.octets[1],
           ip.octets[2], ip.octets[3]);

    // En little-endian, les octets sont inversés
    printf("  Octets: ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", ip.octets[i]);
    }
    printf("\n\n");
}

// ============================================================================
// DEMO 11 : Application offensive - Message flags
// ============================================================================

typedef enum {
    MSG_FLAG_NONE       = 0,
    MSG_FLAG_ENCRYPTED  = 1 << 0,
    MSG_FLAG_COMPRESSED = 1 << 1,
    MSG_FLAG_CHUNKED    = 1 << 2,
    MSG_FLAG_PRIORITY   = 1 << 3,
    MSG_FLAG_ACK_REQ    = 1 << 4
} MessageFlags;

typedef struct {
    uint32_t id;
    MessageFlags flags;
    uint32_t data_len;
} MessageHeader;

void print_msg_flags(MessageFlags f) {
    printf("[");
    if (f & MSG_FLAG_ENCRYPTED)  printf("ENC ");
    if (f & MSG_FLAG_COMPRESSED) printf("COMP ");
    if (f & MSG_FLAG_CHUNKED)    printf("CHUNK ");
    if (f & MSG_FLAG_PRIORITY)   printf("PRIO ");
    if (f & MSG_FLAG_ACK_REQ)    printf("ACK ");
    if (f == MSG_FLAG_NONE)      printf("NONE");
    printf("]");
}

void demo_message_flags(void) {
    printf("=== DEMO 11 : Message Flags ===\n\n");

    MessageHeader msgs[] = {
        {1, MSG_FLAG_ENCRYPTED | MSG_FLAG_ACK_REQ, 256},
        {2, MSG_FLAG_COMPRESSED | MSG_FLAG_CHUNKED, 1024},
        {3, MSG_FLAG_PRIORITY | MSG_FLAG_ENCRYPTED | MSG_FLAG_COMPRESSED, 512},
        {4, MSG_FLAG_NONE, 64}
    };

    int count = sizeof(msgs) / sizeof(msgs[0]);

    printf("%-6s %-20s %s\n", "ID", "FLAGS", "SIZE");
    printf("────────────────────────────────────\n");

    for (int i = 0; i < count; i++) {
        printf("%-6u ", msgs[i].id);
        print_msg_flags(msgs[i].flags);
        printf(" %u bytes\n", msgs[i].data_len);
    }
    printf("\n");
}

// ============================================================================
// DEMO 12 : Endianness swap
// ============================================================================

typedef union {
    uint16_t value;
    uint8_t bytes[2];
} Word16;

typedef union {
    uint32_t value;
    uint8_t bytes[4];
} Word32;

uint16_t bswap16(uint16_t val) {
    Word16 w;
    w.value = val;
    return (w.bytes[0] << 8) | w.bytes[1];
}

uint32_t bswap32(uint32_t val) {
    Word32 w;
    w.value = val;
    return (w.bytes[0] << 24) | (w.bytes[1] << 16) |
           (w.bytes[2] << 8)  | w.bytes[3];
}

void demo_endianness(void) {
    printf("=== DEMO 12 : Endianness Swap ===\n\n");

    uint16_t port = 0x1234;
    printf("Port 0x%04X -> swapped: 0x%04X\n", port, bswap16(port));

    uint32_t addr = 0xC0A80164;  // 192.168.1.100
    printf("Addr 0x%08X -> swapped: 0x%08X\n", addr, bswap32(addr));
    printf("\n");
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("================================================================\n");
    printf("     MODULE 12 : UNIONS ET ENUMS - DEMONSTRATIONS\n");
    printf("================================================================\n\n");

    demo_basic_union();
    demo_type_punning();
    demo_ieee754();
    demo_basic_enum();
    demo_http_status();
    demo_enum_flags();
    demo_tagged_union();
    demo_implant_state();
    demo_c2_commands();
    demo_ip_parsing();
    demo_message_flags();
    demo_endianness();

    printf("================================================================\n");
    printf("                  FIN DES DEMONSTRATIONS\n");
    printf("================================================================\n");

    return 0;
}

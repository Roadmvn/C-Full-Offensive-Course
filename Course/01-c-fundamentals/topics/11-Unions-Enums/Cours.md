# Module 12 : Unions et Énumérations

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :
- Comprendre les unions et le partage mémoire
- Utiliser le type punning pour manipuler les représentations binaires
- Définir et utiliser des énumérations
- Créer des flags avec des bitfields enum
- Combiner struct, union et enum
- Applications offensives : parsing de protocoles, variant types, state machines

---

## 1. Introduction aux unions

### C'est quoi une union ?

Une **union** est comme une structure, mais tous les membres **partagent la même zone mémoire**. Un seul membre peut contenir une valeur valide à la fois.

```c
union Data {
    int i;
    float f;
    char str[20];
};
```

### Différence struct vs union

```c
struct MyStruct {
    int i;      // 4 bytes
    float f;    // 4 bytes
    char c;     // 1 byte
};  // Total : ~12 bytes (avec padding)

union MyUnion {
    int i;      // 4 bytes
    float f;    // 4 bytes
    char c;     // 1 byte
};  // Total : 4 bytes (taille du plus grand membre)
```

### Schéma mémoire

```
struct (membres séparés) :
┌──────────┬──────────┬──────────┐
│   int i  │  float f │  char c  │
│ 4 bytes  │ 4 bytes  │ 1 byte   │
└──────────┴──────────┴──────────┘
        Total : ~12 bytes

union (membres superposés) :
┌──────────────────────────────────┐
│          int i                   │
│          float f     (MÊME zone) │
│          char c                  │
│                                  │
└──────────────────────────────────┘
        Total : 4 bytes
```

---

## 2. Utilisation des unions

### Syntaxe de base

```c
union Data {
    int i;
    float f;
    char str[20];
};

int main(void) {
    union Data d;

    // Utiliser comme int
    d.i = 42;
    printf("i = %d\n", d.i);  // 42

    // Utiliser comme float (écrase i)
    d.f = 3.14f;
    printf("f = %f\n", d.f);  // 3.14
    printf("i = %d\n", d.i);  // GARBAGE (écrasé)

    return 0;
}
```

### sizeof d'une union

```c
union Example {
    char c;         // 1 byte
    int i;          // 4 bytes
    double d;       // 8 bytes
    char str[20];   // 20 bytes
};

printf("Size: %lu\n", sizeof(union Example));  // 20 (le plus grand)
```

### typedef pour simplifier

```c
typedef union {
    int i;
    float f;
    char str[20];
} Data;

Data d;  // Plus besoin de "union"
d.i = 100;
```

---

## 3. Type Punning (réinterprétation de bits)

### Concept

Le **type punning** permet de voir la représentation binaire d'une valeur en l'interprétant comme un autre type.

```c
union FloatBits {
    float f;
    unsigned int bits;
};

union FloatBits fb;
fb.f = 3.14f;

printf("Float: %f\n", fb.f);
printf("Bits:  0x%08X\n", fb.bits);  // 0x4048F5C3
```

### Schéma

```
float 3.14 en mémoire :
┌────────────────────────────────┐
│ 0x4048F5C3                     │
│ 01000000 01001000 11110101 ... │
└────────────────────────────────┘
         ↓                    ↓
    float f = 3.14      uint bits = 0x4048F5C3
    (interprété)        (même bytes)
```

### Manipulation de bits IEEE 754

```c
typedef union {
    float f;
    struct {
        unsigned int mantissa : 23;
        unsigned int exponent : 8;
        unsigned int sign : 1;
    } parts;
} Float32;

Float32 num;
num.f = -3.14f;

printf("Sign:     %u\n", num.parts.sign);      // 1 (négatif)
printf("Exponent: %u\n", num.parts.exponent);  // 128 (biaisé)
printf("Mantissa: 0x%X\n", num.parts.mantissa);
```

---

## 4. Énumérations (enum)

### C'est quoi un enum ?

Un **enum** définit un ensemble de constantes nommées avec des valeurs entières.

```c
enum Color {
    RED,    // 0
    GREEN,  // 1
    BLUE    // 2
};

enum Color c = GREEN;
printf("Color: %d\n", c);  // 1
```

### Valeurs personnalisées

```c
enum HttpStatus {
    OK = 200,
    CREATED = 201,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    NOT_FOUND = 404,
    INTERNAL_ERROR = 500
};

enum HttpStatus status = NOT_FOUND;
printf("Status: %d\n", status);  // 404
```

### typedef pour simplifier

```c
typedef enum {
    STATE_IDLE,
    STATE_RUNNING,
    STATE_STOPPED,
    STATE_ERROR
} State;

State current = STATE_RUNNING;
```

### Enum comme flags (bitwise)

```c
typedef enum {
    PERM_NONE    = 0,        // 0000
    PERM_READ    = 1 << 0,   // 0001
    PERM_WRITE   = 1 << 1,   // 0010
    PERM_EXECUTE = 1 << 2,   // 0100
    PERM_ADMIN   = 1 << 3    // 1000
} Permission;

// Combinaison de flags
Permission user_perms = PERM_READ | PERM_WRITE;  // 0011

// Test de flag
if (user_perms & PERM_READ) {
    printf("Can read\n");
}

// Ajouter un flag
user_perms |= PERM_EXECUTE;  // 0111

// Retirer un flag
user_perms &= ~PERM_WRITE;   // 0101
```

---

## 5. Combiner struct, union et enum

### Tagged union (union discriminée)

```c
typedef enum {
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING
} DataType;

typedef struct {
    DataType type;  // Tag pour savoir quel membre utiliser
    union {
        int i;
        float f;
        char str[32];
    } value;
} Variant;

void print_variant(Variant *v) {
    switch (v->type) {
        case TYPE_INT:
            printf("Int: %d\n", v->value.i);
            break;
        case TYPE_FLOAT:
            printf("Float: %f\n", v->value.f);
            break;
        case TYPE_STRING:
            printf("String: %s\n", v->value.str);
            break;
    }
}

int main(void) {
    Variant v1 = {TYPE_INT, .value.i = 42};
    Variant v2 = {TYPE_FLOAT, .value.f = 3.14f};
    Variant v3 = {TYPE_STRING, .value.str = "Hello"};

    print_variant(&v1);  // Int: 42
    print_variant(&v2);  // Float: 3.14
    print_variant(&v3);  // String: Hello

    return 0;
}
```

### Schéma tagged union

```
Variant v1 (TYPE_INT):
┌────────────┬───────────────────────────────┐
│ type = 0   │ value (union)                 │
│ (TYPE_INT) │ i = 42 (actif)                │
│            │ f = ??? (ignoré)              │
│            │ str = ??? (ignoré)            │
└────────────┴───────────────────────────────┘

Le tag "type" indique quel membre de l'union est valide.
```

---

## 6. Applications offensives

### 6.1 Parsing d'adresses IP

```c
typedef union {
    uint32_t addr;  // Adresse comme entier
    uint8_t octets[4];  // Adresse comme 4 bytes
    struct {
        uint8_t d;
        uint8_t c;
        uint8_t b;
        uint8_t a;
    } parts;
} IPv4Address;

IPv4Address ip;
ip.addr = 0xC0A80101;  // 192.168.1.1 (big-endian)

printf("IP: %u.%u.%u.%u\n",
       ip.octets[3], ip.octets[2],
       ip.octets[1], ip.octets[0]);
// IP: 192.168.1.1
```

### 6.2 Parsing de paquets réseau

```c
typedef enum {
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMP = 1
} Protocol;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    // ... autres champs
} TCPHeader;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UDPHeader;

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
} ICMPHeader;

typedef struct {
    Protocol proto;
    union {
        TCPHeader tcp;
        UDPHeader udp;
        ICMPHeader icmp;
        uint8_t raw[64];
    } header;
} TransportPacket;

void parse_packet(TransportPacket *pkt, uint8_t *data, Protocol proto) {
    pkt->proto = proto;

    switch (proto) {
        case PROTO_TCP:
            memcpy(&pkt->header.tcp, data, sizeof(TCPHeader));
            printf("TCP: %u -> %u\n",
                   ntohs(pkt->header.tcp.src_port),
                   ntohs(pkt->header.tcp.dst_port));
            break;

        case PROTO_UDP:
            memcpy(&pkt->header.udp, data, sizeof(UDPHeader));
            printf("UDP: %u -> %u\n",
                   ntohs(pkt->header.udp.src_port),
                   ntohs(pkt->header.udp.dst_port));
            break;

        case PROTO_ICMP:
            memcpy(&pkt->header.icmp, data, sizeof(ICMPHeader));
            printf("ICMP: type=%u code=%u\n",
                   pkt->header.icmp.type,
                   pkt->header.icmp.code);
            break;
    }
}
```

### 6.3 État d'un implant (state machine)

```c
typedef enum {
    IMPLANT_INIT,
    IMPLANT_CONNECTING,
    IMPLANT_CONNECTED,
    IMPLANT_EXECUTING,
    IMPLANT_SLEEPING,
    IMPLANT_ERROR,
    IMPLANT_DEAD
} ImplantState;

typedef struct {
    char id[32];
    ImplantState state;
    int error_code;
    time_t last_checkin;
} Implant;

const char *state_to_string(ImplantState s) {
    switch (s) {
        case IMPLANT_INIT:       return "INIT";
        case IMPLANT_CONNECTING: return "CONNECTING";
        case IMPLANT_CONNECTED:  return "CONNECTED";
        case IMPLANT_EXECUTING:  return "EXECUTING";
        case IMPLANT_SLEEPING:   return "SLEEPING";
        case IMPLANT_ERROR:      return "ERROR";
        case IMPLANT_DEAD:       return "DEAD";
        default:                 return "UNKNOWN";
    }
}

void implant_transition(Implant *imp, ImplantState new_state) {
    printf("[%s] %s -> %s\n",
           imp->id,
           state_to_string(imp->state),
           state_to_string(new_state));
    imp->state = new_state;
}
```

### 6.4 Type de commande C2

```c
typedef enum {
    CMD_SHELL      = 0x01,
    CMD_DOWNLOAD   = 0x02,
    CMD_UPLOAD     = 0x03,
    CMD_SCREENSHOT = 0x04,
    CMD_KEYLOG     = 0x05,
    CMD_SLEEP      = 0x06,
    CMD_EXIT       = 0xFF
} CommandType;

typedef struct {
    char path[256];
    char url[256];
} DownloadArgs;

typedef struct {
    char local_path[256];
    char remote_path[256];
} UploadArgs;

typedef struct {
    int seconds;
    int jitter;
} SleepArgs;

typedef struct {
    CommandType type;
    uint32_t id;
    union {
        char shell_cmd[512];
        DownloadArgs download;
        UploadArgs upload;
        SleepArgs sleep;
    } args;
} C2Command;

void execute_command(C2Command *cmd) {
    printf("[CMD %u] ", cmd->id);

    switch (cmd->type) {
        case CMD_SHELL:
            printf("SHELL: %s\n", cmd->args.shell_cmd);
            // system(cmd->args.shell_cmd);
            break;

        case CMD_DOWNLOAD:
            printf("DOWNLOAD: %s -> %s\n",
                   cmd->args.download.url,
                   cmd->args.download.path);
            break;

        case CMD_UPLOAD:
            printf("UPLOAD: %s -> %s\n",
                   cmd->args.upload.local_path,
                   cmd->args.upload.remote_path);
            break;

        case CMD_SLEEP:
            printf("SLEEP: %d seconds (±%d%% jitter)\n",
                   cmd->args.sleep.seconds,
                   cmd->args.sleep.jitter);
            break;

        case CMD_EXIT:
            printf("EXIT\n");
            break;

        default:
            printf("UNKNOWN TYPE: 0x%02X\n", cmd->type);
    }
}
```

### 6.5 Permissions et flags

```c
typedef enum {
    FLAG_NONE       = 0,
    FLAG_ENCRYPTED  = 1 << 0,   // Communication chiffrée
    FLAG_COMPRESSED = 1 << 1,   // Données compressées
    FLAG_CHUNKED    = 1 << 2,   // Envoi par morceaux
    FLAG_PRIORITY   = 1 << 3,   // Message prioritaire
    FLAG_ACK_REQ    = 1 << 4    // Accusé de réception requis
} MessageFlags;

typedef struct {
    uint32_t id;
    MessageFlags flags;
    uint32_t data_len;
    uint8_t data[];
} Message;

void print_flags(MessageFlags flags) {
    printf("Flags: ");
    if (flags == FLAG_NONE) {
        printf("NONE");
    } else {
        if (flags & FLAG_ENCRYPTED)  printf("ENCRYPTED ");
        if (flags & FLAG_COMPRESSED) printf("COMPRESSED ");
        if (flags & FLAG_CHUNKED)    printf("CHUNKED ");
        if (flags & FLAG_PRIORITY)   printf("PRIORITY ");
        if (flags & FLAG_ACK_REQ)    printf("ACK_REQ ");
    }
    printf("\n");
}

// Usage
MessageFlags flags = FLAG_ENCRYPTED | FLAG_COMPRESSED | FLAG_ACK_REQ;
print_flags(flags);  // ENCRYPTED COMPRESSED ACK_REQ
```

### 6.6 Conversion d'endianness

```c
typedef union {
    uint16_t value;
    uint8_t bytes[2];
} Word16;

typedef union {
    uint32_t value;
    uint8_t bytes[4];
} Word32;

uint16_t swap16(uint16_t val) {
    Word16 w;
    w.value = val;
    return (w.bytes[0] << 8) | w.bytes[1];
}

uint32_t swap32(uint32_t val) {
    Word32 w;
    w.value = val;
    return (w.bytes[0] << 24) |
           (w.bytes[1] << 16) |
           (w.bytes[2] << 8)  |
           w.bytes[3];
}

// Test
uint16_t port = 0x1234;
printf("Original: 0x%04X\n", port);       // 0x1234
printf("Swapped:  0x%04X\n", swap16(port)); // 0x3412
```

---

## 7. Bonnes pratiques

### Toujours utiliser un tag pour les unions

```c
// MAL : on ne sait pas quel membre est valide
union Bad {
    int i;
    float f;
};

// BIEN : le tag indique le type actif
typedef struct {
    enum { TAG_INT, TAG_FLOAT } tag;
    union {
        int i;
        float f;
    } value;
} Good;
```

### Enum : utiliser des valeurs explicites pour les protocoles

```c
// Pour les protocoles, définir explicitement les valeurs
typedef enum {
    MSG_BEACON    = 0x0001,
    MSG_TASK      = 0x0002,
    MSG_RESULT    = 0x0003,
    // Laisser de la place pour les futures versions
    MSG_HEARTBEAT = 0x0010
} MessageType;
```

### Union : attention à l'alignement

```c
// Les unions peuvent avoir un padding implicite
union Example {
    char c;      // 1 byte
    double d;    // 8 bytes
};  // Taille = 8 bytes (aligné sur double)
```

### Documenter les unions

```c
typedef union {
    uint32_t raw;           // Accès brut aux 4 bytes
    uint8_t bytes[4];       // Accès byte par byte
    struct {
        uint16_t low;       // 2 bytes de poids faible
        uint16_t high;      // 2 bytes de poids fort
    } words;
} Register32;  // Représente un registre 32-bit
```

---

## 8. Récapitulatif

| Concept | Description | Usage |
|---------|-------------|-------|
| union | Membres partagent la même mémoire | Type punning, variant types |
| sizeof(union) | Taille du plus grand membre | Optimisation mémoire |
| enum | Constantes nommées | États, types, codes d'erreur |
| Enum flags | Valeurs puissance de 2 | Permissions, options combinables |
| Tagged union | struct + enum + union | Variant types sûrs |
| Type punning | Réinterpréter les bits | Parsing binaire, IEEE 754 |

---

## 9. Exercices

Voir [exercice.md](exercice.md) pour les exercices pratiques.

## 10. Prochaine étape

Le module suivant abordera le **préprocesseur** :
- Macros (#define)
- Compilation conditionnelle (#ifdef)
- Inclusion de fichiers (#include)
- Applications : anti-debug, obfuscation

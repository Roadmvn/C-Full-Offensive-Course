# Module 12 : Unions et Enums - Solutions

## Solution 1 : Union de base

```c
#include <stdio.h>
#include <string.h>

union Value {
    int i;
    float f;
    char str[16];
};

int main(void) {
    union Value v;
    printf("sizeof(union Value) = %lu\n", sizeof(v));  // 16

    v.i = 42;
    printf("v.i = %d\n", v.i);

    v.f = 3.14f;
    printf("v.f = %f\n", v.f);
    printf("v.i = %d (écrasé)\n", v.i);

    strcpy(v.str, "Hello");
    printf("v.str = %s\n", v.str);

    return 0;
}
```

---

## Solution 2 : Type Punning

```c
#include <stdio.h>
#include <stdint.h>

typedef union {
    float f;
    uint32_t bits;
    uint8_t bytes[4];
} FloatBits;

int main(void) {
    FloatBits fb;
    fb.f = 3.14f;

    printf("Float: %f\n", fb.f);
    printf("Hex: 0x%08X\n", fb.bits);
    printf("Bytes: ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", fb.bytes[i]);
    }
    printf("\n");

    return 0;
}
```

---

## Solution 3 : Enum de base

```c
#include <stdio.h>

typedef enum {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
} LogLevel;

const char *level_names[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};

void log_message(LogLevel level, const char *msg) {
    printf("[%s] %s\n", level_names[level], msg);
}

int main(void) {
    log_message(DEBUG, "Starting application");
    log_message(INFO, "Connected to server");
    log_message(WARNING, "High memory usage");
    log_message(ERROR, "Connection lost");
    log_message(CRITICAL, "System failure");
    return 0;
}
```

---

## Solution 4 : Enum flags

```c
#include <stdio.h>

typedef enum {
    MODE_NONE    = 0,
    MODE_READ    = 1 << 0,
    MODE_WRITE   = 1 << 1,
    MODE_EXECUTE = 1 << 2,
    MODE_HIDDEN  = 1 << 3
} FileMode;

int has_flag(FileMode mode, FileMode flag) {
    return (mode & flag) != 0;
}

FileMode add_flag(FileMode mode, FileMode flag) {
    return mode | flag;
}

FileMode remove_flag(FileMode mode, FileMode flag) {
    return mode & ~flag;
}

void print_mode(FileMode m) {
    printf("Mode: ");
    if (m & MODE_READ)    printf("R");
    if (m & MODE_WRITE)   printf("W");
    if (m & MODE_EXECUTE) printf("X");
    if (m & MODE_HIDDEN)  printf("H");
    if (m == MODE_NONE)   printf("NONE");
    printf("\n");
}

int main(void) {
    FileMode m = MODE_READ | MODE_WRITE;
    print_mode(m);  // RW

    m = add_flag(m, MODE_EXECUTE);
    print_mode(m);  // RWX

    m = remove_flag(m, MODE_WRITE);
    print_mode(m);  // RX

    return 0;
}
```

---

## Solution 5 : Tagged Union

```c
#include <stdio.h>
#include <string.h>

typedef enum { CFG_INT, CFG_STRING, CFG_BOOL } ConfigType;

typedef struct {
    ConfigType type;
    union {
        int i;
        char str[64];
        int b;
    } value;
} ConfigValue;

void print_config(const char *name, ConfigValue *v) {
    printf("%s = ", name);
    switch (v->type) {
        case CFG_INT:    printf("%d\n", v->value.i); break;
        case CFG_STRING: printf("\"%s\"\n", v->value.str); break;
        case CFG_BOOL:   printf("%s\n", v->value.b ? "true" : "false"); break;
    }
}

int main(void) {
    ConfigValue port = {CFG_INT, .value.i = 8080};
    ConfigValue host = {CFG_STRING}; strcpy(host.value.str, "localhost");
    ConfigValue debug = {CFG_BOOL, .value.b = 1};

    print_config("port", &port);
    print_config("host", &host);
    print_config("debug", &debug);

    return 0;
}
```

---

## Solution 6 : Parsing IP

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef union {
    uint32_t addr;
    uint8_t octets[4];
} IPv4;

IPv4 ip_from_string(const char *str) {
    IPv4 ip = {0};
    int a, b, c, d;
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    ip.octets[0] = a;
    ip.octets[1] = b;
    ip.octets[2] = c;
    ip.octets[3] = d;
    return ip;
}

void ip_to_string(IPv4 ip, char *buf, int size) {
    snprintf(buf, size, "%u.%u.%u.%u",
             ip.octets[0], ip.octets[1],
             ip.octets[2], ip.octets[3]);
}

int main(void) {
    IPv4 ip = ip_from_string("192.168.1.100");
    char buf[16];
    ip_to_string(ip, buf, sizeof(buf));
    printf("IP: %s (0x%08X)\n", buf, ip.addr);
    return 0;
}
```

---

## Solution 7 : État d'implant

```c
#include <stdio.h>

typedef enum {
    STATE_INIT, STATE_CONNECTING, STATE_CONNECTED,
    STATE_EXECUTING, STATE_SLEEPING, STATE_DEAD
} State;

const char *state_str[] = {
    "INIT", "CONNECTING", "CONNECTED",
    "EXECUTING", "SLEEPING", "DEAD"
};

typedef struct {
    char id[16];
    State state;
} Implant;

int transition(Implant *imp, State new_state) {
    printf("[%s] %s -> %s\n", imp->id,
           state_str[imp->state], state_str[new_state]);
    imp->state = new_state;
    return 0;
}

int main(void) {
    Implant imp = {"IMP-001", STATE_INIT};
    transition(&imp, STATE_CONNECTING);
    transition(&imp, STATE_CONNECTED);
    transition(&imp, STATE_EXECUTING);
    transition(&imp, STATE_SLEEPING);
    return 0;
}
```

---

## Solution 8-9 : Commandes C2

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef enum {
    CMD_SHELL = 0x01,
    CMD_DOWNLOAD = 0x02,
    CMD_SLEEP = 0x04,
    CMD_EXIT = 0xFF
} CmdType;

typedef struct {
    CmdType type;
    uint32_t id;
    union {
        char shell_cmd[256];
        struct { char url[128]; char path[128]; } download;
        struct { int seconds; int jitter; } sleep;
    } args;
} Command;

void dispatch(Command *cmd) {
    printf("[%u] ", cmd->id);
    switch (cmd->type) {
        case CMD_SHELL:
            printf("SHELL: %s\n", cmd->args.shell_cmd);
            break;
        case CMD_DOWNLOAD:
            printf("DOWNLOAD: %s -> %s\n",
                   cmd->args.download.url, cmd->args.download.path);
            break;
        case CMD_SLEEP:
            printf("SLEEP: %ds\n", cmd->args.sleep.seconds);
            break;
        case CMD_EXIT:
            printf("EXIT\n");
            break;
    }
}

int main(void) {
    Command c1 = {CMD_SHELL, 1, .args.shell_cmd = "whoami"};
    Command c2 = {CMD_SLEEP, 2, .args.sleep = {60, 20}};
    dispatch(&c1);
    dispatch(&c2);
    return 0;
}
```

---

## Solution 10 : Registre CPU

```c
#include <stdio.h>
#include <stdint.h>

typedef union {
    uint64_t qword;
    uint32_t dword[2];
    uint16_t word[4];
    uint8_t byte[8];
} Register64;

int main(void) {
    Register64 rax;
    rax.qword = 0x0102030405060708ULL;

    printf("QWORD: 0x%016llX\n", (unsigned long long)rax.qword);
    printf("DWORD[0]: 0x%08X, DWORD[1]: 0x%08X\n",
           rax.dword[0], rax.dword[1]);
    printf("WORD[0-3]: ");
    for (int i = 0; i < 4; i++) printf("0x%04X ", rax.word[i]);
    printf("\nBYTE[0-7]: ");
    for (int i = 0; i < 8; i++) printf("0x%02X ", rax.byte[i]);
    printf("\n");

    return 0;
}
```

---

## Solution 11-12 : Variant JSON simplifié

```c
#include <stdio.h>
#include <string.h>

typedef enum { J_NULL, J_BOOL, J_INT, J_FLOAT, J_STRING } JsonType;

typedef struct {
    JsonType type;
    union {
        int b;
        int i;
        float f;
        char str[64];
    } value;
} JsonValue;

void print_json(JsonValue *v) {
    switch (v->type) {
        case J_NULL:   printf("null"); break;
        case J_BOOL:   printf("%s", v->value.b ? "true" : "false"); break;
        case J_INT:    printf("%d", v->value.i); break;
        case J_FLOAT:  printf("%f", v->value.f); break;
        case J_STRING: printf("\"%s\"", v->value.str); break;
    }
}

int main(void) {
    JsonValue vals[] = {
        {J_NULL},
        {J_BOOL, .value.b = 1},
        {J_INT, .value.i = 42},
        {J_STRING, .value.str = "hello"}
    };

    for (int i = 0; i < 4; i++) {
        print_json(&vals[i]);
        printf("\n");
    }
    return 0;
}
```

---

## Résumé

| Concept | Application |
|---------|-------------|
| union | Partage mémoire, type punning |
| enum | Constantes nommées, états |
| Enum flags | Permissions, options combinables |
| Tagged union | Variant types sûrs |
| Type punning | Parsing binaire |

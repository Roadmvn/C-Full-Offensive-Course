# Solutions - Module 06 : Fonctions (Functions)

## Solution Exercice 1 : Fonction simple

```c
#include <stdio.h>

// Fonction sans retour ni paramètre
void print_banner(void) {
    printf("[*] Agent v1.0 initialized\n");
}

// Fonction avec paramètres et retour
int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int main(void) {
    print_banner();

    printf("add(10, 25) = %d\n", add(10, 25));
    printf("multiply(6, 7) = %d\n", multiply(6, 7));

    return 0;
}
```

**Explication** :
- `void` signifie "pas de retour"
- `(void)` signifie "pas de paramètre"
- `return` termine la fonction et renvoie une valeur

---

## Solution Exercice 2 : Fonctions avec tableaux

```c
#include <stdio.h>

int sum_array(int arr[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}

int find_max(int arr[], int size) {
    int max = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

int find_min(int arr[], int size) {
    int min = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] < min) {
            min = arr[i];
        }
    }
    return min;
}

int main(void) {
    int ports[] = {22, 80, 443, 3306, 8080, 21, 25};
    int size = 7;

    printf("Somme: %d\n", sum_array(ports, size));
    printf("Max: %d\n", find_max(ports, size));
    printf("Min: %d\n", find_min(ports, size));

    return 0;
}
```

**Note** : En C, les tableaux sont toujours passés par référence (l'adresse du premier élément). Il faut donc passer la taille séparément.

---

## Solution Exercice 3 : Passage par pointeur

```c
#include <stdio.h>

void double_value(int *x) {
    *x = *x * 2;  // Déréférence et modifie
}

void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

void get_min_max(int arr[], int size, int *min, int *max) {
    *min = arr[0];
    *max = arr[0];

    for (int i = 1; i < size; i++) {
        if (arr[i] < *min) *min = arr[i];
        if (arr[i] > *max) *max = arr[i];
    }
}

int main(void) {
    int x = 10;
    printf("Avant double: x = %d\n", x);
    double_value(&x);
    printf("Après double: x = %d\n", x);

    int a = 100, b = 200;
    printf("\nAvant swap: a=%d, b=%d\n", a, b);
    swap(&a, &b);
    printf("Après swap: a=%d, b=%d\n", a, b);

    int data[] = {45, 12, 78, 23, 56, 9, 67};
    int min, max;
    get_min_max(data, 7, &min, &max);
    printf("\nMin: %d, Max: %d\n", min, max);

    return 0;
}
```

**Application offensive** : Le passage par pointeur permet de modifier des buffers en mémoire, essentiel pour l'injection de shellcode ou la manipulation de données.

---

## Solution Exercice 4 : Variables statiques

```c
#include <stdio.h>

int get_next_id(void) {
    static int id = 0;  // Initialisé une seule fois
    return ++id;        // Pré-incrémente et retourne
}

int count_calls(void) {
    static int count = 0;
    count++;
    return count;
}

int is_first_run(void) {
    static int first = 1;  // 1 = première fois

    if (first) {
        first = 0;  // Marque comme déjà exécuté
        return 1;
    }
    return 0;
}

int main(void) {
    printf("[*] Génération d'IDs:\n");
    for (int i = 0; i < 5; i++) {
        printf("    Agent ID: %d\n", get_next_id());
    }

    printf("\n[*] Compteur d'appels:\n");
    for (int i = 0; i < 3; i++) {
        printf("    Appel #%d\n", count_calls());
    }

    printf("\n[*] Détection première exécution:\n");
    for (int i = 0; i < 3; i++) {
        if (is_first_run()) {
            printf("    Première exécution!\n");
        } else {
            printf("    Exécution suivante\n");
        }
    }

    return 0;
}
```

**Application offensive** :
- `is_first_run` : Détecte si le malware a déjà été analysé (anti-sandbox)
- `count_calls` : Compte les exécutions pour détecter un environnement d'analyse automatique

---

## Solution Exercice 5 : Récursion

```c
#include <stdio.h>

unsigned long factorial(int n) {
    // Cas de base
    if (n <= 1) return 1;

    // Appel récursif
    return n * factorial(n - 1);
}

unsigned long power(int base, int exp) {
    // Cas de base
    if (exp == 0) return 1;

    // Appel récursif
    return base * power(base, exp - 1);
}

int sum_digits(int n) {
    // Cas de base
    if (n == 0) return 0;

    // Dernier chiffre + récursion sur le reste
    return (n % 10) + sum_digits(n / 10);
}

int main(void) {
    printf("[*] Factorielles:\n");
    for (int i = 0; i <= 6; i++) {
        printf("    %d! = %lu\n", i, factorial(i));
    }

    printf("\n[*] Puissances:\n");
    printf("    2^10 = %lu\n", power(2, 10));
    printf("    3^5 = %lu\n", power(3, 5));

    printf("\n[*] Somme des chiffres:\n");
    printf("    sum_digits(1234) = %d\n", sum_digits(1234));
    printf("    sum_digits(9999) = %d\n", sum_digits(9999));

    return 0;
}
```

**Application offensive** : La récursion est utilisée pour le parcours de répertoires (recherche de fichiers sensibles).

---

## Solution Exercice 6 : Pointeurs de fonctions

```c
#include <stdio.h>

// Opérations mathématiques
int add(int a, int b) { return a + b; }
int subtract(int a, int b) { return a - b; }
int multiply(int a, int b) { return a * b; }
int divide(int a, int b) { return b != 0 ? a / b : 0; }

// Type pointeur de fonction
typedef int (*Operation)(int, int);

// Fonction qui utilise le pointeur de fonction
int calculate(int a, int b, Operation op) {
    return op(a, b);
}

int main(void) {
    int a = 100, b = 25;

    printf("Calculatrice:\n");
    printf("  %d + %d = %d\n", a, b, calculate(a, b, add));
    printf("  %d - %d = %d\n", a, b, calculate(a, b, subtract));
    printf("  %d * %d = %d\n", a, b, calculate(a, b, multiply));
    printf("  %d / %d = %d\n", a, b, calculate(a, b, divide));

    // Bonus: tableau d'opérations
    printf("\nAvec tableau d'opérations:\n");
    Operation ops[] = {add, subtract, multiply, divide};
    const char *names[] = {"+", "-", "*", "/"};

    for (int i = 0; i < 4; i++) {
        printf("  %d %s %d = %d\n", a, names[i], b, ops[i](a, b));
    }

    return 0;
}
```

**Pourquoi c'est important** : Les pointeurs de fonctions permettent le polymorphisme en C, utilisé dans les tables de dispatch C2.

---

## Solution Exercice 7 : Command Dispatcher

```c
#include <stdio.h>
#include <string.h>

// Handlers de commandes
int cmd_whoami(void) {
    printf("    -> DESKTOP-TARGET\\Admin\n");
    return 0;
}

int cmd_pwd(void) {
    printf("    -> C:\\Users\\Admin\\Desktop\n");
    return 0;
}

int cmd_ls(void) {
    printf("    -> Documents/\n");
    printf("    -> Downloads/\n");
    printf("    -> passwords.txt\n");
    return 0;
}

int cmd_exit(void) {
    printf("    -> Terminating agent...\n");
    return -1;  // Signal de sortie
}

// Structure Command
typedef struct {
    const char *name;
    int (*handler)(void);
} Command;

// Dispatcher
int dispatch(const char *cmd, Command *commands, int num) {
    for (int i = 0; i < num; i++) {
        if (strcmp(cmd, commands[i].name) == 0) {
            return commands[i].handler();
        }
    }
    return 1;  // Commande inconnue
}

int main(void) {
    Command commands[] = {
        {"whoami", cmd_whoami},
        {"pwd", cmd_pwd},
        {"ls", cmd_ls},
        {"exit", cmd_exit}
    };
    int num_commands = sizeof(commands) / sizeof(commands[0]);

    const char *received[] = {"whoami", "pwd", "ls", "unknown", "exit"};
    int num_received = 5;

    printf("[*] C2 Command Dispatcher\n\n");

    for (int i = 0; i < num_received; i++) {
        printf("[>] Command: %s\n", received[i]);
        int result = dispatch(received[i], commands, num_commands);

        if (result == -1) {
            printf("[!] Exiting...\n");
            break;
        }
        if (result == 1) {
            printf("[-] Unknown command\n");
        }
        printf("\n");
    }

    return 0;
}
```

**Pattern C2** : C'est exactement comme ça que fonctionnent les agents C2 réels. Ils reçoivent des commandes et les exécutent via une table de dispatch.

---

## Solution Exercice 8 : Callbacks - Encodeur modulaire

```c
#include <stdio.h>
#include <string.h>

// Type callback encodeur
typedef unsigned char (*Encoder)(unsigned char byte, unsigned char key);

// Encodeurs
unsigned char xor_encode(unsigned char byte, unsigned char key) {
    return byte ^ key;
}

unsigned char add_encode(unsigned char byte, unsigned char key) {
    return byte + key;
}

unsigned char sub_encode(unsigned char byte, unsigned char key) {
    return byte - key;
}

// Fonction générique d'encodage
void encode_buffer(unsigned char *data, int size, unsigned char key,
                   Encoder encoder) {
    for (int i = 0; i < size; i++) {
        data[i] = encoder(data[i], key);
    }
}

void print_hex(unsigned char *data, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char payload[] = "ATTACK";
    int size = 6;
    unsigned char key = 0x42;

    printf("[*] Payload original: %s\n", payload);
    printf("[*] Hex: ");
    print_hex(payload, size);

    // XOR encode
    printf("\n[*] XOR encoded (key=0x42): ");
    encode_buffer(payload, size, key, xor_encode);
    print_hex(payload, size);

    // XOR decode (même opération car XOR est réversible)
    printf("[*] XOR decoded: ");
    encode_buffer(payload, size, key, xor_encode);
    print_hex(payload, size);
    printf("    String: %s\n", payload);

    // ADD encode
    printf("\n[*] ADD encoded (key=0x42): ");
    encode_buffer(payload, size, key, add_encode);
    print_hex(payload, size);

    // SUB decode (inverse de ADD)
    printf("[*] SUB decoded: ");
    encode_buffer(payload, size, key, sub_encode);
    print_hex(payload, size);
    printf("    String: %s\n", payload);

    return 0;
}
```

**Avantage** : Un seul code, plusieurs algorithmes. Facilite l'évasion en changeant simplement le callback.

---

## Solution Exercice 9 : Fonctions variadiques

```c
#include <stdio.h>
#include <stdarg.h>

void log_msg(const char *level, const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[%s] ", level);
    vprintf(format, args);
    printf("\n");

    va_end(args);
}

int sum_all(int count, ...) {
    va_list args;
    va_start(args, count);

    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += va_arg(args, int);
    }

    va_end(args);
    return sum;
}

int max_of(int count, ...) {
    va_list args;
    va_start(args, count);

    int max = va_arg(args, int);  // Premier argument

    for (int i = 1; i < count; i++) {
        int val = va_arg(args, int);
        if (val > max) {
            max = val;
        }
    }

    va_end(args);
    return max;
}

int main(void) {
    printf("[*] Logger:\n");
    log_msg("INFO", "Agent started on port %d", 4444);
    log_msg("DEBUG", "Target: %s:%d", "192.168.1.100", 8080);
    log_msg("ERROR", "Connection failed after %d attempts", 3);
    log_msg("WARN", "Retry in %d seconds", 30);

    printf("\n[*] Somme:\n");
    printf("    sum_all(3, 10, 20, 30) = %d\n", sum_all(3, 10, 20, 30));
    printf("    sum_all(5, 1, 2, 3, 4, 5) = %d\n", sum_all(5, 1, 2, 3, 4, 5));

    printf("\n[*] Maximum:\n");
    printf("    max_of(4, 23, 87, 12, 45) = %d\n", max_of(4, 23, 87, 12, 45));
    printf("    max_of(3, 100, 50, 75) = %d\n", max_of(3, 100, 50, 75));

    return 0;
}
```

**Macros utilisées** :
- `va_list` : Type pour la liste d'arguments
- `va_start` : Initialise la liste
- `va_arg` : Récupère l'argument suivant
- `va_end` : Libère les ressources

---

## Solution Exercice 10 : Agent modulaire

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Structure avec pointeurs de fonctions (vtable)
typedef struct {
    int (*init)(void);
    int (*beacon)(void);
    int (*execute)(const char *cmd);
    void (*cleanup)(void);
} AgentVTable;

// Implémentation des fonctions agent
int agent_init(void) {
    srand(time(NULL));
    printf("  [*] Initializing...\n");
    printf("  [+] Agent ID: 0x%04X\n", rand() % 0xFFFF);
    printf("  [+] Init complete\n");
    return 0;
}

int agent_beacon(void) {
    static int count = 0;
    count++;
    printf("  [*] Beacon #%d -> C2\n", count);
    return 0;
}

int agent_execute(const char *cmd) {
    printf("  [*] Executing: %s\n", cmd);
    printf("  [+] Output: <simulated result>\n");
    return 0;
}

void agent_cleanup(void) {
    printf("  [*] Cleaning traces...\n");
    printf("  [*] Closing connections...\n");
    printf("  [+] Agent terminated\n");
}

int main(void) {
    printf("[*] Modular Agent Demo\n\n");

    // Initialise la vtable
    AgentVTable agent = {
        .init = agent_init,
        .beacon = agent_beacon,
        .execute = agent_execute,
        .cleanup = agent_cleanup
    };

    // Lifecycle complet
    printf("[PHASE: INIT]\n");
    agent.init();

    printf("\n[PHASE: OPERATE]\n");
    for (int i = 0; i < 3; i++) {
        agent.beacon();
        if (i == 1) {
            agent.execute("ipconfig /all");
        }
    }

    printf("\n[PHASE: CLEANUP]\n");
    agent.cleanup();

    return 0;
}
```

**Pourquoi cette architecture** :
- Modularité : Change les fonctions sans toucher au code principal
- Testabilité : Facile de mocker les fonctions
- Extensibilité : Ajoute de nouvelles capacités facilement

---

## Solution Exercice 11 : XOR multi-clé

```c
#include <stdio.h>
#include <string.h>

void print_hex(unsigned char *data, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void encode_single_xor(unsigned char *data, int size, unsigned char key) {
    for (int i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

void encode_rolling_xor(unsigned char *data, int size,
                        unsigned char *keys, int num_keys) {
    for (int i = 0; i < size; i++) {
        data[i] ^= keys[i % num_keys];  // Rotation des clés
    }
}

// Version avec callback
typedef void (*XorEncoder)(unsigned char*, int, unsigned char*, int);

void apply_encoding(unsigned char *data, int size,
                   unsigned char *keys, int num_keys,
                   XorEncoder encoder) {
    encoder(data, size, keys, num_keys);
}

// Wrappers pour le callback
void single_wrapper(unsigned char *data, int size,
                   unsigned char *keys, int num_keys) {
    encode_single_xor(data, size, keys[0]);
}

void rolling_wrapper(unsigned char *data, int size,
                    unsigned char *keys, int num_keys) {
    encode_rolling_xor(data, size, keys, num_keys);
}

int main(void) {
    unsigned char payload[] = "MALWARE";
    int size = strlen((char*)payload);

    unsigned char keys[] = {0x11, 0x22, 0x33};
    int num_keys = 3;

    printf("[*] Payload: %s\n", payload);
    printf("[*] Original: ");
    print_hex(payload, size);

    // Single XOR
    printf("\n[*] Single XOR (key=0x42):\n");
    unsigned char single_key = 0x42;
    encode_single_xor(payload, size, single_key);
    printf("    Encoded: ");
    print_hex(payload, size);
    encode_single_xor(payload, size, single_key);  // Decode
    printf("    Decoded: %s\n", payload);

    // Rolling XOR
    printf("\n[*] Rolling XOR (keys=0x11,0x22,0x33):\n");
    encode_rolling_xor(payload, size, keys, num_keys);
    printf("    Encoded: ");
    print_hex(payload, size);
    encode_rolling_xor(payload, size, keys, num_keys);  // Decode
    printf("    Decoded: %s\n", payload);

    return 0;
}
```

**Avantage du rolling XOR** : Plus difficile à détecter que le single-byte XOR car le pattern n'est pas constant.

---

## Solution Exercice 12 : Générateur de shellcode

```c
#include <stdio.h>
#include <string.h>

// Templates
unsigned char nop_sled[] = {0x90, 0x90, 0x90, 0x90};
unsigned char ret_instruction[] = {0xC3};

// Type callback encodeur
typedef unsigned char (*ShellcodeEncoder)(unsigned char);

// Encodeurs
unsigned char xor_encode(unsigned char byte) {
    return byte ^ 0x55;
}

unsigned char no_encode(unsigned char byte) {
    return byte;
}

// Fonctions de construction
int prepend_nops(unsigned char *dest, int offset, int count) {
    for (int i = 0; i < count; i++) {
        dest[offset + i] = 0x90;
    }
    return offset + count;
}

int append_payload(unsigned char *dest, int offset,
                   unsigned char *payload, int size,
                   ShellcodeEncoder encoder) {
    for (int i = 0; i < size; i++) {
        dest[offset + i] = encoder(payload[i]);
    }
    return offset + size;
}

int append_ret(unsigned char *dest, int offset) {
    dest[offset] = 0xC3;
    return offset + 1;
}

void print_shellcode(unsigned char *code, int size) {
    printf("unsigned char shellcode[] = {");
    for (int i = 0; i < size; i++) {
        if (i % 8 == 0) printf("\n    ");
        printf("0x%02X", code[i]);
        if (i < size - 1) printf(", ");
    }
    printf("\n};\n");
}

int main(void) {
    unsigned char payload[] = {0x31, 0xC0, 0x50, 0x68};
    int payload_size = 4;

    unsigned char final_shellcode[64];
    int offset = 0;

    printf("[*] Building shellcode...\n\n");

    // 1. NOP sled (4 bytes)
    printf("  [+] Adding NOP sled\n");
    offset = prepend_nops(final_shellcode, offset, 4);

    // 2. Payload encodé XOR 0x55
    printf("  [+] Adding encoded payload (XOR 0x55)\n");
    offset = append_payload(final_shellcode, offset,
                           payload, payload_size, xor_encode);

    // 3. RET instruction
    printf("  [+] Adding RET instruction\n");
    offset = append_ret(final_shellcode, offset);

    printf("\n[*] Final size: %d bytes\n\n", offset);

    printf("[*] Generated Shellcode:\n");
    print_shellcode(final_shellcode, offset);

    // Affiche aussi le payload original pour comparaison
    printf("\n[*] Original payload: ");
    for (int i = 0; i < payload_size; i++) {
        printf("%02X ", payload[i]);
    }
    printf("\n");

    return 0;
}
```

---

## Solution Exercice 13 : Table de syscalls

```c
#include <stdio.h>
#include <string.h>

typedef int (*SyscallHandler)(int arg1, int arg2, int arg3);

typedef struct {
    int number;
    const char *name;
    SyscallHandler handler;
} Syscall;

// Handlers de syscalls (simulés)
int sys_read(int fd, int buf, int count) {
    printf("  [syscall] read(fd=%d, buf=0x%X, count=%d)\n", fd, buf, count);
    printf("  [+] Read %d bytes\n", count);
    return count;
}

int sys_write(int fd, int buf, int count) {
    printf("  [syscall] write(fd=%d, buf=0x%X, count=%d)\n", fd, buf, count);
    printf("  [+] Wrote %d bytes\n", count);
    return count;
}

int sys_open(int pathname, int flags, int mode) {
    printf("  [syscall] open(path=0x%X, flags=%d, mode=%o)\n",
           pathname, flags, mode);
    printf("  [+] Opened file, fd=3\n");
    return 3;  // File descriptor simulé
}

int sys_exit(int code, int unused1, int unused2) {
    printf("  [syscall] exit(code=%d)\n", code);
    printf("  [+] Process would terminate\n");
    return 0;
}

// Dispatcher
int syscall_dispatch(int syscall_num, int arg1, int arg2, int arg3,
                     Syscall *table, int num_syscalls) {
    for (int i = 0; i < num_syscalls; i++) {
        if (table[i].number == syscall_num) {
            printf("\n[>] Syscall %d (%s)\n", syscall_num, table[i].name);
            return table[i].handler(arg1, arg2, arg3);
        }
    }
    printf("\n[-] Unknown syscall: %d\n", syscall_num);
    return -1;
}

int main(void) {
    Syscall syscall_table[] = {
        {0, "sys_read", sys_read},
        {1, "sys_write", sys_write},
        {2, "sys_open", sys_open},
        {60, "sys_exit", sys_exit}
    };
    int num_syscalls = sizeof(syscall_table) / sizeof(syscall_table[0]);

    printf("[*] Syscall Table Simulation\n");
    printf("[*] Linux x64 syscall numbers\n");

    // Simule un programme qui:
    // 1. write(1, msg, 13) - écrit sur stdout
    syscall_dispatch(1, 1, 0x401000, 13, syscall_table, num_syscalls);

    // 2. open("/etc/passwd", O_RDONLY, 0)
    syscall_dispatch(2, 0x402000, 0, 0, syscall_table, num_syscalls);

    // 3. read(3, buffer, 100)
    syscall_dispatch(0, 3, 0x403000, 100, syscall_table, num_syscalls);

    // 4. exit(0)
    syscall_dispatch(60, 0, 0, 0, syscall_table, num_syscalls);

    return 0;
}
```

**Application** : C'est ainsi que fonctionne un émulateur de syscalls ou un hook de syscall pour l'analyse de malware.

---

## Solution Exercice 14 : Plugin system

```c
#include <stdio.h>

typedef struct Plugin {
    const char *name;
    int version;
    int (*init)(void);
    int (*run)(const char *arg);
    void (*cleanup)(void);
} Plugin;

// ===== KEYLOGGER PLUGIN =====
int keylogger_init(void) {
    printf("      Installing keyboard hook...\n");
    return 0;
}

int keylogger_run(const char *arg) {
    printf("  [Keylogger] Recording keystrokes for: %s\n", arg);
    printf("      Captured: admin:P@ssw0rd123\n");
    return 0;
}

void keylogger_cleanup(void) {
    printf("  [Keylogger] Removing hook, saving log...\n");
}

// ===== SCREENSHOT PLUGIN =====
int screenshot_init(void) {
    printf("      Initializing GDI capture...\n");
    return 0;
}

int screenshot_run(const char *arg) {
    printf("  [Screenshot] Capturing screen for: %s\n", arg);
    printf("      Saved: screenshot_001.png (1920x1080)\n");
    return 0;
}

void screenshot_cleanup(void) {
    printf("  [Screenshot] Releasing GDI resources...\n");
}

// ===== EXFIL PLUGIN =====
int exfil_init(void) {
    printf("      Connecting to C2 server...\n");
    return 0;
}

int exfil_run(const char *arg) {
    printf("  [Exfil] Exfiltrating: %s\n", arg);
    printf("      Sent 1.5MB to 192.168.1.100:443\n");
    return 0;
}

void exfil_cleanup(void) {
    printf("  [Exfil] Closing C2 connection...\n");
}

int main(void) {
    printf("[*] Plugin System Demo\n\n");

    Plugin plugins[] = {
        {
            .name = "Keylogger",
            .version = 1,
            .init = keylogger_init,
            .run = keylogger_run,
            .cleanup = keylogger_cleanup
        },
        {
            .name = "Screenshot",
            .version = 2,
            .init = screenshot_init,
            .run = screenshot_run,
            .cleanup = screenshot_cleanup
        },
        {
            .name = "Exfiltrator",
            .version = 1,
            .init = exfil_init,
            .run = exfil_run,
            .cleanup = exfil_cleanup
        }
    };
    int num_plugins = sizeof(plugins) / sizeof(plugins[0]);

    // Phase 1: Initialisation
    printf("[PHASE 1: INIT]\n");
    printf("[*] Loading plugins...\n");
    for (int i = 0; i < num_plugins; i++) {
        printf("  [+] %s v%d: ", plugins[i].name, plugins[i].version);
        if (plugins[i].init() == 0) {
            printf("OK\n");
        } else {
            printf("FAILED\n");
        }
    }

    // Phase 2: Exécution
    printf("\n[PHASE 2: RUN]\n");
    printf("[*] Running plugins...\n");
    for (int i = 0; i < num_plugins; i++) {
        plugins[i].run("target_data");
    }

    // Phase 3: Cleanup
    printf("\n[PHASE 3: CLEANUP]\n");
    printf("[*] Unloading plugins...\n");
    for (int i = num_plugins - 1; i >= 0; i--) {
        plugins[i].cleanup();
    }

    printf("\n[+] All plugins unloaded\n");

    return 0;
}
```

**Architecture réelle** : C'est exactement comme ça que fonctionnent les frameworks modulaires comme Metasploit ou Cobalt Strike avec leurs modules post-exploitation.

---

## Récapitulatif des patterns offensifs

| Pattern | Fonction | Application |
|---------|----------|-------------|
| Command Dispatcher | Pointeurs de fonctions | Agents C2 |
| Callbacks | Encodeurs modulaires | Obfuscation de payload |
| Variables statiques | Compteurs persistants | Anti-sandbox |
| Récursion | Parcours de répertoires | Recherche de fichiers |
| Vtables | Architecture modulaire | Plugins d'agent |
| Variadiques | Logging flexible | Debug/exfiltration |

---

## Points clés à retenir

1. **Passage par pointeur** : Permet de modifier les données en place (buffers, shellcode)
2. **Variables statiques** : Persistent entre les appels (anti-analyse)
3. **Pointeurs de fonctions** : Permettent le polymorphisme (dispatchers)
4. **Callbacks** : Rendent le code modulaire (encodeurs interchangeables)
5. **Vtables** : Architecture extensible (système de plugins)

Ces concepts sont la base de tout développement offensif sérieux en C.

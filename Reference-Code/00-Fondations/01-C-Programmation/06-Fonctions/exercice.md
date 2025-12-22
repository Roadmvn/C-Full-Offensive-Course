# Exercices - Module 06 : Fonctions (Functions)

## Exercice 1 : Fonction simple (Très facile)

**Objectif** : Créer et appeler une fonction de base.

### Instructions

```c
#include <stdio.h>

// TODO:
// 1. Crée une fonction "print_banner" qui affiche:
//    "[*] Agent v1.0 initialized"
// 2. Crée une fonction "add" qui prend deux int et retourne leur somme
// 3. Crée une fonction "multiply" qui prend deux int et retourne leur produit

int main(void) {
    // TODO: Appelle print_banner
    // TODO: Affiche add(10, 25) = 35
    // TODO: Affiche multiply(6, 7) = 42

    return 0;
}
```

---

## Exercice 2 : Fonctions avec tableaux (Facile)

**Objectif** : Passer des tableaux à des fonctions.

### Instructions

```c
#include <stdio.h>

// TODO:
// 1. Crée une fonction "sum_array" qui calcule la somme d'un tableau
// 2. Crée une fonction "find_max" qui trouve le maximum d'un tableau
// 3. Crée une fonction "find_min" qui trouve le minimum d'un tableau
// Toutes prennent (int arr[], int size) en paramètres

int main(void) {
    int ports[] = {22, 80, 443, 3306, 8080, 21, 25};
    int size = 7;

    // TODO: Affiche la somme, le max et le min

    return 0;
}
```

---

## Exercice 3 : Passage par pointeur (Facile)

**Objectif** : Modifier des variables via pointeurs.

### Instructions

```c
#include <stdio.h>

// TODO:
// 1. Crée une fonction "double_value" qui double la valeur via pointeur
// 2. Crée une fonction "swap" qui échange deux valeurs
// 3. Crée une fonction "get_min_max" qui retourne min ET max
//    via deux pointeurs

int main(void) {
    int x = 10;
    printf("Avant double: x = %d\n", x);
    // TODO: double_value(&x);
    printf("Après double: x = %d\n", x);  // Devrait afficher 20

    int a = 100, b = 200;
    printf("\nAvant swap: a=%d, b=%d\n", a, b);
    // TODO: swap(&a, &b);
    printf("Après swap: a=%d, b=%d\n", a, b);  // a=200, b=100

    int data[] = {45, 12, 78, 23, 56, 9, 67};
    int min, max;
    // TODO: get_min_max(data, 7, &min, &max);
    printf("\nMin: %d, Max: %d\n", min, max);  // Min: 9, Max: 78

    return 0;
}
```

---

## Exercice 4 : Variables statiques (Facile)

**Objectif** : Utiliser des variables statiques pour la persistance.

### Instructions

```c
#include <stdio.h>

// TODO:
// 1. Crée une fonction "get_next_id" qui retourne un ID incrémenté
//    à chaque appel (utilise static)
// 2. Crée une fonction "count_calls" qui compte combien de fois
//    elle a été appelée (utilise static)
// 3. Crée une fonction "is_first_run" qui retourne 1 la première fois,
//    0 ensuite (anti-sandbox pattern)

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

---

## Exercice 5 : Récursion (Moyen)

**Objectif** : Implémenter des fonctions récursives.

### Instructions

```c
#include <stdio.h>

// TODO:
// 1. Crée une fonction récursive "factorial" qui calcule n!
// 2. Crée une fonction récursive "power" qui calcule base^exp
// 3. Crée une fonction récursive "sum_digits" qui additionne
//    les chiffres d'un nombre (ex: 1234 -> 1+2+3+4 = 10)

int main(void) {
    printf("[*] Factorielles:\n");
    for (int i = 0; i <= 6; i++) {
        printf("    %d! = %lu\n", i, factorial(i));
    }

    printf("\n[*] Puissances:\n");
    printf("    2^10 = %lu\n", power(2, 10));  // 1024
    printf("    3^5 = %lu\n", power(3, 5));    // 243

    printf("\n[*] Somme des chiffres:\n");
    printf("    sum_digits(1234) = %d\n", sum_digits(1234));  // 10
    printf("    sum_digits(9999) = %d\n", sum_digits(9999));  // 36

    return 0;
}
```

---

## Exercice 6 : Pointeurs de fonctions (Moyen)

**Objectif** : Utiliser des pointeurs de fonctions.

### Instructions

```c
#include <stdio.h>

// Opérations mathématiques
int add(int a, int b) { return a + b; }
int subtract(int a, int b) { return a - b; }
int multiply(int a, int b) { return a * b; }
int divide(int a, int b) { return b != 0 ? a / b : 0; }

// TODO:
// 1. Crée un type "Operation" pour pointeur de fonction
//    prenant (int, int) et retournant int
// 2. Crée une fonction "calculate" qui prend deux int et
//    un pointeur de fonction, puis applique l'opération
// 3. Crée un tableau d'opérations et itère dessus

int main(void) {
    int a = 100, b = 25;

    // TODO: Utilise calculate avec chaque opération
    printf("Calculatrice:\n");
    printf("  %d + %d = %d\n", a, b, calculate(a, b, add));
    printf("  %d - %d = %d\n", a, b, calculate(a, b, subtract));
    printf("  %d * %d = %d\n", a, b, calculate(a, b, multiply));
    printf("  %d / %d = %d\n", a, b, calculate(a, b, divide));

    return 0;
}
```

---

## Exercice 7 : Command Dispatcher (Moyen)

**Objectif** : Implémenter un dispatcher de commandes C2.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO:
// 1. Crée des fonctions cmd_whoami, cmd_pwd, cmd_ls, cmd_exit
//    qui retournent int (0=succès, -1=quitter)
// 2. Crée une structure Command avec (name, handler)
// 3. Crée une fonction "dispatch" qui cherche et exécute la commande

// Structure Command
typedef struct {
    const char *name;
    int (*handler)(void);
} Command;

int main(void) {
    // Table de commandes
    Command commands[] = {
        {"whoami", cmd_whoami},
        {"pwd", cmd_pwd},
        {"ls", cmd_ls},
        {"exit", cmd_exit}
    };
    int num_commands = sizeof(commands) / sizeof(commands[0]);

    // Simule des commandes reçues
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

---

## Exercice 8 : Callbacks - Encodeur modulaire (Moyen)

**Objectif** : Utiliser les callbacks pour des encodeurs interchangeables.

### Instructions

```c
#include <stdio.h>

// TODO:
// 1. Crée un type Encoder: unsigned char (*)(unsigned char, unsigned char)
// 2. Implémente xor_encode, add_encode, sub_encode
// 3. Crée encode_buffer qui prend un buffer et un callback Encoder

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

    // TODO:
    // 1. Encode avec XOR
    // 2. Affiche le résultat
    // 3. Encode avec ADD
    // 4. Affiche le résultat
    // 5. Decode (XOR est réversible, ADD nécessite SUB)

    return 0;
}
```

---

## Exercice 9 : Fonctions variadiques (Challenge)

**Objectif** : Créer des fonctions avec nombre variable d'arguments.

### Instructions

```c
#include <stdio.h>
#include <stdarg.h>

// TODO:
// 1. Crée une fonction "log_msg" qui prend (level, format, ...)
//    et affiche "[LEVEL] message"
// 2. Crée une fonction "sum_all" qui prend (count, ...) et
//    retourne la somme de count nombres
// 3. Crée une fonction "max_of" qui prend (count, ...) et
//    retourne le maximum de count nombres

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

---

## Exercice 10 : Agent modulaire (Challenge)

**Objectif** : Créer un agent avec architecture modulaire.

### Instructions

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// TODO:
// 1. Crée une structure AgentVTable avec pointeurs vers:
//    - init() -> int
//    - beacon() -> int
//    - execute(const char*) -> int
//    - cleanup() -> void
// 2. Implémente chaque fonction
// 3. Crée et utilise l'agent via la vtable

typedef struct {
    // TODO: Pointeurs de fonctions
} AgentVTable;

// TODO: Implémente les fonctions de l'agent

int main(void) {
    printf("[*] Modular Agent Demo\n\n");

    AgentVTable agent = {
        // TODO: Initialise avec les pointeurs
    };

    // Lifecycle
    agent.init();

    for (int i = 0; i < 3; i++) {
        agent.beacon();
        if (i == 1) {
            agent.execute("ipconfig /all");
        }
    }

    agent.cleanup();

    return 0;
}
```

---

## Exercice 11 : XOR multi-clé (Challenge)

**Objectif** : Encoder avec plusieurs clés via callbacks.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO:
// 1. Crée une fonction encode_single_xor(data, size, key)
// 2. Crée une fonction encode_rolling_xor(data, size, keys, num_keys)
//    qui utilise une clé différente pour chaque byte (rotation)
// 3. Crée une fonction qui utilise un callback pour le choix d'encodage

int main(void) {
    unsigned char payload[] = "MALWARE";
    int size = strlen((char*)payload);

    unsigned char keys[] = {0x11, 0x22, 0x33};
    int num_keys = 3;

    printf("[*] Payload: %s\n\n", payload);

    // TODO: Applique single XOR avec 0x42
    // TODO: Affiche résultat

    // Restaure payload
    memcpy(payload, "MALWARE", size);

    // TODO: Applique rolling XOR avec keys
    // TODO: Affiche résultat

    return 0;
}
```

---

## Exercice 12 : Générateur de shellcode (Challenge)

**Objectif** : Créer un générateur de shellcode modulaire.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// Shellcode templates (NOP sled + placeholder)
unsigned char nop_sled[] = {0x90, 0x90, 0x90, 0x90};
unsigned char ret_instruction[] = {0xC3};

// TODO:
// 1. Crée une fonction "generate_shellcode" qui prend:
//    - un buffer destination
//    - un payload
//    - une fonction d'encodage (callback)
// 2. Crée une fonction "prepend_nops" qui ajoute un NOP sled
// 3. Crée une fonction "append_ret" qui ajoute RET à la fin

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
    unsigned char payload[] = {0x31, 0xC0, 0x50, 0x68};  // xor eax,eax; push eax; push ...
    int payload_size = 4;

    unsigned char final_shellcode[64];
    int final_size = 0;

    // TODO: Génère le shellcode avec:
    // 1. NOP sled
    // 2. Payload encodé XOR 0x55
    // 3. RET instruction

    printf("[*] Generated Shellcode:\n");
    print_shellcode(final_shellcode, final_size);

    return 0;
}
```

---

## Exercice 13 : Table de syscalls (Challenge)

**Objectif** : Simuler une table de syscalls.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO:
// 1. Crée une structure Syscall avec (number, name, handler)
// 2. Crée des handlers pour: sys_read, sys_write, sys_open, sys_exit
// 3. Crée une fonction "syscall_dispatch" qui trouve et exécute

typedef int (*SyscallHandler)(int arg1, int arg2, int arg3);

typedef struct {
    int number;
    const char *name;
    SyscallHandler handler;
} Syscall;

// TODO: Implémente les handlers

int main(void) {
    Syscall syscall_table[] = {
        {0, "sys_read", sys_read},
        {1, "sys_write", sys_write},
        {2, "sys_open", sys_open},
        {60, "sys_exit", sys_exit}
    };
    int num_syscalls = sizeof(syscall_table) / sizeof(syscall_table[0]);

    printf("[*] Syscall Table Simulation\n\n");

    // Simule des appels système
    syscall_dispatch(1, 1, 0, 13, syscall_table, num_syscalls);  // write
    syscall_dispatch(2, 0, 0, 0, syscall_table, num_syscalls);   // open
    syscall_dispatch(0, 0, 0, 100, syscall_table, num_syscalls); // read
    syscall_dispatch(60, 0, 0, 0, syscall_table, num_syscalls);  // exit

    return 0;
}
```

---

## Exercice 14 : Plugin system (Challenge)

**Objectif** : Créer un système de plugins modulaire.

### Instructions

```c
#include <stdio.h>

// TODO:
// 1. Crée une structure Plugin avec:
//    - name (const char*)
//    - version (int)
//    - init() -> int
//    - run(const char* arg) -> int
//    - cleanup() -> void
// 2. Crée 3 plugins: KeyloggerPlugin, ScreenshotPlugin, ExfilPlugin
// 3. Crée un PluginManager qui charge et exécute les plugins

typedef struct Plugin {
    const char *name;
    int version;
    int (*init)(void);
    int (*run)(const char *arg);
    void (*cleanup)(void);
} Plugin;

// TODO: Implémente les fonctions des plugins

int main(void) {
    printf("[*] Plugin System Demo\n\n");

    Plugin plugins[] = {
        // TODO: Initialise les plugins
    };
    int num_plugins = sizeof(plugins) / sizeof(plugins[0]);

    // Initialise tous les plugins
    printf("[*] Loading plugins...\n");
    for (int i = 0; i < num_plugins; i++) {
        printf("  [+] %s v%d: ", plugins[i].name, plugins[i].version);
        if (plugins[i].init() == 0) {
            printf("OK\n");
        } else {
            printf("FAILED\n");
        }
    }

    // Exécute chaque plugin
    printf("\n[*] Running plugins...\n");
    for (int i = 0; i < num_plugins; i++) {
        plugins[i].run("target_data");
    }

    // Cleanup
    printf("\n[*] Unloading plugins...\n");
    for (int i = num_plugins - 1; i >= 0; i--) {
        plugins[i].cleanup();
    }

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Créer et appeler des fonctions simples
- [ ] Passer des paramètres par valeur et par pointeur
- [ ] Utiliser des tableaux comme paramètres
- [ ] Utiliser des variables statiques
- [ ] Écrire des fonctions récursives
- [ ] Déclarer et utiliser des pointeurs de fonctions
- [ ] Implémenter un command dispatcher
- [ ] Utiliser des callbacks
- [ ] Créer des fonctions variadiques
- [ ] Concevoir une architecture modulaire

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.

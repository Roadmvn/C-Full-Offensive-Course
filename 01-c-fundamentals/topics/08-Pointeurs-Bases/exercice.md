# Exercices - Module 09 : Pointeurs

**Objectif** : Maîtriser les pointeurs avec des applications offensives réelles.

---

## Exo 1 : Hexdump (5 min)

**But** : Voir ce que voit un analyste dans un dump mémoire.

```c
#include <stdio.h>

void hexdump(void* addr, int len) {
    // TODO:
    // 1. Caste addr en unsigned char*
    // 2. Pour chaque byte :
    //    - Affiche offset tous les 16 bytes (format: %08lX: )
    //    - Affiche le byte en hex (%02X )
    //    - Nouvelle ligne tous les 16 bytes
}

int main(void) {
    int value = 0xDEADBEEF;
    char msg[] = "ATTACK";
    unsigned char sc[] = {0x48, 0x31, 0xC0, 0x50, 0x68, 0x2F, 0x2F, 0x73, 0x68};

    printf("=== Int 0xDEADBEEF ===\n");
    hexdump(&value, sizeof(value));

    printf("\n=== String \"ATTACK\" ===\n");
    hexdump(msg, sizeof(msg));

    printf("\n=== Shellcode ===\n");
    hexdump(sc, sizeof(sc));

    return 0;
}
```

**Output attendu** :
```
=== Int 0xDEADBEEF ===
00000000: EF BE AD DE

=== String "ATTACK" ===
00000000: 41 54 54 41 43 4B 00
```

---

## Exo 2 : XOR sans index (5 min)

**But** : Manipuler des données avec uniquement l'arithmétique de pointeurs.

```c
#include <stdio.h>
#include <string.h>

// ❌ Interdit d'utiliser data[i]
// ✅ Utilise uniquement *ptr, ptr++, ptr < end
void xor_crypt(unsigned char* data, int len, unsigned char key) {
    // TODO
}

int main(void) {
    char secret[] = "cmd.exe /c whoami";
    unsigned char key = 0x55;

    printf("Original: %s\n", secret);

    xor_crypt((unsigned char*)secret, strlen(secret), key);
    printf("Encodé: ");
    for (int i = 0; secret[i]; i++) printf("%02X ", (unsigned char)secret[i]);
    printf("\n");

    xor_crypt((unsigned char*)secret, strlen(secret), key);
    printf("Décodé: %s\n", secret);

    return 0;
}
```

---

## Exo 3 : Pattern finder (10 min)

**But** : Chercher des signatures dans du code/mémoire (base du patching).

```c
#include <stdio.h>

// Retourne pointeur vers première occurrence, ou NULL
unsigned char* find_pattern(unsigned char* haystack, int hay_len,
                            unsigned char* needle, int needle_len) {
    // TODO
}

// BONUS: Trouve TOUTES les occurrences
int find_all_patterns(unsigned char* haystack, int hay_len,
                      unsigned char* needle, int needle_len,
                      unsigned char** results, int max_results) {
    // TODO: Stocke les pointeurs dans results[], retourne le count
    return 0;
}

int main(void) {
    // Simule du code avec des NOP (0x90)
    unsigned char code[] = {
        0x55,                    // push rbp
        0x90, 0x90,              // nop nop
        0x48, 0x89, 0xE5,        // mov rbp, rsp
        0x90, 0x90, 0x90,        // nop nop nop
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x90, 0x90,              // nop nop
        0xC3                     // ret
    };

    unsigned char pattern[] = {0x90, 0x90};

    printf("Cherche NOP NOP (0x90 0x90)...\n\n");

    // Simple search
    unsigned char* found = find_pattern(code, sizeof(code), pattern, 2);
    if (found) {
        printf("[+] Trouvé à l'offset %ld\n", found - code);
    }

    // Find all
    unsigned char* results[10];
    int count = find_all_patterns(code, sizeof(code), pattern, 2, results, 10);
    printf("\n[*] Total: %d occurrences\n", count);
    for (int i = 0; i < count; i++) {
        printf("    Offset %ld\n", results[i] - code);
    }

    return 0;
}
```

---

## Exo 4 : License bypass (10 min)

**But** : Patcher du code machine pour bypasser une vérification.

```c
#include <stdio.h>

// Simule une fonction avec vérification
unsigned char license_check[] = {
    0x55,                    // push rbp
    0x48, 0x89, 0xE5,        // mov rbp, rsp
    0x83, 0xFF, 0x01,        // cmp edi, 1
    0x75, 0x07,              // JNE +7 (si pas 1, saute)
    0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1 (licensed)
    0xC9,                    // leave
    0xC3,                    // ret
    0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0 (not licensed)
    0xC9,                    // leave
    0xC3                     // ret
};

void hexdump(unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    printf("\n");
}

unsigned char* find_byte(unsigned char* data, int len, unsigned char target) {
    // TODO: Trouve la première occurrence de target
    return NULL;
}

int main(void) {
    printf("=== License Check Bypass ===\n\n");

    printf("Code original:\n");
    hexdump(license_check, sizeof(license_check));

    // TODO:
    // 1. Trouve l'instruction JNE (0x75)
    // 2. Remplace par JMP (0xEB) ou NOP (0x90 0x90)
    // 3. Affiche le code patché

    unsigned char* jne = find_byte(license_check, sizeof(license_check), 0x75);
    if (jne) {
        printf("[+] JNE trouvé à l'offset %ld\n", jne - license_check);

        // Patch JNE -> JMP
        printf("[*] Patching 0x75 -> 0xEB\n");
        *jne = 0xEB;

        printf("\nCode patché:\n");
        hexdump(license_check, sizeof(license_check));

        printf("[+] License check bypassed!\n");
    }

    return 0;
}
```

---

## Exo 5 : Memory copy générique (5 min)

**But** : Réimplémenter memcpy avec void* (comprendre les fonctions système).

```c
#include <stdio.h>

void my_memcpy(void* dest, void* src, int size) {
    // TODO: Copie byte par byte
    // Caste en unsigned char* pour manipuler
}

void my_memset(void* ptr, unsigned char val, int size) {
    // TODO: Remplit size bytes avec val
}

int main(void) {
    // Test memcpy
    unsigned char shellcode[] = {0x48, 0x31, 0xC0, 0xC3};
    unsigned char buffer[16] = {0};

    my_memcpy(buffer, shellcode, sizeof(shellcode));

    printf("Shellcode copié: ");
    for (int i = 0; i < sizeof(shellcode); i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    // Test memset - créer NOP sled
    my_memset(buffer, 0x90, 16);

    printf("NOP sled: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    return 0;
}
```

---

## Exo 6 : Pointeur de fonction - Dispatch (10 min)

**But** : Implémenter un système de commandes C2 basique.

```c
#include <stdio.h>
#include <string.h>

typedef void (*cmd_handler)(const char* arg);

void cmd_whoami(const char* arg) {
    printf("[+] Current user: root\n");
}

void cmd_pwd(const char* arg) {
    printf("[+] /home/target\n");
}

void cmd_echo(const char* arg) {
    printf("[+] %s\n", arg);
}

// TODO: Complète la structure
struct Command {
    const char* name;
    cmd_handler handler;
    const char* description;
};

struct Command commands[] = {
    // TODO: Remplis avec les commandes
    {NULL, NULL, NULL}  // Sentinelle
};

void list_commands(void) {
    // TODO: Affiche toutes les commandes disponibles
}

void execute(const char* name, const char* arg) {
    // TODO: Trouve et exécute la commande
    // Si pas trouvée: printf("[-] Unknown command: %s\n", name);
}

int main(void) {
    printf("=== Mini C2 Shell ===\n\n");

    list_commands();
    printf("\n");

    execute("whoami", NULL);
    execute("pwd", NULL);
    execute("echo", "Hello from implant!");
    execute("invalid", NULL);

    return 0;
}
```

---

## Exo 7 : Swap et modification via pointeurs (5 min)

**But** : Maîtriser le passage par référence.

```c
#include <stdio.h>

void swap(int* a, int* b) {
    // TODO: Échange les valeurs
}

void triple(int* x) {
    // TODO: Multiplie par 3
}

// Retourne plusieurs valeurs via pointeurs
void divide_with_remainder(int dividend, int divisor, int* quotient, int* remainder) {
    // TODO
}

int main(void) {
    int x = 10, y = 20;
    printf("Avant swap: x=%d, y=%d\n", x, y);
    swap(&x, &y);
    printf("Après swap: x=%d, y=%d\n", x, y);

    int val = 5;
    printf("\nAvant triple: %d\n", val);
    triple(&val);
    printf("Après triple: %d\n", val);

    int q, r;
    divide_with_remainder(17, 5, &q, &r);
    printf("\n17 / 5 = %d reste %d\n", q, r);

    return 0;
}
```

---

## Exo 8 : XOR multi-byte key (10 min)

**But** : Encoder avec une clé de plusieurs bytes (plus résistant).

```c
#include <stdio.h>
#include <string.h>

// Clé tourne sur elle-même (key[i % key_len])
void xor_multi(unsigned char* data, int data_len,
               unsigned char* key, int key_len) {
    // TODO
}

void print_hex(unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(void) {
    char payload[] = "http://evil.com/beacon";
    unsigned char key[] = {0xDE, 0xAD, 0xBE, 0xEF};

    printf("Original: %s\n", payload);
    printf("Clé: ");
    print_hex(key, sizeof(key));

    xor_multi((unsigned char*)payload, strlen(payload), key, sizeof(key));
    printf("\nEncodé: ");
    print_hex((unsigned char*)payload, strlen(payload));

    xor_multi((unsigned char*)payload, strlen(payload), key, sizeof(key));
    printf("Décodé: %s\n", payload);

    return 0;
}
```

---

## Exo 9 : Générateur de code C (Challenge - 15 min)

**But** : Générer du code C avec payload encodé (workflow maldev).

```c
#include <stdio.h>
#include <string.h>

void generate_c_array(const char* var_name, unsigned char* data, int len) {
    // TODO: Génère:
    // unsigned char var_name[] = {0xXX, 0xXX, ...};
    printf("unsigned char %s[] = {", var_name);
    // ...
}

void generate_decoder_function(unsigned char key) {
    // TODO: Génère une fonction de décodage en C
    printf("void decode(unsigned char* data, int len) {\n");
    printf("    for (int i = 0; i < len; i++) data[i] ^= 0x%02X;\n", key);
    printf("}\n");
}

int main(void) {
    char* payloads[] = {
        "cmd.exe",
        "powershell.exe",
        "/bin/sh"
    };
    unsigned char key = 0x42;

    printf("// Auto-generated payload code\n");
    printf("// Key: 0x%02X\n\n", key);

    for (int i = 0; i < 3; i++) {
        unsigned char buf[256];
        int len = strlen(payloads[i]);
        memcpy(buf, payloads[i], len);

        // Encode
        for (int j = 0; j < len; j++) buf[j] ^= key;

        char name[32];
        sprintf(name, "payload_%d", i);
        generate_c_array(name, buf, len);
        printf(" // \"%s\"\n", payloads[i]);
    }

    printf("\n");
    generate_decoder_function(key);

    return 0;
}
```

**Output attendu** :
```c
// Auto-generated payload code
// Key: 0x42

unsigned char payload_0[] = {0x21, 0x2F, 0x26, 0x6C, 0x27, 0x3A, 0x27}; // "cmd.exe"
unsigned char payload_1[] = {...}; // "powershell.exe"
unsigned char payload_2[] = {...}; // "/bin/sh"

void decode(unsigned char* data, int len) {
    for (int i = 0; i < len; i++) data[i] ^= 0x42;
}
```

---

## Exo 10 : Dangling pointer detector (Challenge - 10 min)

**But** : Comprendre les bugs de dangling pointers.

```c
#include <stdio.h>

// ❌ DANGEREUX - Explique pourquoi
char* dangerous_get_string(void) {
    char buffer[64] = "This is local data";
    return buffer;  // Que se passe-t-il ici ?
}

// ✅ SAFE - Version avec buffer externe
char* safe_get_string_v1(char* buffer, int max_len) {
    // TODO: Copie "Safe data v1" dans buffer
    return buffer;
}

// ✅ SAFE - Version avec static
char* safe_get_string_v2(void) {
    // TODO: Utilise static pour que les données persistent
    return NULL;
}

int main(void) {
    // Test dangerous (comportement indéfini!)
    // char* bad = dangerous_get_string();
    // printf("Dangerous: %s\n", bad);  // Crash ou garbage

    // Test safe v1
    char buffer[64];
    char* result1 = safe_get_string_v1(buffer, sizeof(buffer));
    printf("Safe v1: %s\n", result1);

    // Test safe v2
    char* result2 = safe_get_string_v2();
    printf("Safe v2: %s\n", result2);

    return 0;
}
```

**Questions** :
1. Pourquoi `dangerous_get_string` est dangereux ?
2. Que contient la zone mémoire après le return ?
3. Comment un attaquant pourrait exploiter ça ?

---

## Checklist finale

```
□ Je sais implémenter hexdump
□ Je maîtrise XOR avec pointeurs (sans index)
□ Je sais chercher des patterns en mémoire
□ Je sais patcher du code machine
□ Je comprends void* et les casts
□ Je sais utiliser les pointeurs de fonction
□ Je comprends le passage par référence
□ Je sais générer du code avec payloads encodés
□ Je comprends les dangers des dangling pointers
```

---

## Solutions

Voir [solution.md](solution.md)

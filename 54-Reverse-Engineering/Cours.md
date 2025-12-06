# Module 54 : Reverse Engineering

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Désassembler et analyser des binaires
- Comprendre le code assembleur x86/x64
- Techniques d'analyse statique et dynamique
- Unpacking de malwares
- Cracking de protections logicielles
- Analyse de protocoles propriétaires
- Outils de reverse engineering (GDB, radare2, Ghidra)

## 📚 Théorie

### C'est quoi le Reverse Engineering ?

Le **Reverse Engineering** consiste à analyser un programme compilé pour comprendre son fonctionnement interne sans avoir accès au code source. En Red Team, c'est essentiel pour :
- Analyser des malwares
- Trouver des vulnérabilités
- Contourner des protections
- Comprendre des protocoles propriétaires

### Types d'analyse

1. **Analyse statique** : Examiner le code sans l'exécuter
   - Désassemblage
   - Décompilation
   - Analyse de strings
   - Analyse de structure

2. **Analyse dynamique** : Observer le comportement à l'exécution
   - Debugging
   - Tracing
   - Monitoring API calls
   - Analyse réseau

3. **Analyse hybride** : Combinaison des deux approches

### Formats de fichiers

1. **ELF (Linux)** : Executable and Linkable Format
2. **PE (Windows)** : Portable Executable
3. **Mach-O (macOS)** : Mach Object

## 🔍 Visualisation

### Structure d'un binaire ELF

```
┌─────────────────────────────────────────────────────┐
│             ELF FILE STRUCTURE                      │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ ELF Header                       │              │
│  │ - Magic: 0x7F 'E' 'L' 'F'        │              │
│  │ - Class: 32/64 bits              │              │
│  │ - Entry Point: 0x08048000        │              │
│  │ - Program Headers offset         │              │
│  │ - Section Headers offset         │              │
│  └──────────────────────────────────┘              │
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ Program Headers                  │              │
│  │ - LOAD segments (code, data)     │              │
│  │ - DYNAMIC (liens dynamiques)     │              │
│  │ - INTERP (interpreteur)          │              │
│  └──────────────────────────────────┘              │
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ .text section (code)             │              │
│  │ - Instructions assembleur        │              │
│  │ - Entry point                    │              │
│  │ - Fonctions                      │              │
│  └──────────────────────────────────┘              │
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ .rodata (constantes)             │              │
│  │ - Strings constantes             │              │
│  │ - Tables de données              │              │
│  └──────────────────────────────────┘              │
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ .data (variables initialisées)   │              │
│  │ - Variables globales             │              │
│  │ - Variables statiques            │              │
│  └──────────────────────────────────┘              │
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ .bss (variables non init)        │              │
│  │ - Alloué à l'exécution           │              │
│  └──────────────────────────────────┘              │
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ Symbol Table                     │              │
│  │ - Noms de fonctions              │              │
│  │ - Variables exportées            │              │
│  └──────────────────────────────────┘              │
│                                                     │
│  ┌──────────────────────────────────┐              │
│  │ Relocation Table                 │              │
│  │ - GOT (Global Offset Table)      │              │
│  │ - PLT (Procedure Linkage Table)  │              │
│  └──────────────────────────────────┘              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Flux d'analyse de malware

```
┌─────────────────────────────────────────────────────┐
│         MALWARE ANALYSIS WORKFLOW                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Reconnaissance initiale                         │
│  ┌────────────────────────────────────┐            │
│  │ - file malware.bin                 │            │
│  │ - strings malware.bin              │            │
│  │ - md5sum / sha256sum               │            │
│  │ - Vérifier sur VirusTotal          │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  2. Analyse statique                                │
│  ┌────────────────────────────────────┐            │
│  │ - objdump -d malware.bin           │            │
│  │ - radare2 malware.bin              │            │
│  │ - Ghidra decompilation             │            │
│  │ - Identifier fonctions suspectes   │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  3. Unpacking (si packed)                           │
│  ┌────────────────────────────────────┐            │
│  │ - Détecter packer (UPX, etc.)      │            │
│  │ - Dumper en mémoire                │            │
│  │ - Reconstruire l'import table      │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  4. Analyse dynamique                               │
│  ┌────────────────────────────────────┐            │
│  │ - gdb / strace / ltrace             │            │
│  │ - Sandbox (Cuckoo, Any.run)        │            │
│  │ - Monitoring réseau (Wireshark)    │            │
│  │ - Breakpoints sur API critiques    │            │
│  └────────────────────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  5. Compréhension & Documentation                   │
│  ┌────────────────────────────────────┐            │
│  │ - Identifier IOCs                  │            │
│  │ - Extraction de configuration      │            │
│  │ - Rédaction du rapport             │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Assembleur x64 essentiel

```
┌─────────────────────────────────────────────────────┐
│         x64 ASSEMBLY CHEAT SHEET                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Registres 64-bit:                                  │
│  RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP            │
│  R8, R9, R10, R11, R12, R13, R14, R15              │
│                                                     │
│  Conventions d'appel (x64 Linux):                   │
│  ┌────────────────────────────────────┐            │
│  │ Arg 1: RDI                         │            │
│  │ Arg 2: RSI                         │            │
│  │ Arg 3: RDX                         │            │
│  │ Arg 4: RCX                         │            │
│  │ Arg 5: R8                          │            │
│  │ Arg 6: R9                          │            │
│  │ Retour: RAX                        │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Instructions courantes:                            │
│  ┌────────────────────────────────────┐            │
│  │ mov rax, rbx    ; rax = rbx        │            │
│  │ add rax, 5      ; rax += 5         │            │
│  │ sub rax, rbx    ; rax -= rbx       │            │
│  │ push rax        ; empiler rax      │            │
│  │ pop rbx         ; dépiler dans rbx │            │
│  │ call function   ; appeler fonction │            │
│  │ ret             ; retourner        │            │
│  │ jmp address     ; saut incond.     │            │
│  │ je address      ; saut si égal     │            │
│  │ jne address     ; saut si différent│            │
│  │ cmp rax, rbx    ; comparer         │            │
│  │ test rax, rax   ; AND logique      │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Exemple de fonction:                               │
│  ┌────────────────────────────────────┐            │
│  │ 00401000 push rbp                  │            │
│  │ 00401001 mov rbp, rsp               │            │
│  │ 00401004 sub rsp, 0x20              │            │
│  │ 00401008 mov [rbp-0x4], edi         │            │
│  │ 0040100b mov eax, [rbp-0x4]         │            │
│  │ 0040100e add eax, 0x5               │            │
│  │ 00401011 leave                      │            │
│  │ 00401012 ret                        │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Équivalent C:                                      │
│  int func(int x) {                                  │
│      return x + 5;                                  │
│  }                                                  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Crackme simple

```c
#include <stdio.h>
#include <string.h>

int check_password(const char *password) {
    // Password: "Cr4ckM3"
    const char *correct = "Cr4ckM3";

    if (strcmp(password, correct) == 0) {
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    printf("=== Simple Crackme ===\n\n");

    if (check_password(argv[1])) {
        printf("[+] Correct password!\n");
        printf("[+] Flag: CTF{y0u_cr4ck3d_m3}\n");
    } else {
        printf("[-] Wrong password!\n");
    }

    return 0;
}

/*
Reverse Engineering avec strings:

1. Compiler:
   gcc crackme.c -o crackme

2. Analyse:
   strings crackme | grep -i password
   # Révèle "Cr4ckM3"

3. Solution:
   ./crackme Cr4ckM3
*/
```

### Exemple 2 : Analyse d'un binaire obfusqué

```c
#include <stdio.h>
#include <string.h>

// Fonction obfusquée (logique complexe pour masquer)
int verify(const char *input) {
    int sum = 0;
    int expected[] = {67, 114, 52, 99, 107, 77, 51}; // "Cr4ckM3"

    if (strlen(input) != 7) {
        return 0;
    }

    for (int i = 0; i < 7; i++) {
        if (input[i] != expected[i]) {
            return 0;
        }
        sum += input[i];
    }

    // Check additionnel obfusqué
    if ((sum ^ 0xDEAD) != 0xDCA0) {
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <key>\n", argv[0]);
        return 1;
    }

    printf("=== Obfuscated Crackme ===\n\n");

    if (verify(argv[1])) {
        printf("[+] Success!\n");
        printf("[+] You reverse engineered it!\n");
    } else {
        printf("[-] Try again...\n");
    }

    return 0;
}

/*
Reverse Engineering:

1. Désassembler avec objdump:
   objdump -d obfuscated > disasm.txt

2. Trouver la fonction verify()

3. Analyser les comparaisons:
   - Array expected[] contient les valeurs ASCII
   - Convertir: chr(67) = 'C', chr(114) = 'r', etc.

4. Vérifier le XOR check:
   sum = sum of ASCII values
   sum ^ 0xDEAD == 0xDCA0

5. Solution:
   ./obfuscated Cr4ckM3
*/
```

### Exemple 3 : Unpacker simple

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Code "packed" (XOR encodé)
unsigned char packed_code[] = {
    0x8a, 0x73, 0xca, 0xf2, 0x73, 0xfe, 0xf2, 0x73,
    0xd4, 0x5a, 0xf7, 0x56, 0x5a, 0xf4, 0x5d, 0xfa,
    0xbb, 0xfa, 0x87
};

unsigned char xor_key = 0x42;

void unpack_and_execute() {
    printf("=== Unpacker Demo ===\n\n");

    int code_len = sizeof(packed_code);

    printf("[*] Packed code size: %d bytes\n", code_len);
    printf("[*] XOR key: 0x%02x\n\n", xor_key);

    // Unpacking
    printf("[+] Unpacking...\n");

    unsigned char *unpacked = malloc(code_len + 1);

    for (int i = 0; i < code_len; i++) {
        unpacked[i] = packed_code[i] ^ xor_key;
    }
    unpacked[code_len] = '\0';

    printf("[+] Unpacked code: %s\n", unpacked);

    // En pratique, on exécuterait le code unpacked
    // mais ici on l'affiche simplement

    free(unpacked);
}

int main() {
    unpack_and_execute();
    return 0;
}

/*
Reverse Engineering d'un packer:

1. Identifier le stub de décodage (unpacker)

2. Trouver:
   - L'algorithme de décodage (XOR ici)
   - La clé de décodage
   - Le code packed

3. Recréer le décodeur ou dumper en mémoire:
   - Breakpoint après le unpack
   - Dumper la mémoire avec gdb

4. Analyser le code dépacké
*/
```

### Exemple 4 : Analyse de protocole réseau

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Protocole propriétaire custom
typedef struct __attribute__((packed)) {
    uint16_t magic;        // 0xDEAD
    uint8_t version;       // 1
    uint8_t command;       // 0=ping, 1=exec, 2=exfil
    uint32_t length;       // Taille des données
    uint8_t checksum;      // XOR de tous les bytes
    char data[256];        // Payload
} CustomProtocol;

uint8_t calculate_checksum(CustomProtocol *packet) {
    uint8_t checksum = 0;
    uint8_t *bytes = (uint8_t*)packet;

    for (size_t i = 0; i < sizeof(CustomProtocol) - 1; i++) {
        checksum ^= bytes[i];
    }

    return checksum;
}

void create_packet(CustomProtocol *packet, uint8_t command, const char *data) {
    packet->magic = 0xDEAD;
    packet->version = 1;
    packet->command = command;
    packet->length = strlen(data);

    strncpy(packet->data, data, sizeof(packet->data) - 1);

    packet->checksum = calculate_checksum(packet);
}

void parse_packet(CustomProtocol *packet) {
    printf("=== Protocol Analysis ===\n\n");

    printf("Magic: 0x%04X\n", packet->magic);
    printf("Version: %d\n", packet->version);
    printf("Command: %d\n", packet->command);
    printf("Length: %d\n", packet->length);
    printf("Checksum: 0x%02X\n", packet->checksum);
    printf("Data: %s\n", packet->data);

    // Vérifier checksum
    uint8_t computed = calculate_checksum(packet);

    if (computed == packet->checksum) {
        printf("\n[+] Checksum valid!\n");
    } else {
        printf("\n[-] Checksum invalid!\n");
    }
}

int main() {
    CustomProtocol packet;

    // Créer un paquet
    create_packet(&packet, 1, "whoami");

    // Simuler l'envoi réseau
    printf("=== Sending packet ===\n");
    printf("Raw bytes: ");

    uint8_t *raw = (uint8_t*)&packet;
    for (size_t i = 0; i < 20; i++) {
        printf("%02x ", raw[i]);
    }
    printf("\n\n");

    // Analyser (reverse engineering du protocole)
    parse_packet(&packet);

    return 0;
}

/*
Reverse Engineering d'un protocole:

1. Capturer le trafic avec Wireshark/tcpdump

2. Identifier les patterns:
   - Magic bytes (signature)
   - Structure répétitive
   - Taille des champs

3. Reconstruire la structure:
   - Analyser plusieurs paquets
   - Identifier les champs variables
   - Trouver les checksums/CRC

4. Créer un parser:
   - Définir la structure en C
   - Implémenter la validation
   - Tester avec des paquets capturés
*/
```

### Exemple 5 : Anti-RE tricks

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>

// Technique 1: Anti-debugging
int check_debugger() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1; // Debugger détecté
    }
    return 0;
}

// Technique 2: Obfuscation de strings
void decrypt_string(char *str, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Technique 3: Code mort / junk code
void junk_function() {
    int x = rand();
    if (x < 0) { // Jamais vrai
        printf("This will never execute\n");
        system("/bin/sh");
    }
}

// Technique 4: Self-modifying code (avancé)
void obfuscated_logic() {
    // String chiffrée
    char encrypted[] = {0x33, 0x27, 0x16, 0x27, 0x21, 0x30};
    int len = sizeof(encrypted);

    // Déchiffrer au runtime
    decrypt_string(encrypted, len, 0x42);

    printf("Decrypted: %s\n", encrypted);
}

// Technique 5: Control flow flattening
void flattened_function(int input) {
    int state = 0;

    while (1) {
        switch(state) {
            case 0:
                if (input > 10) {
                    state = 1;
                } else {
                    state = 2;
                }
                break;

            case 1:
                printf("Input > 10\n");
                state = 3;
                break;

            case 2:
                printf("Input <= 10\n");
                state = 3;
                break;

            case 3:
                return;
        }
    }
}

int main() {
    printf("=== Anti-RE Techniques Demo ===\n\n");

    // Check 1: Anti-debugging
    if (check_debugger()) {
        printf("[!] Debugger detected! Exiting...\n");
        return 1;
    }

    printf("[+] No debugger detected\n\n");

    // Junk code
    junk_function();

    // Obfuscation
    printf("[*] Running obfuscated logic...\n");
    obfuscated_logic();

    // Control flow flattening
    printf("\n[*] Testing flattened control flow...\n");
    flattened_function(15);

    return 0;
}

/*
Comment reverse engineer ce programme:

1. Anti-debugging bypass:
   - Patcher l'instruction ptrace
   - Ou utiliser LD_PRELOAD pour hooker ptrace

2. String obfuscation:
   - Trouver la fonction decrypt_string()
   - Identifier la clé (0x42)
   - Décrypter manuellement les strings

3. Junk code:
   - Analyser le control flow
   - Identifier les branches jamais prises

4. Control flow flattening:
   - Reconstruire le control flow original
   - Simplifier le graphe

Outils:
- Ghidra pour décompiler
- radare2 pour analyser le control flow
- IDA Pro pour le graphe de fonctions
*/
```

## 📝 Points clés à retenir

1. **Analyse statique** : Désassembler sans exécuter
2. **Analyse dynamique** : Observer à l'exécution
3. **Assembleur** : Comprendre x86/x64 est essentiel
4. **Unpacking** : Décoder les binaires packés
5. **Anti-RE** : Détecter et contourner les protections

### Outils essentiels

```
Outil            Utilité                            Plateforme
──────────────────────────────────────────────────────────────────
GDB/gef          Debugging                          Linux
radare2          Désassemblage, analyse             Multi
Ghidra           Décompilation                      Multi
IDA Pro          Analyse statique (commercial)      Multi
objdump          Désassemblage rapide               Linux
strings          Extraction de strings              Linux
strace           Trace syscalls                     Linux
ltrace           Trace library calls                Linux
Wireshark        Analyse réseau                     Multi
```

### Workflow typique

```
1. Reconnaissance
   ↓
2. Analyse statique (strings, imports, sections)
   ↓
3. Désassemblage (trouver fonctions intéressantes)
   ↓
4. Décompilation (comprendre la logique)
   ↓
5. Analyse dynamique (debugging, tracing)
   ↓
6. Documentation (IOCs, rapport)
```

## ➡️ Prochaine étape

Maintenant que tu maîtrises le reverse engineering, tu es prêt pour le **Module 55 : Développement de Malware Avancé**, où tu apprendras à créer des malwares sophistiqués avec toutes les techniques apprises (évasion, chiffrement, C2, etc.).

### Ce que tu as appris
- Désassembler des binaires
- Lire l'assembleur x86/x64
- Cracker des protections simples
- Unpacker des binaires
- Analyser des protocoles
- Contourner l'anti-RE

### Ce qui t'attend
- Architecture complète de malware
- Modules de C2 avancés
- Techniques de persistence
- Lateral movement
- Exfiltration de données
- Projet complet de RAT (Remote Access Trojan)

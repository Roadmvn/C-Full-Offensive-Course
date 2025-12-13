# Module 37 : Linux Syscalls - Appels Système Directs

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser les appels système (syscalls) Linux de bas niveau :
- Comprendre la frontière User Space / Kernel Space
- Exécuter des syscalls directs sans passer par la libc
- Utiliser l'assembleur inline pour les syscalls
- Bypasser les hooks LD_PRELOAD
- Créer du code furtif pour les opérations Red Team

## 📚 Théorie

### C'est quoi un Syscall ?

Un **syscall** (appel système) est le mécanisme qui permet à un programme utilisateur de demander au noyau Linux d'effectuer une opération privilégiée.

**Architecture Linux** :
```ascii
┌────────────────────────────────────────────────────────┐
│                  USER SPACE (Ring 3)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │
│  │   Ton    │  │  libc    │  │  Autres libs     │    │
│  │ Programme│  │          │  │                  │    │
│  │   C      │  │  open()  │  │   libssl, etc.   │    │
│  └────┬─────┘  │  read()  │  │                  │    │
│       │        │  write() │  │                  │    │
│       └────────┤  fork()  │  │                  │    │
│                └────┬─────┘  └──────────────────┘    │
│                     │                                  │
│                     │ Wrapper functions                │
│                     ▼                                  │
├────────────────────────────────────────────────────────┤
│                SYSCALL INTERFACE                       │
│                                                        │
│          syscall instruction (x86-64)                  │
│          svc instruction (ARM64)                       │
│                     │                                  │
│                     ▼                                  │
├════════════════════════════════════════════════════════┤  ← Changement de Ring
│                KERNEL SPACE (Ring 0)                   │
│  ┌──────────────────────────────────────────────┐    │
│  │        System Call Dispatcher                 │    │
│  │         (syscall table lookup)                │    │
│  └─────────────────┬────────────────────────────┘    │
│                    │                                   │
│      ┌─────────────┼─────────────┬────────────┐      │
│      ▼             ▼             ▼            ▼       │
│  sys_read()   sys_write()   sys_open()   sys_fork()  │
│      │             │             │            │       │
│      └─────────────┴─────────────┴────────────┘      │
│                    │                                   │
│            Hardware Access Layer                      │
│         (Disk, Network, Memory, CPU)                  │
└────────────────────────────────────────────────────────┘
```

### Pourquoi utiliser les syscalls directs ?

**Normalement**, quand tu fais :
```c
printf("Hello\n");
```

Voici ce qui se passe :
```ascii
printf() (libc)
   ↓
write() (libc wrapper)
   ↓
syscall instruction
   ↓
sys_write() (kernel)
   ↓
Terminal output
```

**En Red Team**, tu veux parfois bypasser les couches intermédiaires :
```ascii
Ton code C
   ↓
syscall instruction DIRECT
   ↓
sys_write() (kernel)
   ↓
Terminal output
```

**Avantages Red Team** :
1. **Bypass LD_PRELOAD** : Les hooks sur les fonctions libc sont contournés
2. **Obfuscation** : Code moins évident à analyser
3. **Furtivité** : Certains outils de monitoring surveillent les appels libc, pas les syscalls directs
4. **Performance** : Pas d'overhead des wrappers (minime mais réel)

### Comment fonctionne un Syscall x86-64 ?

**Convention d'appel syscall Linux x86-64** :

```ascii
Registres utilisés :
┌────────┬──────────────────────────────────────┐
│  RAX   │  Numéro du syscall                   │
├────────┼──────────────────────────────────────┤
│  RDI   │  Argument 1                          │
│  RSI   │  Argument 2                          │
│  RDX   │  Argument 3                          │
│  R10   │  Argument 4                          │
│  R8    │  Argument 5                          │
│  R9    │  Argument 6                          │
├────────┼──────────────────────────────────────┤
│  RAX   │  Valeur de retour (après syscall)    │
└────────┴──────────────────────────────────────┘

Instruction : syscall
```

**Exemple concret - write()** :
```c
// Signature : ssize_t write(int fd, const void *buf, size_t count);
// Syscall number : 1

// En C normal
write(1, "Hello\n", 6);

// En assembleur équivalent
mov rax, 1              ; SYS_write = 1
mov rdi, 1              ; fd = 1 (stdout)
lea rsi, [message]      ; buf = adresse du message
mov rdx, 6              ; count = 6 bytes
syscall                 ; Appel kernel
```

### Numéros de Syscall Linux x86-64

**Syscalls les plus utilisés** :
```c
// Fichiers
#define SYS_read      0
#define SYS_write     1
#define SYS_open      2
#define SYS_close     3
#define SYS_stat      4
#define SYS_lseek     8
#define SYS_mmap      9
#define SYS_munmap    11

// Processus
#define SYS_fork      57
#define SYS_execve    59
#define SYS_exit      60
#define SYS_wait4     61
#define SYS_kill      62
#define SYS_getpid    39
#define SYS_getppid   110

// Réseau
#define SYS_socket    41
#define SYS_connect   42
#define SYS_accept    43
#define SYS_sendto    44
#define SYS_recvfrom  45
```

**Où trouver tous les numéros ?**
```bash
# Fichier header système
cat /usr/include/asm/unistd_64.h

# Ou en ligne
# https://filippo.io/linux-syscall-table/
```

## 🔍 Visualisation

### Flux d'exécution d'un Syscall

```ascii
AVANT SYSCALL                PENDANT SYSCALL              APRÈS SYSCALL
══════════════               ═══════════════              ═══════════════

User Space                   User Space                   User Space
┌──────────┐                ┌──────────┐                ┌──────────┐
│ Programme│                │ Programme│                │ Programme│
│          │                │ (paused) │                │          │
│ RAX = 1  │                │          │                │ RAX = 6  │ ← bytes written
│ RDI = 1  │                │          │                │          │
│ RSI = buf│                │          │                │          │
│ RDX = 6  │                │          │                │          │
│          │                │          │                │          │
│ syscall ─┼────────┐       │          │       ┌────────┼─ retour  │
└──────────┘        │       └──────────┘       │        └──────────┘
                    │                           │
CPU: Ring 3         │       CPU: Ring 0         │        CPU: Ring 3
                    │       ┌──────────┐       │
                    └──────→│  Kernel  │───────┘
                            │          │
                            │sys_write │
                            │   (fd=1, │
                            │    buf,  │
                            │    len=6)│
                            │          │
                            │    ↓     │
                            │ [Écrit   │
                            │  dans    │
                            │  stdout] │
                            └──────────┘
```

### Transition Ring 3 → Ring 0

```ascii
┌─────────────────────────────────────────────────────┐
│              CPU Protection Rings                   │
│                                                     │
│         Ring 0 (Kernel Mode)                        │
│    ┌────────────────────────────────┐              │
│    │  Accès complet hardware        │              │
│    │  Accès toute la mémoire        │              │
│    │  Instructions privilégiées     │              │
│    │                                 │              │
│    │    Ring 1-2 (Drivers)          │              │
│    │  ┌──────────────────────┐      │              │
│    │  │  Peu utilisé Linux   │      │              │
│    │  │                      │      │              │
│    │  │   Ring 3 (User)     │      │              │
│    │  │ ┌────────────────┐  │      │              │
│    │  │ │ Ton programme  │  │      │              │
│    │  │ │                │  │      │              │
│    │  │ │ Protégé du     │  │      │              │
│    │  │ │ hardware       │  │      │              │
│    │  │ └────────────────┘  │      │              │
│    │  └──────────────────────┘      │              │
│    └────────────────────────────────┘              │
│                                                     │
│  syscall = seul moyen de passer Ring 3 → Ring 0    │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Méthode 1 : Via la fonction syscall() de la libc

**Code simple mais utilise encore la libc** :

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
    const char *message = "Hello via syscall()!\n";

    // Appel syscall via wrapper libc
    // syscall(numero, arg1, arg2, arg3, ...)
    long result = syscall(SYS_write,     // 1
                          1,              // stdout
                          message,        // buffer
                          21);            // length

    printf("Bytes written: %ld\n", result);

    // Autre exemple : getpid
    long pid = syscall(SYS_getpid);
    printf("PID: %ld\n", pid);

    return 0;
}
```

**Compilation et test** :
```bash
gcc -o syscall_basic syscall_basic.c
./syscall_basic
```

**Sortie** :
```
Hello via syscall()!
Bytes written: 21
PID: 12345
```

### Méthode 2 : Assembleur inline (VRAI syscall direct)

**Code sans dépendance libc** :

```c
#include <unistd.h>

// Fonction qui fait un syscall write directement
ssize_t my_write(int fd, const void *buf, size_t count) {
    long ret;

    // Assembleur inline x86-64
    __asm__ volatile (
        "mov $1, %%rax\n"        // SYS_write = 1
        "mov %1, %%rdi\n"        // arg1 = fd
        "mov %2, %%rsi\n"        // arg2 = buf
        "mov %3, %%rdx\n"        // arg3 = count
        "syscall\n"              // Appel kernel
        "mov %%rax, %0\n"        // Récupérer retour
        : "=r" (ret)             // Output
        : "r" ((long)fd),        // Inputs
          "r" (buf),
          "r" (count)
        : "rax", "rdi", "rsi", "rdx"  // Clobbered registers
    );

    return ret;
}

// Fonction exit directe
void my_exit(int status) {
    __asm__ volatile (
        "mov $60, %%rax\n"       // SYS_exit = 60
        "mov %0, %%rdi\n"        // arg1 = status
        "syscall\n"
        :
        : "r" ((long)status)
        : "rax", "rdi"
    );
}

// Point d'entrée custom (sans libc du tout)
void _start(void) {
    const char *msg = "Direct syscall - No libc!\n";

    // Calculer longueur manuellement
    size_t len = 0;
    while (msg[len]) len++;

    // Write via syscall direct
    my_write(1, msg, len);

    // Exit via syscall direct
    my_exit(0);
}
```

**Compilation SANS libc** :
```bash
gcc -nostdlib -static -o syscall_pure syscall_pure.c
./syscall_pure
```

**Sortie** :
```
Direct syscall - No libc!
```

**Vérification (pas de libc)** :
```bash
ldd syscall_pure
# Output: "not a dynamic executable"

objdump -d syscall_pure | grep -A5 "_start:"
# Tu verras directement les instructions syscall
```

### Méthode 3 : Programme complet avec plusieurs syscalls

**Exemple : Mini-shell via syscalls directs**

```c
// syscall_shell.c
#define SYS_read    0
#define SYS_write   1
#define SYS_open    2
#define SYS_close   3
#define SYS_fork    57
#define SYS_execve  59
#define SYS_exit    60

typedef unsigned long size_t;
typedef long ssize_t;

// Syscall wrapper générique
static inline long syscall1(long n, long a1) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

// Wrappers syscalls
ssize_t sys_write(int fd, const void *buf, size_t count) {
    return syscall3(SYS_write, fd, (long)buf, count);
}

ssize_t sys_read(int fd, void *buf, size_t count) {
    return syscall3(SYS_read, fd, (long)buf, count);
}

void sys_exit(int status) {
    syscall1(SYS_exit, status);
}

// Fonction utilitaires
size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// Point d'entrée
void _start(void) {
    char buf[128];
    const char *prompt = "syscall-shell> ";
    const char *bye = "Bye!\n";

    while (1) {
        // Afficher prompt
        sys_write(1, prompt, strlen(prompt));

        // Lire commande
        ssize_t n = sys_read(0, buf, sizeof(buf) - 1);
        if (n <= 0) break;

        buf[n - 1] = '\0';  // Enlever \n

        // Traiter commandes
        if (strcmp(buf, "exit") == 0) {
            sys_write(1, bye, strlen(bye));
            break;
        } else if (strcmp(buf, "hello") == 0) {
            sys_write(1, "World!\n", 7);
        } else {
            sys_write(1, "Unknown command\n", 16);
        }
    }

    sys_exit(0);
}
```

**Compilation** :
```bash
gcc -nostdlib -static -o syscall_shell syscall_shell.c
./syscall_shell
```

**Utilisation** :
```
syscall-shell> hello
World!
syscall-shell> test
Unknown command
syscall-shell> exit
Bye!
```

### Méthode 4 : Syscall avec gestion d'erreur

**Code robuste** :

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

// Wrapper qui gère errno
ssize_t safe_syscall_write(int fd, const void *buf, size_t count) {
    long ret;

    __asm__ volatile (
        "mov $1, %%rax\n"
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r" (ret)
        : "r" ((long)fd), "r" (buf), "r" (count)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );

    // Sur Linux, syscall retourne -errno en cas d'erreur
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

int main(void) {
    const char *msg = "Test\n";

    // FD invalide
    ssize_t ret = safe_syscall_write(999, msg, 5);
    if (ret == -1) {
        printf("Erreur: %d (%s)\n", errno, strerror(errno));
        // Erreur: 9 (Bad file descriptor)
    }

    // FD valide
    ret = safe_syscall_write(1, msg, 5);
    printf("Écrit: %zd bytes\n", ret);

    return 0;
}
```

## 🎯 Application Red Team

### 1. Bypass LD_PRELOAD hooks

**Scénario** : Un outil de monitoring utilise `LD_PRELOAD` pour hooker `write()` de la libc.

**Code hookable (utilise libc)** :
```c
#include <unistd.h>

int main(void) {
    write(1, "Secret data\n", 12);  // ← HOOKABLE
    return 0;
}
```

**Code non-hookable (syscall direct)** :
```c
void _start(void) {
    __asm__ volatile (
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "lea msg(%%rip), %%rsi\n"
        "mov $12, %%rdx\n"
        "syscall\n"

        "mov $60, %%rax\n"
        "xor %%rdi, %%rdi\n"
        "syscall\n"
        ::: "rax", "rdi", "rsi", "rdx"
    );
}

__asm__(
    "msg: .ascii \"Secret data\\n\""
);
```

**Test** :
```bash
# Avec hook
LD_PRELOAD=./hook.so ./program_libc
# [HOOK] write() détecté

# Sans hook (syscall direct)
LD_PRELOAD=./hook.so ./program_syscall
# Rien détecté !
```

### 2. Obfuscation des appels système

**Code obfusqué avec syscalls** :

```c
// Rend l'analyse statique plus difficile
void obfuscated_write(const char *data, size_t len) {
    // Numéro syscall calculé dynamiquement
    long syscall_num = (5 * 2) - 9;  // = 1 (write)

    // Arguments dispersés
    long args[3];
    args[0] = 1;      // fd
    args[1] = (long)data;
    args[2] = len;

    // Syscall indirect
    __asm__ volatile (
        "mov %0, %%rax\n"
        "mov 0(%1), %%rdi\n"
        "mov 8(%1), %%rsi\n"
        "mov 16(%1), %%rdx\n"
        "syscall\n"
        :
        : "r" (syscall_num), "r" (args)
        : "rax", "rdi", "rsi", "rdx", "memory"
    );
}
```

### 3. Shellcode utilisant syscalls

**Shellcode execve("/bin/sh")** :

```c
// Shellcode en C (sera converti en bytes)
void shellcode(void) {
    __asm__ volatile (
        // execve("/bin/sh", NULL, NULL)
        "xor %%rdx, %%rdx\n"              // envp = NULL
        "xor %%rsi, %%rsi\n"              // argv = NULL
        "movabs $0x68732f6e69622f, %%rdi\n"  // "/bin/sh" en little-endian
        "push %%rdi\n"
        "mov %%rsp, %%rdi\n"              // rdi = pointeur vers "/bin/sh"
        "mov $59, %%rax\n"                // SYS_execve = 59
        "syscall\n"
        :::
    );
}

// Extraction du shellcode
unsigned char shellcode_bytes[] =
    "\x48\x31\xd2"                    // xor rdx, rdx
    "\x48\x31\xf6"                    // xor rsi, rsi
    "\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00"  // movabs /bin/sh
    "\x57"                            // push rdi
    "\x48\x89\xe7"                    // mov rdi, rsp
    "\xb8\x3b\x00\x00\x00"           // mov eax, 59
    "\x0f\x05";                       // syscall
```

## 📝 Points clés

### À retenir absolument

1. **Syscall = passage User → Kernel**
   - Seul moyen d'accéder au hardware
   - Change le CPU de Ring 3 à Ring 0

2. **Convention x86-64**
   - RAX = numéro syscall
   - RDI, RSI, RDX, R10, R8, R9 = arguments
   - RAX = retour

3. **Avantages Red Team**
   - Bypass hooks LD_PRELOAD
   - Code plus furtif
   - Moins de dépendances

4. **Limitations**
   - Code moins portable (dépend de l'architecture)
   - Plus complexe à maintenir
   - Pas de gestion errno automatique

### Syscalls essentiels à connaître

```c
// Fichiers
SYS_read    (0)   - Lire depuis fd
SYS_write   (1)   - Écrire vers fd
SYS_open    (2)   - Ouvrir fichier
SYS_close   (3)   - Fermer fd

// Processus
SYS_fork    (57)  - Créer processus
SYS_execve  (59)  - Exécuter programme
SYS_exit    (60)  - Terminer processus
SYS_getpid  (39)  - Obtenir PID

// Réseau
SYS_socket  (41)  - Créer socket
SYS_connect (42)  - Connecter socket
SYS_bind    (49)  - Bind socket
SYS_listen  (50)  - Listen socket
```

### Outils de debug

```bash
# Tracer les syscalls
strace ./programme
strace -e write,read ./programme

# Voir la syscall table
cat /usr/include/asm/unistd_64.h

# Désassembler
objdump -d programme
gdb programme
```

## ➡️ Prochaine étape

**Module 38 : ELF Parsing**

Maintenant que tu sais faire des syscalls directs, le prochain module te montrera comment parser le format ELF (Executable and Linkable Format) pour :
- Lire les headers d'un exécutable
- Extraire les sections et segments
- Modifier des binaires à la volée
- Créer des injecteurs de code

Les syscalls directs + parsing ELF = base pour créer des rootkits et malwares avancés.

## 📚 Ressources

**Documentation officielle** :
- [Linux Syscall Table](https://filippo.io/linux-syscall-table/)
- [syscalls(2) man page](https://man7.org/linux/man-pages/man2/syscalls.2.html)
- [x86-64 ABI](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)

**Outils** :
- `strace` - Tracer syscalls
- `ltrace` - Tracer library calls
- `gdb` - Debugger
- `/proc/<pid>/syscall` - Voir syscall en cours

**Pour aller plus loin** :
- Seccomp (filtrage syscalls)
- Syscall hooking (kernel modules)
- VDSO (syscalls optimisés)

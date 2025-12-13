# Cours : Appels Système (Syscalls)

## 1. Introduction - La Frontière entre Utilisateur et Noyau

### 1.1 Les Deux Mondes

Un système d'exploitation moderne sépare la mémoire en **deux espaces** :

```ascii
┌─────────────────────────────────────────────────────────┐
│  USER SPACE (Espace Utilisateur)                        │
│  - Applications (Chrome, Terminal, votre code C)        │
│  - Bibliothèques (libc, libSystem)                      │
│  - Mode NON-privilégié                                  │
│  - Ne peut PAS :                                        │
│    • Accéder directement au matériel                    │
│    • Modifier la mémoire d'autres processus             │
│    • Exécuter certaines instructions CPU                │
├─────────────────────────────────────────────────────────┤
│                   ════════════                          │  ← Frontière
│                  SYSCALL BARRIER                        │
│                   ════════════                          │
├─────────────────────────────────────────────────────────┤
│  KERNEL SPACE (Espace Noyau)                            │
│  - Noyau du système d'exploitation                      │
│  - Drivers (pilotes matériels)                          │
│  - Mode PRIVILÉGIÉ                                      │
│  - Peut TOUT faire :                                    │
│    • Accéder au disque dur, réseau, GPU                 │
│    • Gérer la mémoire de tous les processus             │
│    • Exécuter toutes les instructions CPU               │
└─────────────────────────────────────────────────────────┘
```

### 1.2 Qu'est-ce qu'un Syscall ?

Un **syscall** (appel système) est la **seule façon** pour votre code utilisateur de demander au noyau d'effectuer une opération privilégiée.

**Exemples concrets** :
- Ouvrir un fichier → `open()` syscall
- Lire depuis le clavier → `read()` syscall
- Afficher à l'écran → `write()` syscall
- Créer un processus → `fork()` syscall
- Envoyer sur le réseau → `send()` syscall

**Analogie** : Pensez au noyau comme un **majordome** :
- Vous (code utilisateur) ne pouvez pas accéder directement aux ressources
- Vous devez **demander** au majordome (syscall)
- Le majordome vérifie vos permissions et exécute la tâche

## 2. Anatomie d'un Syscall - Le Voyage du Code

### 2.1 Vue d'Ensemble

```ascii
┌─────────────────────────────────────────────────────────┐
│  VOTRE CODE C                                           │
│                                                         │
│  int fd = open("/tmp/file.txt", O_RDONLY);             │
│            ↓                                            │
├─────────────────────────────────────────────────────────┤
│  WRAPPER LIBC (libc ou libSystem sur macOS)             │
│                                                         │
│  open() {                                               │
│      // Préparer registres                             │
│      // Appeler syscall                                │
│  }                                                      │
│            ↓                                            │
├─────────────────────────────────────────────────────────┤
│  INSTRUCTION MACHINE                                    │
│                                                         │
│  syscall (x86-64) ou svc (ARM64)                       │
│            ↓                                            │
│  ═══════════════════════════════════════ Transition    │
│            ↓                             Mode Kernel     │
├─────────────────────────────────────────────────────────┤
│  NOYAU (Kernel)                                         │
│                                                         │
│  sys_open() {                                           │
│      // Vérifier permissions                           │
│      // Accéder au système de fichiers                 │
│      // Retourner file descriptor                      │
│  }                                                      │
│            ↓                                            │
│  ═══════════════════════════════════════ Transition    │
│            ↓                             Mode User      │
├─────────────────────────────────────────────────────────┤
│  RETOUR AU CODE                                         │
│                                                         │
│  fd = 3;  // File descriptor retourné                  │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Changement de Mode CPU

Quand un syscall est exécuté, le CPU change physiquement de **mode** :

```ascii
AVANT SYSCALL :
┌──────────────────┐
│  CPU en          │
│  USER MODE       │  ← Droits limités
│  Ring 3 (x86)    │
└──────────────────┘

Instruction "syscall" ou "svc"
       ↓

PENDANT SYSCALL :
┌──────────────────┐
│  CPU en          │
│  KERNEL MODE     │  ← Droits complets
│  Ring 0 (x86)    │  ← Accès hardware
└──────────────────┘

Retour du syscall
       ↓

APRÈS SYSCALL :
┌──────────────────┐
│  CPU en          │
│  USER MODE       │  ← Retour mode limité
│  Ring 3          │
└──────────────────┘
```

**Pourquoi c'est important ?**

En **USER MODE**, votre code ne peut PAS :
- Accéder aux ports I/O (disque, réseau)
- Modifier les tables de pages mémoire
- Désactiver les interruptions
- Accéder à la mémoire d'autres processus

**Seul le kernel en mode privilégié peut faire ça !**

### 1.3 Tous les Exécutables Doivent Être Signés

```bash
# Tenter d'exécuter un binaire non signé
./unsigned_binary
# Erreur : "killed: 9" (SIGKILL par le système)
```

**Gatekeeper** vérifie la signature à chaque exécution.

### En Assembleur (x86-64)

```asm
; syscall read(fd=0, buffer, count=10)
mov rax, 0          ; Numéro syscall (0 = read)
mov rdi, 0          ; fd (stdin)
mov rsi, buffer     ; Adresse buffer
mov rdx, 10         ; Nombre bytes
syscall             ; Appel noyau

; Résultat dans RAX
```

## 3. Syscalls Courants

### Fichiers

```c
// open
int fd = open("/path/file", O_RDONLY);

// read
char buf[100];
ssize_t bytes = read(fd, buf, sizeof(buf));

// write
write(fd, "data", 4);

// close
close(fd);

// stat (infos fichier)
struct stat st;
stat("/path/file", &st);
printf("Taille: %ld\n", st.st_size);
```

### Processus

```c
// fork - créer processus
pid_t pid = fork();

// execve - remplacer processus
char *args[] = {"/bin/ls", NULL};
execve("/bin/ls", args, NULL);

// wait - attendre enfant
int status;
wait(&status);

// exit - terminer
exit(0);

// getpid/getppid
printf("PID: %d, PPID: %d\n", getpid(), getppid());
```

### Mémoire

```c
// brk/sbrk - heap
void *ptr = sbrk(4096);  // Alloue 4KB

// mmap - mapper mémoire
void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

munmap(addr, 4096);
```

### Signaux

```c
// kill - envoyer signal
kill(pid, SIGTERM);

// sigaction - installer handler
struct sigaction sa;
sa.sa_handler = handler;
sigaction(SIGINT, &sa, NULL);
```

## 4. Appeler Directement un Syscall

### Via syscall()

```c
#include <sys/syscall.h>
#include <unistd.h>

// Appel direct
long result = syscall(SYS_write, 1, "Hello\n", 6);
```

### En Assembleur Inline

```c
long my_write(int fd, const char *buf, size_t count) {
    long ret;
    asm volatile (
        "mov $1, %%rax\n"      // SYS_write = 1
        "mov %1, %%rdi\n"      // fd
        "mov %2, %%rsi\n"      // buf
        "mov %3, %%rdx\n"      // count
        "syscall\n"
        "mov %%rax, %0\n"      // résultat
        : "=r" (ret)
        : "r" ((long)fd), "r" (buf), "r" (count)
        : "rax", "rdi", "rsi", "rdx"
    );
    return ret;
}
```

## 5. Numéros de Syscall

### Linux x86-64

```c
#define SYS_read      0
#define SYS_write     1
#define SYS_open      2
#define SYS_close     3
#define SYS_stat      4
#define SYS_fork      57
#define SYS_execve    59
#define SYS_exit      60
```

Voir `/usr/include/asm/unistd_64.h`

## 6. Tracage des Syscalls

### strace

```bash
strace ./programme
strace -e open,read ./programme
strace -c ./programme  # Statistiques
```

### ltrace (bibliothèques)

```bash
ltrace ./programme
```

## 7. Conventions d'Appel

### x86-64 (System V)

**Arguments** : RDI, RSI, RDX, RCX, R8, R9
**Syscall** : RAX = numéro
**Retour** : RAX

### ARM64

**Arguments** : X0-X7
**Syscall** : X8 = numéro
**Retour** : X0

## 8. Exploitation et Sécurité

### Hooking Syscalls

```c
// LD_PRELOAD pour intercepter
ssize_t write(int fd, const void *buf, size_t count) {
    // Log avant appel réel
    fprintf(stderr, "[HOOK] write(%d, ...)\n", fd);
    
    // Appel original
    return syscall(SYS_write, fd, buf, count);
}
```

### Seccomp (Filtrer Syscalls)

```c
#include <seccomp.h>

scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_read, 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_write, 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SYS_exit, 0);
seccomp_load(ctx);

// Maintenant, seuls read/write/exit sont autorisés
```

### ROP avec Syscalls

```c
// Shellcode utilisant syscalls directs
// execve("/bin/sh", NULL, NULL)
char shellcode[] = 
    "\x48\x31\xd2"              // xor rdx, rdx
    "\x48\xbb\x2f\x62\x69\x6e"  // mov rbx, "/bin/sh"
    "\x2f\x73\x68"
    "\x53"                      // push rbx
    "\x48\x89\xe7"              // mov rdi, rsp
    "\x48\x31\xc0"              // xor rax, rax
    "\xb0\x3b"                  // mov al, 59 (execve)
    "\x0f\x05";                 // syscall
```

## 9. Gestion d'Erreurs

```c
int fd = open("file.txt", O_RDONLY);
if (fd == -1) {
    perror("open");
    printf("errno: %d\n", errno);
    // errno défini par syscall en cas d'erreur
}
```

**Codes errno courants** :
- EACCES (13) : Permission denied
- ENOENT (2) : No such file
- EINTR (4) : Interrupted
- EAGAIN (11) : Resource temp unavailable

## 10. Bonnes Pratiques

1. **Vérifier** toujours retours des syscalls
2. **Utiliser** wrappers libc (plus portables)
3. **Tracer** avec strace pour débugger
4. **Comprendre** errno
5. **Sécuriser** avec seccomp si possible

## Ressources

- [Linux Syscall Table](https://filippo.io/linux-syscall-table/)
- [syscalls(2)](https://man7.org/linux/man-pages/man2/syscalls.2.html)
- [Seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)


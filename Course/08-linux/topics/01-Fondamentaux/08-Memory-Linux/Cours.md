# Module L08 : Gestion Mémoire Linux - mmap, mprotect, /proc/pid/mem

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser la gestion mémoire bas niveau sous Linux :
- Allouer de la mémoire avec mmap() au lieu de malloc()
- Modifier les permissions mémoire avec mprotect()
- Lire/écrire dans la mémoire d'autres processus via /proc
- Manipuler les mappings mémoire pour des techniques Red Team
- Créer des zones mémoire exécutables pour du shellcode

## 📚 Théorie

### C'est quoi la mémoire virtuelle ?

Sous Linux, chaque processus a son propre **espace d'adressage virtuel**. Le kernel traduit ces adresses virtuelles en adresses physiques (RAM).

**Architecture de la mémoire d'un processus** :
```ascii
Adresses hautes (0x7FFF...)
┌───────────────────────────────┐
│         STACK                 │  ← Grandit vers le bas
│  (variables locales, args)    │
│         ↓                     │
├───────────────────────────────┤
│                               │
│         (libre)               │
│                               │
├───────────────────────────────┤
│         ↑                     │
│  HEAP (malloc, new)           │  ← Grandit vers le haut
├───────────────────────────────┤
│  BSS (variables non init)     │
├───────────────────────────────┤
│  DATA (variables init)        │
├───────────────────────────────┤
│  TEXT (code exécutable)       │  ← Read-only + Execute
└───────────────────────────────┘
Adresses basses (0x0000...)
```

**Visualiser avec /proc** :
```bash
# Voir les mappings mémoire d'un processus
cat /proc/self/maps

# Exemple de sortie :
# 00400000-00401000 r-xp ... /bin/cat       ← CODE (lecture + exec)
# 00600000-00601000 r--p ... /bin/cat       ← DATA (lecture seule)
# 00601000-00602000 rw-p ... /bin/cat       ← DATA (lecture/écriture)
# 7f8a12345000-...  rw-p ... [heap]         ← HEAP
# 7ffed1234000-...  rw-p ... [stack]        ← STACK
```

### mmap() - Allocation mémoire bas niveau

**Signature** :
```c
void *mmap(void *addr,           // Adresse souhaitée (NULL = automatique)
           size_t length,        // Taille en bytes
           int prot,             // Permissions (PROT_READ, PROT_WRITE, PROT_EXEC)
           int flags,            // Flags (MAP_PRIVATE, MAP_ANONYMOUS, etc.)
           int fd,               // File descriptor (ou -1 si MAP_ANONYMOUS)
           off_t offset);        // Offset dans le fichier
```

**Différence avec malloc()** :
```ascii
malloc()                          mmap()
════════                          ══════
┌────────────┐                   ┌────────────┐
│   libc     │                   │  syscall   │
│  (wrapper) │                   │  direct    │
└─────┬──────┘                   └─────┬──────┘
      │                                │
      │ Utilise sbrk/mmap              │
      ▼                                ▼
┌────────────────┐            ┌────────────────┐
│  Gère un pool  │            │ Mapping direct │
│  réutilisable  │            │  dans kernel   │
│  (heap)        │            │                │
│  Overhead      │            │  Pas d'overhead│
└────────────────┘            └────────────────┘

Utilisé pour:                 Utilisé pour:
- Petites allocations         - Grandes allocations
- Allocations fréquentes      - Mappings de fichiers
                              - Mémoire partagée
                              - Shellcode injection
```

**Permissions mémoire** :
```c
PROT_NONE   // Pas d'accès
PROT_READ   // Lecture
PROT_WRITE  // Écriture
PROT_EXEC   // Exécution

// Combinaisons courantes :
PROT_READ | PROT_WRITE              // RW-  (data)
PROT_READ | PROT_EXEC               // R-X  (code)
PROT_READ | PROT_WRITE | PROT_EXEC  // RWX  (shellcode - SUSPECT!)
```

**Flags mmap()** :
```c
MAP_PRIVATE     // Modifications privées au processus
MAP_SHARED      // Modifications visibles par autres processus
MAP_ANONYMOUS   // Pas de fichier associé (mémoire pure)
MAP_FIXED       // Force l'adresse spécifiée
```

### mprotect() - Changer les permissions

**Signature** :
```c
int mprotect(void *addr,        // Adresse (doit être alignée sur page)
             size_t len,        // Taille
             int prot);         // Nouvelles permissions
```

**Use case Red Team** :
```ascii
1. Allouer zone RW (pas d'alerte)
   ┌──────────┐
   │   RW-    │  ← Écriture de shellcode
   └──────────┘

2. Écrire le shellcode
   ┌──────────┐
   │ shellcode│
   │   RW-    │
   └──────────┘

3. Changer en R-X avec mprotect()
   ┌──────────┐
   │ shellcode│
   │   R-X    │  ← Exécution
   └──────────┘

4. Exécuter
   ((void(*)())addr)();
```

### /proc/pid/mem - Accès mémoire inter-processus

**Chemin** : `/proc/<PID>/mem`

**Fonctionnement** :
```ascii
Processus A (PID 1234)              Processus B (ton code)
┌────────────────────┐             ┌──────────────────┐
│  int secret = 42;  │             │ int fd = open(   │
│  addr: 0x7fff1234  │             │   "/proc/1234/   │
│                    │             │        mem", RW) │
└────────────────────┘             │                  │
                                   │ lseek(fd,        │
                                   │   0x7fff1234, .)│
                                   │                  │
                                   │ read(fd, buf, 4) │
                                   │ → buf = 42       │
                                   └──────────────────┘
```

**Limitations** :
- Nécessite permissions (même UID ou root)
- Détectable par antivirus/EDR
- Nécessite de connaître l'adresse exacte

### /proc/self/maps - Inspection des mappings

**Format** :
```
address           perms offset  dev   inode       pathname
00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/program
00651000-00652000 r--p 00051000 08:02 173521      /usr/bin/program
00652000-00655000 rw-p 00052000 08:02 173521      /usr/bin/program
```

**Parser les mappings** :
```c
typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[5];  // rwxp
    char pathname[256];
} memory_map_t;
```

## 🔍 Visualisation

### Flux mmap()

```ascii
Programme utilisateur
       │
       ▼
   mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
       │
       ▼
┌──────────────────────────────────────────┐
│         SYSCALL sys_mmap()               │
│                                          │
│  1. Trouve zone libre dans VMA          │
│     (Virtual Memory Area)                │
│                                          │
│  2. Crée structure vm_area_struct        │
│                                          │
│  3. Ajoute au arbre RB du processus     │
│                                          │
│  4. Retourne adresse virtuelle          │
└──────────────────────────────────────────┘
       │
       ▼
Retour : 0x7f1234567000  (adresse virtuelle)
       │
       ▼
┌──────────────────────────────────────────┐
│   /proc/self/maps mis à jour :           │
│   7f1234567000-7f1234568000 rw-p ...     │
└──────────────────────────────────────────┘
```

### Page Fault lors du premier accès

```ascii
ÉTAPE 1 : mmap() retourne             ÉTAPE 2 : Premier accès
┌────────────────────┐                ┌────────────────────┐
│  Adresse virtuelle │                │  *ptr = 0x41;      │
│  allouée mais PAS  │                │         │          │
│  de RAM physique   │                │         ▼          │
│                    │                │   PAGE FAULT!      │
└────────────────────┘                └────────┬───────────┘
                                               │
                                               ▼
                                    ┌────────────────────┐
                                    │  Kernel alloue     │
                                    │  vraie page RAM    │
                                    │  (4096 bytes)      │
                                    │                    │
                                    │  Met à jour        │
                                    │  Page Table        │
                                    └─────────┬──────────┘
                                              │
                                              ▼
                                    Retour au programme
                                    Écriture réussie
```

## 💻 Exemples pratiques

### Exemple 1 : mmap() basique

```c
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    size_t size = 4096;  // 1 page (getpagesize())

    // Allouer 4KB RW
    void *addr = mmap(NULL,                    // Adresse auto
                      size,                    // Taille
                      PROT_READ | PROT_WRITE,  // Permissions
                      MAP_PRIVATE | MAP_ANONYMOUS,  // Flags
                      -1,                      // Pas de fd
                      0);                      // Pas d'offset

    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("Mémoire allouée à : %p\n", addr);

    // Utiliser la mémoire
    strcpy(addr, "Hello from mmap!");
    printf("Contenu : %s\n", (char*)addr);

    // Libérer
    munmap(addr, size);

    return 0;
}
```

### Exemple 2 : Mémoire exécutable (shellcode)

```c
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

int main(void) {
    // Shellcode : ret (0xc3)
    unsigned char code[] = { 0xc3 };

    size_t size = 4096;

    // Allouer RWX (dangereux mais nécessaire pour shellcode)
    void *mem = mmap(NULL, size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copier shellcode
    memcpy(mem, code, sizeof(code));

    // Exécuter
    void (*func)(void) = mem;
    func();  // Appelle le shellcode (retourne immédiatement)

    printf("Shellcode exécuté avec succès!\n");

    munmap(mem, size);
    return 0;
}
```

### Exemple 3 : mprotect() - W^X bypass

```c
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    size_t pagesize = getpagesize();

    // ÉTAPE 1 : Allouer RW (pas suspect)
    void *mem = mmap(NULL, pagesize,
                     PROT_READ | PROT_WRITE,  // PAS d'EXEC
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("[+] Mémoire RW allouée : %p\n", mem);

    // ÉTAPE 2 : Écrire shellcode
    // Shellcode : mov rax, 42; ret
    unsigned char shellcode[] = {
        0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00,  // mov rax, 42
        0xc3                                        // ret
    };

    memcpy(mem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode écrit\n");

    // ÉTAPE 3 : Changer en RX (enlever WRITE)
    if (mprotect(mem, pagesize, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        munmap(mem, pagesize);
        return 1;
    }

    printf("[+] Permissions changées en R-X\n");

    // ÉTAPE 4 : Exécuter
    long (*func)(void) = (long (*)(void))mem;
    long result = func();

    printf("[+] Shellcode retourné : %ld\n", result);

    munmap(mem, pagesize);
    return 0;
}
```

### Exemple 4 : Lire /proc/self/maps

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char line[512];
    printf("Mappings mémoire du processus :\n");
    printf("%-18s %-4s %-20s\n", "Adresses", "Perm", "Pathname");
    printf("─────────────────────────────────────────────────────\n");

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perms[5], pathname[256] = "";

        sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]",
               &start, &end, perms, pathname);

        printf("%016lx-%016lx %-4s %s\n", start, end, perms, pathname);
    }

    fclose(fp);
    return 0;
}
```

### Exemple 5 : Lire mémoire d'un autre processus

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

// Lire 4 bytes à l'adresse addr du processus pid
int read_process_memory(pid_t pid, unsigned long addr, void *buffer, size_t len) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int fd = open(mem_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    // Positionner à l'adresse
    if (lseek(fd, addr, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        return -1;
    }

    // Lire
    ssize_t n = read(fd, buffer, len);
    close(fd);

    return n;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <address_hex>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    unsigned long addr = strtoul(argv[2], NULL, 16);

    int value;
    if (read_process_memory(pid, addr, &value, sizeof(value)) == sizeof(value)) {
        printf("Valeur à 0x%lx dans PID %d : %d (0x%x)\n",
               addr, pid, value, value);
    } else {
        fprintf(stderr, "Échec de lecture\n");
        return 1;
    }

    return 0;
}
```

## 🎯 Application Red Team

### 1. Injection de shellcode avec W^X bypass

```c
// Technique furtive : allouer RW, écrire, puis changer en RX
void* inject_shellcode(unsigned char *shellcode, size_t len) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t alloc_size = (len + page_size - 1) & ~(page_size - 1);

    // 1. Allouer RW
    void *mem = mmap(NULL, alloc_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (mem == MAP_FAILED) return NULL;

    // 2. Écrire shellcode
    memcpy(mem, shellcode, len);

    // 3. Changer en RX
    if (mprotect(mem, alloc_size, PROT_READ | PROT_EXEC) == -1) {
        munmap(mem, alloc_size);
        return NULL;
    }

    return mem;
}

// Utilisation
unsigned char shellcode[] = { /* ... */ };
void *code = inject_shellcode(shellcode, sizeof(shellcode));
if (code) {
    ((void(*)(void))code)();  // Exécute
}
```

### 2. Trouver une région mémoire spécifique

```c
// Trouve l'adresse du heap
unsigned long find_heap_address(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    unsigned long heap_addr = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "[heap]")) {
            sscanf(line, "%lx", &heap_addr);
            break;
        }
    }

    fclose(fp);
    return heap_addr;
}

// Trouve la libc
unsigned long find_libc_base(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    unsigned long libc_base = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libc") && strstr(line, "r-xp")) {
            sscanf(line, "%lx", &libc_base);
            break;
        }
    }

    fclose(fp);
    return libc_base;
}
```

### 3. Dumper la mémoire d'un processus

```c
// Dump toute la mémoire lisible d'un processus
void dump_process_memory(pid_t pid, const char *output_file) {
    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    FILE *maps = fopen(maps_path, "r");
    int mem_fd = open(mem_path, O_RDONLY);
    FILE *out = fopen(output_file, "wb");

    if (!maps || mem_fd == -1 || !out) {
        perror("open");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];

        sscanf(line, "%lx-%lx %4s", &start, &end, perms);

        // Lire seulement les zones lisibles
        if (perms[0] != 'r') continue;

        size_t len = end - start;
        void *buf = malloc(len);

        if (lseek(mem_fd, start, SEEK_SET) != -1) {
            ssize_t n = read(mem_fd, buf, len);
            if (n > 0) {
                fprintf(out, "# Region %lx-%lx %s\n", start, end, perms);
                fwrite(buf, 1, n, out);
            }
        }

        free(buf);
    }

    fclose(maps);
    close(mem_fd);
    fclose(out);
}
```

### 4. Détection de pages RWX (suspect)

```c
// Scan pour détecter des zones RWX (potentiel shellcode)
void detect_rwx_pages(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[512];
    int found = 0;

    printf("[!] Scan de pages RWX suspectes :\n");

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "rwxp")) {
            printf("[SUSPECT] %s", line);
            found++;
        }
    }

    if (!found) {
        printf("[OK] Aucune page RWX détectée\n");
    }

    fclose(fp);
}
```

## 📝 Points clés

### À retenir absolument

1. **mmap() vs malloc()**
   - mmap() = mapping direct kernel (syscall)
   - malloc() = gestion libc au-dessus de mmap/sbrk
   - Pour shellcode : utiliser mmap()

2. **Permissions mémoire**
   - R = Read, W = Write, X = Execute
   - RWX = TRÈS suspect (détectable)
   - Technique furtive : RW → écriture → RX

3. **W^X (Write XOR Execute)**
   - Politique sécurité : une page ne peut pas être WX
   - Bypass : mprotect() pour changer permissions
   - DEP/NX = protection matérielle

4. **Page size**
   - Taille standard : 4096 bytes (4KB)
   - mmap/mprotect travaillent sur pages entières
   - Alignement requis : adresse % pagesize == 0

5. **/proc/pid/mem**
   - Accès raw à la mémoire d'un processus
   - Nécessite permissions (ptrace_scope)
   - Alternative : ptrace() PEEKDATA/POKEDATA

### Commandes utiles

```bash
# Taille page système
getconf PAGESIZE

# Voir mappings d'un processus
cat /proc/<PID>/maps
pmap <PID>

# Voir limites mémoire
cat /proc/<PID>/limits

# Dump mémoire
gcore <PID>

# Analyser dump
strings core.<PID>
```

### Considérations OPSEC

1. **Pages RWX**
   - Très détectable par EDR/AV
   - Utiliser W^X bypass (RW puis RX)

2. **Accès /proc/pid/mem**
   - Nécessite permissions (tracé dans audit logs)
   - Alternative : injection via ptrace (plus furtif)

3. **Memory forensics**
   - mmap anonyme laisse traces dans /proc/maps
   - Considérer fileless execution

## 📚 Ressources complémentaires

- [mmap(2) man page](https://man7.org/linux/man-pages/man2/mmap.2.html)
- [mprotect(2) man page](https://man7.org/linux/man-pages/man2/mprotect.2.html)
- [proc(5) man page](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Linux Virtual Memory](https://www.kernel.org/doc/gorman/html/understand/understand006.html)

---

**Navigation**
- [Module précédent : L07 File Permissions](../L07_file_permissions/)
- [Module suivant : L09 Process Injection](../../PHASE_L02_LINUX_INTERNALS/L09_process_injection_linux/)

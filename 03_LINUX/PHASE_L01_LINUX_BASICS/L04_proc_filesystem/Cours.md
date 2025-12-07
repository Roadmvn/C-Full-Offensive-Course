# Module L04 : Proc Filesystem - Espionner le Système via /proc

## Ce que tu vas apprendre

Dans ce module, tu vas maîtriser le système de fichiers /proc sous Linux :
- Comprendre l'architecture du filesystem /proc
- Lire les informations des processus en cours
- Extraire des données sensibles (mémoire, environnement, fichiers ouverts)
- Manipuler les processus via /proc
- Techniques Red Team d'énumération et d'exfiltration

## Théorie

### C'est quoi /proc ?

Le répertoire **/proc** est un **pseudo-filesystem** : ce ne sont pas de vrais fichiers sur le disque, mais une interface virtuelle vers le kernel Linux.

**Analogie** :
```ascii
/proc = tableau de bord du système

Imagine une voiture :
┌─────────────────────────────────────┐
│  Dashboard (Tableau de bord)        │
│  ┌────┐ ┌────┐ ┌────┐              │
│  │ RPM│ │Temp│ │Fuel│  ← Indicateurs│
│  └────┘ └────┘ └────┘              │
└─────────────────────────────────────┘
         ↓
┌─────────────────────────────────────┐
│   Moteur (Kernel Linux)             │
│  ┌────────┐ ┌─────────┐            │
│  │Processus│ │ Mémoire │            │
│  │  CPU   │ │ Network │            │
│  └────────┘ └─────────┘            │
└─────────────────────────────────────┘

/proc te donne les "indicateurs" du système
sans démonter le moteur
```

### Architecture de /proc

```ascii
/proc/
├── 1/               ← Processus PID 1 (init/systemd)
│   ├── cmdline      ← Ligne de commande du processus
│   ├── environ      ← Variables d'environnement
│   ├── exe          ← Lien vers l'exécutable
│   ├── fd/          ← Fichiers ouverts (file descriptors)
│   ├── maps         ← Memory mapping (régions mémoire)
│   ├── mem          ← Mémoire du processus
│   ├── status       ← État du processus
│   ├── cwd          ← Current working directory
│   └── root         ← Root directory du processus
│
├── 1234/            ← Autre processus
├── 5678/
│
├── cpuinfo          ← Informations CPU
├── meminfo          ← Informations mémoire
├── version          ← Version du kernel
├── net/             ← Informations réseau
│   ├── tcp          ← Connexions TCP
│   ├── udp          ← Connexions UDP
│   └── route        ← Table de routage
│
├── sys/             ← Paramètres kernel (sysctl)
│   └── kernel/
│       └── randomize_va_space  ← ASLR activé ?
│
└── self/            ← Lien symbolique vers le processus courant
```

### Pourquoi /proc est important en Red Team ?

**Énumération furtive** :
- Lister tous les processus sans exécuter `ps`
- Voir les connexions réseau sans `netstat`
- Lire les fichiers ouverts sans `lsof`
- Pas de commande suspecte dans l'historique

**Exfiltration de données** :
- Variables d'environnement (tokens, secrets)
- Mémoire des processus (credentials en RAM)
- Fichiers ouverts (logs, databases)

**Manipulation** :
- Injecter du code via `/proc/pid/mem`
- Modifier les limites d'un processus
- Changer le OOM score

## Visualisation

### Flux de lecture /proc

```ascii
Programme C                /proc                  Kernel
┌──────────┐              ┌──────┐              ┌────────┐
│          │              │      │              │        │
│ open()   ├─────────────→│/proc/│─────────────→│ Kernel │
│          │  /proc/123/  │ 123/ │   Requête    │ génère │
│          │  status      │status│   données    │ données│
│          │              │      │              │ à la   │
│          │              │      │              │ volée  │
│          │              │      │              │        │
│ read()   │←─────────────┤Data  │←─────────────┤ Retour │
│          │   "Name:     │      │   struct     │ struct │
│          │    bash\n    │      │   task_struct│ process│
│          │    State: S" │      │              │        │
└──────────┘              └──────┘              └────────┘

Important : Les données sont générées dynamiquement,
            elles ne sont PAS stockées sur le disque !
```

### Structure d'un processus dans /proc

```ascii
/proc/1234/
│
├── cmdline          → "bash\0-c\0echo test\0"
│                      Commande avec arguments (séparés par \0)
│
├── environ          → "PATH=/usr/bin\0HOME=/root\0TOKEN=secret123\0"
│                      Variables d'environnement (séparés par \0)
│
├── exe              → /bin/bash (lien symbolique)
│
├── fd/              → File Descriptors
│   ├── 0 → /dev/pts/0   (stdin)
│   ├── 1 → /dev/pts/0   (stdout)
│   ├── 2 → /dev/pts/0   (stderr)
│   └── 3 → /var/log/app.log
│
├── maps             → Memory Layout
│   │  Address Range      Perms   Object
│   │  7f1234000-7f1235000 r-xp   /lib/libc.so
│   │  7fff00000-7fff01000 rw-p   [stack]
│   │  7fff80000-7fff81000 r--p   [vdso]
│
├── mem              → Accès direct à la mémoire du processus
│                      (dangereux, nécessite ptrace ou root)
│
└── status           → État du processus (texte lisible)
    │  Name:    bash
    │  State:   S (sleeping)
    │  Pid:     1234
    │  PPid:    1000
    │  Uid:     1000
    │  Gid:     1000
    │  VmSize:  10240 kB
```

## Mise en pratique

### Exemple 1 : Lister tous les processus

**Sans utiliser `ps` :**

```c
// proc_list.c
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>

// Vérifier si un nom de répertoire est un PID (chiffres uniquement)
int is_pid(const char *name) {
    for (int i = 0; name[i]; i++) {
        if (!isdigit(name[i]))
            return 0;
    }
    return 1;
}

// Lire le nom du processus depuis /proc/PID/status
void get_process_name(int pid, char *name, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(name, size, "???");
        return;
    }

    char line[256];
    if (fgets(line, sizeof(line), f)) {
        // Format : "Name:\tprocess_name\n"
        sscanf(line, "Name:\t%s", name);
    }

    fclose(f);
}

int main(void) {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return 1;
    }

    printf("PID    PROCESS\n");
    printf("─────────────────\n");

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        // Ne traiter que les répertoires avec des noms numériques (PIDs)
        if (entry->d_type == DT_DIR && is_pid(entry->d_name)) {
            int pid = atoi(entry->d_name);
            char name[256];
            get_process_name(pid, name, sizeof(name));
            printf("%-6d %s\n", pid, name);
        }
    }

    closedir(proc);
    return 0;
}
```

**Compilation et test** :
```bash
gcc -o proc_list proc_list.c
./proc_list
```

**Sortie** :
```
PID    PROCESS
─────────────────
1      systemd
2      kthreadd
123    sshd
456    bash
789    nginx
```

### Exemple 2 : Lire la ligne de commande d'un processus

```c
// proc_cmdline.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_cmdline(int pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        printf("Erreur : impossible de lire le processus %d\n", pid);
        return;
    }

    // cmdline contient des arguments séparés par \0
    char buffer[1024];
    size_t n = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);

    if (n == 0) {
        printf("Processus %d : [kernel thread]\n", pid);
        return;
    }

    printf("Processus %d : ", pid);

    // Remplacer les \0 par des espaces pour affichage
    for (size_t i = 0; i < n; i++) {
        if (buffer[i] == '\0')
            buffer[i] = ' ';
    }
    buffer[n] = '\0';

    printf("%s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    print_cmdline(pid);

    return 0;
}
```

**Utilisation** :
```bash
gcc -o proc_cmdline proc_cmdline.c
./proc_cmdline $$   # PID du shell courant
# Processus 12345 : bash
./proc_cmdline 1
# Processus 1 : /sbin/init
```

### Exemple 3 : Lire les variables d'environnement (SENSIBLE)

```c
// proc_environ.c
#include <stdio.h>
#include <stdlib.h>

void dump_environ(int pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return;
    }

    printf("=== Variables d'environnement PID %d ===\n", pid);

    char buffer[4096];
    size_t n = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);

    // Format : VAR1=value1\0VAR2=value2\0
    for (size_t i = 0; i < n; ) {
        char *var = &buffer[i];
        printf("%s\n", var);

        // Avancer au prochain \0
        while (i < n && buffer[i] != '\0')
            i++;
        i++;  // Sauter le \0
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    dump_environ(pid);

    return 0;
}
```

**Exemple d'utilisation Red Team** :
```bash
# Énumérer tous les processus avec des tokens AWS
for pid in /proc/[0-9]*; do
    grep -a "AWS_" "$pid/environ" 2>/dev/null && echo "PID: $pid"
done
```

### Exemple 4 : Lister les fichiers ouverts par un processus

```c
// proc_fd.c
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

void list_fds(int pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);

    DIR *fd_dir = opendir(path);
    if (!fd_dir) {
        perror("opendir");
        return;
    }

    printf("=== Fichiers ouverts par PID %d ===\n", pid);
    printf("FD   TARGET\n");
    printf("──────────────────────────────────\n");

    struct dirent *entry;
    while ((entry = readdir(fd_dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        // Construire le chemin complet : /proc/PID/fd/N
        char fd_path[512];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", path, entry->d_name);

        // Lire le lien symbolique
        char target[256];
        ssize_t len = readlink(fd_path, target, sizeof(target) - 1);
        if (len != -1) {
            target[len] = '\0';
            printf("%-4s %s\n", entry->d_name, target);
        }
    }

    closedir(fd_dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    list_fds(pid);

    return 0;
}
```

**Sortie exemple** :
```
=== Fichiers ouverts par PID 1234 ===
FD   TARGET
──────────────────────────────────
0    /dev/pts/0
1    /dev/pts/0
2    /dev/pts/0
3    socket:[12345]
4    /var/log/app.log
5    /etc/passwd
```

### Exemple 5 : Lire la memory map (régions mémoire)

```c
// proc_maps.c
#include <stdio.h>
#include <stdlib.h>

void dump_maps(int pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return;
    }

    printf("=== Memory Map PID %d ===\n", pid);
    printf("ADDRESS RANGE          PERMS  OFFSET   DEVICE   INODE    PATHNAME\n");
    printf("────────────────────────────────────────────────────────────────────\n");

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
    }

    fclose(f);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    dump_maps(pid);

    return 0;
}
```

**Sortie exemple** :
```
=== Memory Map PID 1234 ===
ADDRESS RANGE          PERMS  OFFSET   DEVICE   INODE    PATHNAME
────────────────────────────────────────────────────────────────────
55a123400000-55a123401000 r--p 00000000 08:01 123456   /bin/bash
55a123401000-55a12340f000 r-xp 00001000 08:01 123456   /bin/bash
55a12340f000-55a123410000 r--p 0000f000 08:01 123456   /bin/bash
7f1234000000-7f1234100000 r-xp 00000000 08:01 789012   /lib/libc.so.6
7ffd12340000-7ffd12360000 rw-p 00000000 00:00 0        [stack]
7ffd12380000-7ffd12381000 r-xp 00000000 00:00 0        [vdso]
```

### Exemple 6 : Informations système

```c
// proc_sysinfo.c
#include <stdio.h>
#include <string.h>

// Lire et afficher un fichier /proc
void cat_proc(const char *filename, const char *title) {
    printf("=== %s ===\n", title);

    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("Non disponible\n\n");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        printf("%s", line);
    }

    fclose(f);
    printf("\n");
}

int main(void) {
    cat_proc("/proc/version", "Version du Kernel");
    cat_proc("/proc/cpuinfo", "Info CPU");
    cat_proc("/proc/meminfo", "Info Mémoire");

    return 0;
}
```

## Application offensive

### Contexte Red Team

#### 1. Énumération furtive

**Objectif** : Énumérer le système sans exécuter de commandes suspectes.

**Technique** : Lire /proc au lieu d'utiliser `ps`, `netstat`, `lsof`.

```c
// stealth_enum.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

// Chercher des processus intéressants (SSH, sudo, etc.)
void find_interesting_processes(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type != DT_DIR || entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;

        int pid = atoi(entry->d_name);
        char path[256], cmdline[1024];

        // Lire cmdline
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        cmdline[n] = '\0';

        // Chercher des mots-clés
        if (strstr(cmdline, "ssh") || strstr(cmdline, "sudo") ||
            strstr(cmdline, "mysql") || strstr(cmdline, "postgres")) {
            printf("[!] PID %d : %s\n", pid, cmdline);
        }
    }

    closedir(proc);
}

int main(void) {
    find_interesting_processes();
    return 0;
}
```

#### 2. Exfiltration de credentials

**Scénario** : Un processus a chargé des credentials en variables d'environnement.

```bash
# Rechercher AWS credentials
for pid in /proc/[0-9]*; do
    if grep -qa "AWS_SECRET" "$pid/environ" 2>/dev/null; then
        echo "Credentials trouvés dans $pid"
        cat "$pid/environ" | tr '\0' '\n' | grep AWS
    fi
done
```

#### 3. Lecture de connexions réseau

```c
// proc_net_tcp.c
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

void parse_tcp_connections(void) {
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) {
        perror("fopen");
        return;
    }

    printf("=== Connexions TCP ===\n");
    printf("LOCAL ADDRESS        REMOTE ADDRESS       STATE\n");
    printf("──────────────────────────────────────────────────\n");

    char line[512];
    fgets(line, sizeof(line), f);  // Skip header

    while (fgets(line, sizeof(line), f)) {
        unsigned int local_addr, local_port;
        unsigned int remote_addr, remote_port;
        int state;

        sscanf(line, "%*d: %X:%X %X:%X %X",
               &local_addr, &local_port,
               &remote_addr, &remote_port,
               &state);

        // Convertir en format lisible
        struct in_addr l, r;
        l.s_addr = local_addr;
        r.s_addr = remote_addr;

        printf("%-20s %-20s %d\n",
               inet_ntoa(l), inet_ntoa(r), state);
    }

    fclose(f);
}

int main(void) {
    parse_tcp_connections();
    return 0;
}
```

#### 4. Recherche de processus avec droits élevés

```c
// find_root_processes.c
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

void find_root_processes(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return;

    printf("=== Processus ROOT ===\n");

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type != DT_DIR || entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;

        int pid = atoi(entry->d_name);
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/status", pid);

        FILE *f = fopen(path, "r");
        if (!f) continue;

        char line[256];
        int uid = -1;
        char name[256] = "???";

        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:", 5) == 0) {
                sscanf(line, "Name:\t%s", name);
            } else if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line, "Uid:\t%d", &uid);
                break;
            }
        }

        fclose(f);

        if (uid == 0) {
            printf("PID %-6d : %s\n", pid, name);
        }
    }

    closedir(proc);
}

int main(void) {
    find_root_processes();
    return 0;
}
```

### Considérations OPSEC

**1. Permissions** :
- `/proc/PID/environ`, `/proc/PID/mem` nécessitent les droits du propriétaire ou root
- `/proc/PID/cmdline`, `/proc/PID/maps` sont lisibles par tous (faille d'information)

**2. Détection** :
- L'accès à `/proc` est rarement loggé
- Éviter d'ouvrir `/proc/PID/mem` (peut être détecté par ptrace)
- Préférer les lectures séquentielles aux accès répétés

**3. Furtivité** :
```c
// Bon : Un seul parcours
DIR *proc = opendir("/proc");
// Lire tout ce qui est nécessaire
closedir(proc);

// Mauvais : Multiples appels
system("ls /proc > /tmp/out1");
system("cat /proc/1/cmdline > /tmp/out2");
// Traces dans les logs, fichiers temporaires
```

## Résumé

- `/proc` est un filesystem virtuel donnant accès au kernel
- Chaque processus a un répertoire `/proc/PID/`
- Fichiers clés :
  - `cmdline` : Ligne de commande
  - `environ` : Variables d'environnement (SENSIBLE)
  - `fd/` : Fichiers ouverts
  - `maps` : Memory layout
  - `status` : État du processus
- En Red Team : énumération furtive sans commandes externes
- Attention aux permissions et à la détection

## Ressources complémentaires

**Documentation** :
- `man 5 proc` - Documentation complète de /proc
- [Kernel.org - procfs](https://www.kernel.org/doc/Documentation/filesystems/proc.txt)

**Fichiers /proc utiles** :
```
/proc/cpuinfo       - Info CPU
/proc/meminfo       - Info mémoire
/proc/version       - Version kernel
/proc/cmdline       - Paramètres boot kernel
/proc/net/tcp       - Connexions TCP
/proc/net/udp       - Connexions UDP
/proc/sys/kernel/*  - Paramètres kernel (sysctl)
```

**Outils** :
- `procfs` (Python) - Parser /proc
- `pspy` - Monitor processus via /proc (outil Red Team)

---

**Navigation**
- [Module précédent](../L03_ptrace/)
- [Module suivant](../L05_shared_libraries/)

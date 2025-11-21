# Cours : Entrées/Sorties Fichiers (File I/O)

## 1. Introduction

Les opérations d'**entrée/sortie sur fichiers** permettent de lire et écrire des données persistantes. En C, il existe deux approches principales :
- **Haut niveau** : `fopen()`, `fread()`, `fwrite()` (buffered I/O)
- **Bas niveau** : `open()`, `read()`, `write()` (syscalls directs)

## 2. Fichiers en C - Haut Niveau

### Ouvrir un Fichier

```c
FILE *fp = fopen("fichier.txt", "r");
if (fp == NULL) {
    perror("Erreur ouverture");
    exit(1);
}
```

**Modes d'ouverture** :
- `"r"` : Lecture seule
- `"w"` : Écriture (écrase si existe)
- `"a"` : Ajout (append)
- `"r+"` : Lecture/Écriture
- `"w+"` : Lecture/Écriture (crée/écrase)
- `"rb"`, `"wb"` : Mode binaire

### Lire depuis un Fichier

```c
char buffer[256];

// Lire ligne par ligne
while (fgets(buffer, sizeof(buffer), fp) != NULL) {
    printf("%s", buffer);
}

// Lire caractère par caractère
int c;
while ((c = fgetc(fp)) != EOF) {
    putchar(c);
}

// Lire un bloc
size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
```

### Écrire dans un Fichier

```c
fprintf(fp, "Bonjour %s\n", nom);
fputs("Ligne de texte\n", fp);
fputc('A', fp);

// Écriture binaire
fwrite(data, sizeof(data[0]), count, fp);
```

### Fermer un Fichier

```c
fclose(fp);  // TOUJOURS fermer !
```

## 3. Fichiers Bas Niveau (POSIX)

### Ouvrir avec open()

```c
#include <fcntl.h>
#include <unistd.h>

int fd = open("fichier.txt", O_RDONLY);
if (fd == -1) {
    perror("open");
    exit(1);
}
```

**Flags** :
- `O_RDONLY` : Lecture
- `O_WRONLY` : Écriture
- `O_RDWR` : Lecture/Écriture
- `O_CREAT` : Créer si n'existe pas
- `O_TRUNC` : Tronquer à 0
- `O_APPEND` : Ajouter à la fin

### Permissions (avec O_CREAT)

```c
int fd = open("new.txt", O_WRONLY | O_CREAT, 0644);
// 0644 = rw-r--r--
```

### Lire avec read()

```c
char buffer[1024];
ssize_t bytes_read = read(fd, buffer, sizeof(buffer));

if (bytes_read == -1) {
    perror("read");
} else if (bytes_read == 0) {
    printf("EOF\n");
} else {
    printf("Lu %zd bytes\n", bytes_read);
}
```

### Écrire avec write()

```c
const char *msg = "Hello World\n";
ssize_t bytes_written = write(fd, msg, strlen(msg));

if (bytes_written == -1) {
    perror("write");
}
```

### Fermer

```c
close(fd);
```

## 4. Positionnement dans un Fichier

### Haut niveau

```c
fseek(fp, 0, SEEK_SET);  // Début
fseek(fp, 0, SEEK_END);  // Fin
fseek(fp, 10, SEEK_CUR); // +10 depuis position actuelle

long pos = ftell(fp);    // Position actuelle
rewind(fp);              // Retour au début
```

### Bas niveau

```c
off_t pos = lseek(fd, 0, SEEK_END);  // Position à la fin
lseek(fd, 0, SEEK_SET);              // Retour au début
```

## 5. Comparaison Haut vs Bas Niveau

| Aspect      | Haut Niveau (FILE*) | Bas Niveau (fd) |
|-------------|---------------------|-----------------|
| **Performance** | Buffered (rapide) | Direct (contrôle) |
| **Portabilité** | Standard C (portable) | POSIX (Unix/Linux) |
| **Flexibilité** | Simple | Avancé (mmap, etc) |
| **Usage** | Fichiers texte | Fichiers binaires, devices |

## 6. Bufferisation

```c
// Désactiver le buffer
setvbuf(fp, NULL, _IONBF, 0);

// Buffer ligne par ligne
setvbuf(fp, NULL, _IOLBF, 0);

// Buffer complet (défaut)
setvbuf(fp, buffer, _IOFBF, sizeof(buffer));

// Forcer l'écriture
fflush(fp);
```

## 7. Gestion d'Erreurs

```c
if (ferror(fp)) {
    fprintf(stderr, "Erreur I/O\n");
    clearerr(fp);
}

if (feof(fp)) {
    printf("Fin de fichier atteinte\n");
}
```

## 8. Fichiers Binaires

```c
typedef struct {
    char nom[50];
    int age;
} Personne;

// Écrire
Personne p = {"Alice", 25};
fwrite(&p, sizeof(Personne), 1, fp);

// Lire
Personne p2;
fread(&p2, sizeof(Personne), 1, fp);
```

## 9. Sécurité & Risques

### ⚠️ Ne Pas Fermer les Fichiers

```c
FILE *fp = fopen("data.txt", "r");
// ... utilisation ...
// OUBLI de fclose(fp) → Memory leak
```

### ⚠️ Buffer Overflow

```c
char buffer[10];
fgets(buffer, 100, fp);  // ERREUR ! Dépassement
```

### ⚠️ TOCTOU (Time-Of-Check-Time-Of-Use)

```c
// VULNÉRABLE
if (access("file.txt", F_OK) == 0) {
    // Attaquant peut créer un lien symbolique ici !
    FILE *fp = fopen("file.txt", "w");
}

// MIEUX : Utiliser O_EXCL
int fd = open("file.txt", O_WRONLY | O_CREAT | O_EXCL, 0644);
```

### ⚠️ Path Traversal

```c
// DANGEREUX
char filename[256];
scanf("%s", filename);
FILE *fp = fopen(filename, "r");  // Attaquant peut lire /etc/passwd

// MIEUX : Valider le chemin
if (strstr(filename, "..") != NULL) {
    fprintf(stderr, "Chemin invalide\n");
    exit(1);
}
```

## 10. Opérations Avancées

### Copier un Fichier

```c
void copy_file(const char *src, const char *dst) {
    int fd_in = open(src, O_RDONLY);
    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    
    char buffer[4096];
    ssize_t bytes;
    
    while ((bytes = read(fd_in, buffer, sizeof(buffer))) > 0) {
        write(fd_out, buffer, bytes);
    }
    
    close(fd_in);
    close(fd_out);
}
```

### Lire un Fichier Entier

```c
char* read_entire_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    fread(content, 1, size, fp);
    content[size] = '\0';
    
    fclose(fp);
    return content;
}
```

## 11. Fichiers Temporaires

```c
// Fichier temp sécurisé
FILE *temp = tmpfile();  // Supprimé automatiquement
fprintf(temp, "Data temporaire\n");
rewind(temp);
// ... utilisation ...
fclose(temp);

// Nom de fichier temp
char template[] = "/tmp/myfileXXXXXX";
int fd = mkstemp(template);  // Crée nom unique
```

## 12. Bonnes Pratiques

1. **Toujours vérifier** les valeurs de retour
2. **Fermer les fichiers** (ou utiliser RAII en C++)
3. **Valider les chemins** utilisateur
4. **Gérer les erreurs** avec `perror()` ou `strerror()`
5. **Utiliser O_EXCL** pour éviter les races
6. **Préférer bas niveau** pour les opérations critiques

## Ressources

- [File I/O (cppreference)](https://en.cppreference.com/w/c/io)
- [POSIX open()](https://man7.org/linux/man-pages/man2/open.2.html)


# Cours : Fichiers I/O (Entrées/Sorties)

## Objectif du Module

Maîtriser les opérations d'entrée/sortie sur fichiers : ouvrir/fermer avec fopen/fclose, lire/écrire avec fread/fwrite/fgets/fputs, comprendre les modes d'ouverture (r, w, a, b), naviguer dans un fichier avec fseek/ftell/rewind, différencier fichiers texte vs binaires, et parser des fichiers binaires. Application Red Team : extraction de données, parsing de logs, manipulation de payloads.

---

## 1. Ouverture et Fermeture de Fichiers

### 1.1 fopen() - Ouvrir un Fichier

```c
FILE *fopen(const char *filename, const char *mode);
```

Retourne un pointeur `FILE*` ou `NULL` en cas d'erreur.

```c
FILE *fp = fopen("fichier.txt", "r");
if (fp == NULL) {
    perror("Erreur ouverture");
    exit(1);
}

// ... utilisation ...

fclose(fp);  // TOUJOURS fermer !
```

### 1.2 Modes d'Ouverture

```
┌──────┬─────────────────────────────────────────────┐
│ Mode │ Description                                 │
├──────┼─────────────────────────────────────────────┤
│ "r"  │ Lecture seule (fichier doit exister)       │
│ "w"  │ Écriture (crée ou ÉCRASE)                   │
│ "a"  │ Ajout (append à la fin)                     │
│ "r+" │ Lecture + écriture (doit exister)           │
│ "w+" │ Lecture + écriture (crée ou écrase)         │
│ "a+" │ Lecture + ajout                             │
├──────┼─────────────────────────────────────────────┤
│ "rb" │ Lecture BINAIRE                             │
│ "wb" │ Écriture BINAIRE                            │
│ "ab" │ Ajout BINAIRE                               │
│ ...  │ (ajouter 'b' pour mode binaire)             │
└──────┴─────────────────────────────────────────────┘
```

**Schéma modes :**
```
"r" (read) :
fichier.txt existe → OK, lecture
fichier.txt n'existe pas → NULL (échec)

"w" (write) :
fichier.txt existe → ÉCRASE tout, puis écriture
fichier.txt n'existe pas → CRÉE, puis écriture

"a" (append) :
fichier.txt existe → Ajoute à la FIN
fichier.txt n'existe pas → CRÉE, puis écriture
```

---

## 2. Lecture de Fichiers

### 2.1 fgets() - Lire Ligne par Ligne (Texte)

```c
char *fgets(char *str, int n, FILE *stream);
```

```c
FILE *fp = fopen("fichier.txt", "r");
char buffer[256];

while (fgets(buffer, sizeof(buffer), fp) != NULL) {
    printf("%s", buffer);  // Affiche chaque ligne
}

fclose(fp);
```

**Schéma :**
```
fichier.txt :
┌────────────────┐
│ Ligne 1\n      │ ← fgets() lit jusqu'au \n
│ Ligne 2\n      │ ← ou jusqu'à n-1 caractères
│ Ligne 3\n      │
└────────────────┘
```

### 2.2 fread() - Lire Bloc Binaire

```c
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
```

```c
FILE *fp = fopen("data.bin", "rb");
int buffer[10];

size_t count = fread(buffer, sizeof(int), 10, fp);
printf("Lu %zu entiers\n", count);

fclose(fp);
```

**Schéma :**
```
fread(buffer, sizeof(int), 10, fp) :
        │        │          │
        │        │          └─ Nombre d'éléments
        │        └─ Taille de chaque élément
        └─ Destination

Lit : 10 × 4 bytes = 40 bytes
```

### 2.3 fgetc() - Lire Caractère par Caractère

```c
int c;
while ((c = fgetc(fp)) != EOF) {
    putchar(c);
}
```

---

## 3. Écriture de Fichiers

### 3.1 fprintf() - Écrire Formaté (Texte)

```c
FILE *fp = fopen("output.txt", "w");
fprintf(fp, "Nom: %s, Age: %d\n", "Alice", 25);
fclose(fp);
```

### 3.2 fputs() - Écrire Chaîne

```c
FILE *fp = fopen("output.txt", "w");
fputs("Ligne de texte\n", fp);
fclose(fp);
```

### 3.3 fwrite() - Écrire Bloc Binaire

```c
FILE *fp = fopen("data.bin", "wb");

int data[5] = {10, 20, 30, 40, 50};
fwrite(data, sizeof(int), 5, fp);

fclose(fp);
```

**Schéma :**
```
fwrite(data, sizeof(int), 5, fp) :

Écrit : 5 × 4 bytes = 20 bytes

data.bin :
┌────┬────┬────┬────┬────┐
│ 10 │ 20 │ 30 │ 40 │ 50 │  (binaire, pas texte)
└────┴────┴────┴────┴────┘
```

---

## 4. Navigation dans un Fichier

### 4.1 fseek() - Déplacer le Curseur

```c
int fseek(FILE *stream, long offset, int whence);
```

**Constantes `whence` :**
- `SEEK_SET` : Depuis le début
- `SEEK_CUR` : Depuis position actuelle
- `SEEK_END` : Depuis la fin

```c
FILE *fp = fopen("data.bin", "rb");

fseek(fp, 0, SEEK_END);   // Aller à la fin
long size = ftell(fp);     // Taille du fichier
fseek(fp, 0, SEEK_SET);   // Retour au début

printf("Taille : %ld bytes\n", size);
fclose(fp);
```

**Schéma :**
```
fichier.bin (100 bytes) :
┌────────────────────────────────────┐
│ [0] ... [50] ... [99]              │
└────────────────────────────────────┘
  ↑                    ↑
SEEK_SET (début)     SEEK_END (fin)

fseek(fp, 10, SEEK_SET) :
┌────────────────────────────────────┐
│ [0] ... [10] ... [99]              │
└─────────┬──────────────────────────┘
          ↑
     Curseur à l'offset 10

fseek(fp, -5, SEEK_END) :
┌────────────────────────────────────┐
│ [0] ... [94] ... [99]              │
└────────────────────┬───────────────┘
                     ↑
            Curseur à 99-5=94
```

### 4.2 ftell() - Position Actuelle

```c
long pos = ftell(fp);
printf("Position : %ld\n", pos);
```

### 4.3 rewind() - Retour au Début

```c
rewind(fp);  // Équivaut à fseek(fp, 0, SEEK_SET)
```

---

## 5. Fichiers Texte vs Binaires

### 5.1 Fichier Texte

```c
// Écriture texte
FILE *fp = fopen("text.txt", "w");
fprintf(fp, "%d", 42);  // Écrit "42" (2 caractères ASCII)
fclose(fp);

// Contenu du fichier :
// '4' '2' (0x34 0x32 en ASCII)
```

### 5.2 Fichier Binaire

```c
// Écriture binaire
FILE *fp = fopen("binary.bin", "wb");
int num = 42;
fwrite(&num, sizeof(int), 1, fp);  // Écrit 42 (4 bytes binaires)
fclose(fp);

// Contenu du fichier :
// 0x2A 0x00 0x00 0x00 (little-endian)
```

**Comparaison :**
```
TEXTE (fprintf) :
Le nombre 12345 → "12345" (5 bytes ASCII)
┌───┬───┬───┬───┬───┐
│'1'│'2'│'3'│'4'│'5'│
│0x31│0x32│0x33│0x34│0x35│
└───┴───┴───┴───┴───┘

BINAIRE (fwrite) :
Le nombre 12345 → 0x3039 (4 bytes int)
┌────┬────┬────┬────┐
│0x39│0x30│0x00│0x00│  (little-endian)
└────┴────┴────┴────┘

Fichier texte = lisible par humain
Fichier binaire = compact mais illisible
```

---

## 6. Lire un Fichier Entier

```c
char* read_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) return NULL;

    // Taille du fichier
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allouer buffer
    char *content = malloc(size + 1);
    fread(content, 1, size, fp);
    content[size] = '\0';  // Null-terminator

    fclose(fp);
    return content;
}

// Utilisation
char *data = read_file("fichier.txt");
printf("%s\n", data);
free(data);
```

---

## 7. Gestion d'Erreurs

```c
FILE *fp = fopen("fichier.txt", "r");
if (fp == NULL) {
    perror("fopen");  // Affiche l'erreur système
    exit(1);
}

// Vérifier erreurs de lecture
if (ferror(fp)) {
    fprintf(stderr, "Erreur I/O\n");
    clearerr(fp);  // Effacer le flag d'erreur
}

// Vérifier fin de fichier
if (feof(fp)) {
    printf("Fin de fichier atteinte\n");
}

fclose(fp);
```

---

## 8. Application Red Team

### 8.1 Extraction de Payload depuis Fichier

```c
// Lire un shellcode depuis un fichier binaire
FILE *fp = fopen("shellcode.bin", "rb");

fseek(fp, 0, SEEK_END);
long size = ftell(fp);
fseek(fp, 0, SEEK_SET);

unsigned char *shellcode = malloc(size);
fread(shellcode, 1, size, fp);
fclose(fp);

// Exécuter
void (*run)() = (void(*)())shellcode;
run();
```

### 8.2 Parsing de Logs

```c
FILE *fp = fopen("/var/log/auth.log", "r");
char line[1024];

while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "Failed password")) {
        printf("[ALERT] %s", line);
    }
}

fclose(fp);
```

### 8.3 Injection dans un Exécutable (Patching)

```c
// Modifier un byte à l'offset 0x1234
FILE *fp = fopen("program.exe", "r+b");

fseek(fp, 0x1234, SEEK_SET);  // Aller à l'offset
unsigned char patch = 0x90;    // NOP instruction
fwrite(&patch, 1, 1, fp);      // Écrire le patch

fclose(fp);
```

### 8.4 Exfiltration de Données

```c
// Exfiltrer des données sensibles
FILE *fp = fopen("/tmp/.hidden.txt", "w");

fprintf(fp, "Username: %s\n", getenv("USER"));
fprintf(fp, "Path: %s\n", getenv("PATH"));

// Données système
system("uname -a >> /tmp/.hidden.txt");

fclose(fp);
```

---

## 9. Sécurité et Risques

### 9.1 Path Traversal

```c
// VULNÉRABLE
char filename[256];
scanf("%s", filename);
FILE *fp = fopen(filename, "r");  // Attaquant peut lire /etc/passwd

// SÉCURISÉ
if (strstr(filename, "..") != NULL) {
    fprintf(stderr, "Path traversal detected\n");
    exit(1);
}
```

### 9.2 Buffer Overflow sur fgets

```c
char buffer[10];

// VULNÉRABLE
fgets(buffer, 100, fp);  // Peut déborder buffer[10]

// SÉCURISÉ
fgets(buffer, sizeof(buffer), fp);  // Limite à la taille réelle
```

---

## 10. Checklist de Compréhension

- [ ] Différence entre "r", "w", "a" ?
- [ ] Quand utiliser "rb" vs "r" ?
- [ ] Comment lire un fichier entier ?
- [ ] À quoi sert fseek() ?
- [ ] Différence fgets() vs fread() ?
- [ ] Pourquoi toujours fermer les fichiers ?
- [ ] Comment vérifier les erreurs I/O ?

---

## 11. Exercices Pratiques

Voir `exercice.txt` pour :
- Copier un fichier binaire
- Parser un fichier CSV
- Modifier un exécutable (patching)
- Extraire un payload depuis un PNG (stéganographie basique)

---

**Fin de la Phase 01 - C Fundamentals !** Vous maîtrisez maintenant les bases du C. Prochaine phase : Phase 02 - Memory Management.

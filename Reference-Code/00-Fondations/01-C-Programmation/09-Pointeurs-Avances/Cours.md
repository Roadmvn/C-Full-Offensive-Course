# Module 10 : Pointeurs Avancés

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :
- Allouer et libérer de la mémoire dynamiquement (malloc, free, realloc)
- Utiliser des pointeurs de pointeurs (int **)
- Créer et utiliser des pointeurs de fonctions
- Gérer des tableaux de pointeurs
- Comprendre les problèmes de mémoire (leaks, use-after-free)
- Applications offensives : shellcode loaders, hooking, callbacks

---

## 1. Allocation dynamique de mémoire

### Pourquoi l'allocation dynamique ?

Jusqu'ici, on déclarait des tableaux de taille fixe :
```c
int arr[100];  // Taille fixée à la compilation
```

Problèmes :
- Taille inconnue à l'avance
- Gaspillage de mémoire si trop grand
- Stack limitée (généralement quelques MB)

**Solution** : Allouer sur le **heap** (tas) avec `malloc`.

### malloc - Memory Allocation

```c
#include <stdlib.h>

void *malloc(size_t size);
```

`malloc` alloue `size` bytes et retourne un pointeur vers cette zone.

```c
// Allouer un tableau de 100 entiers
int *arr = (int *)malloc(100 * sizeof(int));

if (arr == NULL) {
    printf("Erreur d'allocation!\n");
    return 1;
}

// Utiliser le tableau
arr[0] = 42;
arr[99] = 100;

// Libérer quand on n'en a plus besoin
free(arr);
```

### Schéma mémoire

```
STACK (pile)                    HEAP (tas)
┌──────────────┐               ┌──────────────────────┐
│ int *arr     │───────────────│ 400 bytes alloués    │
│ = 0x10000    │               │ (100 * sizeof(int))  │
└──────────────┘               └──────────────────────┘
                               Adresse : 0x10000
```

### free - Libérer la mémoire

```c
void free(void *ptr);
```

**OBLIGATOIRE** : Libérer la mémoire allouée quand on n'en a plus besoin.

```c
int *data = malloc(1000);
// ... utilisation ...
free(data);     // Libère la mémoire
data = NULL;    // Bonne pratique : évite les dangling pointers
```

### calloc - Allocation avec initialisation à zéro

```c
void *calloc(size_t nmemb, size_t size);
```

Comme malloc mais initialise tout à zéro.

```c
// Allouer 100 entiers initialisés à 0
int *arr = (int *)calloc(100, sizeof(int));
// arr[0] == 0, arr[1] == 0, etc.
```

### realloc - Redimensionner

```c
void *realloc(void *ptr, size_t new_size);
```

Change la taille d'une zone allouée.

```c
int *arr = malloc(10 * sizeof(int));
// ... besoin de plus d'espace ...
arr = realloc(arr, 20 * sizeof(int));
// arr contient maintenant 20 entiers
// Les 10 premiers sont préservés
```

---

## 2. Pointeurs de pointeurs

### Le concept

Un pointeur de pointeur stocke l'adresse d'un pointeur.

```c
int x = 42;
int *p = &x;      // p pointe vers x
int **pp = &p;    // pp pointe vers p
```

### Schéma

```
┌───────────┐     ┌───────────┐     ┌───────────┐
│ pp        │────→│ p         │────→│ x = 42    │
│ = &p      │     │ = &x      │     │           │
└───────────┘     └───────────┘     └───────────┘
  int **            int *              int
```

### Accès aux valeurs

```c
int x = 42;
int *p = &x;
int **pp = &p;

printf("%d\n", x);      // 42
printf("%d\n", *p);     // 42
printf("%d\n", **pp);   // 42 (double déréférencement)

printf("%p\n", p);      // Adresse de x
printf("%p\n", *pp);    // Adresse de x (identique)
printf("%p\n", pp);     // Adresse de p
```

### Modification à plusieurs niveaux

```c
**pp = 100;     // Modifie x
*pp = autre_ptr; // Fait pointer p vers autre chose
```

### Cas d'usage : Modifier un pointeur dans une fonction

```c
// PROBLÈME : ne modifie pas le pointeur original
void bad_alloc(int *ptr) {
    ptr = malloc(sizeof(int));  // Modifie la copie locale!
}

// SOLUTION : passer un pointeur de pointeur
void good_alloc(int **ptr) {
    *ptr = malloc(sizeof(int));  // Modifie le pointeur original
}

int main(void) {
    int *data = NULL;
    good_alloc(&data);  // Maintenant data pointe vers la mémoire allouée
    *data = 42;
    free(data);
    return 0;
}
```

---

## 3. Tableaux de pointeurs

### Déclaration

```c
int *arr[10];   // Tableau de 10 pointeurs vers int
char *args[5];  // Tableau de 5 pointeurs vers char (strings)
```

### Tableau de strings

```c
char *commands[] = {
    "whoami",
    "pwd",
    "ls -la",
    "cat /etc/passwd",
    NULL  // Sentinelle
};

// Parcours
for (int i = 0; commands[i] != NULL; i++) {
    printf("[%d] %s\n", i, commands[i]);
}
```

### Schéma

```
commands (tableau de pointeurs)
┌─────────┐
│ [0]     │────→ "whoami\0"
├─────────┤
│ [1]     │────→ "pwd\0"
├─────────┤
│ [2]     │────→ "ls -la\0"
├─────────┤
│ [3]     │────→ "cat /etc/passwd\0"
├─────────┤
│ [4]     │────→ NULL
└─────────┘
```

### Allocation dynamique d'un tableau 2D

```c
// Allouer une matrice rows x cols
int **matrix = malloc(rows * sizeof(int *));
for (int i = 0; i < rows; i++) {
    matrix[i] = malloc(cols * sizeof(int));
}

// Utilisation
matrix[2][3] = 42;

// Libération (dans l'ordre inverse!)
for (int i = 0; i < rows; i++) {
    free(matrix[i]);
}
free(matrix);
```

---

## 4. Pointeurs de fonctions

### Le concept

Une fonction a une adresse en mémoire. On peut stocker cette adresse dans un pointeur.

```c
// Déclaration d'un pointeur de fonction
int (*func_ptr)(int, int);

// func_ptr peut pointer vers n'importe quelle fonction
// qui prend 2 int et retourne un int
```

### Syntaxe détaillée

```
int (*func_ptr)(int, int);
│    │         │
│    │         └─ Paramètres de la fonction
│    └─ Nom du pointeur (les parenthèses sont obligatoires!)
└─ Type de retour
```

### Exemple de base

```c
int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int main(void) {
    // Pointeur de fonction
    int (*operation)(int, int);

    // Pointer vers add
    operation = add;
    printf("5 + 3 = %d\n", operation(5, 3));  // 8

    // Pointer vers multiply
    operation = multiply;
    printf("5 * 3 = %d\n", operation(5, 3));  // 15

    return 0;
}
```

### typedef pour simplifier

```c
// Définir un type de pointeur de fonction
typedef int (*math_func)(int, int);

int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }

int main(void) {
    math_func op = add;
    printf("%d\n", op(10, 5));  // 15

    op = sub;
    printf("%d\n", op(10, 5));  // 5

    return 0;
}
```

### Tableau de pointeurs de fonctions

```c
typedef void (*cmd_handler)(const char *);

void cmd_whoami(const char *arg) {
    printf("Current user: root\n");
}

void cmd_pwd(const char *arg) {
    printf("/home/hacker\n");
}

void cmd_echo(const char *arg) {
    printf("%s\n", arg);
}

int main(void) {
    // Tableau de fonctions
    cmd_handler handlers[] = {cmd_whoami, cmd_pwd, cmd_echo};

    handlers[0]("");        // whoami
    handlers[1]("");        // pwd
    handlers[2]("Hello!");  // echo

    return 0;
}
```

---

## 5. Callbacks

### Le concept

Un callback est une fonction passée en paramètre à une autre fonction.

```c
void process_data(int *data, int size, void (*callback)(int)) {
    for (int i = 0; i < size; i++) {
        callback(data[i]);  // Appelle la fonction passée
    }
}

void print_value(int x) {
    printf("%d ", x);
}

void double_value(int x) {
    printf("%d ", x * 2);
}

int main(void) {
    int data[] = {1, 2, 3, 4, 5};

    printf("Original: ");
    process_data(data, 5, print_value);
    printf("\n");

    printf("Doubled: ");
    process_data(data, 5, double_value);
    printf("\n");

    return 0;
}
```

### Application : Encodeurs modulaires

```c
typedef void (*encoder_t)(unsigned char *, int);

void xor_encoder(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= 0x42;
    }
}

void add_encoder(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] += 5;
    }
}

void encode_payload(unsigned char *data, int len, encoder_t encoder) {
    encoder(data, len);  // Utilise l'encodeur passé
}

// Usage
encode_payload(shellcode, len, xor_encoder);
```

---

## 6. Problèmes de mémoire courants

### Memory Leak (fuite mémoire)

```c
void memory_leak(void) {
    int *data = malloc(1000);
    // ... utilisation ...
    // OUBLI de free(data) !
}  // data perdu, mémoire jamais libérée
```

**Solution** : Toujours `free()` ce qui a été `malloc()`.

### Double Free

```c
int *data = malloc(100);
free(data);
free(data);  // CRASH ou corruption!
```

**Solution** : Mettre le pointeur à NULL après free.
```c
free(data);
data = NULL;
```

### Use-After-Free

```c
int *data = malloc(100);
free(data);
data[0] = 42;  // DANGER : mémoire peut être réutilisée!
```

**Solution** : Ne jamais utiliser un pointeur après free.

### Dangling Pointer

```c
int *get_value(void) {
    int x = 42;
    return &x;  // DANGER : x n'existe plus après return!
}

int *ptr = get_value();
printf("%d\n", *ptr);  // Comportement indéfini!
```

### Buffer Overflow

```c
int *data = malloc(10 * sizeof(int));
data[100] = 42;  // Écriture hors limites!
```

---

## 7. Applications offensives

### 7.1 Shellcode Loader

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main(void) {
    // Shellcode minimal (exit(0))
    unsigned char shellcode[] = {
        0x48, 0x31, 0xc0,  // xor rax, rax
        0xb0, 0x3c,        // mov al, 60 (sys_exit)
        0x48, 0x31, 0xff,  // xor rdi, rdi
        0x0f, 0x05         // syscall
    };

    int size = sizeof(shellcode);

    // Allouer mémoire exécutable
    void *mem = mmap(NULL, size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copier le shellcode
    memcpy(mem, shellcode, size);

    // Créer pointeur de fonction et exécuter
    void (*func)(void) = (void (*)(void))mem;
    func();

    return 0;  // N'arrive jamais (shellcode fait exit)
}
```

### 7.2 Table de dispatch C2

```c
typedef struct {
    const char *name;
    void (*handler)(const char *arg);
} Command;

void cmd_download(const char *url) {
    printf("[*] Downloading: %s\n", url);
}

void cmd_execute(const char *cmd) {
    printf("[*] Executing: %s\n", cmd);
    system(cmd);
}

void cmd_exfil(const char *path) {
    printf("[*] Exfiltrating: %s\n", path);
}

Command commands[] = {
    {"download", cmd_download},
    {"execute", cmd_execute},
    {"exfil", cmd_exfil},
    {NULL, NULL}  // Sentinelle
};

void dispatch(const char *name, const char *arg) {
    for (int i = 0; commands[i].name != NULL; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            commands[i].handler(arg);
            return;
        }
    }
    printf("[-] Unknown command: %s\n", name);
}
```

### 7.3 Fonction Hooking

```c
#include <stdio.h>

// Fonction originale
int (*original_check)(int) = NULL;

int real_check_license(int key) {
    return (key == 12345);  // True seulement si clé valide
}

// Notre hook (bypass)
int hooked_check(int key) {
    printf("[HOOK] License check bypassed!\n");
    return 1;  // Toujours valide
}

int main(void) {
    // Normalement
    original_check = real_check_license;
    printf("License valid: %d\n", original_check(99999));  // 0

    // Après hook
    original_check = hooked_check;
    printf("License valid: %d\n", original_check(99999));  // 1 (bypass!)

    return 0;
}
```

### 7.4 Allocation de payload dynamique

```c
unsigned char *create_encoded_payload(unsigned char *raw, int size, unsigned char key) {
    unsigned char *encoded = malloc(size);
    if (!encoded) return NULL;

    for (int i = 0; i < size; i++) {
        encoded[i] = raw[i] ^ key;
    }

    return encoded;  // Caller doit free()
}

void decode_and_execute(unsigned char *encoded, int size, unsigned char key) {
    // Décoder in-place
    for (int i = 0; i < size; i++) {
        encoded[i] ^= key;
    }

    // Exécuter (nécessite mémoire exécutable)
    // ...
}
```

---

## 8. Bonnes pratiques

### Vérifier les allocations

```c
int *data = malloc(size);
if (data == NULL) {
    fprintf(stderr, "Allocation failed\n");
    return -1;
}
```

### Initialiser après allocation

```c
int *data = malloc(100 * sizeof(int));
memset(data, 0, 100 * sizeof(int));
// Ou utiliser calloc
```

### Libérer dans l'ordre inverse

```c
// Allocation
char **matrix = malloc(rows * sizeof(char *));
for (int i = 0; i < rows; i++) {
    matrix[i] = malloc(cols);
}

// Libération (ordre inverse!)
for (int i = 0; i < rows; i++) {
    free(matrix[i]);
}
free(matrix);
```

### Mettre à NULL après free

```c
free(data);
data = NULL;  // Évite use-after-free accidentel
```

---

## 9. Récapitulatif

| Concept | Description | Exemple |
|---------|-------------|---------|
| malloc | Allouer mémoire | `int *p = malloc(n);` |
| calloc | Allouer + init à 0 | `int *p = calloc(n, sizeof(int));` |
| realloc | Redimensionner | `p = realloc(p, new_size);` |
| free | Libérer | `free(p);` |
| int ** | Pointeur de pointeur | `int **pp = &p;` |
| Function ptr | Pointeur de fonction | `int (*f)(int) = func;` |
| Callback | Fonction passée en arg | `process(data, callback);` |

---

## 10. Exercices

Voir [exercice.md](exercice.md) pour les exercices pratiques.

## 11. Prochaine étape

Le module suivant abordera les **structures** :
- Définition de structures
- Pointeurs vers structures
- Structures imbriquées
- Applications : représentation de données réseau, C2 protocols

# Module 09 : Pointeurs - Les Fondamentaux

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :
- Ce qu'est un pointeur et pourquoi il est essentiel en C
- Déclarer et initialiser des pointeurs
- Utiliser les opérateurs `&` (adresse) et `*` (déréférencement)
- Comprendre la relation entre pointeurs et mémoire
- Passer des paramètres par référence
- Manipuler des pointeurs sur tableaux
- Applications offensives : modification mémoire, shellcode, API hooking

---

## 1. Introduction aux pointeurs

### C'est quoi un pointeur ?

Un **pointeur** est une variable qui contient une **adresse mémoire**. Au lieu de stocker une valeur directement (comme `int x = 5`), un pointeur stocke l'emplacement en mémoire où cette valeur se trouve.

```c
int x = 42;       // x contient la valeur 42
int *ptr = &x;    // ptr contient l'ADRESSE de x
```

### Pourquoi les pointeurs existent ?

1. **Accès direct à la mémoire** - Essentiel pour la programmation système
2. **Passage par référence** - Modifier des variables dans des fonctions
3. **Allocation dynamique** - Créer des structures de taille variable
4. **Structures de données** - Listes chaînées, arbres, graphes
5. **Performance** - Éviter de copier des grandes quantités de données

### Importance en sécurité offensive

Les pointeurs sont au coeur de :
- **Buffer overflows** - Écraser des adresses de retour
- **Shellcode** - Exécuter du code en mémoire
- **Hooking** - Rediriger l'exécution de fonctions
- **Memory forensics** - Analyser la mémoire d'un processus
- **Exploitation** - Contrôler le flux d'exécution

---

## 2. La mémoire et les adresses

### Organisation de la mémoire

Chaque variable en C occupe un emplacement en mémoire avec une **adresse unique** :

```
Adresse       Contenu         Variable
─────────────────────────────────────────
0x7FFE0000    42              int x
0x7FFE0004    3.14            float y
0x7FFE0008    'A'             char c
0x7FFE0010    0x7FFE0000      int *ptr
```

### L'opérateur & (adresse de)

L'opérateur `&` retourne l'adresse mémoire d'une variable :

```c
int x = 42;
printf("Valeur de x : %d\n", x);       // 42
printf("Adresse de x : %p\n", &x);     // 0x7ffd12345678 (exemple)
```

### Visualisation

```
Variable x :
┌─────────────────────────────────┐
│ Valeur : 42                     │
│ Adresse : 0x7ffd12345678        │
│ Taille : 4 bytes (int)          │
└─────────────────────────────────┘

&x retourne → 0x7ffd12345678
```

---

## 3. Déclaration de pointeurs

### Syntaxe

```c
type *nom_pointeur;
```

Le `*` dans la déclaration indique que la variable est un pointeur.

### Exemples

```c
int *ptr_int;       // Pointeur vers un int
char *ptr_char;     // Pointeur vers un char
float *ptr_float;   // Pointeur vers un float
void *ptr_void;     // Pointeur générique (peut pointer vers n'importe quoi)
```

### Initialisation

**TOUJOURS initialiser un pointeur** avant de l'utiliser :

```c
// Bonne pratique : initialiser à NULL
int *ptr = NULL;

// Ou initialiser avec une adresse valide
int x = 42;
int *ptr = &x;
```

### Pointeur NULL

`NULL` est une valeur spéciale (généralement 0) indiquant qu'un pointeur ne pointe nulle part :

```c
int *ptr = NULL;

if (ptr == NULL) {
    printf("Pointeur non initialisé!\n");
}

// DANGER : déréférencer NULL = crash
// *ptr = 10;  // Segmentation fault!
```

---

## 4. Déréférencement avec *

### L'opérateur * (déréférencement)

L'opérateur `*` permet d'accéder à la valeur stockée à l'adresse pointée :

```c
int x = 42;
int *ptr = &x;

printf("Adresse : %p\n", ptr);    // 0x7ffd12345678
printf("Valeur : %d\n", *ptr);    // 42 (valeur à cette adresse)
```

### Lire et écrire via un pointeur

```c
int x = 10;
int *ptr = &x;

// Lire la valeur
printf("x = %d\n", *ptr);    // 10

// Modifier la valeur
*ptr = 99;
printf("x = %d\n", x);       // 99 (x a été modifié via ptr!)
```

### Visualisation

```
Avant *ptr = 99 :
┌─────────────┐     ┌─────────────┐
│ x = 10      │ ←── │ ptr         │
│ @0x1000     │     │ = 0x1000    │
└─────────────┘     └─────────────┘

Après *ptr = 99 :
┌─────────────┐     ┌─────────────┐
│ x = 99      │ ←── │ ptr         │
│ @0x1000     │     │ = 0x1000    │
└─────────────┘     └─────────────┘
```

---

## 5. Pointeurs et types

### Taille des pointeurs

La taille d'un pointeur dépend de l'architecture :
- **32 bits** : 4 bytes
- **64 bits** : 8 bytes

```c
printf("Taille de int* : %lu\n", sizeof(int*));     // 8 (sur 64-bit)
printf("Taille de char* : %lu\n", sizeof(char*));   // 8
printf("Taille de void* : %lu\n", sizeof(void*));   // 8
```

### Pourquoi le type est important ?

Le type du pointeur détermine comment les données sont interprétées :

```c
int x = 0x41424344;  // "DCBA" en little-endian

int *pi = &x;
char *pc = (char*)&x;

printf("Via int* : 0x%X\n", *pi);    // 0x41424344
printf("Via char* : '%c'\n", *pc);   // 'D' (premier byte)
```

### Arithmétique de pointeurs

L'incrément d'un pointeur dépend du type :

```c
int arr[] = {10, 20, 30, 40};
int *ptr = arr;

printf("%d\n", *ptr);       // 10
ptr++;                      // Avance de sizeof(int) = 4 bytes
printf("%d\n", *ptr);       // 20
ptr++;
printf("%d\n", *ptr);       // 30
```

---

## 6. Passage par référence

### Le problème du passage par valeur

```c
void modifier(int x) {
    x = 100;  // Modifie seulement la copie locale
}

int main(void) {
    int a = 5;
    modifier(a);
    printf("a = %d\n", a);  // Toujours 5!
    return 0;
}
```

### Solution : passer un pointeur

```c
void modifier(int *x) {
    *x = 100;  // Modifie la valeur à l'adresse pointée
}

int main(void) {
    int a = 5;
    modifier(&a);          // Passe l'adresse de a
    printf("a = %d\n", a); // 100!
    return 0;
}
```

### Exemple classique : swap

```c
void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main(void) {
    int x = 10, y = 20;
    printf("Avant: x=%d, y=%d\n", x, y);
    swap(&x, &y);
    printf("Après: x=%d, y=%d\n", x, y);  // x=20, y=10
    return 0;
}
```

---

## 7. Pointeurs et tableaux

### Relation fondamentale

En C, le nom d'un tableau EST un pointeur vers son premier élément :

```c
int arr[] = {10, 20, 30};

printf("arr = %p\n", arr);      // Adresse du premier élément
printf("&arr[0] = %p\n", &arr[0]); // Même adresse!

printf("*arr = %d\n", *arr);    // 10 (premier élément)
printf("arr[0] = %d\n", arr[0]); // 10 (équivalent)
```

### Équivalence syntaxique

```c
int arr[] = {10, 20, 30};
int *ptr = arr;

// Ces expressions sont équivalentes :
arr[0]  ←→  *arr        ←→  *ptr       ←→  ptr[0]
arr[1]  ←→  *(arr+1)    ←→  *(ptr+1)   ←→  ptr[1]
arr[i]  ←→  *(arr+i)    ←→  *(ptr+i)   ←→  ptr[i]
```

### Parcours de tableau avec pointeur

```c
int arr[] = {10, 20, 30, 40, 50};
int size = 5;

// Méthode 1 : index
for (int i = 0; i < size; i++) {
    printf("%d ", arr[i]);
}

// Méthode 2 : pointeur
int *ptr = arr;
for (int i = 0; i < size; i++) {
    printf("%d ", *ptr);
    ptr++;
}

// Méthode 3 : arithmétique de pointeur
for (int *p = arr; p < arr + size; p++) {
    printf("%d ", *p);
}
```

---

## 8. Pointeur void*

### C'est quoi ?

`void*` est un pointeur **générique** qui peut pointer vers n'importe quel type :

```c
int x = 42;
float y = 3.14;
char c = 'A';

void *ptr;

ptr = &x;  // OK
ptr = &y;  // OK
ptr = &c;  // OK
```

### Utilisation

Pour utiliser la valeur, il faut **caster** vers le bon type :

```c
int x = 42;
void *ptr = &x;

// Doit caster pour déréférencer
printf("%d\n", *(int*)ptr);  // 42
```

### Cas d'usage

- Fonctions génériques (malloc, memcpy, etc.)
- Callbacks avec données utilisateur
- Structures de données génériques

---

## 9. Applications offensives

### 9.1 Modification de mémoire

Accéder directement à des adresses mémoire :

```c
// Modifier une valeur à une adresse arbitraire (DANGEREUX)
unsigned int *target = (unsigned int*)0x12345678;
*target = 0xDEADBEEF;

// En pratique : modifier des données dans un processus
```

### 9.2 Shellcode en mémoire

Stocker et exécuter du code :

```c
unsigned char shellcode[] = {
    0x48, 0x31, 0xc0,  // xor rax, rax
    0xc3               // ret
};

// Pointeur de fonction
void (*func)(void) = (void (*)(void))shellcode;

// ATTENTION : nécessite mémoire exécutable
// En pratique : utiliser mmap avec PROT_EXEC ou VirtualAlloc
```

### 9.3 Analyse de structure mémoire

```c
void hexdump(void *ptr, int size) {
    unsigned char *bytes = (unsigned char*)ptr;
    for (int i = 0; i < size; i++) {
        printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int x = 0x41424344;
hexdump(&x, sizeof(x));  // 44 43 42 41 (little-endian)
```

### 9.4 Parcours de tableaux de bytes

```c
// Décoder un payload XOR
void xor_decode(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

unsigned char encoded[] = {0x0A, 0x27, 0x38, 0x38, 0x3B};  // "hello" ^ 0x42
xor_decode(encoded, 5, 0x42);
printf("%s\n", encoded);  // "hello"
```

### 9.5 Pointeur vers fonction (callbacks)

```c
// Type de fonction
typedef void (*command_handler)(char *arg);

void cmd_whoami(char *arg) {
    printf("Current user: root\n");
}

void cmd_download(char *arg) {
    printf("Downloading: %s\n", arg);
}

// Table de dispatch
struct {
    char *name;
    command_handler handler;
} commands[] = {
    {"whoami", cmd_whoami},
    {"download", cmd_download}
};
```

---

## 10. Erreurs courantes

### 10.1 Pointeur non initialisé

```c
int *ptr;           // DANGER : valeur aléatoire
*ptr = 42;          // Comportement indéfini!

// Solution :
int *ptr = NULL;    // Ou initialiser avec une adresse valide
```

### 10.2 Déréférencer NULL

```c
int *ptr = NULL;
*ptr = 42;          // Segmentation fault!

// Solution : toujours vérifier
if (ptr != NULL) {
    *ptr = 42;
}
```

### 10.3 Dangling pointer

Pointeur vers une variable qui n'existe plus :

```c
int* mauvaise_fonction(void) {
    int x = 42;
    return &x;      // DANGER : x n'existe plus après return!
}

int *ptr = mauvaise_fonction();
printf("%d\n", *ptr);  // Comportement indéfini!
```

### 10.4 Confusion & et *

```c
int x = 42;
int *ptr = &x;

// CORRECT
printf("%d\n", *ptr);   // 42 (valeur)
printf("%p\n", ptr);    // adresse

// ERREUR COMMUNE
printf("%d\n", ptr);    // Imprime l'adresse comme int (incorrect)
printf("%p\n", *ptr);   // Imprime la valeur comme adresse (incorrect)
```

---

## 11. Bonnes pratiques

### Toujours initialiser

```c
int *ptr = NULL;  // Ou avec une adresse valide
```

### Vérifier avant déréférencement

```c
if (ptr != NULL) {
    *ptr = valeur;
}
```

### Documenter la propriété

```c
// Ce pointeur est propriétaire (doit être libéré)
int *data = malloc(100 * sizeof(int));

// Ce pointeur est un emprunt (ne pas libérer)
int *view = data;
```

### Utiliser const quand approprié

```c
// Le pointeur ne modifiera pas les données
void afficher(const int *ptr) {
    printf("%d\n", *ptr);
    // *ptr = 10;  // Erreur de compilation!
}
```

---

## 12. Récapitulatif

| Concept | Syntaxe | Description |
|---------|---------|-------------|
| Déclaration | `int *ptr;` | Déclare un pointeur vers int |
| Adresse de | `&variable` | Obtient l'adresse d'une variable |
| Déréférencement | `*ptr` | Accède à la valeur pointée |
| Initialisation | `ptr = &x;` | Fait pointer vers x |
| NULL | `ptr = NULL;` | Pointeur invalide/non utilisé |
| Tableau | `ptr = arr;` | Pointe vers le premier élément |
| Arithmétique | `ptr++` | Avance de sizeof(*ptr) bytes |

---

## 13. Exercices

Voir [exercice.md](exercice.md) pour les exercices pratiques.

## 14. Prochaine étape

Le module suivant abordera les **pointeurs avancés** :
- Pointeurs de pointeurs (`int **`)
- Allocation dynamique (`malloc`, `free`)
- Pointeurs de fonctions
- Tableaux de pointeurs

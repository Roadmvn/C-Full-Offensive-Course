# Module 06 : Fonctions

## Partie 0 : Pourquoi les fonctions en sécurité offensive ?

Les fonctions sont la **base de tout code réutilisable et structuré**. En offensive security, elles permettent :

### Applications directes

| Concept | Application offensive |
|---------|----------------------|
| Modularisation | Séparer payload, encoder, loader |
| Callbacks | Hooks, shellcode, API hijacking |
| Pointeurs de fonction | Technique anti-analyse, obfuscation |
| Conventions d'appel | Shellcode, ROP chains, calling conventions |
| Récursion | Traversée de systèmes de fichiers |
| Variadic functions | Format string attacks |

### Exemple motivant

```c
// Sans fonctions : code répétitif et impossible à maintenir
unsigned char encoded1 = data1 ^ 0x42;
unsigned char encoded2 = data2 ^ 0x42;
unsigned char encoded3 = data3 ^ 0x42;
// ... répété 100 fois

// Avec fonction : propre et réutilisable
unsigned char xor_encode(unsigned char byte, unsigned char key) {
    return byte ^ key;
}

for (int i = 0; i < data_len; i++) {
    data[i] = xor_encode(data[i], 0x42);
}
```

---

## Partie 1 : Anatomie d'une fonction

### Structure de base

```c
type_retour nom_fonction(paramètres) {
    // Corps de la fonction
    return valeur;
}
```

### Les 4 composants

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  int    add    (int a, int b)    {                         │
│   │      │          │                                       │
│   │      │          └─── Paramètres (entrées)              │
│   │      └────────────── Nom de la fonction                │
│   └───────────────────── Type de retour (sortie)           │
│                                                             │
│      return a + b;   ← Valeur retournée                    │
│  }                                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Exemples simples

```c
#include <stdio.h>

// Fonction sans retour ni paramètres
void say_hello(void) {
    printf("Hello!\n");
}

// Fonction avec retour, sans paramètres
int get_magic_number(void) {
    return 42;
}

// Fonction avec paramètres et retour
int add(int a, int b) {
    return a + b;
}

// Fonction avec paramètres, sans retour
void print_number(int n) {
    printf("Number: %d\n", n);
}

int main(void) {
    say_hello();                          // Hello!
    int magic = get_magic_number();       // magic = 42
    int sum = add(5, 3);                  // sum = 8
    print_number(sum);                    // Number: 8
    return 0;
}
```

---

## Partie 2 : Déclaration vs Définition

### Le problème

```c
int main(void) {
    greet();  // ERREUR : greet() pas encore défini !
    return 0;
}

void greet(void) {
    printf("Hello!\n");
}
```

### Solution : Prototype (déclaration)

```c
// Prototype : annonce l'existence de la fonction
void greet(void);

int main(void) {
    greet();  // OK : le compilateur connaît greet()
    return 0;
}

// Définition : implémentation complète
void greet(void) {
    printf("Hello!\n");
}
```

### Règle d'or

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  PROTOTYPE : type nom(paramètres);   ← avec point-virgule  │
│                                                             │
│  DÉFINITION : type nom(paramètres) { ... }  ← avec corps   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Organisation typique

```c
// ===== Prototypes (en haut du fichier) =====
int xor_encode(unsigned char* data, int len, unsigned char key);
void print_hex(unsigned char* data, int len);
int check_signature(unsigned char* data);

// ===== Main =====
int main(void) {
    // Utilise les fonctions
    return 0;
}

// ===== Définitions (en bas du fichier) =====
int xor_encode(unsigned char* data, int len, unsigned char key) {
    // Implémentation
}

void print_hex(unsigned char* data, int len) {
    // Implémentation
}
```

---

## Partie 3 : Passage de paramètres

### Passage par valeur (copie)

```c
void double_value(int x) {
    x = x * 2;  // Modifie la COPIE, pas l'original
}

int main(void) {
    int n = 5;
    double_value(n);
    printf("%d\n", n);  // Affiche 5 (inchangé !)
    return 0;
}
```

### Passage par pointeur (adresse)

```c
void double_value(int* x) {
    *x = *x * 2;  // Modifie l'original via le pointeur
}

int main(void) {
    int n = 5;
    double_value(&n);  // Passe l'adresse
    printf("%d\n", n);  // Affiche 10 (modifié !)
    return 0;
}
```

### Visualisation

```
Passage par valeur :              Passage par pointeur :
┌───────┐      ┌───────┐          ┌───────┐
│ n = 5 │      │ x = 5 │          │ n = 5 │ ←─────────┐
└───────┘      └───────┘          └───────┘           │
  main()        double_value()      main()            │
                                                      │
                copie                          ┌──────┴──────┐
                indépendante                   │ x = adresse │
                                               └─────────────┘
                                                double_value()
                                                modifie via *x
```

### Tableaux : toujours par pointeur

```c
// Les tableaux sont TOUJOURS passés par pointeur
void modify_array(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;  // Modifie l'original !
    }
}

int main(void) {
    int numbers[] = {1, 2, 3, 4, 5};
    modify_array(numbers, 5);
    // numbers est maintenant {2, 4, 6, 8, 10}
    return 0;
}
```

---

## Partie 4 : Retour de valeurs

### Types de retour simples

```c
int get_random(void) {
    return rand() % 100;
}

float calculate_average(int a, int b) {
    return (float)(a + b) / 2;
}

char get_first_char(const char* str) {
    return str[0];
}
```

### Retour de pointeur (attention !)

```c
// MAUVAIS : retourne un pointeur vers une variable locale
char* get_string_wrong(void) {
    char str[] = "Hello";  // Locale, disparaît après return !
    return str;  // DANGEREUX : pointeur invalide
}

// BON : retourne un pointeur vers de la mémoire allouée
char* get_string_good(void) {
    char* str = malloc(6);
    strcpy(str, "Hello");
    return str;  // OK : mémoire persistante (penser à free())
}

// BON : retourne un pointeur vers une constante statique
const char* get_string_static(void) {
    return "Hello";  // OK : chaîne littérale, persistante
}
```

### Retour multiple via pointeurs

```c
// Retourne plusieurs valeurs via des pointeurs
void get_min_max(int* arr, int size, int* min, int* max) {
    *min = arr[0];
    *max = arr[0];

    for (int i = 1; i < size; i++) {
        if (arr[i] < *min) *min = arr[i];
        if (arr[i] > *max) *max = arr[i];
    }
}

int main(void) {
    int numbers[] = {5, 2, 8, 1, 9};
    int min, max;

    get_min_max(numbers, 5, &min, &max);
    printf("Min: %d, Max: %d\n", min, max);  // Min: 1, Max: 9

    return 0;
}
```

---

## Partie 5 : Portée et durée de vie

### Variables locales

```c
void example(void) {
    int x = 10;  // Locale : existe seulement dans cette fonction
}  // x est détruit ici

int main(void) {
    example();
    // printf("%d", x);  // ERREUR : x n'existe pas ici
    return 0;
}
```

### Variables globales

```c
int global_counter = 0;  // Globale : accessible partout

void increment(void) {
    global_counter++;  // OK
}

int main(void) {
    increment();
    increment();
    printf("%d\n", global_counter);  // 2
    return 0;
}
```

### Variables statiques

```c
void count_calls(void) {
    static int counter = 0;  // Initialisé une seule fois !
    counter++;
    printf("Called %d times\n", counter);
}

int main(void) {
    count_calls();  // Called 1 times
    count_calls();  // Called 2 times
    count_calls();  // Called 3 times
    return 0;
}
```

### Application offensive : Compteur d'exécution

```c
// Détection anti-sandbox : compter les exécutions
int should_execute(void) {
    static int exec_count = 0;
    exec_count++;

    // Ne s'exécute qu'après 3 appels (évite les analyses rapides)
    return (exec_count >= 3);
}
```

---

## Partie 6 : Récursion

### Concept

Une fonction qui s'appelle elle-même.

```c
int factorial(int n) {
    if (n <= 1) {
        return 1;  // Cas de base (arrête la récursion)
    }
    return n * factorial(n - 1);  // Appel récursif
}

// factorial(4) = 4 * factorial(3)
//              = 4 * 3 * factorial(2)
//              = 4 * 3 * 2 * factorial(1)
//              = 4 * 3 * 2 * 1
//              = 24
```

### Visualisation de la pile

```
┌─────────────────────────────────────────────────────┐
│                    PILE D'APPELS                    │
├─────────────────────────────────────────────────────┤
│  factorial(1) → return 1                            │
├─────────────────────────────────────────────────────┤
│  factorial(2) → return 2 * factorial(1) = 2        │
├─────────────────────────────────────────────────────┤
│  factorial(3) → return 3 * factorial(2) = 6        │
├─────────────────────────────────────────────────────┤
│  factorial(4) → return 4 * factorial(3) = 24       │
├─────────────────────────────────────────────────────┤
│  main()                                             │
└─────────────────────────────────────────────────────┘
```

### Application offensive : Parcours de répertoires

```c
#include <dirent.h>
#include <stdio.h>
#include <string.h>

void scan_directory(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignore . et ..
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        if (entry->d_type == DT_DIR) {
            // Répertoire : appel récursif
            scan_directory(full_path);
        } else {
            // Fichier : traiter
            printf("Found: %s\n", full_path);
        }
    }

    closedir(dir);
}
```

---

## Partie 7 : Pointeurs de fonction

### Concept

Un pointeur qui pointe vers le code d'une fonction (pas vers des données).

```c
// Déclaration d'un pointeur de fonction
int (*operation)(int, int);

// Fonctions cibles
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }

int main(void) {
    operation = add;  // Pointe vers add()
    printf("%d\n", operation(5, 3));  // 8

    operation = sub;  // Pointe vers sub()
    printf("%d\n", operation(5, 3));  // 2

    operation = mul;  // Pointe vers mul()
    printf("%d\n", operation(5, 3));  // 15

    return 0;
}
```

### Syntaxe des pointeurs de fonction

```
int (*nom)(int, int)
 │    │    │
 │    │    └─── Paramètres de la fonction
 │    └──────── Nom du pointeur
 └───────────── Type de retour
```

### Tableau de pointeurs de fonction

```c
typedef int (*math_op)(int, int);

int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }
int div_op(int a, int b) { return b != 0 ? a / b : 0; }

int main(void) {
    math_op operations[] = {add, sub, mul, div_op};

    for (int i = 0; i < 4; i++) {
        printf("Result: %d\n", operations[i](10, 5));
    }
    // Output: 15, 5, 50, 2

    return 0;
}
```

### Application offensive : Dispatcher de commandes

```c
typedef void (*command_handler)(const char*);

void cmd_shell(const char* arg) {
    printf("[SHELL] Executing: %s\n", arg);
    // system(arg);
}

void cmd_download(const char* arg) {
    printf("[DOWNLOAD] File: %s\n", arg);
}

void cmd_upload(const char* arg) {
    printf("[UPLOAD] File: %s\n", arg);
}

void cmd_exit(const char* arg) {
    printf("[EXIT] Terminating...\n");
}

int main(void) {
    // Table de handlers indexée par ID de commande
    command_handler handlers[] = {
        cmd_shell,      // 0
        cmd_download,   // 1
        cmd_upload,     // 2
        cmd_exit        // 3
    };

    // Dispatch
    int cmd_id = 0;
    handlers[cmd_id]("whoami");  // Appelle cmd_shell

    return 0;
}
```

---

## Partie 8 : Callbacks

### Concept

Une fonction passée en paramètre à une autre fonction.

```c
// Fonction qui accepte un callback
void process_array(int* arr, int size, int (*callback)(int)) {
    for (int i = 0; i < size; i++) {
        arr[i] = callback(arr[i]);
    }
}

// Callbacks possibles
int double_it(int x) { return x * 2; }
int square_it(int x) { return x * x; }
int negate_it(int x) { return -x; }

int main(void) {
    int numbers[] = {1, 2, 3, 4, 5};

    process_array(numbers, 5, double_it);
    // numbers = {2, 4, 6, 8, 10}

    process_array(numbers, 5, square_it);
    // numbers = {4, 16, 36, 64, 100}

    return 0;
}
```

### Application offensive : Encoder personnalisable

```c
typedef unsigned char (*encoder_func)(unsigned char, int);

unsigned char xor_encoder(unsigned char byte, int key) {
    return byte ^ key;
}

unsigned char add_encoder(unsigned char byte, int key) {
    return byte + key;
}

unsigned char rot_encoder(unsigned char byte, int key) {
    return (byte << key) | (byte >> (8 - key));
}

void encode_payload(unsigned char* data, int len, int key,
                    encoder_func encoder) {
    for (int i = 0; i < len; i++) {
        data[i] = encoder(data[i], key);
    }
}

int main(void) {
    unsigned char payload[] = {0x90, 0x90, 0x31, 0xC0};
    int len = 4;

    // Encoder avec XOR
    encode_payload(payload, len, 0x42, xor_encoder);

    // Ou encoder avec ADD
    // encode_payload(payload, len, 5, add_encoder);

    return 0;
}
```

---

## Partie 9 : Conventions d'appel

### Importance pour l'offensive

Les conventions d'appel définissent comment les arguments sont passés et les valeurs retournées. Crucial pour :
- Écrire du shellcode
- Créer des ROP chains
- Appeler des API Windows/Linux
- Analyser du code compilé

### x86 (32-bit) - cdecl

```
┌─────────────────────────────────────────────────────────────┐
│                      cdecl (x86)                            │
├─────────────────────────────────────────────────────────────┤
│  Arguments : empilés de droite à gauche sur la pile         │
│  Retour    : EAX                                            │
│  Nettoyage : l'appelant nettoie la pile                     │
├─────────────────────────────────────────────────────────────┤
│  func(1, 2, 3)                                              │
│                                                             │
│       PUSH 3                                                │
│       PUSH 2                                                │
│       PUSH 1                                                │
│       CALL func                                             │
│       ADD ESP, 12  ; Nettoie 3 arguments (3 × 4 bytes)     │
└─────────────────────────────────────────────────────────────┘
```

### x64 (64-bit) - System V AMD64 ABI (Linux)

```
┌─────────────────────────────────────────────────────────────┐
│                 System V AMD64 (Linux)                      │
├─────────────────────────────────────────────────────────────┤
│  Arguments :                                                │
│    1er → RDI                                                │
│    2e  → RSI                                                │
│    3e  → RDX                                                │
│    4e  → RCX                                                │
│    5e  → R8                                                 │
│    6e  → R9                                                 │
│    7e+ → pile                                               │
│                                                             │
│  Retour : RAX                                               │
├─────────────────────────────────────────────────────────────┤
│  func(a, b, c, d)                                           │
│                                                             │
│       MOV RDI, a                                            │
│       MOV RSI, b                                            │
│       MOV RDX, c                                            │
│       MOV RCX, d                                            │
│       CALL func                                             │
└─────────────────────────────────────────────────────────────┘
```

### x64 (64-bit) - Microsoft x64 (Windows)

```
┌─────────────────────────────────────────────────────────────┐
│                  Microsoft x64 (Windows)                    │
├─────────────────────────────────────────────────────────────┤
│  Arguments :                                                │
│    1er → RCX                                                │
│    2e  → RDX                                                │
│    3e  → R8                                                 │
│    4e  → R9                                                 │
│    5e+ → pile                                               │
│                                                             │
│  Retour : RAX                                               │
│                                                             │
│  Shadow space : 32 bytes réservés sur la pile              │
└─────────────────────────────────────────────────────────────┘
```

### Application offensive : Shellcode syscall (Linux x64)

```c
// write(1, "Hi", 2) en shellcode
// syscall number pour write = 1
// RDI = fd (1 = stdout)
// RSI = buffer
// RDX = length

unsigned char shellcode[] = {
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1 (syscall #)
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1 (stdout)
    0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,  // lea rsi, [rip+10]
    0x48, 0xc7, 0xc2, 0x02, 0x00, 0x00, 0x00,  // mov rdx, 2 (length)
    0x0f, 0x05,                                 // syscall
    0xc3,                                       // ret
    'H', 'i'                                    // data: "Hi"
};
```

---

## Partie 10 : Bonnes pratiques

### Nommage clair

```c
// MAUVAIS
int f(int a, int b);
void p(char* s);

// BON
int calculate_checksum(unsigned char* data, int length);
void send_beacon(const char* c2_server);
int verify_signature(unsigned char* data, int len);
```

### Documentation minimale

```c
// Encode les données avec XOR
// Retourne 0 en cas de succès, -1 en cas d'erreur
int xor_encode(unsigned char* data, int len, unsigned char key) {
    if (data == NULL || len <= 0) {
        return -1;
    }

    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }

    return 0;
}
```

### Validation des paramètres

```c
char* read_file(const char* filename) {
    // Valider les entrées
    if (filename == NULL) {
        return NULL;
    }

    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        return NULL;
    }

    // ... reste du code

    return buffer;
}
```

### Fonctions courtes et focalisées

```c
// MAUVAIS : fonction qui fait tout
void do_everything(void) {
    // 200 lignes de code
}

// BON : fonctions séparées
void connect_to_server(void);
void authenticate(void);
void receive_command(void);
void execute_command(void);
void send_result(void);
```

---

## Résumé visuel

```
┌─────────────────────────────────────────────────────────────┐
│                      FONCTIONS EN C                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DÉCLARATION : void func(int x);  ← prototype              │
│                                                             │
│  DÉFINITION  : void func(int x) { ... }  ← implémentation  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  PASSAGE DE PARAMÈTRES :                                    │
│    • Par valeur : copie, original inchangé                 │
│    • Par pointeur : modifie l'original                     │
│    • Tableaux : toujours par pointeur                      │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  DURÉE DE VIE :                                             │
│    • Locale : dans la fonction seulement                   │
│    • Globale : partout                                      │
│    • Statique : persiste entre les appels                  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  POINTEURS DE FONCTION :                                    │
│    int (*ptr)(int, int);  ← pointe vers code               │
│    ptr = add;             ← assigne                        │
│    ptr(5, 3);             ← appelle                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Exercices

Voir [exercice.md](exercice.md) pour pratiquer ces concepts.

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.

# Cours : Pointeurs Avancés

## Objectif du Module

Maîtriser les concepts avancés de pointeurs : pointeurs de pointeurs (multi-niveaux), pointeurs de fonctions (callbacks, tables de jump), pointeurs void* (généricité), tableaux de pointeurs (argv), et qualificateurs const.

---

## 1. Pointeur de Pointeur (**) - Multi-Niveau

### 1.1 Concept : Plusieurs Niveaux d'Indirection

Un pointeur de pointeur contient l'adresse d'un autre pointeur.

```c
int valeur = 42;
int *ptr = &valeur;     // ptr pointe vers valeur
int **ptr_ptr = &ptr;   // ptr_ptr pointe vers ptr
```

**Schéma Multi-Niveau :**
```
NIVEAU 3 - La Donnée :
┌─────────────────────────┐
│ Adresse : 0x1000        │
│ valeur = 42             │
└─────────────────────────┘
           ▲
           │ ptr pointe ici
           │
NIVEAU 2 - Pointeur Simple :
┌─────────────────────────┐
│ Adresse : 0x2000        │
│ ptr = 0x1000            │ (contient l'adresse de valeur)
└─────────────────────────┘
           ▲
           │ ptr_ptr pointe ici
           │
NIVEAU 1 - Pointeur de Pointeur :
┌─────────────────────────┐
│ Adresse : 0x3000        │
│ ptr_ptr = 0x2000        │ (contient l'adresse de ptr)
└─────────────────────────┘

ACCÈS :
valeur      → 42
*ptr        → 42
**ptr_ptr   → 42

ptr         → 0x1000
*ptr_ptr    → 0x1000

ptr_ptr     → 0x2000
```

### 1.2 Pourquoi Utiliser ** ?

**Cas d'usage 1 : Modifier un pointeur dans une fonction**

```c
void allouer(int **ptr) {
    *ptr = malloc(sizeof(int));  // Modifie le pointeur original
    **ptr = 100;
}

int main() {
    int *p = NULL;
    allouer(&p);  // Passe l'ADRESSE du pointeur
    printf("%d\n", *p);  // Affiche 100
    free(p);
    return 0;
}
```

**Schéma du passage :**
```
SANS ** (ne fonctionne PAS) :
void allouer(int *ptr) {
    ptr = malloc(...);  ← Modifie la COPIE
}

AVEC ** (fonctionne) :
void allouer(int **ptr) {
    *ptr = malloc(...);  ← Modifie l'ORIGINAL via l'adresse
}
```

**Cas d'usage 2 : Tableau de chaînes (char**)**

```c
char *noms[] = {"Alice", "Bob", "Charlie"};
char **p = noms;

printf("%s\n", p[0]);   // Alice
printf("%s\n", p[1]);   // Bob
printf("%s\n", *(p+2)); // Charlie
```

**Schéma mémoire :**
```
noms (char**) :
┌─────────┐
│ 0x5000  │───→ "Alice\0"
├─────────┤
│ 0x5100  │───→ "Bob\0"
├─────────┤
│ 0x5200  │───→ "Charlie\0"
└─────────┘

p = noms → pointe vers le tableau de pointeurs
*p → premier pointeur (0x5000)
**p → premier caractère ('A')
```

---

## 2. Pointeur de Fonction - Le Concept Avancé

### 2.1 Les Fonctions Ont des Adresses

Chaque fonction est stockée en mémoire avec une adresse unique.

```
SEGMENT CODE (.text) :
┌──────────────────────────┐
│ 0x100000: int add(a,b) { │
│               return a+b;│
│           }              │
├──────────────────────────┤
│ 0x100020: int sub(a,b) { │
│               return a-b;│
│           }              │
└──────────────────────────┘

add a l'adresse 0x100000
sub a l'adresse 0x100020
```

### 2.2 Syntaxe des Pointeurs de Fonction

```c
// Déclaration :
int (*func_ptr)(int, int);
│    │    │      │
│    │    │      └─ Paramètres
│    │    └─ Nom
│    └─ * = pointeur
└─ Type de retour

// Affectation :
int add(int a, int b) { return a + b; }
func_ptr = add;  // ou &add

// Appel :
int result = func_ptr(10, 20);  // Appelle add(10, 20)
```

**Attention : Parenthèses obligatoires !**
```c
int (*func_ptr)(int);  // Pointeur vers fonction
int *func_ptr(int);    // Fonction qui retourne int* (différent !)
```

### 2.3 Cas d'Usage : Table de Fonctions (Callbacks)

```c
#include <stdio.h>

int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }
int div(int a, int b) { return a / b; }

int main() {
    // Tableau de pointeurs de fonctions
    int (*operations[4])(int, int) = {add, sub, mul, div};

    int choix = 2;  // Multiplication
    int result = operations[choix](10, 5);  // Appelle mul(10, 5)
    printf("Résultat : %d\n", result);  // 50

    return 0;
}
```

**Schéma table de fonctions :**
```
operations[] :
┌───┬─────────┐
│ 0 │ add  ───┼──→ 0x100000
├───┼─────────┤
│ 1 │ sub  ───┼──→ 0x100020
├───┼─────────┤
│ 2 │ mul  ───┼──→ 0x100040  ← operations[2] pointe ici
├───┼─────────┤
│ 3 │ div  ───┼──→ 0x100060
└───┴─────────┘

operations[choix](10, 5) → appelle la fonction à l'index choix
```

### 2.4 Application Red Team : API Hooking

```c
// Fonction système originale (simulation)
void system_api() {
    printf("API originale\n");
}

// Notre hook malveillant
void hooked_api() {
    printf("[HOOK] API interceptée !\n");
}

int main() {
    void (*api_ptr)() = system_api;

    api_ptr();  // "API originale"

    // HOOK : Remplacer le pointeur
    api_ptr = hooked_api;

    api_ptr();  // "[HOOK] API interceptée !"

    return 0;
}
```

---

## 3. Pointeur void* - Le Pointeur Générique

### 3.1 Qu'est-ce que void* ?

Un `void*` peut pointer vers N'IMPORTE QUEL type.

```c
void *ptr;  // Pointeur générique

int x = 42;
ptr = &x;   // Pointer vers int

char c = 'A';
ptr = &c;   // Pointer vers char (même variable)
```

**Schéma :**
```
void *ptr = pointeur SANS type spécifique

┌────────────┐
│ void *ptr  │ peut pointer vers :
└────────────┘
      │
      ├───→ int
      ├───→ char
      ├───→ float
      ├───→ struct
      └───→ n'importe quoi !
```

### 3.2 Casting Obligatoire

Tu ne peux PAS déréférencer directement un `void*`.

```c
void *ptr = malloc(sizeof(int));

*ptr = 42;  // ERREUR ! void* ne peut pas être déréférencé

int *int_ptr = (int*)ptr;  // Cast nécessaire
*int_ptr = 42;  // OK
```

### 3.3 Cas d'Usage : malloc() et mémoire générique

```c
// malloc retourne void* car il ne sait pas quel type tu veux
void *ptr = malloc(100);  // 100 bytes bruts

// Tu décides du type :
int *i = (int*)ptr;     // Utiliser comme int[]
char *c = (char*)ptr;   // Ou comme char[]
float *f = (float*)ptr; // Ou comme float[]
```

### 3.4 Application Red Team : Shellcode Storage

```c
// Stocker du shellcode en mémoire
unsigned char shellcode[] = "\x90\x90\x90\xcc";

void *exec_mem = malloc(sizeof(shellcode));
memcpy(exec_mem, shellcode, sizeof(shellcode));

// Cast en pointeur de fonction et exécution
void (*run_shellcode)() = (void(*)())exec_mem;
run_shellcode();  // Exécute le shellcode !
```

---

## 4. Tableaux de Pointeurs

### 4.1 Tableau de Pointeurs vers int

```c
int a = 10, b = 20, c = 30;
int *arr[3] = {&a, &b, &c};

printf("%d\n", *arr[0]);  // 10
printf("%d\n", *arr[1]);  // 20
printf("%d\n", *arr[2]);  // 30
```

**Schéma :**
```
Variables :                 Tableau de pointeurs :
┌───────┐                   ┌─────────┐
│ a = 10│ 0x1000            │ arr[0]  │───→ 0x1000
├───────┤                   ├─────────┤
│ b = 20│ 0x1004            │ arr[1]  │───→ 0x1004
├───────┤                   ├─────────┤
│ c = 30│ 0x1008            │ arr[2]  │───→ 0x1008
└───────┘                   └─────────┘
```

### 4.2 argv[] - Arguments Ligne de Commande

```c
int main(int argc, char *argv[]) {
    // argv est un char** (tableau de char*)
    for (int i = 0; i < argc; i++) {
        printf("Argument %d : %s\n", i, argv[i]);
    }
    return 0;
}
```

**Schéma argv :**
```
$ ./program arg1 arg2 arg3

argc = 4
argv :
┌──────────┐
│ argv[0]  │───→ "./program\0"
├──────────┤
│ argv[1]  │───→ "arg1\0"
├──────────┤
│ argv[2]  │───→ "arg2\0"
├──────────┤
│ argv[3]  │───→ "arg3\0"
├──────────┤
│ argv[4]  │ = NULL (fin)
└──────────┘
```

---

## 5. const et Pointeurs - Les 4 Combinaisons

### 5.1 Pointeur vers const

```c
const int x = 10;
const int *ptr = &x;  // Pointeur vers constante

*ptr = 20;  // ERREUR ! Ne peut pas modifier la valeur pointée
ptr = &y;   // OK : Peut changer l'adresse
```

### 5.2 Pointeur const

```c
int x = 10, y = 20;
int * const ptr = &x;  // Pointeur constant

*ptr = 30;  // OK : Peut modifier la valeur
ptr = &y;   // ERREUR ! Ne peut pas changer l'adresse
```

### 5.3 Pointeur const vers const

```c
const int x = 10;
const int * const ptr = &x;  // Les deux const

*ptr = 20;  // ERREUR ! Valeur en lecture seule
ptr = &y;   // ERREUR ! Pointeur en lecture seule
```

### 5.4 Tableau Récapitulatif

```
┌──────────────────────┬─────────────┬───────────────┐
│ Déclaration          │ Modifier *p │ Modifier p    │
├──────────────────────┼─────────────┼───────────────┤
│ int *p               │     OUI     │      OUI      │
│ const int *p         │     NON     │      OUI      │
│ int * const p        │     OUI     │      NON      │
│ const int * const p  │     NON     │      NON      │
└──────────────────────┴─────────────┴───────────────┘

Astuce : Lire de droite à gauche
const int *p  → p est un pointeur vers un int constant
int * const p → p est un pointeur constant vers un int
```

---

## 6. Application Red Team

### 6.1 Function Pointer Hijacking

```c
// Détourner l'exécution en modifiant un pointeur de fonction
typedef void (*callback_t)(void);

void safe_function() {
    printf("Fonction légitime\n");
}

void malicious_function() {
    printf("[MALWARE] Code malveillant exécuté !\n");
}

int main() {
    callback_t func = safe_function;

    // Vulnérabilité : pointeur modifiable
    func = malicious_function;  // Hijack !

    func();  // Exécute le code malveillant
    return 0;
}
```

### 6.2 GOT/PLT Overwrite (Aperçu)

```
En exploitation binaire, on peut écraser les pointeurs
dans la Global Offset Table (GOT) pour rediriger
les appels de fonctions système vers notre code.

GOT :
┌──────────┐
│ printf   │───→ 0x7fff1234  (libc printf)
├──────────┤
│ malloc   │───→ 0x7fff5678  (libc malloc)
└──────────┘

Après overwrite :
┌──────────┐
│ printf   │───→ 0x41414141  (notre shellcode)
└──────────┘

Tout appel à printf() exécute maintenant notre code !
```

### 6.3 Pointeurs dans Shellcode

```c
// Exemple de shellcode qui utilise des pointeurs
unsigned char shellcode[] =
    "\x31\xc0"             // xor eax, eax
    "\x50"                 // push eax (NULL)
    "\x68\x2f\x2f\x73\x68" // push "//sh"
    "\x68\x2f\x62\x69\x6e" // push "/bin"
    "\x89\xe3"             // mov ebx, esp (pointeur vers "/bin//sh")
    "\x50"                 // push eax
    "\x53"                 // push ebx (pointeur)
    "\x89\xe1"             // mov ecx, esp (argv)
    "\xb0\x0b"             // mov al, 11 (execve)
    "\xcd\x80";            // int 0x80

// Le shellcode manipule des pointeurs en assembleur !
```

---

## 7. Checklist de Compréhension

- [ ] Comprendre `int **ptr` (pointeur de pointeur)
- [ ] Savoir déclarer et utiliser un pointeur de fonction
- [ ] Différencier `void*` des pointeurs typés
- [ ] Maîtriser `char *argv[]` (tableau de pointeurs)
- [ ] Connaître les 4 combinaisons de const
- [ ] Comprendre l'usage Red Team des pointeurs de fonctions

---

## 8. Exercices Pratiques

Voir `exercice.txt` pour :
- Manipuler des pointeurs de pointeurs
- Créer une table de callbacks
- Implémenter un parser d'arguments (argv)
- Simuler un hook de fonction

---

**Prochaine étape :** Module 13 - Memory Management (Stack vs Heap, malloc/free, memory leaks).

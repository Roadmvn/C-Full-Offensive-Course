# Cours : Gestion de la Mémoire (Memory Management)

## Objectif du Module

Maîtriser la gestion manuelle de la mémoire en C : comprendre la différence entre Stack et Heap, utiliser malloc/free correctement, détecter et prévenir les memory leaks, gérer double-free et use-after-free, et découvrir mmap/VirtualAlloc pour l'allocation bas-niveau.

---

## 1. Stack vs Heap - Les Deux Zones Mémoire

### 1.1 Schéma Complet de la Mémoire d'un Processus

```
MÉMOIRE D'UN PROCESSUS (de haut en bas) :

┌─────────────────────────────────────────┐ Adresses HAUTES
│                                         │
│  STACK (Pile)                           │ ← Taille limitée (~8 MB)
│  ├─ Variables locales                   │ ← Gestion AUTOMATIQUE
│  ├─ Paramètres de fonction              │ ← Croît vers le BAS ↓
│  └─ Adresses de retour                  │
│                                         │
│         ↓↓↓ Croissance ↓↓↓              │
│                                         │
│  ═══════ ESPACE LIBRE ═══════           │
│                                         │
│         ↑↑↑ Croissance ↑↑↑              │
│                                         │
│  HEAP (Tas)                             │ ← Taille quasi-illimitée
│  ├─ malloc(), calloc(), realloc()       │ ← Gestion MANUELLE
│  └─ Alloué dynamiquement                │ ← Croît vers le HAUT ↑
│                                         │
├─────────────────────────────────────────┤
│  BSS (Données non-initialisées)         │
│  └─ Variables globales = 0              │
├─────────────────────────────────────────┤
│  DATA (Données initialisées)            │
│  └─ Variables globales avec valeur      │
├─────────────────────────────────────────┤
│  TEXT (Code exécutable)                 │
│  └─ Instructions machine (lecture seule)│
└─────────────────────────────────────────┘ Adresses BASSES
```

### 1.2 Comparaison Stack vs Heap

```
┌─────────────────┬──────────────────┬──────────────────┐
│ Aspect          │ STACK            │ HEAP             │
├─────────────────┼──────────────────┼──────────────────┤
│ Gestion         │ AUTOMATIQUE      │ MANUELLE         │
│                 │ (compilateur)    │ (malloc/free)    │
├─────────────────┼──────────────────┼──────────────────┤
│ Durée de vie    │ Variable locale  │ Tant que tu veux │
│                 │ (scope limité)   │ (jusqu'à free)   │
├─────────────────┼──────────────────┼──────────────────┤
│ Taille          │ Limitée (~8 MB)  │ Quasi-illimitée  │
│                 │ Stack overflow   │ (RAM disponible) │
├─────────────────┼──────────────────┼──────────────────┤
│ Vitesse         │ TRÈS RAPIDE      │ Plus lent        │
│                 │ (juste ptr++)    │ (gestion alloc)  │
├─────────────────┼──────────────────┼──────────────────┤
│ Fragmentation   │ Aucune           │ Possible         │
├─────────────────┼──────────────────┼──────────────────┤
│ Accès           │ LIFO             │ Aléatoire        │
│                 │ (dernier entré,  │                  │
│                 │  premier sorti)  │                  │
└─────────────────┴──────────────────┴──────────────────┘
```

### 1.3 Exemple Visuel

```c
#include <stdlib.h>

int global = 10;  // DATA segment

int main() {
    int stack_var = 25;               // STACK
    int *heap_var = malloc(sizeof(int));  // HEAP
    *heap_var = 30;

    // ...

    free(heap_var);  // Libération manuelle obligatoire !
    return 0;
}  // stack_var libéré automatiquement ici
```

**Schéma mémoire :**
```
┌────────────────────────────────┐
│ STACK                          │
│                                │
│ 0x7ffe00  stack_var = 25       │ ← Automatique
│ 0x7ffe08  heap_var = 0x5000    │ ← Pointeur (sur stack)
│                                │
└────────────────────────────────┘
         ↑
         │ heap_var pointe ici
         ↓
┌────────────────────────────────┐
│ HEAP                           │
│                                │
│ 0x5000    *heap_var = 30       │ ← Alloué par malloc
│                                │
└────────────────────────────────┘

┌────────────────────────────────┐
│ DATA                           │
│                                │
│ 0x400000  global = 10          │
└────────────────────────────────┘
```

---

## 2. malloc() - Allocation Dynamique

### 2.1 Qu'est-ce que malloc() ?

`malloc()` = "Memory ALLOCation"

```c
void* malloc(size_t size);
```

Retourne un **pointeur** vers un bloc de `size` bytes sur le **HEAP**.

```c
int *ptr = malloc(sizeof(int));  // Alloue 4 bytes
if (ptr == NULL) {
    // Échec d'allocation
    exit(1);
}
*ptr = 42;  // Utilisation
free(ptr);  // Libération obligatoire
```

### 2.2 Que Se Passe-t-il sous le Capot ?

```
AVANT malloc(12) :

HEAP (vide) :
┌──────────────────────────────┐
│                              │
│  ... espace libre ...        │
│                              │
└──────────────────────────────┘

═══════════════════════════════════

malloc(12) :
1. malloc cherche un bloc libre de 12+ bytes
2. Marque ce bloc comme "occupé" (métadonnées)
3. Retourne l'adresse du début du bloc

═══════════════════════════════════

APRÈS malloc(12) :

HEAP :
┌──────────────────────────────┐
│  Métadonnées (taille, flags) │ ← malloc garde des infos
├──────────────────────────────┤
│  ┌────────────────────────┐  │
│  │ 12 bytes ALLOUÉS       │  │ ← Bloc retourné
│  │ Adresse: 0x5000        │  │
│  │ Contenu: ??? (garbage) │  │ ← NON INITIALISÉ !
│  └────────────────────────┘  │
├──────────────────────────────┤
│  ... espace libre ...        │
└──────────────────────────────┘

ptr = 0x5000
```

### 2.3 Vérifier NULL

malloc() peut ÉCHOUER si :
- Plus de RAM disponible
- Demande trop grande
- Heap corrompu

```c
int *ptr = malloc(sizeof(int) * 1000000);

if (ptr == NULL) {
    fprintf(stderr, "Erreur : allocation échouée\n");
    perror("malloc");  // Affiche la raison système
    exit(1);
}

// Utilisation sûre
*ptr = 42;
free(ptr);
```

### 2.4 Calculer la Taille avec sizeof()

```c
// Allouer 1 int
int *ptr = malloc(sizeof(int));  // 4 bytes

// Allouer 10 ints
int *arr = malloc(sizeof(int) * 10);  // 40 bytes

// Allouer 100 chars
char *str = malloc(sizeof(char) * 100);  // 100 bytes

// Allouer une structure
struct Person *p = malloc(sizeof(struct Person));
```

**Schéma :**
```
malloc(sizeof(int) * 10) :

Calcul : 4 × 10 = 40 bytes

┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐
│ [0]│ [1]│ [2]│ [3]│ [4]│ [5]│ [6]│ [7]│ [8]│ [9]│
└────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
  4    4    4    4    4    4    4    4    4    4  bytes

Total : 10 éléments × 4 bytes = 40 bytes
```

---

## 3. free() - Libération Mémoire

### 3.1 Pourquoi free() est OBLIGATOIRE ?

Sans free(), tu crées des **MEMORY LEAKS** (fuites mémoire).

```c
for (int i = 0; i < 1000000; i++) {
    int *ptr = malloc(1024);  // Alloue 1 KB
    // OUBLI de free(ptr) !
}
// Résultat : 1 GB de RAM perdue !
```

**Schéma du problème :**
```
Début :
HEAP: ░░░░░░░░░░░░░░░░░░░░  (10% utilisé)

Après 100 malloc() sans free() :
HEAP: ▓▓▓▓▓▓▓▓▓░░░░░░░░░░░  (50% utilisé)

Après 1000 malloc() sans free() :
HEAP: ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  (100% utilisé)
       ↓
  PLUS DE MÉMOIRE !
  Programme CRASH ou système ralenti
```

### 3.2 Utilisation Correcte de free()

```c
int *ptr = malloc(sizeof(int));
if (ptr == NULL) { exit(1); }

*ptr = 42;  // Utilisation

free(ptr);  // Libération
ptr = NULL; // BONNE PRATIQUE : évite dangling pointer
```

**Schéma :**
```
AVANT free(ptr) :

HEAP :
┌────────────────────┐
│ Métadonnées        │
├────────────────────┤
│ ▓▓▓ OCCUPÉ ▓▓▓     │ ← ptr = 0x5000
│ Valeur: 42         │
└────────────────────┘

free(ptr) :

HEAP :
┌────────────────────┐
│ Métadonnées (MAJ)  │ ← Marqué comme libre
├────────────────────┤
│ ░░░ LIBÉRÉ ░░░     │ ← Peut être réutilisé
│ (contenu indéfini) │
└────────────────────┘

ptr = 0x5000  ← DANGLING POINTER (dangereux !)

ptr = NULL :

ptr = NULL  ← Sûr : ne pointe plus nulle part
```

### 3.3 Les 3 Erreurs MORTELLES

**Erreur 1 : Double Free**

```c
int *ptr = malloc(sizeof(int));
free(ptr);
free(ptr);  // ❌ ERREUR : Déjà libéré !
// CRASH ou corruption du heap
```

**Schéma du problème :**
```
Premier free(ptr) :
┌────────────────┐
│ LIBÉRÉ ✅      │
└────────────────┘

Second free(ptr) :
┌────────────────┐
│ CORROMPU ❌    │ ← Métadonnées détruites
└────────────────┘
    ↓
  CRASH
```

**Erreur 2 : Use-After-Free**

```c
int *ptr = malloc(sizeof(int));
*ptr = 42;
free(ptr);
printf("%d\n", *ptr);  // ❌ ERREUR : Mémoire libérée !
```

**Schéma du problème :**
```
APRÈS free(ptr) :

ptr = 0x5000  (toujours non-NULL)
         ↓
0x5000  ┌────────┐
        │  ???   │ ← Mémoire libérée (peut être réallouée)
        └────────┘

Accès : *ptr
  ↓
Comportement INDÉFINI :
- Peut afficher garbage
- Peut afficher la nouvelle valeur si réalloué
- Peut crasher
```

**Erreur 3 : Memory Leak**

```c
int *ptr = malloc(sizeof(int));
ptr = NULL;  // ❌ ERREUR : Adresse perdue, impossible de free() !
```

**Schéma du problème :**
```
AVANT :
┌──────────┐         ┌──────────────┐
│ ptr      │────────→│ Bloc alloué  │
└──────────┘         └──────────────┘

ptr = NULL :
┌──────────┐         ┌──────────────┐
│ ptr=NULL │  X      │ Bloc alloué  │ ← ORPHELIN !
└──────────┘         └──────────────┘

Impossible de libérer → MEMORY LEAK
```

---

## 4. calloc() - malloc() avec Initialisation

```c
void* calloc(size_t nmemb, size_t size);
```

Alloue ET initialise à ZÉRO.

```c
// malloc : contenu indéfini
int *arr1 = malloc(sizeof(int) * 5);
// arr1[0] = ???, arr1[1] = ???, ...

// calloc : tout à zéro
int *arr2 = calloc(5, sizeof(int));
// arr2[0] = 0, arr2[1] = 0, arr2[2] = 0, ...
```

**Schéma comparatif :**
```
malloc(20) :
┌────┬────┬────┬────┬────┐
│ ?? │ ?? │ ?? │ ?? │ ?? │  ← Garbage
└────┴────┴────┴────┴────┘

calloc(5, 4) :
┌────┬────┬────┬────┬────┐
│  0 │  0 │  0 │  0 │  0 │  ← Initialisé
└────┴────┴────┴────┴────┘
```

---

## 5. realloc() - Redimensionner

```c
void* realloc(void *ptr, size_t new_size);
```

Redimensionne un bloc existant.

```c
int *arr = malloc(sizeof(int) * 5);  // 5 éléments

// Besoin de plus d'espace
arr = realloc(arr, sizeof(int) * 10);  // 10 éléments

// TOUJOURS vérifier NULL
if (arr == NULL) {
    // Échec, ancien bloc toujours valide
}
```

**Schéma realloc() :**
```
CAS 1 : Espace disponible après le bloc

AVANT :
┌──────────┬─────────────┐
│ 5 ints   │  libre      │
└──────────┴─────────────┘
  0x5000

realloc(arr, 10*sizeof(int)) :

APRÈS :
┌────────────────────────┐
│ 10 ints (étendu)       │ ← Même adresse (0x5000)
└────────────────────────┘

════════════════════════════════

CAS 2 : Pas d'espace (déplacement)

AVANT :
┌──────────┬──────┐
│ 5 ints   │occupé│
└──────────┴──────┘
  0x5000

realloc() cherche un nouveau bloc :

APRÈS :
┌──────────┬──────┬────────────────────────┐
│░ libéré ░│occupé│  10 ints (nouveau)     │
└──────────┴──────┴────────────────────────┘
                   0x7000 ← Nouvelle adresse !

Anciennes données COPIÉES automatiquement
```

---

## 6. mmap() et VirtualAlloc() - Allocation Bas-Niveau

### 6.1 mmap() (Linux/macOS)

```c
#include <sys/mman.h>

void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

if (addr == MAP_FAILED) {
    perror("mmap");
    exit(1);
}

// Utilisation
strcpy(addr, "Hello mmap");

// Libération
munmap(addr, 4096);
```

**Permissions :**
- `PROT_READ` : Lecture
- `PROT_WRITE` : Écriture
- `PROT_EXEC` : Exécution (shellcode !)

### 6.2 VirtualAlloc() (Windows)

```c
#include <windows.h>

LPVOID addr = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE);

if (addr == NULL) {
    fprintf(stderr, "VirtualAlloc failed\n");
    exit(1);
}

// Utilisation
memcpy(addr, shellcode, sizeof(shellcode));

// Exécution
((void(*)())addr)();

// Libération
VirtualFree(addr, 0, MEM_RELEASE);
```

---

## 7. Application Red Team

### 7.1 Shellcode Injection

```c
// Allouer mémoire exécutable
void *exec_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// Copier shellcode
unsigned char shellcode[] = "\x90\x90\xcc";  // NOP NOP INT3
memcpy(exec_mem, shellcode, sizeof(shellcode));

// Exécuter
void (*run)() = (void(*)())exec_mem;
run();
```

### 7.2 Heap Spray

```c
// Technique : Remplir le heap avec du shellcode

for (int i = 0; i < 1000; i++) {
    void *ptr = malloc(0x1000);
    memset(ptr, 0x90, 0x1000);  // NOP sled
    memcpy(ptr + 0x800, shellcode, sizeof(shellcode));
    // Ne pas free() volontairement
}

// Espoir : jump aléatoire atterrit dans notre shellcode
```

### 7.3 Use-After-Free Exploitation

```c
struct vtable {
    void (*func1)();
    void (*func2)();
};

struct Object {
    struct vtable *vptr;
    int data;
};

struct Object *obj = malloc(sizeof(struct Object));
obj->vptr = &legitimate_vtable;

free(obj);  // Vulnérabilité

// Réallouer la même zone avec nos données
struct Object *evil = malloc(sizeof(struct Object));
evil->vptr = &malicious_vtable;  // Pointeur vers notre code

obj->vptr->func1();  // Exécute notre code !
```

---

## 8. Checklist de Compréhension

- [ ] Différence entre Stack et Heap ?
- [ ] Pourquoi malloc() peut retourner NULL ?
- [ ] Que se passe-t-il si on oublie free() ?
- [ ] C'est quoi un double-free ?
- [ ] Pourquoi `ptr = NULL` après free() ?
- [ ] Différence calloc() vs malloc() ?
- [ ] Comment realloc() fonctionne ?
- [ ] À quoi sert mmap() / VirtualAlloc() ?

---

## 9. Exercices Pratiques

Voir `exercice.txt` pour :
- Allocation dynamique de tableaux
- Détection de memory leaks avec valgrind
- Simuler un use-after-free
- Créer une structure de données dynamique (linked list)

**Debug avec Valgrind :**
```bash
gcc -g program.c -o program
valgrind --leak-check=full ./program
```

---

**Prochaine étape :** Module 14 - Structures et Unions (struct, union, typedef, padding).

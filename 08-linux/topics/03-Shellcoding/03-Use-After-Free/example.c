/*
 * OBJECTIF  : Comprendre les vulnerabilites Use-After-Free (UAF)
 * PREREQUIS : Bases C, malloc/free, heap internals
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre le concept de Use-After-Free : utiliser
 * un pointeur apres qu'il a ete libere, comment le heap recycle
 * les chunks, et comment cela mene a une exploitation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Structure simulant un objet utilisateur */
typedef struct {
    char name[32];
    int privilege_level;
    void (*greet)(const char *);
} User;

static void normal_greet(const char *name) {
    printf("      Bonjour, %s (utilisateur normal)\n", name);
}

static void admin_greet(const char *name) {
    printf("      [ADMIN] Bienvenue, %s ! Acces total accorde.\n", name);
}

/*
 * Etape 1 : Comprendre le probleme UAF
 */
static void explain_uaf(void) {
    printf("[*] Etape 1 : Qu'est-ce qu'un Use-After-Free ?\n\n");

    printf("    Use-After-Free (UAF) = utiliser un pointeur apres free()\n\n");

    printf("    Etapes d'un UAF :\n");
    printf("    1. ptr = malloc(size)     <- Allocation\n");
    printf("    2. free(ptr)              <- Liberation\n");
    printf("    3. ptr->field = value     <- UAF ! Le pointeur est 'dangling'\n\n");

    printf("    Pourquoi c'est dangereux :\n");
    printf("    - Le heap recycle la memoire liberee\n");
    printf("    - Un nouvel objet peut occuper la meme adresse\n");
    printf("    - L'ancien pointeur modifie le nouvel objet\n\n");
}

/*
 * Etape 2 : Demonstration simple de recyclage
 */
static void demo_recycling(void) {
    printf("[*] Etape 2 : Recyclage des chunks heap\n\n");

    char *a = malloc(48);
    printf("    malloc(48) = %p [a]\n", (void *)a);
    strcpy(a, "Premier objet");

    free(a);
    printf("    free(a)\n");

    char *b = malloc(48);
    printf("    malloc(48) = %p [b]", (void *)b);
    if (b == a)
        printf("  <- MEME ADRESSE que a !");
    printf("\n");

    /* a est un dangling pointer - il pointe vers la meme memoire que b */
    strcpy(b, "Deuxieme objet");
    printf("    b contient : \"%s\"\n", b);
    printf("    a contient : \"%s\"  (via dangling pointer !)\n\n", a);

    free(b);
}

/*
 * Etape 3 : UAF avec des structures (exploitation type confusion)
 */
static void demo_type_confusion(void) {
    printf("[*] Etape 3 : UAF avec type confusion\n\n");

    /* Creer un utilisateur normal */
    User *user = malloc(sizeof(User));
    strcpy(user->name, "Alice");
    user->privilege_level = 0;
    user->greet = normal_greet;

    printf("    Utilisateur cree :\n");
    printf("      Nom      : %s\n", user->name);
    printf("      Privilege : %d\n", user->privilege_level);
    printf("      Greet    : %p (normal_greet)\n", (void *)user->greet);
    user->greet(user->name);
    printf("\n");

    /* Liberer l'utilisateur (mais garder le pointeur !) */
    printf("    free(user) -- mais on garde le pointeur !\n\n");
    free(user);

    /* Allouer un nouveau bloc de MEME TAILLE avec des donnees controlees */
    printf("    Allocation d'un bloc de meme taille avec des donnees malveillantes :\n");
    User *evil = malloc(sizeof(User));
    printf("    evil = %p", (void *)evil);
    if ((void *)evil == (void *)user)
        printf("  <- MEME ADRESSE que user !");
    printf("\n");

    /* Remplir avec des donnees d'admin */
    strcpy(evil->name, "Hacker");
    evil->privilege_level = 9999;
    evil->greet = admin_greet;

    /* Utiliser l'ancien pointeur (UAF !) */
    printf("\n    Acces via l'ancien pointeur user (UAF) :\n");
    printf("      Nom      : %s\n", user->name);
    printf("      Privilege : %d\n", user->privilege_level);
    printf("      Greet    : %p (admin_greet !)\n", (void *)user->greet);
    user->greet(user->name);
    printf("    [!] L'ancien user a ete transforme en admin via UAF !\n\n");

    free(evil);
}

/*
 * Etape 4 : UAF avec pointeur de fonction (code execution)
 */
static void demo_code_execution(void) {
    printf("[*] Etape 4 : UAF -> execution de code arbitraire\n\n");

    typedef struct {
        char data[24];
        void (*callback)(void);
    } Obj;

    void safe_callback(void) {
        printf("      [safe] Callback normal execute\n");
    }
    void evil_callback(void) {
        printf("      [EVIL] Code arbitraire execute via UAF !\n");
    }

    /* Creer et utiliser l'objet normalement */
    Obj *obj = malloc(sizeof(Obj));
    strcpy(obj->data, "legitimate data");
    obj->callback = safe_callback;

    printf("    Objet cree : callback = %p\n", (void *)obj->callback);
    obj->callback();

    /* Free */
    free(obj);

    /* Allouer un nouveau bloc et ecraser le callback */
    char *fake = malloc(sizeof(Obj));
    memset(fake, 0, sizeof(Obj));
    /* Ecrire l'adresse de evil_callback a l'offset du callback */
    void (*evil_ptr)(void) = evil_callback;
    memcpy(fake + 24, &evil_ptr, sizeof(evil_ptr));

    /* Appeler via le dangling pointer */
    printf("    Apres UAF : callback = %p\n", (void *)obj->callback);
    obj->callback();
    printf("    [!] Le pointeur de fonction a ete redirige !\n\n");

    free(fake);
}

/*
 * Etape 5 : Prevention
 */
static void explain_prevention(void) {
    printf("[*] Etape 5 : Prevention des UAF\n\n");

    printf("    1. Mettre le pointeur a NULL apres free() :\n");
    printf("       free(ptr);\n");
    printf("       ptr = NULL;  // Plus de dangling pointer\n\n");

    printf("    2. Utiliser des smart pointers (C++) ou RAII\n\n");

    printf("    3. Address Sanitizer (ASan) :\n");
    printf("       gcc -fsanitize=address -o prog prog.c\n");
    printf("       Detecte les UAF a l'execution\n\n");

    printf("    4. Valgrind :\n");
    printf("       valgrind --tool=memcheck ./prog\n");
    printf("       Detecte les acces memoire invalides\n\n");

    printf("    5. Hardened allocators (jemalloc, hardened_malloc)\n");
    printf("       Rendent l'exploitation plus difficile\n\n");
}

int main(void) {
    printf("[*] Demo : Use-After-Free (UAF)\n\n");

    explain_uaf();
    demo_recycling();
    demo_type_confusion();
    demo_code_execution();
    explain_prevention();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

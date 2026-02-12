/*
 * OBJECTIF  : Comprendre les shared libraries et LD_PRELOAD sous Linux
 * PREREQUIS : Bases C, compilation gcc, fonctionnement du linker
 * COMPILE   :
 *   Programme principal : gcc -o example example.c -ldl
 *   Hook library       : gcc -shared -fPIC -o hook.so hook_demo.c -ldl
 *   Utilisation         : LD_PRELOAD=./hook.so ./example
 *
 * Ce programme demontre le fonctionnement des bibliotheques partagees,
 * comment charger dynamiquement des .so avec dlopen/dlsym, et comment
 * LD_PRELOAD permet de hooker des fonctions systeme.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <link.h>

/*
 * Etape 1 : Lister les bibliotheques chargees par notre processus
 * dl_iterate_phdr parcourt chaque objet ELF charge en memoire
 */
static int list_loaded_libs(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    int *count = (int *)data;

    if (info->dlpi_name && info->dlpi_name[0]) {
        printf("    [%d] %s (base: %p)\n", *count, info->dlpi_name,
               (void *)info->dlpi_addr);
        (*count)++;
    }
    return 0;
}

/*
 * Etape 2 : Charger dynamiquement une bibliotheque avec dlopen/dlsym
 * C'est le mecanisme utilise par les loaders de plugins
 */
static void demo_dlopen(void) {
    printf("[*] Etape 2 : Chargement dynamique avec dlopen/dlsym\n\n");

    /* Charger la libc (deja chargee, mais on obtient un handle) */
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
        printf("    [-] dlopen echoue : %s\n", dlerror());
        printf("    (normal sur certains systemes, libc peut avoir un autre nom)\n\n");
        return;
    }

    /* Resoudre le symbole 'getpid' dans la libc */
    typedef pid_t (*getpid_fn)(void);
    getpid_fn my_getpid = (getpid_fn)dlsym(handle, "getpid");
    if (!my_getpid) {
        printf("    [-] dlsym echoue : %s\n", dlerror());
        dlclose(handle);
        return;
    }

    printf("    Adresse de getpid resolue : %p\n", (void *)my_getpid);
    printf("    Appel via dlsym : PID = %d\n", my_getpid());
    printf("    Appel direct    : PID = %d\n", getpid());
    printf("    (les deux doivent etre identiques)\n\n");

    /* Resoudre 'puts' pour afficher un message */
    typedef int (*puts_fn)(const char *);
    puts_fn my_puts = (puts_fn)dlsym(handle, "puts");
    if (my_puts) {
        printf("    Appel de puts() via dlsym :\n    ");
        my_puts(">>> Message affiche via dlsym(handle, \"puts\")");
    }

    dlclose(handle);
    printf("\n");
}

/*
 * Etape 3 : Resoudre des symboles avec RTLD_NEXT
 * RTLD_NEXT cherche le symbole dans la PROCHAINE bibliotheque
 * C'est la base du hooking via LD_PRELOAD
 */
static void demo_rtld_next(void) {
    printf("[*] Etape 3 : Resolution avec RTLD_NEXT\n\n");

    /* Trouver la 'vraie' fonction write dans la libc */
    typedef ssize_t (*write_fn)(int, const void *, size_t);
    write_fn real_write = (write_fn)dlsym(RTLD_NEXT, "write");

    if (real_write) {
        const char *msg = "    >>> Ecrit directement via le pointeur real_write\n";
        real_write(STDOUT_FILENO, msg, strlen(msg));
    } else {
        printf("    [-] dlsym(RTLD_NEXT, \"write\") echoue : %s\n", dlerror());
    }
    printf("\n");
}

/*
 * Etape 4 : Verifier si LD_PRELOAD est actif
 * Un programme peut detecter s'il est hooke en verifiant cette variable
 */
static void check_ld_preload(void) {
    printf("[*] Etape 4 : Detection de LD_PRELOAD\n\n");

    const char *preload = getenv("LD_PRELOAD");
    if (preload) {
        printf("    [!] LD_PRELOAD detecte : %s\n", preload);
        printf("    Des fonctions de ce programme sont potentiellement hookees !\n");
    } else {
        printf("    [+] Aucun LD_PRELOAD actif\n");
        printf("    Pour tester le hooking, creez un fichier hook_demo.c :\n\n");
        printf("    --- hook_demo.c ---\n");
        printf("    #define _GNU_SOURCE\n");
        printf("    #include <stdio.h>\n");
        printf("    #include <dlfcn.h>\n");
        printf("    #include <unistd.h>\n");
        printf("    #include <string.h>\n\n");
        printf("    /* Hook de write() : intercepte tous les appels ecriture */\n");
        printf("    ssize_t write(int fd, const void *buf, size_t count) {\n");
        printf("        typedef ssize_t (*orig_fn)(int, const void *, size_t);\n");
        printf("        orig_fn orig = (orig_fn)dlsym(RTLD_NEXT, \"write\");\n");
        printf("        if (fd == STDOUT_FILENO) {\n");
        printf("            const char *tag = \"[HOOKED] \";\n");
        printf("            orig(fd, tag, strlen(tag));\n");
        printf("        }\n");
        printf("        return orig(fd, buf, count);\n");
        printf("    }\n");
        printf("    ---\n\n");
        printf("    Compiler : gcc -shared -fPIC -o hook.so hook_demo.c -ldl\n");
        printf("    Utiliser : LD_PRELOAD=./hook.so ./example\n");
    }
    printf("\n");
}

/*
 * Etape 5 : Afficher les informations de resolution des symboles
 * Permet de comprendre comment le linker resout les appels
 */
static void demo_symbol_info(void) {
    printf("[*] Etape 5 : Informations sur les symboles\n\n");

    Dl_info info;
    /* Trouver dans quel .so se trouve printf */
    if (dladdr((void *)printf, &info)) {
        printf("    printf() :\n");
        printf("      Fichier  : %s\n", info.dli_fname);
        printf("      Base     : %p\n", info.dli_fbase);
        printf("      Symbole  : %s\n", info.dli_sname ? info.dli_sname : "(inconnu)");
        printf("      Adresse  : %p\n", info.dli_saddr);
    }

    /* Trouver dans quel .so se trouve malloc */
    if (dladdr((void *)malloc, &info)) {
        printf("\n    malloc() :\n");
        printf("      Fichier  : %s\n", info.dli_fname);
        printf("      Symbole  : %s\n", info.dli_sname ? info.dli_sname : "(inconnu)");
        printf("      Adresse  : %p\n", info.dli_saddr);
    }

    /* Trouver ou se trouve notre propre main */
    if (dladdr((void *)main, &info)) {
        printf("\n    main() :\n");
        printf("      Fichier  : %s\n", info.dli_fname);
        printf("      Symbole  : %s\n", info.dli_sname ? info.dli_sname : "(inconnu)");
        printf("      Adresse  : %p\n", info.dli_saddr);
    }
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Shared Libraries - dlopen, dlsym, LD_PRELOAD\n\n");

    /* Etape 1 : Lister les bibliotheques chargees */
    printf("[*] Etape 1 : Bibliotheques partagees chargees\n\n");
    int count = 0;
    dl_iterate_phdr(list_loaded_libs, &count);
    printf("    Total : %d bibliotheques\n\n", count);

    /* Etape 2 : dlopen / dlsym */
    demo_dlopen();

    /* Etape 3 : RTLD_NEXT */
    demo_rtld_next();

    /* Etape 4 : Detection LD_PRELOAD */
    check_ld_preload();

    /* Etape 5 : Informations symboles */
    demo_symbol_info();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

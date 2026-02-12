/*
 * OBJECTIF  : Comprendre le hooking de syscalls en userland (GOT/PLT)
 * PREREQUIS : Bases C, ELF format, liaison dynamique
 * COMPILE   : gcc -o example example.c -ldl
 *
 * Ce programme demontre comment les appels de fonctions sont resolus
 * via la GOT/PLT, comment localiser la GOT en memoire, et le
 * principe du hooking en userland. Pour le LD_PRELOAD, voir le
 * module 05-Shared-Libraries.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <link.h>

/*
 * Etape 1 : Comprendre la GOT et la PLT
 *
 * Quand un programme appelle printf(), il passe par :
 *   1. La PLT (Procedure Linkage Table) - un trampoline
 *   2. La GOT (Global Offset Table) - contient l'adresse reelle
 *
 * Au premier appel, la GOT pointe vers le resolver du linker
 * Apres resolution, la GOT contient l'adresse reelle de printf
 */
static void explain_got_plt(void) {
    printf("[*] Etape 1 : Comprendre GOT/PLT\n\n");

    printf("    Flux d'un appel a printf() :\n");
    printf("    ┌──────────────────┐\n");
    printf("    │ call printf@PLT  │  <- Code de votre programme\n");
    printf("    └────────┬─────────┘\n");
    printf("             v\n");
    printf("    ┌──────────────────┐\n");
    printf("    │ PLT stub:        │  <- Trampoline dans la PLT\n");
    printf("    │ jmp *GOT[printf] │\n");
    printf("    └────────┬─────────┘\n");
    printf("             v\n");
    printf("    ┌──────────────────┐\n");
    printf("    │ GOT[printf]      │  <- Adresse reelle de printf\n");
    printf("    │ = 0x7f...        │     dans la libc\n");
    printf("    └──────────────────┘\n\n");

    printf("    Si on ecrase GOT[printf] avec notre adresse,\n");
    printf("    tous les appels a printf() iront vers notre fonction !\n\n");
}

/*
 * Etape 2 : Trouver les adresses reelles des fonctions via dlsym
 * dlsym permet de resoudre l'adresse d'un symbole dans une shared library
 */
static void show_function_addresses(void) {
    printf("[*] Etape 2 : Adresses des fonctions (resolution dynamique)\n\n");

    /* Adresse de printf telle que vue par le programme */
    printf("    printf  (adresse directe)  : %p\n", (void *)printf);
    printf("    puts    (adresse directe)  : %p\n", (void *)puts);
    printf("    malloc  (adresse directe)  : %p\n", (void *)malloc);
    printf("    write   (adresse directe)  : %p\n", (void *)(ssize_t(*)(int, const void *, size_t))write);

    /* Resoudre avec dlsym - devrait donner la meme adresse */
    void *real_printf = dlsym(RTLD_NEXT, "printf");
    void *real_puts = dlsym(RTLD_NEXT, "puts");
    printf("\n    printf  (via dlsym NEXT)   : %p\n", real_printf);
    printf("    puts    (via dlsym NEXT)   : %p\n", real_puts);

    /* Verifier si les adresses correspondent */
    Dl_info info;
    if (dladdr((void *)printf, &info)) {
        printf("\n    printf provient de : %s\n", info.dli_fname);
        printf("    Base de la libc    : %p\n", info.dli_fbase);
    }
    printf("\n");
}

/*
 * Etape 3 : Lister les sections ELF de notre propre binaire
 * Pour le hooking GOT, il faut trouver la section .got.plt
 */
static int show_elf_sections(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;

    /* On s'interesse seulement a notre propre binaire (nom vide) */
    if (info->dlpi_name[0] != '\0')
        return 0;

    printf("    Programme principal (base: %p) :\n", (void *)info->dlpi_addr);

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr *phdr = &info->dlpi_phdr[i];
        const char *type_name;

        switch (phdr->p_type) {
        case PT_LOAD:    type_name = "LOAD";    break;
        case PT_DYNAMIC: type_name = "DYNAMIC"; break;
        case PT_GNU_RELRO: type_name = "RELRO"; break;
        case PT_GNU_STACK: type_name = "STACK";  break;
        default:         type_name = "OTHER";   break;
        }

        if (phdr->p_type == PT_LOAD || phdr->p_type == PT_DYNAMIC ||
            phdr->p_type == PT_GNU_RELRO) {
            printf("      [%d] %-8s  vaddr=0x%lx  memsz=0x%lx  flags=%c%c%c\n",
                   i, type_name,
                   (unsigned long)phdr->p_vaddr,
                   (unsigned long)phdr->p_memsz,
                   (phdr->p_flags & PF_R) ? 'R' : '-',
                   (phdr->p_flags & PF_W) ? 'W' : '-',
                   (phdr->p_flags & PF_X) ? 'X' : '-');
        }
    }
    printf("\n");
    return 0;
}

/*
 * Etape 4 : Demonstration du hooking par remplacement de pointeur
 * On simule le concept de GOT overwrite avec des pointeurs de fonctions
 */

/* Fonctions originales simulees */
static int original_auth(const char *user, const char *pass) {
    return (strcmp(user, "admin") == 0 && strcmp(pass, "secret123") == 0);
}

/* Fonction hook : accepte tout le monde */
static int hooked_auth(const char *user, const char *pass) {
    (void)pass;
    printf("      [HOOK] Authentification interceptee pour: %s\n", user);
    printf("      [HOOK] Mot de passe capture: %s\n", pass);
    return 1;  /* Toujours accepter */
}

/* Table de fonctions simulant la GOT */
static struct {
    int (*authenticate)(const char *, const char *);
} function_table = {
    .authenticate = original_auth
};

static void demo_got_concept(void) {
    printf("[*] Etape 4 : Simulation de hooking GOT\n\n");

    /* Avant le hook */
    printf("    Avant le hook :\n");
    printf("      authenticate pointe vers : %p (original)\n",
           (void *)function_table.authenticate);

    int result = function_table.authenticate("admin", "wrong_pass");
    printf("      auth(\"admin\", \"wrong_pass\") = %d (attendu: 0)\n", result);

    result = function_table.authenticate("admin", "secret123");
    printf("      auth(\"admin\", \"secret123\")  = %d (attendu: 1)\n\n", result);

    /* Remplacer le pointeur (equivalent d'un GOT overwrite) */
    printf("    Hook : remplacement du pointeur de fonction\n");
    function_table.authenticate = hooked_auth;
    printf("      authenticate pointe vers : %p (hook)\n\n",
           (void *)function_table.authenticate);

    /* Apres le hook */
    printf("    Apres le hook :\n");
    result = function_table.authenticate("admin", "wrong_pass");
    printf("      auth(\"admin\", \"wrong_pass\") = %d (attendu: 1 - hooked!)\n", result);

    result = function_table.authenticate("hacker", "anything");
    printf("      auth(\"hacker\", \"anything\")  = %d (attendu: 1 - hooked!)\n\n", result);

    /* Restaurer */
    function_table.authenticate = original_auth;
    printf("    Pointeur restaure vers la fonction originale\n\n");
}

/*
 * Etape 5 : Verifier RELRO (read-only relocations)
 * RELRO protege la GOT contre l'ecriture
 */
static void check_relro(void) {
    printf("[*] Etape 5 : Verification de RELRO\n\n");

    printf("    RELRO (RELocation Read-Only) protege la GOT :\n");
    printf("    - Partial RELRO : .got.plt est encore writable\n");
    printf("    - Full RELRO    : toute la GOT est read-only\n\n");

    /* Lire /proc/self/maps pour verifier les permissions */
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        printf("    (verification via /proc non disponible)\n\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        /* Chercher les regions liees au programme */
        if (strstr(line, "example") || strstr(line, "[heap]") || strstr(line, "[stack]")) {
            printf("    %s", line);
        }
    }
    fclose(fp);

    printf("\n    Pour compiler sans RELRO : gcc -Wl,-z,norelro ...\n");
    printf("    Pour Full RELRO         : gcc -Wl,-z,relro,-z,now ...\n\n");
}

int main(void) {
    printf("[*] Demo : Syscall Hooking Userland - GOT/PLT\n\n");

    explain_got_plt();
    show_function_addresses();

    printf("[*] Etape 3 : Sections ELF du programme\n\n");
    dl_iterate_phdr(show_elf_sections, NULL);

    demo_got_concept();
    check_relro();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

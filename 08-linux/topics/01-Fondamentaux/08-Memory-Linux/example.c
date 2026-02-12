/*
 * OBJECTIF  : Comprendre la gestion memoire bas niveau sous Linux
 * PREREQUIS : Bases C, notions de memoire virtuelle
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre mmap(), mprotect(), la lecture de /proc/self/maps,
 * et comment creer des zones memoire executables pour comprendre
 * les techniques utilisees en exploitation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

/*
 * Etape 1 : Afficher le layout memoire du processus
 * Chaque processus a son propre espace d'adressage virtuel
 */
static void show_memory_layout(void) {
    printf("[*] Etape 1 : Layout memoire du processus\n\n");

    /* Variables dans differentes sections */
    static int data_var = 42;          /* Section .data (initialisee) */
    static int bss_var;                /* Section .bss (non-initialisee) */
    int stack_var = 123;               /* Stack */
    int *heap_var = malloc(sizeof(int)); /* Heap */
    *heap_var = 456;

    printf("    Adresses des differentes regions :\n");
    printf("    Code  (main)     : %p\n", (void *)main);
    printf("    Data  (init)     : %p  (valeur=%d)\n", (void *)&data_var, data_var);
    printf("    BSS   (non-init) : %p  (valeur=%d)\n", (void *)&bss_var, bss_var);
    printf("    Heap  (malloc)   : %p  (valeur=%d)\n", (void *)heap_var, *heap_var);
    printf("    Stack (locale)   : %p  (valeur=%d)\n", (void *)&stack_var, stack_var);
    printf("\n");

    printf("    Ordre en memoire (adresses basses -> hautes) :\n");
    printf("    Code < Data < BSS < Heap ... Stack\n");
    printf("    %p < %p < %p < %p ... %p\n\n",
           (void *)main, (void *)&data_var, (void *)&bss_var,
           (void *)heap_var, (void *)&stack_var);

    free(heap_var);
}

/*
 * Etape 2 : Lire /proc/self/maps pour voir les mappings memoire
 */
static void show_proc_maps(void) {
    printf("[*] Etape 2 : Mappings memoire (/proc/self/maps)\n\n");

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        printf("    [-] Impossible de lire /proc/self/maps\n");
        printf("    (fonctionne uniquement sur Linux)\n\n");
        return;
    }

    printf("    Adresse debut-fin      Perms  Description\n");
    printf("    %-20s  %-5s  %s\n", "---", "---", "---");

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < 15) {
        /* Supprimer le newline */
        line[strcspn(line, "\n")] = '\0';
        printf("    %s\n", line);
        count++;
    }
    if (count >= 15)
        printf("    ... (tronque)\n");

    fclose(fp);
    printf("\n");
}

/*
 * Etape 3 : Allocation memoire avec mmap()
 * mmap est plus flexible que malloc : on controle les permissions
 */
static void demo_mmap(void) {
    printf("[*] Etape 3 : Allocation avec mmap()\n\n");

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    printf("    Taille d'une page memoire : %zu octets\n\n", page_size);

    /* Allouer une page en lecture/ecriture */
    void *mem = mmap(NULL,                   /* Adresse : le kernel choisit */
                     page_size,              /* Taille : 1 page */
                     PROT_READ | PROT_WRITE, /* Permissions : lire + ecrire */
                     MAP_PRIVATE | MAP_ANONYMOUS, /* Pas de fichier */
                     -1,                     /* Pas de file descriptor */
                     0);                     /* Offset */

    if (mem == MAP_FAILED) {
        perror("    mmap");
        return;
    }

    printf("    mmap alloue a l'adresse : %p\n", mem);

    /* Ecrire et lire dans la zone */
    strcpy((char *)mem, "Hello from mmap!");
    printf("    Contenu ecrit : \"%s\"\n", (char *)mem);

    /* Liberer avec munmap (pas free!) */
    munmap(mem, page_size);
    printf("    Zone liberee avec munmap()\n\n");
}

/*
 * Etape 4 : Modifier les permissions memoire avec mprotect()
 * Permet de rendre une zone executable, ou de retirer l'ecriture
 */
static void demo_mprotect(void) {
    printf("[*] Etape 4 : Modification des permissions avec mprotect()\n\n");

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);

    /* Allouer en lecture/ecriture */
    void *mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("    mmap");
        return;
    }

    printf("    Zone allouee en RW a %p\n", mem);
    strcpy((char *)mem, "Donnees sensibles");
    printf("    Ecriture OK : \"%s\"\n", (char *)mem);

    /* Rendre la zone en lecture seule */
    if (mprotect(mem, page_size, PROT_READ) == 0) {
        printf("    mprotect -> READ ONLY\n");
        printf("    Lecture OK : \"%s\"\n", (char *)mem);
        printf("    (une ecriture provoquerait un SIGSEGV)\n");
    } else {
        perror("    mprotect READ");
    }

    /* Rendre la zone executable (base du shellcode injection) */
    if (mprotect(mem, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        printf("    mprotect -> READ + WRITE + EXEC (RWX)\n");
        printf("    [!] Zone maintenant executable - typique de l'injection shellcode\n");
    } else {
        perror("    mprotect RWX");
    }

    /* Retirer tous les droits */
    if (mprotect(mem, page_size, PROT_NONE) == 0) {
        printf("    mprotect -> NONE (aucun acces)\n");
        printf("    (tout acces provoquerait un SIGSEGV)\n");
    }

    munmap(mem, page_size);
    printf("\n");
}

/*
 * Etape 5 : Mapper un fichier en memoire (file-backed mmap)
 * Permet de lire un fichier comme un simple tableau en memoire
 */
static void demo_file_mmap(void) {
    printf("[*] Etape 5 : Mapping de fichier en memoire\n\n");

    const char *filepath = "/etc/hostname";
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        /* Fallback si /etc/hostname n'existe pas */
        filepath = "/etc/passwd";
        fd = open(filepath, O_RDONLY);
        if (fd < 0) {
            printf("    [-] Impossible d'ouvrir un fichier de test\n\n");
            return;
        }
    }

    /* Obtenir la taille du fichier */
    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    if (file_size <= 0) {
        printf("    [-] Fichier vide\n\n");
        close(fd);
        return;
    }

    /* Mapper le fichier en memoire en lecture seule */
    void *mapped = mmap(NULL, (size_t)file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (mapped == MAP_FAILED) {
        perror("    mmap fichier");
        return;
    }

    printf("    Fichier %s mappe a l'adresse %p (%ld octets)\n",
           filepath, mapped, (long)file_size);
    printf("    Premiers 80 caracteres :\n    ");

    /* Afficher les premiers caracteres */
    size_t show = (size_t)file_size < 80 ? (size_t)file_size : 80;
    for (size_t i = 0; i < show; i++) {
        char c = ((char *)mapped)[i];
        if (c == '\n')
            printf("\n    ");
        else
            putchar(c);
    }
    printf("\n");

    munmap(mapped, (size_t)file_size);
    printf("    Fichier demmappe\n\n");
}

/*
 * Etape 6 : Zone executable - base du shellcode
 * On ecrit du code machine et on l'execute depuis la zone allouee
 */
static void demo_executable_memory(void) {
    printf("[*] Etape 6 : Zone memoire executable (concept shellcode)\n\n");

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);

    /* Allouer une zone RWX */
    void *mem = mmap(NULL, page_size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("    mmap RWX");
        printf("    (certains systemes interdisent les allocations RWX)\n\n");
        return;
    }

    printf("    Zone RWX allouee a %p\n", mem);

    /*
     * Ecrire un mini "shellcode" x86_64 qui retourne simplement 42
     * Equivalent de : int func(void) { return 42; }
     *
     * Instructions assembleur :
     *   mov eax, 42    -> B8 2A 00 00 00
     *   ret            -> C3
     */
    unsigned char code[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,  /* mov eax, 42 */
        0xC3                             /* ret */
    };

    memcpy(mem, code, sizeof(code));
    printf("    Code machine ecrit : ");
    for (size_t i = 0; i < sizeof(code); i++)
        printf("%02X ", code[i]);
    printf("\n");

    /* Appeler le code comme une fonction */
    typedef int (*func_t)(void);
    func_t func = (func_t)mem;
    int result = func();

    printf("    Resultat de l'execution : %d (attendu: 42)\n", result);
    printf("    [+] Code execute directement depuis la memoire !\n");

    munmap(mem, page_size);
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Gestion Memoire Linux - mmap, mprotect, mappings\n\n");

    show_memory_layout();
    show_proc_maps();
    demo_mmap();
    demo_mprotect();
    demo_file_mmap();
    demo_executable_memory();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

/*
 * OBJECTIF  : Comprendre le developpement de shellcode sous Linux x86_64
 * PREREQUIS : Bases C, assembleur x86, appels systeme Linux
 * COMPILE   : gcc -o example example.c -z execstack
 *
 * Ce programme demontre comment les shellcodes fonctionnent :
 * ecriture en assembleur, encodage en octets, execution depuis
 * la memoire, et les contraintes (null-free, position-independent).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * Etape 1 : Qu'est-ce qu'un shellcode ?
 * Un shellcode = du code machine brut, executable directement en memoire
 */
static void explain_shellcode(void) {
    printf("[*] Etape 1 : Qu'est-ce qu'un shellcode ?\n\n");

    printf("    Un shellcode est une suite d'octets representant des\n");
    printf("    instructions machine directement executables.\n\n");

    printf("    Contraintes d'un bon shellcode :\n");
    printf("    1. Position-independent : fonctionne a n'importe quelle adresse\n");
    printf("    2. Null-free : pas de \\x00 (arret des fonctions string)\n");
    printf("    3. Compact : le plus petit possible\n");
    printf("    4. Autonome : pas de dependance a la libc\n\n");

    printf("    Syscalls x86_64 utilises :\n");
    printf("      RAX = numero du syscall\n");
    printf("      RDI = 1er argument\n");
    printf("      RSI = 2eme argument\n");
    printf("      RDX = 3eme argument\n");
    printf("      syscall instruction -> appel au kernel\n\n");
}

/*
 * Etape 2 : Shellcode "Hello World" - write(1, msg, len)
 * Syscall write = 1
 * RDI=1 (stdout), RSI=adresse du message, RDX=longueur
 */
static void demo_write_shellcode(void) {
    printf("[*] Etape 2 : Shellcode write() - afficher un message\n\n");

    /*
     * Assembleur equivalent :
     *   jmp short message       ; sauter au message
     * code:
     *   pop rsi                 ; RSI = adresse du message
     *   xor rax, rax            ; RAX = 0
     *   mov al, 1               ; RAX = 1 (sys_write)
     *   xor rdi, rdi            ; RDI = 0
     *   inc rdi                 ; RDI = 1 (stdout)
     *   xor rdx, rdx            ;
     *   mov dl, 14              ; RDX = 14 (longueur)
     *   syscall                 ; appel systeme
     *   xor rax, rax
     *   mov al, 60              ; RAX = 60 (sys_exit)
     *   xor rdi, rdi            ; RDI = 0 (code retour)
     *   syscall
     * message:
     *   call code               ; push adresse du message puis saute
     *   db "Hello, world!", 10  ; le message + newline
     */
    unsigned char shellcode[] =
        "\xeb\x1e"                     /* jmp short message */
        "\x5e"                         /* pop rsi */
        "\x48\x31\xc0"                 /* xor rax, rax */
        "\xb0\x01"                     /* mov al, 1 (sys_write) */
        "\x48\x31\xff"                 /* xor rdi, rdi */
        "\x48\xff\xc7"                 /* inc rdi (stdout) */
        "\x48\x31\xd2"                 /* xor rdx, rdx */
        "\xb2\x0e"                     /* mov dl, 14 (length) */
        "\x0f\x05"                     /* syscall */
        "\x48\x31\xc0"                 /* xor rax, rax */
        "\xb0\x3c"                     /* mov al, 60 (sys_exit) */
        "\x48\x31\xff"                 /* xor rdi, rdi */
        "\x0f\x05"                     /* syscall */
        "\xe8\xdd\xff\xff\xff"         /* call code */
        "Hello, world!\n";            /* le message */

    printf("    Shellcode (%zu octets) :\n    ", sizeof(shellcode) - 1);
    for (size_t i = 0; i < sizeof(shellcode) - 1; i++) {
        printf("\\x%02x", shellcode[i]);
        if ((i + 1) % 16 == 0)
            printf("\n    ");
    }
    printf("\n\n");

    /* Verifier les null bytes */
    int has_null = 0;
    for (size_t i = 0; i < sizeof(shellcode) - 1; i++) {
        if (shellcode[i] == 0x00) {
            has_null = 1;
            break;
        }
    }
    printf("    Null bytes : %s\n\n", has_null ? "OUI (problematique)" : "NON (ok)");
}

/*
 * Etape 3 : Executer un shellcode depuis la memoire
 * On alloue une zone RWX avec mmap et on y copie le shellcode
 */
static void demo_execute_shellcode(void) {
    printf("[*] Etape 3 : Execution de shellcode en memoire\n\n");

    /*
     * Shellcode simple : retourne 42
     * mov eax, 42 ; ret
     */
    unsigned char ret42[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,  /* mov eax, 42 */
        0xC3                             /* ret */
    };

    /* Allouer une page RWX */
    void *mem = mmap(NULL, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("    mmap");
        return;
    }

    /* Copier le shellcode */
    memcpy(mem, ret42, sizeof(ret42));

    /* Executer */
    typedef int (*func_t)(void);
    func_t func = (func_t)mem;
    int result = func();

    printf("    Shellcode 'ret42' execute : resultat = %d (attendu: 42)\n\n", result);

    /*
     * Shellcode : addition de deux nombres
     * Equivalent de : int add(int a, int b) { return a + b; }
     * x86_64 : a dans EDI, b dans ESI
     * mov eax, edi   ; eax = a
     * add eax, esi   ; eax = a + b
     * ret
     */
    unsigned char add_code[] = {
        0x89, 0xF8,   /* mov eax, edi */
        0x01, 0xF0,   /* add eax, esi */
        0xC3          /* ret */
    };

    memcpy(mem, add_code, sizeof(add_code));

    typedef int (*add_fn)(int, int);
    add_fn add = (add_fn)mem;

    printf("    Shellcode 'add' :\n");
    printf("      add(10, 32) = %d (attendu: 42)\n", add(10, 32));
    printf("      add(100, 200) = %d (attendu: 300)\n\n", add(100, 200));

    munmap(mem, 4096);
}

/*
 * Etape 4 : Techniques pour eviter les null bytes
 */
static void explain_null_free(void) {
    printf("[*] Etape 4 : Techniques null-free\n\n");

    printf("    Probleme : beaucoup d'instructions contiennent des \\x00\n\n");

    printf("    mov rax, 1      -> 48 B8 01 00 00 00 00 00 00 00  (plein de nulls!)\n");
    printf("    xor rax, rax    -> 48 31 C0  (aucun null)\n");
    printf("    mov al, 1       -> B0 01     (aucun null)\n\n");

    printf("    Techniques courantes :\n");
    printf("    1. xor reg, reg au lieu de mov reg, 0\n");
    printf("    2. Utiliser les registres 8/16 bits (al, ax) pour petites valeurs\n");
    printf("    3. push/pop au lieu de mov pour les grandes valeurs\n");
    printf("    4. Encodage XOR du shellcode entier\n\n");
}

/*
 * Etape 5 : Encodeur XOR simple
 * Encode le shellcode avec une cle, ajoute un decodeur au debut
 */
static void demo_xor_encoder(void) {
    printf("[*] Etape 5 : Encodeur XOR pour shellcode\n\n");

    unsigned char original[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
    unsigned char encoded[sizeof(original)];
    unsigned char key = 0x41;

    printf("    Original  : ");
    for (size_t i = 0; i < sizeof(original); i++)
        printf("%02X ", original[i]);
    printf("\n");

    /* Encoder avec XOR */
    for (size_t i = 0; i < sizeof(original); i++)
        encoded[i] = original[i] ^ key;

    printf("    Cle XOR   : 0x%02X\n", key);
    printf("    Encode    : ");
    for (size_t i = 0; i < sizeof(encoded); i++)
        printf("%02X ", encoded[i]);
    printf("\n");

    /* Decoder */
    unsigned char decoded[sizeof(original)];
    for (size_t i = 0; i < sizeof(encoded); i++)
        decoded[i] = encoded[i] ^ key;

    printf("    Decode    : ");
    for (size_t i = 0; i < sizeof(decoded); i++)
        printf("%02X ", decoded[i]);
    printf("\n");

    /* Verifier */
    if (memcmp(original, decoded, sizeof(original)) == 0)
        printf("    [+] Decodage correct !\n");
    else
        printf("    [-] Erreur de decodage\n");

    /* Verifier null-free de la version encodee */
    int has_null = 0;
    for (size_t i = 0; i < sizeof(encoded); i++) {
        if (encoded[i] == 0x00) { has_null = 1; break; }
    }
    printf("    Null-free : %s\n\n", has_null ? "NON" : "OUI");
}

int main(void) {
    printf("[*] Demo : Shellcode Linux x86_64\n\n");

    explain_shellcode();
    demo_write_shellcode();
    demo_execute_shellcode();
    explain_null_free();
    demo_xor_encoder();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

/*
 * OBJECTIF  : Comprendre les stack buffer overflows sous Linux
 * PREREQUIS : Bases C, layout memoire, assembleur basique
 * COMPILE   : gcc -o example example.c -fno-stack-protector -z execstack -no-pie
 *
 * Ce programme demontre le fonctionnement d'un stack overflow :
 * layout de la stack, ecrasement du return address, et les
 * protections modernes (canary, NX, ASLR, PIE).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/*
 * Etape 1 : Layout de la stack frame
 */
static void explain_stack_layout(void) {
    printf("[*] Etape 1 : Layout d'une stack frame\n\n");

    printf("    Adresses hautes\n");
    printf("    ┌──────────────────────┐\n");
    printf("    │  arguments (argc...) │\n");
    printf("    ├──────────────────────┤\n");
    printf("    │  return address      │  <- adresse de retour (RIP sauvegarde)\n");
    printf("    ├──────────────────────┤\n");
    printf("    │  saved RBP           │  <- ancien base pointer\n");
    printf("    ├──────────────────────┤\n");
    printf("    │  [canary]            │  <- stack protector (si active)\n");
    printf("    ├──────────────────────┤\n");
    printf("    │  variables locales   │  <- buf[64], etc.\n");
    printf("    │  ...                 │\n");
    printf("    └──────────────────────┘\n");
    printf("    Adresses basses (RSP)\n\n");

    printf("    Un overflow ecrit au-dela du buffer et ecrase :\n");
    printf("    1. Le canary (detection)\n");
    printf("    2. Le saved RBP\n");
    printf("    3. Le return address (redirection du flux)\n\n");
}

/*
 * Etape 2 : Fonction vulnerable - demonstration du layout
 */
static void __attribute__((noinline)) vulnerable_demo(void) {
    char buffer[64];
    int local_var = 0xDEAD;

    printf("[*] Etape 2 : Visualisation de la stack\n\n");

    printf("    Adresses dans la stack frame :\n");
    printf("      buffer     : %p\n", (void *)buffer);
    printf("      local_var  : %p\n", (void *)&local_var);
    printf("      Distance   : %ld octets\n\n", (long)((char *)&local_var - buffer));

    /* Montrer le contenu de la stack autour du buffer */
    printf("    Contenu de la stack (64 octets au-dessus du buffer) :\n    ");
    uint64_t *stack_ptr = (uint64_t *)buffer;
    for (int i = 0; i < 12; i++) {
        printf("    [buf+%02d] 0x%016lx\n", i * 8, (unsigned long)stack_ptr[i]);
    }
    printf("\n");
}

/*
 * Etape 3 : Simuler un overflow (sans crash)
 */
static void demo_overflow_concept(void) {
    printf("[*] Etape 3 : Simulation d'un overflow\n\n");

    struct {
        char buffer[16];
        int important_flag;
        char secret[16];
    } victim;

    victim.important_flag = 0;
    strcpy(victim.secret, "TOP_SECRET");
    memset(victim.buffer, 0, sizeof(victim.buffer));

    printf("    Avant overflow :\n");
    printf("      buffer          : \"%s\"\n", victim.buffer);
    printf("      important_flag  : %d\n", victim.important_flag);
    printf("      secret          : \"%s\"\n\n", victim.secret);

    /* Overflow : ecrire plus que 16 octets dans buffer */
    printf("    Ecriture de 20 octets dans buffer (capacite = 16) :\n");
    memcpy(victim.buffer, "AAAAAAAAAAAAAAAABBBB", 20);

    printf("    Apres overflow :\n");
    printf("      buffer          : \"%.16s\"\n", victim.buffer);
    printf("      important_flag  : 0x%X (= '%c%c%c%c')\n",
           victim.important_flag,
           victim.important_flag & 0xFF,
           (victim.important_flag >> 8) & 0xFF,
           (victim.important_flag >> 16) & 0xFF,
           (victim.important_flag >> 24) & 0xFF);
    printf("      [!] important_flag a ete ecrase par le debordement !\n\n");
}

/*
 * Etape 4 : Demonstration du controle de flux
 * On montre comment un overflow peut rediriger l'execution
 */
static void secret_function(void) {
    printf("      [!] SECRET : Cette fonction n'aurait pas du etre appelee !\n");
    printf("      [!] En exploitation reelle, ce serait du shellcode ou system()\n");
}

static void demo_control_flow(void) {
    printf("[*] Etape 4 : Controle du flux d'execution (concept)\n\n");

    /* Simuler avec des pointeurs de fonction */
    typedef void (*func_ptr)(void);

    struct {
        char buffer[32];
        func_ptr callback;
    } target;

    /* Normalement, callback pointe vers une fonction safe */
    target.callback = NULL;

    printf("    Structure avec buffer + pointeur de fonction :\n");
    printf("      buffer   a %p (32 octets)\n", (void *)target.buffer);
    printf("      callback a %p\n", (void *)&target.callback);
    printf("      Distance : %ld octets\n\n",
           (long)((char *)&target.callback - target.buffer));

    /* Ecrire l'adresse de secret_function dans callback via overflow */
    memset(target.buffer, 'A', 32);
    target.callback = secret_function;

    printf("    Apres overflow du buffer -> callback ecrase :\n");
    printf("      callback = %p (secret_function)\n", (void *)target.callback);

    if (target.callback) {
        target.callback();
    }
    printf("\n");
}

/*
 * Etape 5 : Protections et comment les verifier
 */
static void explain_protections(void) {
    printf("[*] Etape 5 : Protections contre le stack overflow\n\n");

    printf("    Protection     | gcc flag                  | Effet\n");
    printf("    ──────────────|──────────────────────────|──────────────────\n");
    printf("    Stack Canary  | -fstack-protector-strong  | Valeur secrete avant RIP\n");
    printf("    NX (DEP)      | (active par defaut)       | Stack non-executable\n");
    printf("    ASLR          | kernel param              | Adresses aleatoires\n");
    printf("    PIE           | -pie (defaut)             | Code a adresse random\n");
    printf("    RELRO         | -Wl,-z,relro,-z,now       | GOT en lecture seule\n\n");

    printf("    Desactiver pour tester (environnement de lab) :\n");
    printf("      gcc -fno-stack-protector   # Pas de canary\n");
    printf("      gcc -z execstack           # Stack executable\n");
    printf("      gcc -no-pie                # Adresses fixes\n");
    printf("      echo 0 > /proc/sys/kernel/randomize_va_space  # ASLR off\n\n");

    printf("    Verifier : checksec --file=./binary\n\n");
}

/*
 * Etape 6 : Programme vulnerable classique
 */
static void show_classic_vuln(void) {
    printf("[*] Etape 6 : Exemple classique de programme vulnerable\n\n");

    printf("    // vuln.c\n");
    printf("    #include <stdio.h>\n");
    printf("    #include <string.h>\n\n");
    printf("    void vulnerable(char *input) {\n");
    printf("        char buf[64];\n");
    printf("        strcpy(buf, input);  // Pas de verification de taille !\n");
    printf("        printf(\"Vous avez dit : %%s\\n\", buf);\n");
    printf("    }\n\n");
    printf("    int main(int argc, char *argv[]) {\n");
    printf("        if (argc > 1)\n");
    printf("            vulnerable(argv[1]);\n");
    printf("        return 0;\n");
    printf("    }\n\n");

    printf("    Exploitation :\n");
    printf("      1. Trouver l'offset : python -c 'print(\"A\"*72 + \"B\"*8)' | ./vuln\n");
    printf("      2. Trouver l'adresse de retour avec gdb\n");
    printf("      3. Construire le payload : padding + ret_addr + shellcode\n\n");
}

int main(void) {
    printf("[*] Demo : Stack Overflow Linux\n\n");

    explain_stack_layout();
    vulnerable_demo();
    demo_overflow_concept();
    demo_control_flow();
    explain_protections();
    show_classic_vuln();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

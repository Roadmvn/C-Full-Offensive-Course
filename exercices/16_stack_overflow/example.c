/*
 * ⚠️ AVERTISSEMENT : Code éducatif avec vulnérabilités INTENTIONNELLES
 * Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.
 *
 * Ce programme démontre l'exploitation de stack overflow.
 * Compilation : gcc -fno-stack-protector -z execstack -no-pie example.c -o example
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Fonction "secrète" qu'on veut atteindre par overflow
void win() {
    printf("\n");
    printf("╔═══════════════════════════════════════╗\n");
    printf("║  🎉 WIN! CODE EXECUTION HIJACKED 🎉  ║\n");
    printf("╔═══════════════════════════════════════╗\n");
    printf("\n");
    printf("Vous avez réussi à détourner le flux d'exécution !\n");
    printf("L'adresse de retour a été écrasée avec l'adresse de win().\n");
}

// Fonction alternative
void secret() {
    printf("\n🔓 SECRET FUNCTION ACCESSED\n");
    printf("Cette fonction n'est jamais appelée normalement.\n");
}

// Démonstration 1 : Overflow simple avec fonction win()
void demo_simple_overflow() {
    printf("\n=== Démonstration 1 : Redirection vers win() ===\n");

    char buffer[64];

    printf("Adresse de buffer : %p\n", (void*)buffer);
    printf("Adresse de win()  : %p\n", (void*)win);
    printf("Offset estimé     : 72 bytes (64 buffer + 8 saved RBP)\n");

    printf("\nEntrez payload (ou 'quit' pour quitter) : ");
    gets(buffer);  // VULNÉRABLE

    if (strcmp(buffer, "quit") == 0) {
        return;
    }

    printf("Buffer reçu : %.64s...\n", buffer);
    printf("Retour normal de la fonction.\n");
}

// Démonstration 2 : Overflow avec visualisation
void demo_stack_layout() {
    printf("\n=== Démonstration 2 : Layout de la stack ===\n");

    char buffer[32];
    unsigned long saved_rbp_marker = 0xBBBBBBBBBBBBBBBB;
    unsigned long ret_addr_marker = 0xCCCCCCCCCCCCCCCC;

    printf("\nStack layout (approximatif) :\n");
    printf("  [buffer]        @ %p (32 bytes)\n", (void*)buffer);
    printf("  [saved RBP]     @ %p (8 bytes) marker: 0x%lx\n",
           (void*)&saved_rbp_marker, saved_rbp_marker);
    printf("  [return addr]   @ %p (8 bytes) marker: 0x%lx\n",
           (void*)&ret_addr_marker, ret_addr_marker);

    printf("\nOffsets calculés:\n");
    printf("  buffer -> saved_rbp : %ld bytes\n",
           (char*)&saved_rbp_marker - buffer);
    printf("  buffer -> ret_addr  : %ld bytes\n",
           (char*)&ret_addr_marker - buffer);

    printf("\nEntrez payload : ");
    gets(buffer);  // VULNÉRABLE

    printf("\nAprès overflow:\n");
    printf("  saved_rbp marker : 0x%lx ", saved_rbp_marker);
    if (saved_rbp_marker != 0xBBBBBBBBBBBBBBBB) {
        printf("(ÉCRASÉ!)\n");
    } else {
        printf("(intact)\n");
    }

    printf("  ret_addr marker  : 0x%lx ", ret_addr_marker);
    if (ret_addr_marker != 0xCCCCCCCCCCCCCCCC) {
        printf("(ÉCRASÉ!)\n");
    } else {
        printf("(intact)\n");
    }
}

// Démonstration 3 : Pointeur de fonction
void demo_function_pointer() {
    printf("\n=== Démonstration 3 : Écrasement de pointeur de fonction ===\n");

    void (*function_ptr)() = NULL;
    char buffer[48];

    printf("Adresse de buffer       : %p\n", (void*)buffer);
    printf("Adresse de function_ptr : %p\n", (void*)&function_ptr);
    printf("Offset                  : %ld bytes\n",
           (char*)&function_ptr - buffer);

    printf("\nFonctions disponibles:\n");
    printf("  win()    @ %p\n", (void*)win);
    printf("  secret() @ %p\n", (void*)secret);

    printf("\nEntrez payload : ");
    gets(buffer);  // VULNÉRABLE

    printf("\nfunction_ptr = %p\n", (void*)function_ptr);

    if (function_ptr != NULL) {
        printf("Appel de la fonction écrasée...\n");
        function_ptr();
    } else {
        printf("Pointeur NULL, pas d'exécution.\n");
    }
}

// Démonstration 4 : Programme style CTF
void vulnerable_program() {
    printf("\n=== Démonstration 4 : Programme CTF ===\n");
    printf("Entrez le mot de passe pour accéder au système:\n");

    char password[64];
    gets(password);  // VULNÉRABLE

    if (strcmp(password, "secret123") == 0) {
        printf("✓ Authentification réussie.\n");
    } else {
        printf("✗ Mot de passe incorrect.\n");
    }

    printf("Sortie du programme...\n");
    // Au moment du 'ret', si return address écrasée -> win()
}

// Démonstration 5 : Analyse pour GDB
void gdb_analysis_target() {
    printf("\n=== Démonstration 5 : Cible pour analyse GDB ===\n");
    printf("Cette fonction est conçue pour l'analyse avec GDB.\n");
    printf("Placez un breakpoint ici et examinez la stack.\n\n");

    char buffer[100];

    printf("Commandes GDB utiles:\n");
    printf("  (gdb) break gdb_analysis_target\n");
    printf("  (gdb) run\n");
    printf("  (gdb) info frame\n");
    printf("  (gdb) info registers rbp rsp rip\n");
    printf("  (gdb) x/32gx $rsp\n");
    printf("  (gdb) x/gx $rbp+8    # Return address\n");
    printf("  (gdb) print &buffer\n");
    printf("  (gdb) print $rbp+8 - &buffer  # Offset\n\n");

    printf("buffer @ %p\n", (void*)buffer);
    printf("Entrez input : ");
    gets(buffer);  // VULNÉRABLE

    printf("Buffer: %.100s\n", buffer);
}

// Démonstration 6 : Return-to-function simple
void flag_reader() {
    printf("\n🚩 FLAG READER ACTIVATED\n");
    printf("FLAG{stack_0verflow_m4st3r}\n");
    printf("Félicitations pour avoir détourné l'exécution !\n");
}

void demo_ret2func() {
    printf("\n=== Démonstration 6 : Return-to-function ===\n");
    printf("Objectif: Rediriger vers flag_reader() sans l'appeler directement.\n");

    char name[80];

    printf("\nAdresse de flag_reader: %p\n", (void*)flag_reader);
    printf("Offset vers ret addr  : 88 bytes (80 + 8)\n");

    printf("\nVotre nom : ");
    gets(name);  // VULNÉRABLE

    printf("Bonjour, %s!\n", name);
    printf("Fin normale du programme.\n");
}

// Helper : afficher les protections
void check_protections() {
    printf("\n=== Vérification des protections ===\n\n");

    printf("Pour vérifier les protections de ce binaire:\n\n");

    printf("1. Stack Canary:\n");
    printf("   gcc -fno-stack-protector  → DÉSACTIVÉ\n");
    printf("   Résultat: Pas de canary\n\n");

    printf("2. NX/DEP (Non-eXecutable stack):\n");
    printf("   gcc -z execstack  → DÉSACTIVÉ\n");
    printf("   Résultat: Stack exécutable\n\n");

    printf("3. PIE (Position Independent Executable):\n");
    printf("   gcc -no-pie  → DÉSACTIVÉ\n");
    printf("   Résultat: Adresses fixes\n\n");

    printf("4. ASLR (vérifie au niveau système):\n");
    printf("   cat /proc/sys/kernel/randomize_va_space\n");
    printf("   0 = désactivé, 2 = activé\n\n");

    printf("Avec checksec (si installé):\n");
    printf("   checksec --file=./example\n\n");
}

// Menu principal
void print_menu() {
    printf("\n");
    printf("╔════════════════════════════════════════════╗\n");
    printf("║  Stack Overflow - Démonstrations          ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    printf("\n");
    printf("1. Overflow simple -> win()\n");
    printf("2. Visualisation du stack layout\n");
    printf("3. Écrasement de pointeur de fonction\n");
    printf("4. Programme CTF (mot de passe)\n");
    printf("5. Cible pour analyse GDB\n");
    printf("6. Return-to-function (flag_reader)\n");
    printf("7. Vérifier les protections\n");
    printf("0. Quitter\n");
    printf("\n");
    printf("Choix : ");
}

int main() {
    int choice;
    char input[16];

    printf("⚠️  CODE ÉDUCATIF - VULNÉRABLE INTENTIONNELLEMENT\n");
    printf("Compilation : gcc -fno-stack-protector -z execstack -no-pie example.c -o example\n");

    while (1) {
        print_menu();

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        choice = atoi(input);

        switch (choice) {
            case 1:
                demo_simple_overflow();
                break;
            case 2:
                demo_stack_layout();
                break;
            case 3:
                demo_function_pointer();
                break;
            case 4:
                vulnerable_program();
                break;
            case 5:
                gdb_analysis_target();
                break;
            case 6:
                demo_ret2func();
                break;
            case 7:
                check_protections();
                break;
            case 0:
                printf("\nAu revoir.\n");
                return 0;
            default:
                printf("\nChoix invalide.\n");
        }

        printf("\nAppuyez sur Entrée pour continuer...");
        getchar();
    }

    return 0;
}

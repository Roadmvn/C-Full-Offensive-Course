/*
 * ⚠️ AVERTISSEMENT : Code éducatif avec vulnérabilités INTENTIONNELLES
 * Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.
 *
 * Ce programme démontre les concepts de buffer overflow de base.
 * Compilation : gcc -fno-stack-protector -z execstack example.c -o example
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Démonstration 1 : Écrasement de variable adjacente
void demo_variable_overwrite() {
    printf("\n=== Démonstration 1 : Écrasement de variable ===\n");

    int authenticated = 0;  // Variable cible
    char buffer[16];        // Buffer vulnérable

    printf("Adresse de authenticated: %p (valeur: %d)\n", (void*)&authenticated, authenticated);
    printf("Adresse de buffer: %p\n", (void*)buffer);
    printf("Distance: %ld bytes\n", (char*)&authenticated - buffer);

    printf("\nEntrez votre nom (buffer de 16 bytes) : ");
    gets(buffer);  // VULNÉRABLE : pas de limite !

    printf("\nRésultat:\n");
    printf("buffer = '%s'\n", buffer);
    printf("authenticated = %d (0x%08x)\n", authenticated, authenticated);

    if (authenticated != 0) {
        printf("\n🚨 SUCCESS : Variable authenticated écrasée !\n");
        printf("Accès accordé sans mot de passe.\n");
    } else {
        printf("\nAccès refusé.\n");
    }
}

// Démonstration 2 : strcpy vs strncpy
void demo_strcpy_vs_strncpy() {
    printf("\n=== Démonstration 2 : strcpy vs strncpy ===\n");

    char safe_buffer[32];
    char unsafe_buffer[8];
    char secret[16] = "FLAG{SECRET}";

    char *long_input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";  // 34 A

    printf("Input : '%s' (%zu chars)\n", long_input, strlen(long_input));
    printf("Buffer size : 8 bytes\n");
    printf("Secret avant : '%s' à %p\n", secret, (void*)secret);

    // Version DANGEREUSE
    printf("\n[DANGEREUX] strcpy(unsafe_buffer, long_input)...\n");
    strcpy(unsafe_buffer, long_input);  // OVERFLOW !
    printf("unsafe_buffer = '%s'\n", unsafe_buffer);
    printf("Secret après : '%s'\n", secret);

    // Version SÉCURISÉE
    printf("\n[SÉCURISÉ] strncpy(safe_buffer, long_input, 31)...\n");
    strncpy(safe_buffer, long_input, sizeof(safe_buffer) - 1);
    safe_buffer[sizeof(safe_buffer) - 1] = '\0';  // Terminaison manuelle
    printf("safe_buffer = '%s'\n", safe_buffer);
}

// Démonstration 3 : Contrôle précis de l'écrasement
void demo_precise_overwrite() {
    printf("\n=== Démonstration 3 : Contrôle précis ===\n");

    unsigned int target = 0xDEADBEEF;
    char buffer[64];

    printf("Target initial : 0x%08x à %p\n", target, (void*)&target);
    printf("Buffer à : %p\n", (void*)buffer);
    printf("Offset : %ld bytes\n", (char*)&target - buffer);

    printf("\nEntrez payload (buffer[64]) : ");
    gets(buffer);

    printf("\nTarget final : 0x%08x\n", target);

    if (target == 0x41414141) {
        printf("✓ Target écrasé avec 'AAAA'\n");
    } else if (target == 0xDEADBEEF) {
        printf("✗ Target inchangé\n");
    } else {
        printf("✓ Target modifié : 0x%08x\n", target);
    }
}

// Démonstration 4 : Visualisation mémoire
void demo_memory_view() {
    printf("\n=== Démonstration 4 : Visualisation mémoire ===\n");

    char buffer[32];
    int marker1 = 0x11111111;
    int marker2 = 0x22222222;

    printf("Layout mémoire:\n");
    printf("marker1 [0x%08x] @ %p\n", marker1, (void*)&marker1);
    printf("buffer  [32 bytes]  @ %p\n", (void*)buffer);
    printf("marker2 [0x%08x] @ %p\n", marker2, (void*)&marker2);

    // Remplir le buffer
    memset(buffer, 'B', sizeof(buffer));

    printf("\nEntrez données (peut déborder) : ");
    gets(buffer);

    // Afficher l'état de la mémoire
    printf("\nÉtat mémoire après écriture:\n");
    printf("marker1 = 0x%08x\n", marker1);
    printf("buffer  = '%.32s'\n", buffer);
    printf("marker2 = 0x%08x\n", marker2);

    // Dump hexadécimal
    printf("\nDump hex de la région:\n");
    unsigned char *ptr = (unsigned char*)&marker1;
    for (int i = 0; i < 40; i++) {
        if (i % 16 == 0) printf("%p: ", (void*)(ptr + i));
        printf("%02x ", ptr[i]);
        if (i % 16 == 15) printf("\n");
    }
    printf("\n");
}

// Démonstration 5 : Système d'authentification vulnérable
void demo_vulnerable_auth() {
    printf("\n=== Démonstration 5 : Auth bypass ===\n");

    struct {
        char username[32];
        char password[32];
        int is_admin;
    } credentials;

    credentials.is_admin = 0;

    printf("Système d'authentification (vulnérable)\n");
    printf("Structure layout:\n");
    printf("  username[32] @ %p\n", (void*)credentials.username);
    printf("  password[32] @ %p\n", (void*)credentials.password);
    printf("  is_admin     @ %p\n", (void*)&credentials.is_admin);

    printf("\nUsername : ");
    gets(credentials.username);  // VULNÉRABLE

    printf("Password : ");
    gets(credentials.password);  // VULNÉRABLE

    printf("\nVérification...\n");
    printf("is_admin = %d\n", credentials.is_admin);

    if (credentials.is_admin != 0) {
        printf("\n🚨 ADMIN ACCESS GRANTED !\n");
        printf("Privilèges administrateur obtenus sans authentification.\n");
    } else if (strcmp(credentials.username, "admin") == 0 &&
               strcmp(credentials.password, "secret123") == 0) {
        printf("\n✓ Authentification réussie (légitime).\n");
    } else {
        printf("\n✗ Authentification échouée.\n");
    }
}

// Menu principal
void print_menu() {
    printf("\n========================================\n");
    printf("  Buffer Overflow - Démonstrations\n");
    printf("========================================\n");
    printf("1. Écrasement de variable adjacente\n");
    printf("2. strcpy vs strncpy\n");
    printf("3. Contrôle précis de l'écrasement\n");
    printf("4. Visualisation mémoire\n");
    printf("5. Système d'authentification vulnérable\n");
    printf("0. Quitter\n");
    printf("========================================\n");
    printf("Choix : ");
}

int main() {
    int choice;
    char input[16];

    printf("⚠️  CODE ÉDUCATIF - VULNÉRABLE INTENTIONNELLEMENT\n");
    printf("Compilation : gcc -fno-stack-protector -z execstack example.c -o example\n");

    while (1) {
        print_menu();
        fgets(input, sizeof(input), stdin);
        choice = atoi(input);

        switch (choice) {
            case 1:
                demo_variable_overwrite();
                break;
            case 2:
                demo_strcpy_vs_strncpy();
                break;
            case 3:
                demo_precise_overwrite();
                break;
            case 4:
                demo_memory_view();
                break;
            case 5:
                demo_vulnerable_auth();
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

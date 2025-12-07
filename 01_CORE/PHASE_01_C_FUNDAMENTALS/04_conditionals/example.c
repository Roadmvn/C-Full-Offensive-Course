/*
 * =============================================================================
 * Module 04 : Control Flow - Démonstration complète
 * =============================================================================
 *
 * Ce fichier démontre toutes les structures de contrôle en C avec des
 * applications offensives : anti-debug, obfuscation, scanning, etc.
 *
 * Compilation : gcc -Wall -Wextra example.c -o example
 * Exécution   : ./example
 *
 * =============================================================================
 * PRÉREQUIS : Avoir compris les Modules 01-03
 * =============================================================================
 */

#include <stdio.h>      // Pour printf(), scanf()
#include <stdlib.h>     // Pour exit(), rand()
#include <string.h>     // Pour strcmp()
#include <stdint.h>     // Pour uint8_t, etc.
#include <time.h>       // Pour time(), clock()

/* =============================================================================
 * DEMO 1 : Conditionnelle if/else
 *
 * POURQUOI C'EST IMPORTANT :
 * - Vérifications de sécurité
 * - Validation d'entrées
 * - Anti-debug checks
 * =============================================================================
 */
void demo_if_else(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 1 : CONDITIONNELLE IF/ELSE                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // Condition basique : vrai/faux en C
    // -------------------------------------------------------------------------
    printf("--- Vrai/Faux en C ---\n");
    int x = 5;
    int y = 0;

    // En C : 0 = faux, tout le reste = vrai
    if (x) {
        printf("x = %d est considéré VRAI (non-zéro)\n", x);
    }

    if (y) {
        printf("Ce message ne s'affiche PAS\n");
    } else {
        printf("y = %d est considéré FAUX (zéro)\n", y);
    }

    // -------------------------------------------------------------------------
    // if/else classique
    // -------------------------------------------------------------------------
    printf("\n--- If/else classique ---\n");
    int age = 25;

    if (age >= 18) {
        printf("age = %d → Majeur\n", age);
    } else {
        printf("age = %d → Mineur\n", age);
    }

    // -------------------------------------------------------------------------
    // if/else if/else
    // -------------------------------------------------------------------------
    printf("\n--- If/else if/else ---\n");
    int score = 75;

    printf("Score = %d → ", score);
    if (score >= 90) {
        printf("Grade A\n");
    } else if (score >= 80) {
        printf("Grade B\n");
    } else if (score >= 70) {
        printf("Grade C\n");
    } else if (score >= 60) {
        printf("Grade D\n");
    } else {
        printf("Grade F\n");
    }

    // -------------------------------------------------------------------------
    // APPLICATION OFFENSIVE : Vérifications de sécurité
    // -------------------------------------------------------------------------
    printf("\n[APPLICATION OFFENSIVE] Vérifications de sécurité :\n");

    int is_admin = 1;
    int is_logged = 1;
    int is_banned = 0;

    // Vérifications en chaîne (comme dans un vrai agent)
    if (!is_logged) {
        printf("  ERREUR: Utilisateur non connecté\n");
    } else if (is_banned) {
        printf("  ERREUR: Utilisateur banni\n");
    } else if (!is_admin) {
        printf("  AVERTISSEMENT: Accès limité (non-admin)\n");
    } else {
        printf("  OK: Accès admin complet accordé\n");
    }
}

/* =============================================================================
 * DEMO 2 : Switch/Case
 *
 * POURQUOI C'EST IMPORTANT :
 * - Dispatcher de commandes (C2)
 * - State machines pour obfuscation
 * - Parsing de protocoles
 * =============================================================================
 */
void demo_switch(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 2 : SWITCH/CASE                                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // Switch basique
    // -------------------------------------------------------------------------
    printf("--- Switch basique ---\n");
    int choice = 2;

    printf("choice = %d → ", choice);
    switch (choice) {
        case 1:
            printf("Option 1\n");
            break;
        case 2:
            printf("Option 2\n");
            break;
        case 3:
            printf("Option 3\n");
            break;
        default:
            printf("Option invalide\n");
            break;
    }

    // -------------------------------------------------------------------------
    // ATTENTION : Fall-through sans break
    // -------------------------------------------------------------------------
    printf("\n--- Fall-through (sans break) ---\n");
    int val = 1;

    printf("val = %d → Output: ", val);
    switch (val) {
        case 1:
            printf("Un ");
            // PAS DE BREAK - continue au case suivant !
        case 2:
            printf("Deux ");
            // PAS DE BREAK
        case 3:
            printf("Trois");
            break;
        default:
            printf("Autre");
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // Fall-through intentionnel (grouper des cas)
    // -------------------------------------------------------------------------
    printf("\n--- Fall-through intentionnel ---\n");
    char c = 'e';

    printf("'%c' est une ", c);
    switch (c) {
        case 'a':
        case 'e':
        case 'i':
        case 'o':
        case 'u':
            printf("voyelle\n");
            break;
        default:
            printf("consonne\n");
            break;
    }

    // -------------------------------------------------------------------------
    // APPLICATION OFFENSIVE : Command dispatcher
    // -------------------------------------------------------------------------
    printf("\n[APPLICATION OFFENSIVE] Command dispatcher C2 :\n");

    // Simulation de commandes reçues du C2
    uint8_t commands[] = {0x01, 0x04, 0x02, 0xFF};

    for (int i = 0; i < 4; i++) {
        printf("  Commande 0x%02X → ", commands[i]);

        switch (commands[i]) {
            case 0x01:
                printf("SHELL: Exécuter commande système\n");
                break;
            case 0x02:
                printf("DOWNLOAD: Télécharger fichier\n");
                break;
            case 0x03:
                printf("UPLOAD: Envoyer fichier\n");
                break;
            case 0x04:
                printf("SCREENSHOT: Capture d'écran\n");
                break;
            case 0xFF:
                printf("KILL: Self-destruct\n");
                break;
            default:
                printf("UNKNOWN: Commande ignorée\n");
                break;
        }
    }
}

/* =============================================================================
 * DEMO 3 : Boucle for
 *
 * POURQUOI C'EST IMPORTANT :
 * - Scanner de ports
 * - Brute force
 * - Parsing de buffers
 * - XOR encryption
 * =============================================================================
 */
void demo_for_loop(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 3 : BOUCLE FOR                                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // For basique : compter de 0 à 9
    // -------------------------------------------------------------------------
    printf("--- Compter de 0 à 9 ---\n");
    printf("i = ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", i);
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // Compte à rebours
    // -------------------------------------------------------------------------
    printf("\n--- Compte à rebours ---\n");
    printf("i = ");
    for (int i = 5; i > 0; i--) {
        printf("%d ", i);
    }
    printf("BOOM!\n");

    // -------------------------------------------------------------------------
    // Pas personnalisé (step)
    // -------------------------------------------------------------------------
    printf("\n--- Pas de 2 (nombres pairs) ---\n");
    printf("i = ");
    for (int i = 0; i < 20; i += 2) {
        printf("%d ", i);
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // Boucles imbriquées
    // -------------------------------------------------------------------------
    printf("\n--- Matrice 3x3 ---\n");
    for (int row = 0; row < 3; row++) {
        for (int col = 0; col < 3; col++) {
            printf("[%d,%d] ", row, col);
        }
        printf("\n");
    }

    // -------------------------------------------------------------------------
    // APPLICATION OFFENSIVE : XOR Encryption
    // -------------------------------------------------------------------------
    printf("\n[APPLICATION OFFENSIVE] XOR Encryption avec for :\n");

    char message[] = "SECRET";
    unsigned char key[] = {0x41, 0x42, 0x43, 0x44};
    size_t msg_len = strlen(message);
    size_t key_len = sizeof(key);

    printf("  Message original : %s\n", message);

    // Chiffrement
    for (size_t i = 0; i < msg_len; i++) {
        message[i] ^= key[i % key_len];  // Clé cyclique avec modulo
    }

    printf("  Chiffré (hex)    : ");
    for (size_t i = 0; i < msg_len; i++) {
        printf("%02X ", (unsigned char)message[i]);
    }
    printf("\n");

    // Déchiffrement (même opération)
    for (size_t i = 0; i < msg_len; i++) {
        message[i] ^= key[i % key_len];
    }
    printf("  Déchiffré        : %s\n", message);

    // -------------------------------------------------------------------------
    // APPLICATION OFFENSIVE : Port scanner simulé
    // -------------------------------------------------------------------------
    printf("\n[APPLICATION OFFENSIVE] Port scanner simulé :\n");

    // Ports communs à scanner
    int ports[] = {22, 80, 443, 445, 3389, 8080};
    int num_ports = sizeof(ports) / sizeof(ports[0]);

    // Simuler des résultats (en vrai, on utiliserait socket/connect)
    int open_ports[] = {1, 1, 1, 0, 0, 1};  // 1 = ouvert, 0 = fermé

    printf("  Scan de 127.0.0.1:\n");
    for (int i = 0; i < num_ports; i++) {
        if (open_ports[i]) {
            printf("    [+] Port %d OUVERT\n", ports[i]);
        }
    }
}

/* =============================================================================
 * DEMO 4 : Boucle while
 *
 * POURQUOI C'EST IMPORTANT :
 * - Main loop d'un agent
 * - Lecture de données jusqu'à condition
 * - Attente d'événement
 * =============================================================================
 */
void demo_while_loop(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 4 : BOUCLE WHILE                                ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // While basique
    // -------------------------------------------------------------------------
    printf("--- Compter jusqu'à 5 ---\n");
    int count = 0;
    printf("count = ");
    while (count < 5) {
        printf("%d ", count);
        count++;
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // While avec condition de sortie
    // -------------------------------------------------------------------------
    printf("\n--- Recherche dans un tableau ---\n");

    int numbers[] = {10, 25, 8, 42, 17, 33};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    int target = 42;
    int found = 0;
    int index = 0;

    while (index < size && !found) {
        if (numbers[index] == target) {
            found = 1;
        } else {
            index++;
        }
    }

    if (found) {
        printf("  %d trouvé à l'index %d\n", target, index);
    } else {
        printf("  %d non trouvé\n", target);
    }

    // -------------------------------------------------------------------------
    // APPLICATION OFFENSIVE : Agent main loop simulé
    // -------------------------------------------------------------------------
    printf("\n[APPLICATION OFFENSIVE] Agent main loop simulé :\n");

    // Simuler 3 itérations d'un agent
    int running = 1;
    int iterations = 0;
    int max_iterations = 3;

    printf("  Agent démarré...\n");

    while (running && iterations < max_iterations) {
        iterations++;

        // Simuler check-in avec C2
        printf("  [%d] Check-in au C2...\n", iterations);

        // Simuler commande reçue
        char *commands[] = {"scan", "report", "exit"};
        char *cmd = commands[iterations - 1];

        printf("  [%d] Commande reçue: %s\n", iterations, cmd);

        // Traiter la commande
        if (strcmp(cmd, "exit") == 0) {
            printf("  [%d] Commande exit - arrêt de l'agent\n", iterations);
            running = 0;
        } else if (strcmp(cmd, "scan") == 0) {
            printf("  [%d] Exécution scan...\n", iterations);
        } else if (strcmp(cmd, "report") == 0) {
            printf("  [%d] Envoi rapport...\n", iterations);
        }
    }

    printf("  Agent arrêté.\n");
}

/* =============================================================================
 * DEMO 5 : Boucle do-while
 *
 * POURQUOI C'EST IMPORTANT :
 * - Retry avec backoff
 * - Menu interactif
 * - Garantir au moins une exécution
 * =============================================================================
 */
void demo_do_while_loop(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 5 : BOUCLE DO-WHILE                             ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // Do-while basique
    // -------------------------------------------------------------------------
    printf("--- Exécution garantie au moins une fois ---\n");

    int counter = 10;  // Déjà >= 5, mais le corps s'exécute quand même

    printf("counter initial = %d\n", counter);
    printf("Iterations: ");

    do {
        printf("%d ", counter);
        counter++;
    } while (counter < 5);  // Condition fausse dès le départ

    printf("\n(exécuté 1 fois malgré condition fausse)\n");

    // -------------------------------------------------------------------------
    // APPLICATION OFFENSIVE : Retry avec backoff exponentiel
    // -------------------------------------------------------------------------
    printf("\n[APPLICATION OFFENSIVE] Retry avec backoff exponentiel :\n");

    int attempts = 0;
    int max_attempts = 4;
    int delay = 1;  // Secondes (simulées)
    int success = 0;

    printf("  Tentative de connexion au C2...\n");

    do {
        attempts++;
        printf("  Tentative %d (délai: %d sec)... ", attempts, delay);

        // Simuler succès à la 3ème tentative
        if (attempts == 3) {
            success = 1;
            printf("SUCCÈS!\n");
        } else {
            printf("ÉCHEC - retry\n");
            // delay *= 2;  // Backoff exponentiel: 1, 2, 4, 8...
            delay *= 2;
        }
    } while (!success && attempts < max_attempts);

    if (success) {
        printf("  Connexion établie après %d tentative(s)\n", attempts);
    } else {
        printf("  Abandon après %d tentative(s)\n", max_attempts);
    }
}

/* =============================================================================
 * DEMO 6 : break, continue, goto
 *
 * POURQUOI C'EST IMPORTANT :
 * - Early exit sur succès/erreur
 * - Filtrage d'éléments
 * - Gestion d'erreurs avec cleanup
 * - Obfuscation de flux
 * =============================================================================
 */
void demo_break_continue_goto(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 6 : BREAK, CONTINUE, GOTO                       ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // -------------------------------------------------------------------------
    // break : sortir de la boucle
    // -------------------------------------------------------------------------
    printf("--- break : sortir de la boucle ---\n");
    printf("Cherche le premier multiple de 7: ");

    for (int i = 1; i < 100; i++) {
        if (i % 7 == 0) {
            printf("trouvé %d\n", i);
            break;  // Sort immédiatement
        }
    }

    // -------------------------------------------------------------------------
    // continue : sauter à l'itération suivante
    // -------------------------------------------------------------------------
    printf("\n--- continue : sauter les pairs ---\n");
    printf("Nombres impairs de 0 à 10: ");

    for (int i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            continue;  // Saute les pairs
        }
        printf("%d ", i);
    }
    printf("\n");

    // -------------------------------------------------------------------------
    // goto : gestion d'erreurs avec cleanup
    // -------------------------------------------------------------------------
    printf("\n--- goto : gestion d'erreurs ---\n");

    char *buffer = NULL;
    int result = -1;

    printf("Simulation allocation et traitement:\n");

    // Étape 1 : Allocation
    buffer = (char*)malloc(1024);
    if (buffer == NULL) {
        printf("  Erreur allocation - goto cleanup\n");
        goto cleanup;
    }
    printf("  [OK] Allocation réussie\n");

    // Étape 2 : Simulation d'opération (succès)
    printf("  [OK] Opération réussie\n");
    result = 0;

cleanup:  // Label pour le cleanup
    printf("  [CLEANUP] Libération des ressources...\n");
    if (buffer) {
        free(buffer);
        printf("  [CLEANUP] Buffer libéré\n");
    }

    printf("  Résultat final: %s\n", result == 0 ? "SUCCÈS" : "ÉCHEC");

    // -------------------------------------------------------------------------
    // APPLICATION OFFENSIVE : break pour early exit
    // -------------------------------------------------------------------------
    printf("\n[APPLICATION OFFENSIVE] Bruteforce avec early exit :\n");

    // Simuler un bruteforce de PIN (4 chiffres)
    int target_pin = 1337;
    int found_pin = -1;

    printf("  Bruteforce PIN...\n");

    for (int pin = 0; pin < 10000; pin++) {
        if (pin == target_pin) {
            found_pin = pin;
            break;  // PIN trouvé, on arrête
        }
    }

    if (found_pin >= 0) {
        printf("  [+] PIN trouvé: %04d\n", found_pin);
    } else {
        printf("  [-] PIN non trouvé\n");
    }
}

/* =============================================================================
 * DEMO 7 : State machine pour obfuscation
 *
 * POURQUOI C'EST IMPORTANT :
 * - Control flow flattening
 * - Rendre le reverse engineering plus difficile
 * - Exécution non-linéaire
 * =============================================================================
 */
void demo_state_machine(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 7 : STATE MACHINE (OBFUSCATION)                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /*
     * Au lieu d'avoir un flux linéaire comme:
     *   step1();
     *   step2();
     *   step3();
     *
     * On utilise une state machine où l'ordre n'est pas évident.
     */

    printf("Exécution via state machine:\n\n");

    int state = 0;
    int done = 0;
    int iterations = 0;

    while (!done && iterations < 10) {
        iterations++;

        switch (state) {
            case 0:
                printf("  State 0: Initialisation\n");
                state = 3;  // Saute au state 3 (pas linéaire!)
                break;

            case 1:
                printf("  State 1: Exécution payload\n");
                state = 4;  // Saute au state 4
                break;

            case 2:
                printf("  State 2: [Code leurre - jamais atteint]\n");
                state = 0;
                break;

            case 3:
                printf("  State 3: Préparation\n");
                state = 1;  // Va au state 1
                break;

            case 4:
                printf("  State 4: Cleanup\n");
                done = 1;  // Sortie
                break;

            default:
                printf("  State invalide - reset\n");
                state = 0;
                break;
        }
    }

    printf("\nOrdre d'exécution effectif: 0 → 3 → 1 → 4\n");
    printf("(pas évident en regardant le code!)\n");
}

/* =============================================================================
 * DEMO 8 : Timing check (anti-debug simplifié)
 *
 * POURQUOI C'EST IMPORTANT :
 * - Détecter l'exécution sous debugger
 * - Le single-stepping ralentit l'exécution
 * =============================================================================
 */
void demo_timing_check(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         DEMO 8 : TIMING CHECK (ANTI-DEBUG)                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    printf("Principe: Les opérations rapides deviennent lentes sous debugger\n\n");

    // Mesurer le temps d'une opération simple
    clock_t start = clock();

    // Opération qui devrait être très rapide
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++) {
        sum += i;
    }

    clock_t end = clock();
    double elapsed_ms = ((double)(end - start) / CLOCKS_PER_SEC) * 1000;

    printf("Temps d'exécution: %.2f ms\n", elapsed_ms);

    // En exécution normale: quelques ms
    // Sous debugger (single-step): beaucoup plus

    // Threshold arbitraire pour la démo
    double threshold_ms = 100.0;

    if (elapsed_ms > threshold_ms) {
        printf("\n[!] ALERTE: Temps anormalement long (%.2f ms > %.2f ms)\n",
               elapsed_ms, threshold_ms);
        printf("    Possible exécution sous debugger!\n");
    } else {
        printf("\n[OK] Temps normal - pas de debugger détecté\n");
    }

    printf("\nNote: En vrai, on utiliserait GetTickCount(), rdtsc, ou\n");
    printf("QueryPerformanceCounter() pour plus de précision.\n");
}

/* =============================================================================
 * FONCTION PRINCIPALE
 * =============================================================================
 */
int main(void) {
    printf("\n");
    printf("███████████████████████████████████████████████████████████████████\n");
    printf("█                                                                 █\n");
    printf("█  MODULE 04 : CONTROL FLOW - DÉMONSTRATION COMPLÈTE              █\n");
    printf("█                                                                 █\n");
    printf("█  Focus : Conditionnels, Boucles, Anti-debug, Obfuscation        █\n");
    printf("█                                                                 █\n");
    printf("███████████████████████████████████████████████████████████████████\n");

    // Exécute toutes les démos
    demo_if_else();
    demo_switch();
    demo_for_loop();
    demo_while_loop();
    demo_do_while_loop();
    demo_break_continue_goto();
    demo_state_machine();
    demo_timing_check();

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  FIN DES DÉMONSTRATIONS\n");
    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("Points clés à retenir :\n");
    printf("  1. En C : 0 = faux, non-zéro = vrai\n");
    printf("  2. switch : TOUJOURS mettre break (sauf fall-through voulu)\n");
    printf("  3. for : parfait pour itérations comptées (scan, parsing)\n");
    printf("  4. while : parfait pour conditions dynamiques (main loop)\n");
    printf("  5. do-while : garantit au moins une exécution\n");
    printf("  6. break : early exit (succès/erreur)\n");
    printf("  7. continue : sauter des itérations\n");
    printf("  8. goto : cleanup centralisé et obfuscation\n");
    printf("  9. State machine : obfuscation du control flow\n");
    printf("  10. Timing checks : détection anti-debug\n");
    printf("\n");

    return 0;
}

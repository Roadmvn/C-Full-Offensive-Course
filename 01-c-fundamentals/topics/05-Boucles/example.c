/*
 * Module 05 : Boucles (Loops)
 *
 * Description : Démonstration complète des boucles avec applications offensives
 * Compilation : gcc -o example example.c
 * Exécution  : ./example
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// ============================================================================
// DEMO 1 : Boucle for - Fondamentaux
// ============================================================================
void demo_for_basics(void) {
    printf("=== DEMO 1 : Boucle for - Fondamentaux ===\n\n");

    // Compteur croissant
    printf("Croissant 0-9 : ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", i);
    }
    printf("\n");

    // Compteur décroissant
    printf("Décroissant 10-1 : ");
    for (int i = 10; i >= 1; i--) {
        printf("%d ", i);
    }
    printf("\n");

    // Pas de 2 (nombres pairs)
    printf("Pairs 0-10 : ");
    for (int i = 0; i <= 10; i += 2) {
        printf("%d ", i);
    }
    printf("\n");

    // Puissances de 2
    printf("Puissances de 2 : ");
    for (int i = 1; i <= 256; i *= 2) {
        printf("%d ", i);
    }
    printf("\n");

    // Caractères ASCII
    printf("Alphabet : ");
    for (char c = 'A'; c <= 'Z'; c++) {
        printf("%c", c);
    }
    printf("\n\n");
}

// ============================================================================
// DEMO 2 : Port Scanner Simulé
// ============================================================================
int is_port_open(int port) {
    // Simule des ports ouverts
    int open_ports[] = {22, 80, 443, 3306, 8080};
    for (int i = 0; i < 5; i++) {
        if (port == open_ports[i]) return 1;
    }
    return 0;
}

const char* get_service_name(int port) {
    switch (port) {
        case 22:   return "SSH";
        case 80:   return "HTTP";
        case 443:  return "HTTPS";
        case 3306: return "MySQL";
        case 8080: return "HTTP-Proxy";
        default:   return "Unknown";
    }
}

void demo_port_scanner(void) {
    printf("=== DEMO 2 : Port Scanner ===\n\n");

    const char* target = "192.168.1.100";
    int open_count = 0;

    printf("[*] Scanning %s ports 1-100...\n", target);

    for (int port = 1; port <= 100; port++) {
        if (is_port_open(port)) {
            printf("[+] Port %d OPEN - %s\n", port, get_service_name(port));
            open_count++;
        }
    }

    printf("[*] Scan complete: %d ports open\n\n", open_count);
}

// ============================================================================
// DEMO 3 : Boucle while - Attente de condition
// ============================================================================
void demo_while_basics(void) {
    printf("=== DEMO 3 : Boucle while ===\n\n");

    // Compteur simple
    printf("Comptage avec while : ");
    int count = 0;
    while (count < 5) {
        printf("%d ", count);
        count++;
    }
    printf("\n");

    // Recherche dans un tableau
    int data[] = {15, 42, 8, 23, 16, 4, 42, 99};
    int size = sizeof(data) / sizeof(data[0]);
    int target = 42;
    int i = 0;

    printf("Recherche de %d dans le tableau...\n", target);
    while (i < size && data[i] != target) {
        i++;
    }

    if (i < size) {
        printf("[+] Trouvé à l'index %d\n", i);
    } else {
        printf("[-] Non trouvé\n");
    }

    // Simulation attente de processus
    printf("\n[*] Attente d'un processus...\n");
    int attempts = 0;
    int found = 0;
    while (!found && attempts < 5) {
        attempts++;
        printf("[.] Tentative %d...\n", attempts);
        if (attempts >= 3) {
            found = 1;
            printf("[+] Processus trouvé!\n");
        }
    }
    printf("\n");
}

// ============================================================================
// DEMO 4 : Boucle do-while - Menu et beacon
// ============================================================================
void demo_do_while(void) {
    printf("=== DEMO 4 : Boucle do-while ===\n\n");

    // Différence while vs do-while
    int x = 0;

    printf("Test avec x = 0:\n");

    printf("  while (x > 0): ");
    while (x > 0) {
        printf("Exécuté ");
        break;
    }
    printf("(pas exécuté)\n");

    printf("  do-while (x > 0): ");
    do {
        printf("Exécuté une fois!");
    } while (x > 0);
    printf("\n");

    // Simulation menu
    printf("\n[*] Simulation menu:\n");
    int choice = 0;
    int iterations = 0;
    do {
        iterations++;
        // Simule des choix 1, 2, 3, puis 4 (quitter)
        choice = iterations;
        printf("  Itération %d: choix = %d\n", iterations, choice);
    } while (choice != 4 && iterations < 5);

    printf("\n");
}

// ============================================================================
// DEMO 5 : Boucles imbriquées - Bruteforce
// ============================================================================
int verify_pin(const char* pin, const char* correct) {
    return strcmp(pin, correct) == 0;
}

void demo_nested_loops(void) {
    printf("=== DEMO 5 : Boucles imbriquées - Bruteforce ===\n\n");

    // Triangle d'étoiles
    printf("Triangle:\n");
    for (int i = 1; i <= 5; i++) {
        for (int j = 0; j < i; j++) {
            printf("*");
        }
        printf("\n");
    }

    // Bruteforce PIN 3 chiffres
    printf("\n[*] Bruteforce PIN (cible: 247)...\n");
    char pin[4];
    const char* correct_pin = "247";
    int attempts = 0;
    int found = 0;

    for (int d1 = 0; d1 <= 9 && !found; d1++) {
        for (int d2 = 0; d2 <= 9 && !found; d2++) {
            for (int d3 = 0; d3 <= 9 && !found; d3++) {
                sprintf(pin, "%d%d%d", d1, d2, d3);
                attempts++;

                if (verify_pin(pin, correct_pin)) {
                    printf("[+] PIN FOUND: %s (après %d essais)\n", pin, attempts);
                    found = 1;
                }
            }
        }
    }

    // Grille de coordonnées
    printf("\nGrille 3x3:\n");
    for (int row = 0; row < 3; row++) {
        for (int col = 0; col < 3; col++) {
            printf("(%d,%d) ", row, col);
        }
        printf("\n");
    }
    printf("\n");
}

// ============================================================================
// DEMO 6 : break et continue
// ============================================================================
void demo_break_continue(void) {
    printf("=== DEMO 6 : break et continue ===\n\n");

    // Démonstration break
    printf("break à i=5 : ");
    for (int i = 0; i < 10; i++) {
        if (i == 5) {
            break;
        }
        printf("%d ", i);
    }
    printf("(arrêté)\n");

    // Démonstration continue
    printf("continue si pair : ");
    for (int i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            continue;  // Saute les pairs
        }
        printf("%d ", i);
    }
    printf("\n");

    // Recherche avec early exit
    printf("\n[*] Recherche du premier multiple de 7 > 50:\n");
    for (int i = 51; i <= 100; i++) {
        if (i % 7 == 0) {
            printf("[+] Trouvé: %d\n", i);
            break;
        }
    }

    // Filtrage avec continue
    int values[] = {5, -2, 8, -1, 12, 0, 7, 9};
    int size = sizeof(values) / sizeof(values[0]);

    printf("\n[*] Valeurs positives jusqu'à 0:\n    ");
    for (int i = 0; i < size; i++) {
        if (values[i] == 0) {
            printf("(stop)");
            break;
        }
        if (values[i] < 0) {
            continue;  // Ignore les négatifs
        }
        printf("%d ", values[i]);
    }
    printf("\n\n");
}

// ============================================================================
// DEMO 7 : XOR Decode avec boucle
// ============================================================================
void demo_xor_decode(void) {
    printf("=== DEMO 7 : XOR Decode ===\n\n");

    // Message chiffré avec XOR 0x42
    unsigned char encoded[] = {
        0x03, 0x16, 0x16, 0x03, 0x01, 0x0D, // "ATTACK" XOR 0x42
        0x00  // Null terminator
    };
    unsigned char key = 0x42;
    int len = sizeof(encoded) - 1;

    printf("Message encodé (hex): ");
    for (int i = 0; i < len; i++) {
        printf("%02X ", encoded[i]);
    }
    printf("\n");

    printf("Clé: 0x%02X\n", key);

    // Décodage
    printf("Décodage...\n");
    for (int i = 0; i < len; i++) {
        encoded[i] ^= key;
    }

    printf("Message décodé: %s\n", encoded);

    // Re-encodage pour montrer la réversibilité
    printf("\nRe-encodage...\n");
    for (int i = 0; i < len; i++) {
        encoded[i] ^= key;
    }

    printf("Message re-encodé (hex): ");
    for (int i = 0; i < len; i++) {
        printf("%02X ", encoded[i]);
    }
    printf("\n\n");
}

// ============================================================================
// DEMO 8 : Patterns offensifs avancés
// ============================================================================
void demo_advanced_patterns(void) {
    printf("=== DEMO 8 : Patterns offensifs ===\n\n");

    // 1. Retry avec backoff
    printf("[Pattern 1] Retry avec backoff exponentiel:\n");
    int delay = 1;
    for (int attempt = 1; attempt <= 5; attempt++) {
        printf("  Tentative %d, délai: %ds\n", attempt, delay);
        delay *= 2;
        if (delay > 16) delay = 16;  // Cap
    }

    // 2. Scan randomisé
    printf("\n[Pattern 2] Ports dans ordre aléatoire:\n");
    int ports[] = {22, 80, 443, 3389, 8080};
    int num_ports = sizeof(ports) / sizeof(ports[0]);

    // Fisher-Yates shuffle
    srand(42);  // Seed fixe pour reproductibilité
    for (int i = num_ports - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = ports[i];
        ports[i] = ports[j];
        ports[j] = temp;
    }

    printf("  Ordre mélangé: ");
    for (int i = 0; i < num_ports; i++) {
        printf("%d ", ports[i]);
    }
    printf("\n");

    // 3. Recherche de signature
    printf("\n[Pattern 3] Recherche de signature en mémoire:\n");
    unsigned char memory[] = {0x00, 0x90, 0x90, 0xCC, 0x31, 0xC0, 0x50, 0x90};
    unsigned char signature[] = {0xCC, 0x31, 0xC0};  // int3 + xor eax, eax
    int mem_size = sizeof(memory);
    int sig_size = sizeof(signature);

    printf("  Mémoire: ");
    for (int i = 0; i < mem_size; i++) {
        printf("%02X ", memory[i]);
    }
    printf("\n");

    printf("  Signature: ");
    for (int i = 0; i < sig_size; i++) {
        printf("%02X ", signature[i]);
    }
    printf("\n");

    // Recherche
    int found_at = -1;
    for (int i = 0; i <= mem_size - sig_size; i++) {
        int match = 1;
        for (int j = 0; j < sig_size; j++) {
            if (memory[i + j] != signature[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            found_at = i;
            break;
        }
    }

    if (found_at >= 0) {
        printf("  [+] Signature trouvée à l'offset %d\n", found_at);
    } else {
        printf("  [-] Signature non trouvée\n");
    }

    printf("\n");
}

// ============================================================================
// DEMO 9 : Timing - Anti-debug basique
// ============================================================================
void demo_timing(void) {
    printf("=== DEMO 9 : Timing (Anti-debug) ===\n\n");

    clock_t start, end;
    double elapsed;
    int iterations = 100000;

    printf("[*] Exécution de %d itérations...\n", iterations);

    start = clock();

    volatile int sum = 0;  // volatile empêche l'optimisation
    for (int i = 0; i < iterations; i++) {
        sum += i;
    }

    end = clock();
    elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    printf("[*] Temps écoulé: %.6f secondes\n", elapsed);
    printf("[*] Résultat (pour éviter optimisation): %d\n", sum);

    // Vérification anti-debug simplifiée
    double threshold = 1.0;  // 1 seconde = suspicieux
    if (elapsed > threshold) {
        printf("[!] Temps trop long - Debugger possible?\n");
    } else {
        printf("[+] Temps normal - Pas de debugger détecté\n");
    }

    printf("\n");
}

// ============================================================================
// DEMO 10 : Boucle infinie contrôlée (simulée)
// ============================================================================
void demo_infinite_loop(void) {
    printf("=== DEMO 10 : Boucle 'infinie' contrôlée ===\n\n");

    printf("[*] Simulation de beacon C2 (max 5 itérations):\n");

    int running = 1;
    int iteration = 0;
    int max_iterations = 5;  // Limite pour la démo

    while (running) {
        iteration++;
        printf("  [%d] Checking C2 for commands...\n", iteration);

        // Simule réception de commande
        if (iteration == 3) {
            printf("  [+] Command received: 'whoami'\n");
        }

        // Simule commande d'arrêt
        if (iteration >= max_iterations) {
            printf("  [!] Exit command received\n");
            running = 0;
        }
    }

    printf("[*] Beacon terminated\n\n");

    // Alternative avec for(;;)
    printf("[*] Alternative for(;;) (3 itérations):\n");
    iteration = 0;
    for (;;) {
        iteration++;
        printf("  Iteration %d\n", iteration);
        if (iteration >= 3) {
            break;
        }
    }
    printf("\n");
}

// ============================================================================
// MAIN
// ============================================================================
int main(void) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         MODULE 05 : BOUCLES (LOOPS) - DÉMONSTRATIONS         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    demo_for_basics();
    demo_port_scanner();
    demo_while_basics();
    demo_do_while();
    demo_nested_loops();
    demo_break_continue();
    demo_xor_decode();
    demo_advanced_patterns();
    demo_timing();
    demo_infinite_loop();

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    FIN DES DÉMONSTRATIONS                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    return 0;
}

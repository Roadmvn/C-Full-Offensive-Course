#include <stdio.h>

/*
 * Programme : Boucles
 * Description : Démonstration des structures de répétition
 * Compilation : gcc example.c -o example
 */

int main() {
    printf("=== BOUCLES EN C ===\n\n");

    // 1. Boucle for classique
    printf("1. Boucle for (0 à 4)\n");
    for (int i = 0; i < 5; i++) {
        printf("   i = %d\n", i);
    }
    printf("\n");

    // 2. Boucle for avec incrément personnalisé
    printf("2. Boucle for (incrément de 2)\n");
    for (int i = 0; i < 10; i += 2) {
        printf("   i = %d\n", i);
    }
    printf("\n");

    // 3. Boucle for décroissante
    printf("3. Boucle for (compte à rebours)\n");
    for (int i = 5; i >= 1; i--) {
        printf("   %d...\n", i);
    }
    printf("   Décollage!\n\n");

    // 4. Boucle while
    printf("4. Boucle while\n");
    int count = 0;
    while (count < 5) {
        printf("   count = %d\n", count);
        count++;
    }
    printf("\n");

    // 5. Boucle do-while (au moins 1 exécution)
    printf("5. Boucle do-while\n");
    int x = 10;
    do {
        printf("   Exécuté même si x >= 10\n");
        x++;
    } while (x < 10);  // Condition fausse, mais exécuté 1 fois
    printf("\n");

    // 6. break (sortir de la boucle)
    printf("6. break (sortie anticipée)\n");
    for (int i = 0; i < 10; i++) {
        if (i == 5) {
            printf("   Stop à i=%d\n", i);
            break;
        }
        printf("   i = %d\n", i);
    }
    printf("\n");

    // 7. continue (passer à l'itération suivante)
    printf("7. continue (sauter les pairs)\n");
    for (int i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            continue;  // Saute les nombres pairs
        }
        printf("   i = %d (impair)\n", i);
    }
    printf("\n");

    // 8. Boucles imbriquées
    printf("8. Boucles imbriquées (tableau)\n");
    for (int i = 1; i <= 3; i++) {
        for (int j = 1; j <= 3; j++) {
            printf("   (%d,%d) ", i, j);
        }
        printf("\n");
    }
    printf("\n");

    // 9. Parcourir un tableau
    printf("9. Parcourir un tableau\n");
    int ports[] = {80, 443, 22, 21, 3389};
    int size = 5;

    for (int i = 0; i < size; i++) {
        printf("   Port[%d] = %d\n", i, ports[i]);
    }
    printf("\n");

    // 10. Compteur (compter les nombres pairs)
    printf("10. Compteur (nombres pairs entre 0 et 20)\n");
    int even_count = 0;
    for (int i = 0; i <= 20; i++) {
        if (i % 2 == 0) {
            even_count++;
        }
    }
    printf("   Nombres pairs trouvés : %d\n\n", even_count);

    // 11. Accumulateur (somme)
    printf("11. Accumulateur (somme de 1 à 10)\n");
    int sum = 0;
    for (int i = 1; i <= 10; i++) {
        sum += i;
    }
    printf("   Somme : %d\n\n", sum);

    // 12. Recherche dans un tableau
    printf("12. Recherche dans un tableau\n");
    int target = 22;
    int found = 0;

    for (int i = 0; i < size; i++) {
        if (ports[i] == target) {
            printf("   Port %d trouvé à l'index %d\n", target, i);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("   Port %d non trouvé\n", target);
    }
    printf("\n");

    // 13. Exemple Red Team : Scan de ports (simulé)
    printf("13. Exemple Red Team : Scan de ports\n");
    printf("   Scanning ports 1-1024...\n");
    int open_ports[] = {22, 80, 443};  // Ports "ouverts" simulés
    int open_count = 3;

    for (int port = 1; port <= 1024; port++) {
        // Vérifier si le port est dans notre liste
        int is_open = 0;
        for (int i = 0; i < open_count; i++) {
            if (port == open_ports[i]) {
                is_open = 1;
                break;
            }
        }

        if (is_open) {
            printf("   [+] Port %d : OPEN\n", port);
        }

        // Afficher progression tous les 256 ports
        if (port % 256 == 0) {
            printf("   [*] Progression : %d/1024\n", port);
        }
    }
    printf("   [*] Scan terminé.\n\n");

    // 14. XOR encoder un tableau (Red Team)
    printf("14. XOR encoder un tableau\n");
    unsigned char shellcode[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    unsigned char key = 0x42;
    int shellcode_size = 5;

    printf("   Original : ");
    for (int i = 0; i < shellcode_size; i++) {
        printf("%c", shellcode[i]);
    }
    printf("\n");

    // Encodage
    for (int i = 0; i < shellcode_size; i++) {
        shellcode[i] ^= key;
    }

    printf("   Encodé   : ");
    for (int i = 0; i < shellcode_size; i++) {
        printf("\\x%02x ", shellcode[i]);
    }
    printf("\n");

    // Décodage
    for (int i = 0; i < shellcode_size; i++) {
        shellcode[i] ^= key;
    }

    printf("   Décodé   : ");
    for (int i = 0; i < shellcode_size; i++) {
        printf("%c", shellcode[i]);
    }
    printf("\n\n");

    // 15. Boucle infinie (avec sortie contrôlée)
    printf("15. Boucle infinie (avec sortie)\n");
    int iterations = 0;
    while (1) {  // Boucle infinie
        printf("   Itération %d\n", iterations);
        iterations++;

        if (iterations >= 5) {
            printf("   Sortie de la boucle infinie.\n");
            break;  // Sortie propre
        }
    }

    printf("\n[+] Programme terminé avec succès.\n");
    return 0;
}

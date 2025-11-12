#include <stdio.h>

int main() {
    printf("=== BOUCLES EN C ===\n\n");

    // 1. BOUCLE FOR
    printf("1. Boucle FOR (compte de 1 à 5) :\n");
    for (int i = 1; i <= 5; i++) {
        printf("   Iteration %d\n", i);
    }

    // 2. BOUCLE WHILE
    printf("\n2. Boucle WHILE (compte à rebours) :\n");
    int compte = 5;
    while (compte > 0) {
        printf("   %d...\n", compte);
        compte--;
    }
    printf("   Decollage!\n");

    // 3. BOUCLE DO-WHILE
    printf("\n3. Boucle DO-WHILE (execute au moins une fois) :\n");
    int valeur = 0;
    do {
        printf("   Valeur : %d\n", valeur);
        valeur++;
    } while (valeur < 3);

    // 4. BREAK - Sortir d'une boucle
    printf("\n4. Utilisation de BREAK :\n");
    for (int i = 1; i <= 10; i++) {
        if (i == 5) {
            printf("   Stop a 5!\n");
            break;  // Sort de la boucle
        }
        printf("   %d ", i);
    }

    // 5. CONTINUE - Sauter une iteration
    printf("\n\n5. Utilisation de CONTINUE (saute les pairs) :\n");
    for (int i = 1; i <= 8; i++) {
        if (i % 2 == 0) {
            continue;  // Saute les nombres pairs
        }
        printf("   %d ", i);
    }

    // 6. BOUCLES IMBRIQUEES - Table de multiplication
    printf("\n\n6. Boucles imbriquees (table de multiplication 3x3) :\n");
    for (int i = 1; i <= 3; i++) {
        for (int j = 1; j <= 3; j++) {
            printf("   %d x %d = %d\n", i, j, i * j);
        }
    }

    // 7. Boucle avec calcul - Somme des nombres de 1 à 10
    printf("\n7. Calcul de somme :\n");
    int somme = 0;
    for (int i = 1; i <= 10; i++) {
        somme += i;  // Ajoute i à la somme
    }
    printf("   Somme de 1 a 10 = %d\n", somme);

    // 8. Boucle avec input utilisateur
    printf("\n8. Menu avec boucle :\n");
    int choix;
    do {
        printf("\n   Menu :\n");
        printf("   1. Option 1\n");
        printf("   2. Option 2\n");
        printf("   3. Quitter\n");
        printf("   Votre choix : ");
        scanf("%d", &choix);

        if (choix == 1) {
            printf("   -> Vous avez choisi l'option 1\n");
        } else if (choix == 2) {
            printf("   -> Vous avez choisi l'option 2\n");
        } else if (choix == 3) {
            printf("   -> Au revoir!\n");
        } else {
            printf("   -> Choix invalide\n");
        }
    } while (choix != 3);

    return 0;
}

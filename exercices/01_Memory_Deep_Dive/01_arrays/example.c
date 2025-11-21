#include <stdio.h>

int main() {
    printf("=== TABLEAUX EN C ===\n\n");

    // 1. DECLARATION ET INITIALISATION
    printf("1. Declaration et initialisation :\n");
    int nombres[5] = {10, 20, 30, 40, 50};

    printf("   Tableau : ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", nombres[i]);
    }
    printf("\n");

    // 2. ACCES AUX ELEMENTS
    printf("\n2. Acces aux elements :\n");
    printf("   Premier element (index 0) : %d\n", nombres[0]);
    printf("   Troisieme element (index 2) : %d\n", nombres[2]);
    printf("   Dernier element (index 4) : %d\n", nombres[4]);

    // 3. MODIFICATION D'ELEMENTS
    printf("\n3. Modification d'elements :\n");
    nombres[2] = 99;  // Change 30 en 99
    printf("   Apres modification : ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", nombres[i]);
    }
    printf("\n");

    // 4. CALCUL DE LA TAILLE
    printf("\n4. Calcul de la taille :\n");
    int taille = sizeof(nombres) / sizeof(nombres[0]);
    printf("   Taille du tableau : %d elements\n", taille);

    // 5. SOMME DES ELEMENTS
    printf("\n5. Somme des elements :\n");
    int somme = 0;
    for (int i = 0; i < 5; i++) {
        somme += nombres[i];
    }
    printf("   Somme : %d\n", somme);

    // 6. TROUVER LE MAXIMUM
    printf("\n6. Trouver le maximum :\n");
    int max = nombres[0];
    for (int i = 1; i < 5; i++) {
        if (nombres[i] > max) {
            max = nombres[i];
        }
    }
    printf("   Maximum : %d\n", max);

    // 7. TABLEAU 2D (MATRICE)
    printf("\n7. Tableau 2D (matrice 3x3) :\n");
    int matrice[3][3] = {
        {1, 2, 3},
        {4, 5, 6},
        {7, 8, 9}
    };

    for (int i = 0; i < 3; i++) {
        printf("   ");
        for (int j = 0; j < 3; j++) {
            printf("%d ", matrice[i][j]);
        }
        printf("\n");
    }

    // 8. NOTES D'ETUDIANTS
    printf("\n8. Exemple pratique - Notes d'etudiants :\n");
    float notes[5] = {15.5, 18.0, 12.5, 16.0, 14.5};
    float somme_notes = 0;

    printf("   Notes : ");
    for (int i = 0; i < 5; i++) {
        printf("%.1f ", notes[i]);
        somme_notes += notes[i];
    }

    float moyenne = somme_notes / 5;
    printf("\n   Moyenne : %.2f/20\n", moyenne);

    return 0;
}

#include <stdio.h>

// Prototypes (déclarations)
void afficher_menu();
int additionner(int a, int b);
int multiplier(int a, int b);
float calculer_moyenne(int tab[], int taille);
int est_pair(int n);
void afficher_tableau(int tab[], int taille);

int main() {
    printf("=== FONCTIONS EN C ===\n\n");

    // 1. FONCTION SANS PARAMETRES, SANS RETOUR
    printf("1. Fonction void :\n");
    afficher_menu();

    // 2. FONCTION AVEC PARAMETRES ET RETOUR
    printf("\n2. Fonction avec retour :\n");
    int somme = additionner(10, 20);
    printf("   10 + 20 = %d\n", somme);

    int produit = multiplier(5, 6);
    printf("   5 x 6 = %d\n", produit);

    // 3. FONCTION AVEC TABLEAU
    printf("\n3. Fonction avec tableau :\n");
    int notes[5] = {15, 18, 12, 16, 14};
    float moyenne = calculer_moyenne(notes, 5);
    printf("   Moyenne : %.2f\n", moyenne);

    // 4. FONCTION QUI RETOURNE UN BOOLEEN
    printf("\n4. Fonction booleen :\n");
    int nombre = 42;
    if (est_pair(nombre)) {
        printf("   %d est pair\n", nombre);
    } else {
        printf("   %d est impair\n", nombre);
    }

    // 5. FONCTION UTILITAIRE
    printf("\n5. Fonction utilitaire :\n");
    int valeurs[6] = {10, 20, 30, 40, 50, 60};
    printf("   Tableau : ");
    afficher_tableau(valeurs, 6);

    return 0;
}

// Définitions des fonctions

void afficher_menu() {
    printf("   === MENU ===\n");
    printf("   1. Option 1\n");
    printf("   2. Option 2\n");
    printf("   3. Quitter\n");
}

int additionner(int a, int b) {
    return a + b;  // Retourne la somme
}

int multiplier(int a, int b) {
    return a * b;
}

float calculer_moyenne(int tab[], int taille) {
    int somme = 0;

    for (int i = 0; i < taille; i++) {
        somme += tab[i];
    }

    return (float)somme / taille;  // Cast en float pour la division
}

int est_pair(int n) {
    return (n % 2 == 0);  // Retourne 1 si pair, 0 si impair
}

void afficher_tableau(int tab[], int taille) {
    for (int i = 0; i < taille; i++) {
        printf("%d ", tab[i]);
    }
    printf("\n");
}

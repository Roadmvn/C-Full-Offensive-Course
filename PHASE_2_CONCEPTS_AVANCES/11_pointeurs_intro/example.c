#include <stdio.h>
#include <stdlib.h>

// Fonction qui modifie une valeur via un pointeur
void incrementer(int *valeur) {
    (*valeur)++;  // Incrémente la valeur pointée
}

// Fonction qui échange deux valeurs
void echanger(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main() {
    printf("=== Bases des Pointeurs ===\n\n");

    // 1. Déclaration et utilisation basique
    int nombre = 42;
    int *ptr_nombre = &nombre;  // ptr_nombre contient l'adresse de nombre

    printf("Valeur de nombre: %d\n", nombre);
    printf("Adresse de nombre: %p\n", (void*)&nombre);
    printf("Valeur de ptr_nombre (adresse): %p\n", (void*)ptr_nombre);
    printf("Valeur pointée par ptr_nombre: %d\n", *ptr_nombre);
    printf("\n");

    // 2. Modification via pointeur
    *ptr_nombre = 100;  // Change nombre via le pointeur
    printf("Après *ptr_nombre = 100:\n");
    printf("Valeur de nombre: %d\n", nombre);
    printf("\n");

    // 3. Pointeurs et fonctions
    int x = 5;
    printf("Avant incrementer: x = %d\n", x);
    incrementer(&x);  // Passe l'adresse de x
    printf("Après incrementer: x = %d\n", x);
    printf("\n");

    // 4. Échange de valeurs
    int val1 = 10, val2 = 20;
    printf("Avant échange: val1 = %d, val2 = %d\n", val1, val2);
    echanger(&val1, &val2);
    printf("Après échange: val1 = %d, val2 = %d\n", val1, val2);
    printf("\n");

    // 5. Pointeur NULL
    int *ptr_null = NULL;  // Pointeur qui ne pointe vers rien
    printf("Vérification du pointeur NULL:\n");
    if (ptr_null == NULL) {
        printf("Le pointeur est NULL (sécurisé)\n");
    }
    printf("\n");

    // 6. Pointeurs et types de données
    char lettre = 'A';
    char *ptr_char = &lettre;

    float pi = 3.14;
    float *ptr_float = &pi;

    printf("Pointeur char: %p -> valeur: %c\n", (void*)ptr_char, *ptr_char);
    printf("Pointeur float: %p -> valeur: %.2f\n", (void*)ptr_float, *ptr_float);
    printf("\n");

    // 7. Taille des pointeurs
    printf("=== Tailles en mémoire ===\n");
    printf("Taille d'un int: %zu bytes\n", sizeof(int));
    printf("Taille d'un pointeur int*: %zu bytes\n", sizeof(int*));
    printf("Taille d'un char: %zu bytes\n", sizeof(char));
    printf("Taille d'un pointeur char*: %zu bytes\n", sizeof(char*));
    printf("Taille d'un float: %zu bytes\n", sizeof(float));
    printf("Taille d'un pointeur float*: %zu bytes\n", sizeof(float*));
    printf("\n");

    // 8. Exemple avec un tableau (aperçu)
    int tableau[5] = {10, 20, 30, 40, 50};
    int *ptr_tableau = tableau;  // Le nom du tableau est déjà un pointeur

    printf("Premier élément via tableau: %d\n", tableau[0]);
    printf("Premier élément via pointeur: %d\n", *ptr_tableau);
    printf("Deuxième élément via pointeur: %d\n", *(ptr_tableau + 1));
    printf("\n");

    // 9. Comparaison de pointeurs
    int a = 10, b = 20;
    int *ptr_a = &a;
    int *ptr_b = &b;

    if (ptr_a == ptr_b) {
        printf("Les pointeurs pointent vers la même adresse\n");
    } else {
        printf("Les pointeurs pointent vers des adresses différentes\n");
    }

    if (*ptr_a < *ptr_b) {
        printf("La valeur pointée par ptr_a (%d) est plus petite que ptr_b (%d)\n", *ptr_a, *ptr_b);
    }
    printf("\n");

    // 10. Pointeur vers pointeur (aperçu)
    int valeur = 777;
    int *ptr1 = &valeur;
    int **ptr2 = &ptr1;  // Pointeur vers un pointeur

    printf("=== Pointeur vers pointeur ===\n");
    printf("Valeur: %d\n", valeur);
    printf("Via ptr1: %d\n", *ptr1);
    printf("Via ptr2: %d\n", **ptr2);  // Double déréférencement

    return 0;
}

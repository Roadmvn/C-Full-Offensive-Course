#include <stdio.h>

int main() {
    // printf() : affichage formaté

    int age = 25;
    float taille = 1.75;
    char grade = 'A';

    // Format specifiers de base
    printf("Age : %d\n", age);           // %d pour int
    printf("Taille : %.2f m\n", taille); // %.2f pour 2 décimales
    printf("Grade : %c\n", grade);       // %c pour char

    // Largeur de champ
    printf("Avec largeur : [%5d]\n", 42);    // "   42"
    printf("À gauche : [%-5d]\n", 42);       // "42   "

    // scanf() : lecture depuis clavier
    int nombre;
    printf("\nEntrez un nombre : ");
    scanf("%d", &nombre);  // & = adresse de la variable
    printf("Vous avez entré : %d\n", nombre);

    // Lire un caractère
    char lettre;
    printf("Entrez une lettre : ");
    scanf(" %c", &lettre);  // Espace avant %c important
    printf("Vous avez entré : %c\n", lettre);

    // Lire un float
    float valeur;
    printf("Entrez un nombre décimal : ");
    scanf("%f", &valeur);
    printf("Vous avez entré : %.2f\n", valeur);

    return 0;
}

#include <stdio.h>

/*
 * Programme : Hello World
 * Description : Premier programme en C
 * Compilation : gcc example.c -o example
 */

int main() {
    // Affichage simple
    printf("Hello World!\n");

    // Affichage avec des caractères spéciaux
    printf("Bienvenue dans le C offensif.\n");
    printf("Ligne 1\nLigne 2\n");  // \n = nouvelle ligne
    printf("Tab\tIci\n");           // \t = tabulation

    // Affichage de variables
    int age = 25;
    printf("Age: %d\n", age);  // %d pour un entier (decimal)

    // Affichage de plusieurs variables
    int x = 10, y = 20;
    printf("x = %d, y = %d\n", x, y);

    // Affichage de texte
    char* nom = "Hacker";
    printf("Nom: %s\n", nom);  // %s pour une string

    // Formatages courants
    printf("Hexadécimal: 0x%x\n", 255);      // %x = hexa (minuscule)
    printf("Hexadécimal: 0x%X\n", 255);      // %X = hexa (majuscule)
    printf("Pointeur: %p\n", (void*)&age);   // %p = adresse mémoire
    printf("Caractère: %c\n", 'A');          // %c = caractère unique

    // Message de fin
    printf("\n[+] Programme terminé avec succès.\n");

    return 0;  // Code de retour (0 = succès)
}

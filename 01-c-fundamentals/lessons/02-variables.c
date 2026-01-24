/*
 * ============================================================================
 * LESSON 02 : Variables - Les boites de rangement de l'ordinateur
 * ============================================================================
 *
 * OBJECTIF : Comprendre comment stocker des valeurs en memoire
 * PREREQUIS : Lesson 01 (Hello World)
 * COMPILE  : cl 02-variables.c
 *
 * ============================================================================
 * ANALOGIE ENFANT 5 ANS :
 *
 * Imagine des boites de rangement avec des etiquettes :
 * - Chaque boite a un NOM (l'etiquette)
 * - Chaque boite contient UNE VALEUR (ce qu'il y a dedans)
 * - Il existe differentes TAILLES de boites (types)
 *
 * Exemple :
 *   Boite "age"       -> contient 25
 *   Boite "prix"      -> contient 19.99
 *   Boite "initiale"  -> contient 'T'
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    // ========================================================================
    // PARTIE 1 : LES TYPES DE BOITES (types de variables)
    // ========================================================================

    // TYPE 1 : int (integer = nombre entier)
    // Peut stocker : -2 milliards a +2 milliards (environ)
    // Utilise : pour les compteurs, ages, quantites

    int age = 25;
    int score = 1000;
    int temperature = -5;  // Les nombres negatifs marchent aussi !

    printf("=== ENTIERS (int) ===\n");
    printf("Age : %d ans\n", age);
    printf("Score : %d points\n", score);
    printf("Temperature : %d degres\n", temperature);

    // NOTE : %d = "decimal" = affiche un nombre entier
    //        La variable remplace le %d dans le texte


    // TYPE 2 : float (floating point = nombre a virgule)
    // Peut stocker : nombres avec decimales
    // Utilise : pour les prix, mesures, pourcentages

    float prix = 19.99f;     // Le 'f' a la fin indique que c'est un float
    float taille = 1.75f;    // 1 metre 75
    float pi = 3.14159f;

    printf("\n=== DECIMAUX (float) ===\n");
    printf("Prix : %.2f euros\n", prix);      // %.2f = 2 chiffres apres virgule
    printf("Taille : %.2f m\n", taille);
    printf("Pi : %.5f\n", pi);                // %.5f = 5 chiffres apres virgule


    // TYPE 3 : char (character = un seul caractere)
    // Peut stocker : une lettre, un chiffre, un symbole
    // Utilise : pour les initiales, les grades, les reponses O/N

    char initiale = 'T';     // ATTENTION : guillemets SIMPLES pour char
    char grade = 'A';
    char reponse = 'Y';

    printf("\n=== CARACTERES (char) ===\n");
    printf("Initiale : %c\n", initiale);      // %c = character
    printf("Grade : %c\n", grade);
    printf("Reponse : %c\n", reponse);

    // SECRET : En realite, un char stocke un NOMBRE (code ASCII)
    printf("Code ASCII de '%c' : %d\n", initiale, initiale);
    // 'T' = 84 en ASCII


    // ========================================================================
    // PARTIE 2 : MODIFIER LE CONTENU DES BOITES
    // ========================================================================

    printf("\n=== MODIFICATION ===\n");

    int compteur = 0;
    printf("Compteur initial : %d\n", compteur);

    compteur = 10;           // On remplace le contenu
    printf("Apres = 10 : %d\n", compteur);

    compteur = compteur + 5; // On ajoute 5 a la valeur actuelle
    printf("Apres + 5 : %d\n", compteur);

    compteur = compteur * 2; // On multiplie par 2
    printf("Apres * 2 : %d\n", compteur);


    // ========================================================================
    // PARTIE 3 : RACCOURCIS D'ECRITURE
    // ========================================================================

    printf("\n=== RACCOURCIS ===\n");

    int x = 10;

    x += 5;   // Equivalent a : x = x + 5
    printf("x += 5  -> x = %d\n", x);

    x -= 3;   // Equivalent a : x = x - 3
    printf("x -= 3  -> x = %d\n", x);

    x *= 2;   // Equivalent a : x = x * 2
    printf("x *= 2  -> x = %d\n", x);

    x /= 4;   // Equivalent a : x = x / 4
    printf("x /= 4  -> x = %d\n", x);

    x++;      // Equivalent a : x = x + 1 (tres utilise dans les boucles)
    printf("x++    -> x = %d\n", x);

    x--;      // Equivalent a : x = x - 1
    printf("x--    -> x = %d\n", x);


    return 0;
}

/*
 * ============================================================================
 * RESUME DES TYPES :
 *
 * | Type  | Contenu              | Symbole printf | Exemple        |
 * |-------|----------------------|----------------|----------------|
 * | int   | Nombre entier        | %d             | 42, -7, 0      |
 * | float | Nombre a virgule     | %f             | 3.14, -0.5     |
 * | char  | Un seul caractere    | %c             | 'A', '7', '@'  |
 *
 * ============================================================================
 * PIEGES COURANTS :
 *
 * 1. Oublier d'initialiser : int x; (x contient n'importe quoi!)
 *    -> Toujours ecrire : int x = 0;
 *
 * 2. Mauvais type pour printf : printf("%d", 3.14);
 *    -> Affiche n'importe quoi ! Utilise %f pour les float
 *
 * 3. Guillemets doubles pour char : char c = "A";
 *    -> ERREUR ! Utilise guillemets simples : char c = 'A';
 *
 * ============================================================================
 */

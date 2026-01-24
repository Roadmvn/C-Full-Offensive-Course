/*
 * ============================================================================
 * LESSON 05 : Fonctions - Creer ses propres outils
 * ============================================================================
 *
 * OBJECTIF : Organiser le code en blocs reutilisables
 * PREREQUIS : Lesson 04 (Boucles)
 * COMPILE  : cl 05-functions.c
 *
 * ============================================================================
 * ANALOGIE ENFANT 5 ANS :
 *
 * Une fonction, c'est comme une RECETTE DE CUISINE :
 *
 * Recette "faire_crepe" :
 *   - Ingredients (parametres) : farine, oeufs, lait
 *   - Instructions : melanger, chauffer, verser
 *   - Resultat (return) : une crepe !
 *
 * Une fois la recette ecrite, tu peux l'utiliser autant de fois que tu veux
 * sans reecrire toutes les etapes.
 *
 * ============================================================================
 */

#include <stdio.h>

// ============================================================================
// PARTIE 1 : DECLARATION DES FONCTIONS (avant main)
// ============================================================================

// Les fonctions doivent etre declarees AVANT d'etre utilisees
// On les met avant main(), ou on utilise des "prototypes"

// PROTOTYPE : juste la signature de la fonction (sans le code)
// Ca dit au compilateur "cette fonction existe, je te la definis plus tard"

void dire_bonjour(void);                    // Pas de param, pas de retour
int additionner(int a, int b);              // 2 params, retourne int
float calculer_moyenne(int x, int y, int z); // 3 params, retourne float
void afficher_etoiles(int nombre);          // 1 param, pas de retour
int est_pair(int n);                        // 1 param, retourne 0 ou 1


// ============================================================================
// FONCTION MAIN
// ============================================================================

int main()
{
    printf("=== UTILISATION DES FONCTIONS ===\n\n");

    // ------------------------------------------------------------------------
    // Fonction sans parametre ni retour
    // ------------------------------------------------------------------------

    printf("1. Fonction simple (void/void) :\n");
    dire_bonjour();  // Appel de la fonction
    dire_bonjour();  // On peut l'appeler plusieurs fois !


    // ------------------------------------------------------------------------
    // Fonction avec parametres et retour
    // ------------------------------------------------------------------------

    printf("\n2. Fonction avec retour (int) :\n");

    int resultat = additionner(5, 3);
    printf("   5 + 3 = %d\n", resultat);

    // On peut aussi utiliser directement dans printf :
    printf("   10 + 20 = %d\n", additionner(10, 20));

    // On peut passer des variables :
    int a = 100;
    int b = 50;
    printf("   %d + %d = %d\n", a, b, additionner(a, b));


    // ------------------------------------------------------------------------
    // Fonction avec plusieurs parametres
    // ------------------------------------------------------------------------

    printf("\n3. Fonction moyenne (float) :\n");

    float moy = calculer_moyenne(10, 15, 20);
    printf("   Moyenne de 10, 15, 20 = %.2f\n", moy);


    // ------------------------------------------------------------------------
    // Fonction utilitaire
    // ------------------------------------------------------------------------

    printf("\n4. Fonction affichage :\n");

    afficher_etoiles(5);
    afficher_etoiles(10);
    afficher_etoiles(3);


    // ------------------------------------------------------------------------
    // Fonction booleenne (retourne vrai/faux)
    // ------------------------------------------------------------------------

    printf("\n5. Fonction booleenne :\n");

    for (int i = 1; i <= 6; i++)
    {
        if (est_pair(i))
        {
            printf("   %d est pair\n", i);
        }
        else
        {
            printf("   %d est impair\n", i);
        }
    }


    // ------------------------------------------------------------------------
    // Combiner les fonctions
    // ------------------------------------------------------------------------

    printf("\n6. Combiner des fonctions :\n");

    int somme = additionner(additionner(1, 2), additionner(3, 4));
    printf("   (1+2) + (3+4) = %d\n", somme);


    return 0;
}


// ============================================================================
// PARTIE 2 : DEFINITION DES FONCTIONS (apres main)
// ============================================================================

/*
 * Fonction sans parametre ni valeur de retour
 *
 * void = "vide" = pas de valeur de retour
 * (void) = pas de parametres
 */
void dire_bonjour(void)
{
    printf("   Bonjour !\n");
    // Pas de return car void
}


/*
 * Fonction qui additionne deux nombres
 *
 * int a, int b = deux parametres de type int
 * return = renvoie le resultat
 */
int additionner(int a, int b)
{
    int somme = a + b;
    return somme;

    // Version courte :
    // return a + b;
}


/*
 * Fonction qui calcule une moyenne
 *
 * Note : on divise par 3.0 (pas 3) pour avoir un resultat decimal
 */
float calculer_moyenne(int x, int y, int z)
{
    float total = x + y + z;
    return total / 3.0f;
}


/*
 * Fonction qui affiche N etoiles
 *
 * Utilise une boucle interne
 */
void afficher_etoiles(int nombre)
{
    printf("   ");
    for (int i = 0; i < nombre; i++)
    {
        printf("*");
    }
    printf(" (%d etoiles)\n", nombre);
}


/*
 * Fonction qui teste si un nombre est pair
 *
 * Retourne 1 (vrai) si pair, 0 (faux) si impair
 * C'est une "fonction booleenne"
 */
int est_pair(int n)
{
    if (n % 2 == 0)
    {
        return 1;  // Vrai
    }
    else
    {
        return 0;  // Faux
    }

    // Version courte :
    // return (n % 2 == 0);
}


/*
 * ============================================================================
 * RESUME :
 *
 * Structure d'une fonction :
 *
 *     type_retour nom_fonction(type1 param1, type2 param2)
 *     {
 *         // Instructions
 *         return valeur;  // Si pas void
 *     }
 *
 * Types de retour courants :
 *     void  = rien
 *     int   = nombre entier
 *     float = nombre decimal
 *     char  = caractere
 *
 * ============================================================================
 * POURQUOI UTILISER DES FONCTIONS ?
 *
 * 1. REUTILISATION : Ecrire une fois, utiliser partout
 * 2. LISIBILITE : Code organise en blocs logiques
 * 3. MAINTENANCE : Corriger a un seul endroit
 * 4. TEST : Tester chaque fonction separement
 *
 * ============================================================================
 * VOCABULAIRE :
 *
 * - Definition : le code complet de la fonction
 * - Declaration/Prototype : juste la signature (avant main)
 * - Appel : utiliser la fonction
 * - Parametre : variable recue par la fonction
 * - Argument : valeur passee lors de l'appel
 * - Retour : valeur renvoyee par la fonction
 *
 * ============================================================================
 * MALDEV PREVIEW :
 *
 * En maldev, on cree des fonctions pour :
 * - xor_decrypt(data, key)    : Dechiffrer des donnees
 * - resolve_api(hash)         : Trouver une fonction Windows
 * - inject_shellcode(pid, sc) : Injecter du code
 *
 * Chaque fonction fait UNE chose bien, puis on les combine.
 *
 * ============================================================================
 */

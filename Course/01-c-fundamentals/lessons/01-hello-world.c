/*
 * ============================================================================
 * LESSON 01 : Hello World - Ton premier programme C
 * ============================================================================
 *
 * OBJECTIF : Comprendre la structure minimale d'un programme C
 * PREREQUIS : Savoir ouvrir un terminal et un editeur de texte
 * COMPILE  : cl 01-hello-world.c   (Windows)
 *            gcc 01-hello-world.c  (Linux/Mac)
 *
 * ============================================================================
 * ANALOGIE ENFANT 5 ANS :
 *
 * Imagine que tu ecris une lettre a l'ordinateur.
 * - Tu dois d'abord lui dire QUELS OUTILS tu vas utiliser (#include)
 * - Ensuite tu lui donnes des INSTRUCTIONS (dans main)
 * - L'ordinateur lit tes instructions DE HAUT EN BAS
 * - Quand il a fini, il te dit "j'ai fini" (return 0)
 *
 * ============================================================================
 */

// LIGNE 1 : On dit a l'ordinateur "je veux utiliser les outils d'affichage"
//
// #include = "inclure" = "ajouter"
// <stdio.h> = "Standard Input/Output" = outils pour afficher/lire du texte
//
// Sans cette ligne, l'ordinateur ne sait pas ce que veut dire "printf"
// C'est comme essayer de cuisiner sans avoir sorti les ustensiles !

#include <stdio.h>


// LIGNE 2 : La fonction principale - LE POINT DE DEPART
//
// int    = le type de reponse (un nombre entier)
// main   = le nom de la fonction principale (TOUJOURS "main")
// ()     = les parentheses pour les parametres (vide pour l'instant)
// { }    = les accolades contiennent les instructions
//
// Quand tu lances le programme, l'ordinateur cherche "main" et commence la

int main()
{
    // LIGNE 3 : Afficher du texte a l'ecran
    //
    // printf = "print formatted" = "affiche avec mise en forme"
    // "..."  = le texte entre guillemets
    // \n     = "new line" = aller a la ligne (comme appuyer sur Entree)
    // ;      = le point-virgule termine CHAQUE instruction (tres important!)

    printf("Hello, World!\n");

    // LIGNE 4 : Dire a l'ordinateur "tout s'est bien passe"
    //
    // return = "retourner" = donner une reponse
    // 0      = code de succes (0 = pas d'erreur)
    //
    // Si on retournait 1, ca voudrait dire "il y a eu un probleme"

    return 0;
}

/*
 * ============================================================================
 * EXERCICE MENTAL :
 *
 * 1. Que se passe-t-il si tu oublies le ; apres printf ?
 *    -> Erreur de compilation ! Le compilateur ne sait pas ou finit l'instruction
 *
 * 2. Que se passe-t-il si tu oublies \n ?
 *    -> Ca marche, mais le texte suivant sera colle (pas de retour a la ligne)
 *
 * 3. Que se passe-t-il si tu ecris "Main" au lieu de "main" ?
 *    -> Erreur ! C est sensible a la casse (majuscules != minuscules)
 *
 * ============================================================================
 * A TOI DE JOUER :
 *
 * Modifie le texte dans printf pour afficher ton prenom !
 * Compile et execute pour voir le resultat.
 *
 * ============================================================================
 */

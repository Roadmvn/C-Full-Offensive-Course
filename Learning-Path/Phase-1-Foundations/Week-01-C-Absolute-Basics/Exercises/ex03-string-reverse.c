/*
 * ============================================================================
 * EXERCICE 03 : Inverser une chaine de caracteres
 * ============================================================================
 *
 * DIFFICULTE : ⭐⭐⭐ (Difficile)
 *
 * OBJECTIF : Inverser un texte ("HELLO" -> "OLLEH")
 *
 * CE QUE TU VAS PRATIQUER :
 * - Tableaux de caracteres (strings)
 * - Boucles (for)
 * - Indices de tableau
 *
 * COMPILE : cl ex03-string-reverse.c
 *
 * ============================================================================
 * CONTEXTE MALDEV :
 *
 * Pourquoi cet exercice est utile pour le maldev ?
 *
 * Les malwares cachent souvent leurs strings (noms de fichiers, URLs, etc.)
 * en les INVERSANT dans le code source.
 *
 * Au lieu d'ecrire : "cmd.exe"
 * On ecrit : "exe.dmc" et on inverse au runtime
 *
 * Comme ca, les scanners antivirus ne trouvent pas "cmd.exe" dans le binaire !
 *
 * ============================================================================
 * EXEMPLE DE SORTIE ATTENDUE :
 *
 *   String originale : HELLO
 *   String inversee  : OLLEH
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    printf("=== STRING REVERSE ===\n\n");

    // ========================================================================
    // LA STRING A INVERSER
    //
    // En C, une string est un TABLEAU de caracteres termine par '\0'
    // "HELLO" = ['H', 'E', 'L', 'L', 'O', '\0']
    //
    // Les indices commencent a 0 :
    //   str[0] = 'H'
    //   str[1] = 'E'
    //   str[2] = 'L'
    //   str[3] = 'L'
    //   str[4] = 'O'
    //   str[5] = '\0' (caractere de fin)
    // ========================================================================

    char str[] = "HELLO";

    printf("String originale : %s\n", str);


    // ========================================================================
    // TODO 1 : Calcule la longueur de la string
    //
    // Parcours la string jusqu'a trouver '\0' (le caractere de fin)
    // Compte combien de caracteres il y a
    //
    // INDICE :
    //   int len = 0;
    //   while (str[len] != '\0') {
    //       len++;
    //   }
    // ========================================================================

    int len = 0;

    // Ecris ton code ici pour calculer len :



    printf("Longueur : %d\n", len);


    // ========================================================================
    // TODO 2 : Inverse la string EN PLACE
    //
    // Methode : echange le premier avec le dernier, le 2eme avec l'avant-dernier, etc.
    //
    // HELLO (longueur 5)
    //   [0] <-> [4] : H <-> O -> OELLH
    //   [1] <-> [3] : E <-> L -> OLLEH
    //   [2] reste au milieu
    //
    // On s'arrete quand i >= j (on a atteint ou depasse le milieu)
    //
    // STRUCTURE :
    //   int i = 0;           // Debut
    //   int j = len - 1;     // Fin
    //
    //   while (i < j) {
    //       // Echange str[i] et str[j]
    //       // ... ton code ici ...
    //
    //       i++;  // Avance vers le milieu
    //       j--;  // Recule vers le milieu
    //   }
    //
    // INDICE POUR ECHANGER DEUX VALEURS :
    //   char temp = str[i];
    //   str[i] = str[j];
    //   str[j] = temp;
    // ========================================================================

    // Ecris ton code ici pour inverser la string :



    printf("String inversee  : %s\n", str);


    return 0;
}

/*
 * ============================================================================
 * INDICES (ne regarde que si tu es bloque) :
 *
 * INDICE 1 : Calculer la longueur
 *   int len = 0;
 *   while (str[len] != '\0') {
 *       len++;
 *   }
 *   // Apres cette boucle, len = 5 pour "HELLO"
 *
 * INDICE 2 : Echanger deux elements
 *   Pour echanger A et B, on a besoin d'une variable temporaire :
 *   temp = A;   // Sauvegarde A
 *   A = B;      // Ecrase A avec B
 *   B = temp;   // Met l'ancien A dans B
 *
 * INDICE 3 : La boucle complete
 *   int i = 0;
 *   int j = len - 1;
 *   while (i < j) {
 *       char temp = str[i];
 *       str[i] = str[j];
 *       str[j] = temp;
 *       i++;
 *       j--;
 *   }
 *
 * ============================================================================
 * VISUALISATION :
 *
 * "HELLO" (len=5)
 *
 * Debut : i=0, j=4
 *   H E L L O
 *   ^       ^
 *   i       j
 *   Echange H et O -> O E L L H
 *
 * Apres i++, j-- : i=1, j=3
 *   O E L L H
 *     ^   ^
 *     i   j
 *   Echange E et L -> O L L E H
 *
 * Apres i++, j-- : i=2, j=2
 *   i >= j ? NON (2 < 2 est FAUX) -> STOP
 *
 * Resultat : OLLEH
 *
 * ============================================================================
 * BONUS :
 *
 * 1. Modifie pour inverser "MALWARE" -> "ERAWLAM"
 * 2. Cree une fonction : void reverse(char str[])
 * 3. Utilise pour "cacher" une string comme le ferait un malware :
 *    char hidden[] = "exe.dmc";  // cmd.exe inverse
 *    reverse(hidden);
 *    printf("Commande : %s\n", hidden);  // Affiche "cmd.exe"
 *
 * ============================================================================
 */

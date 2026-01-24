/*
 * ============================================================================
 * EXERCICE 01 : Calculatrice simple
 * ============================================================================
 *
 * DIFFICULTE : ⭐ (Facile)
 *
 * OBJECTIF : Creer une calculatrice qui fait +, -, *, /
 *
 * CE QUE TU VAS PRATIQUER :
 * - Variables (int, float)
 * - Conditions (if/else if)
 * - Affichage (printf)
 *
 * COMPILE : cl ex01-calculator.c
 *
 * ============================================================================
 * INSTRUCTIONS :
 *
 * 1. Declare deux nombres (a et b) et un operateur (op)
 * 2. Selon l'operateur, effectue le bon calcul
 * 3. Affiche le resultat
 * 4. BONUS : Gere la division par zero !
 *
 * ============================================================================
 * EXEMPLE DE SORTIE ATTENDUE :
 *
 *   Calculatrice Simple
 *   ====================
 *   a = 10
 *   b = 3
 *   Operateur : +
 *
 *   10 + 3 = 13
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    printf("Calculatrice Simple\n");
    printf("====================\n\n");

    // ========================================================================
    // TODO 1 : Declare les variables
    //
    // - int a : premier nombre (exemple: 10)
    // - int b : deuxieme nombre (exemple: 3)
    // - char op : operateur ('+', '-', '*', '/')
    // ========================================================================

    // Ecris ton code ici :



    // ========================================================================
    // TODO 2 : Affiche les valeurs
    //
    // Affiche a, b et l'operateur choisi
    // ========================================================================

    // Ecris ton code ici :



    // ========================================================================
    // TODO 3 : Effectue le calcul selon l'operateur
    //
    // Utilise if/else if pour tester chaque operateur :
    // - Si op == '+' : affiche a + b
    // - Si op == '-' : affiche a - b
    // - Si op == '*' : affiche a * b
    // - Si op == '/' : affiche a / b (attention a la division par zero !)
    // - Sinon : affiche "Operateur inconnu"
    //
    // INDICE pour division :
    //   Pour avoir un resultat decimal, utilise (float)a / b
    // ========================================================================

    // Ecris ton code ici :



    return 0;
}

/*
 * ============================================================================
 * INDICES (ne regarde que si tu es bloque) :
 *
 * INDICE 1 : Declaration de variables
 *   int a = 10;
 *   int b = 3;
 *   char op = '+';
 *
 * INDICE 2 : Comparaison de caractere
 *   if (op == '+') { ... }
 *   // N'oublie pas les guillemets simples pour les char !
 *
 * INDICE 3 : Division par zero
 *   if (op == '/' && b == 0) {
 *       printf("Erreur : division par zero !\n");
 *   }
 *
 * INDICE 4 : Division avec resultat decimal
 *   float resultat = (float)a / (float)b;
 *   printf("%.2f\n", resultat);
 *
 * ============================================================================
 * QUAND TU AS FINI :
 *
 * 1. Compile : cl ex01-calculator.c
 * 2. Execute : ex01-calculator.exe
 * 3. Change les valeurs de a, b, et op pour tester tous les cas
 * 4. Verifie que la division par zero affiche une erreur
 *
 * ============================================================================
 */

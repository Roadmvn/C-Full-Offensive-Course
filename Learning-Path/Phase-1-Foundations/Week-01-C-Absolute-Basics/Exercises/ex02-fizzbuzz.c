/*
 * ============================================================================
 * EXERCICE 02 : FizzBuzz
 * ============================================================================
 *
 * DIFFICULTE : ⭐⭐ (Moyen)
 *
 * OBJECTIF : Le celebre exercice FizzBuzz (utilise en entretiens d'embauche !)
 *
 * CE QUE TU VAS PRATIQUER :
 * - Boucles (for)
 * - Conditions (if/else if/else)
 * - Operateur modulo (%)
 *
 * COMPILE : cl ex02-fizzbuzz.c
 *
 * ============================================================================
 * REGLES DU JEU :
 *
 * Pour chaque nombre de 1 a 20 :
 * - Si le nombre est divisible par 3 ET par 5 : affiche "FizzBuzz"
 * - Si le nombre est divisible par 3 seulement : affiche "Fizz"
 * - Si le nombre est divisible par 5 seulement : affiche "Buzz"
 * - Sinon : affiche le nombre
 *
 * ============================================================================
 * EXEMPLE DE SORTIE ATTENDUE :
 *
 *   1
 *   2
 *   Fizz
 *   4
 *   Buzz
 *   Fizz
 *   7
 *   8
 *   Fizz
 *   Buzz
 *   11
 *   Fizz
 *   13
 *   14
 *   FizzBuzz
 *   16
 *   17
 *   Fizz
 *   19
 *   Buzz
 *
 * ============================================================================
 */

#include <stdio.h>

int main()
{
    printf("=== FIZZBUZZ ===\n\n");

    // ========================================================================
    // TODO 1 : Cree une boucle de 1 a 20
    //
    // Utilise : for (int i = 1; i <= 20; i++)
    // ========================================================================


    // ========================================================================
    // TODO 2 : Dans la boucle, teste les conditions
    //
    // ATTENTION A L'ORDRE !
    // Tu dois tester "divisible par 3 ET par 5" EN PREMIER
    // Sinon les autres conditions vont "capturer" le cas avant
    //
    // Rappel : "divisible par 3" = (i % 3 == 0)
    // Rappel : "ET" = &&
    // ========================================================================


    // ========================================================================
    // STRUCTURE A SUIVRE :
    //
    // for (int i = 1; i <= 20; i++)
    // {
    //     if (/* divisible par 3 ET par 5 */)
    //     {
    //         printf("FizzBuzz\n");
    //     }
    //     else if (/* divisible par 3 */)
    //     {
    //         printf("Fizz\n");
    //     }
    //     else if (/* divisible par 5 */)
    //     {
    //         printf("Buzz\n");
    //     }
    //     else
    //     {
    //         printf("%d\n", i);
    //     }
    // }
    // ========================================================================

    // Ecris ton code ici :



    return 0;
}

/*
 * ============================================================================
 * INDICES (ne regarde que si tu es bloque) :
 *
 * INDICE 1 : Operateur modulo
 *   Le modulo (%) donne le RESTE de la division
 *   10 % 3 = 1  (10 = 3*3 + 1)
 *   15 % 5 = 0  (15 = 5*3 + 0) -> divisible !
 *   Si le reste est 0, c'est divisible
 *
 * INDICE 2 : Tester divisibilite
 *   if (i % 3 == 0)  // i est divisible par 3
 *   if (i % 5 == 0)  // i est divisible par 5
 *
 * INDICE 3 : Combiner avec ET
 *   if (i % 3 == 0 && i % 5 == 0)  // divisible par les deux
 *
 * INDICE 4 : Pourquoi l'ordre est important ?
 *   15 est divisible par 3 (15 % 3 == 0) VRAI
 *   15 est divisible par 5 (15 % 5 == 0) VRAI
 *   15 est divisible par 3 ET 5 VRAI
 *
 *   Si tu testes "par 3" d'abord, tu affiches "Fizz" et tu rates "FizzBuzz"
 *
 * ============================================================================
 * BONUS :
 *
 * 1. Modifie pour aller de 1 a 100
 * 2. Ajoute "Jazz" pour les multiples de 7
 * 3. Compte combien il y a de Fizz, Buzz, et FizzBuzz
 *
 * ============================================================================
 */

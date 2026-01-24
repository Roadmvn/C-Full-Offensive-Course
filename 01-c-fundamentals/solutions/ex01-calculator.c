/*
 * SOLUTION - Exercice 01 : Calculatrice
 */

#include <stdio.h>

int main()
{
    printf("Calculatrice Simple\n");
    printf("====================\n\n");

    // Variables
    int a = 10;
    int b = 3;
    char op = '+';

    // Affichage
    printf("a = %d\n", a);
    printf("b = %d\n", b);
    printf("Operateur : %c\n\n", op);

    // Calcul selon operateur
    if (op == '+')
    {
        printf("%d + %d = %d\n", a, b, a + b);
    }
    else if (op == '-')
    {
        printf("%d - %d = %d\n", a, b, a - b);
    }
    else if (op == '*')
    {
        printf("%d * %d = %d\n", a, b, a * b);
    }
    else if (op == '/')
    {
        if (b == 0)
        {
            printf("Erreur : division par zero !\n");
        }
        else
        {
            float resultat = (float)a / (float)b;
            printf("%d / %d = %.2f\n", a, b, resultat);
        }
    }
    else
    {
        printf("Operateur inconnu : %c\n", op);
    }

    return 0;
}

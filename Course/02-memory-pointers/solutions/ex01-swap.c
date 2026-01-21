/*
 * SOLUTION - Exercice 01 : Swap
 */

#include <stdio.h>

void swap(int* a, int* b)
{
    int temp = *a;  // Sauvegarde la valeur pointee par a
    *a = *b;        // Met la valeur de b dans a
    *b = temp;      // Met l'ancienne valeur de a dans b
}

int main()
{
    int x = 10;
    int y = 20;

    printf("Avant : x = %d, y = %d\n", x, y);
    swap(&x, &y);
    printf("Apres : x = %d, y = %d\n", x, y);

    if (x == 20 && y == 10)
        printf("\n[OK] Swap fonctionne !\n");

    return 0;
}

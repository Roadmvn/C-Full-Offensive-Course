/*
 * SOLUTION - Exercice 02 : Somme tableau
 */

#include <stdio.h>

int sum_array(int* arr, int size)
{
    int total = 0;
    int* end = arr + size;  // Pointeur vers apres le dernier element

    while (arr < end)
    {
        total += *arr;  // Ajoute la valeur pointee
        arr++;          // Avance au prochain element
    }

    return total;
}

// Version alternative avec for
int sum_array_v2(int* arr, int size)
{
    int total = 0;
    for (int* p = arr; p < arr + size; p++)
    {
        total += *p;
    }
    return total;
}

int main()
{
    int tableau[] = {10, 20, 30, 40, 50};
    int taille = sizeof(tableau) / sizeof(tableau[0]);

    printf("Tableau : ");
    for (int i = 0; i < taille; i++)
        printf("%d ", tableau[i]);
    printf("\n");

    printf("Somme : %d\n", sum_array(tableau, taille));

    return 0;
}

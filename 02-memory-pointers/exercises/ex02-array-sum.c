/*
 * EXERCICE 02 : Somme de tableau via pointeur
 * DIFFICULTE : ⭐⭐
 *
 * OBJECTIF : Calculer la somme d'un tableau en utilisant l'arithmetique des pointeurs
 */

#include <stdio.h>

// TODO: Implemente cette fonction
// Utilise UNIQUEMENT l'arithmetique des pointeurs (pas d'indices [])
int sum_array(int* arr, int size)
{
    int total = 0;

    // Ton code ici
    // INDICE: Utilise *arr pour acceder a la valeur, arr++ pour avancer

    return total;
}

int main()
{
    int tableau[] = {10, 20, 30, 40, 50};
    int taille = sizeof(tableau) / sizeof(tableau[0]);

    printf("Tableau : ");
    for (int i = 0; i < taille; i++)
    {
        printf("%d ", tableau[i]);
    }
    printf("\n");

    int somme = sum_array(tableau, taille);

    printf("Somme : %d\n", somme);

    if (somme == 150)
    {
        printf("\n[OK] Somme correcte !\n");
    }
    else
    {
        printf("\n[ERREUR] La somme devrait etre 150\n");
    }

    return 0;
}

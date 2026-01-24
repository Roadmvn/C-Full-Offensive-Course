/*
 * EXERCICE 01 : Swap - Echanger deux valeurs
 * DIFFICULTE : ⭐
 *
 * OBJECTIF : Ecrire une fonction qui echange deux variables via pointeurs
 *
 * INDICES :
 * - Une fonction normale ne peut pas modifier les variables de l'appelant
 * - Avec des pointeurs, on peut modifier les originaux
 */

#include <stdio.h>

// TODO: Implemente cette fonction
// Elle doit echanger les valeurs pointees par a et b
void swap(int* a, int* b)
{
    // Ton code ici
    // INDICE: Tu as besoin d'une variable temporaire

}

int main()
{
    int x = 10;
    int y = 20;

    printf("Avant : x = %d, y = %d\n", x, y);

    swap(&x, &y);

    printf("Apres : x = %d, y = %d\n", x, y);

    // Verification
    if (x == 20 && y == 10)
    {
        printf("\n[OK] Swap fonctionne !\n");
    }
    else
    {
        printf("\n[ERREUR] x devrait etre 20 et y devrait etre 10\n");
    }

    return 0;
}

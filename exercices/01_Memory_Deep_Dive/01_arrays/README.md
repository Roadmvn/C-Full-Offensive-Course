# Tableaux (Arrays)

Les tableaux permettent de stocker plusieurs valeurs du même type dans une seule variable.

```c
#include <stdio.h>

int main() {
    // Déclaration et initialisation d'un tableau
    int notes[5] = {15, 18, 12, 16, 14};

    // Accès à un élément par son index (commence à 0)
    printf("Premiere note : %d\n", notes[0]);  // 15
    printf("Derniere note : %d\n", notes[4]);  // 14

    // Parcourir un tableau avec une boucle
    for (int i = 0; i < 5; i++) {
        printf("Note %d : %d\n", i + 1, notes[i]);
    }

    // Tableau 2D (matrice)
    int matrice[2][3] = {
        {1, 2, 3},
        {4, 5, 6}
    };

    printf("Element [0][1] : %d\n", matrice[0][1]);  // 2

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `int tableau[5]` : déclare un tableau de 5 entiers
- Index commence à 0 : premier élément = `tableau[0]`, dernier = `tableau[n-1]`
- `{1, 2, 3}` : initialise les valeurs du tableau
- `sizeof(tableau) / sizeof(tableau[0])` : calcule le nombre d'éléments
- Tableau 2D : `int matrice[lignes][colonnes]` pour stocker des grilles
- Parcours : utiliser une boucle for avec l'index

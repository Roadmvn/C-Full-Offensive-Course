SOLUTION 1 : Afficher un tableau
```c

```c
#include <stdio.h>
```


```c
int main() {
    int tableau[7] = {5, 10, 15, 20, 25, 30, 35};
```

    printf("Elements du tableau :\n");
    for (int i = 0; i < 7; i++) {
        printf("tableau[%d] = %d\n", i, tableau[i]);
    }

    return 0;
}
```

SOLUTION 2 : Somme d'un tableau
```c

```c
#include <stdio.h>
```


```c
int main() {
    int tableau[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int somme = 0;
```

    for (int i = 0; i < 10; i++) {
        somme += tableau[i];
    }

    printf("Somme = %d\n", somme);
    return 0;
}
```

SOLUTION 3 : Maximum et minimum
```c

```c
#include <stdio.h>
```


```c
int main() {
    int tableau[8] = {45, 12, 89, 23, 67, 34, 91, 56};
```

    int max = tableau[0];  // Initialiser avec le premier élément
    int min = tableau[0];

    for (int i = 1; i < 8; i++) {
        if (tableau[i] > max) {
            max = tableau[i];
        }
        if (tableau[i] < min) {
            min = tableau[i];
        }
    }

    printf("Maximum : %d\n", max);
    printf("Minimum : %d\n", min);

    return 0;
}
```

SOLUTION 4 : Moyenne des notes
```c

```c
#include <stdio.h>
```


```c
int main() {
```
    float notes[6] = {15.5, 18.0, 12.5, 16.0, 14.5, 17.0};
    float somme = 0;

    for (int i = 0; i < 6; i++) {
        somme += notes[i];
    }

    float moyenne = somme / 6;
    printf("Moyenne : %.2f/20\n", moyenne);

    return 0;
}
```

SOLUTION 5 : Inverser un tableau
```c

```c
#include <stdio.h>
```


```c
int main() {
    int tableau[6] = {1, 2, 3, 4, 5, 6};
    int taille = 6;
```

    printf("Tableau original : ");
    for (int i = 0; i < taille; i++) {
        printf("%d ", tableau[i]);
    }
    printf("\n");


```c
    // Inverser : échanger les éléments
```
    for (int i = 0; i < taille / 2; i++) {
        int temp = tableau[i];
        tableau[i] = tableau[taille - 1 - i];
        tableau[taille - 1 - i] = temp;
    }

    printf("Tableau inverse : ");
    for (int i = 0; i < taille; i++) {
        printf("%d ", tableau[i]);
    }
    printf("\n");

    return 0;
}
```

SOLUTION 6 : Chercher un nombre
```c

```c
#include <stdio.h>
```


```c
int main() {
    int tableau[8] = {10, 20, 30, 40, 50, 60, 70, 80};
    int nombre;
    int trouve = 0;
    int position = -1;
```

    printf("Entrez un nombre a chercher : ");
    scanf("%d", &nombre);

    for (int i = 0; i < 8; i++) {
        if (tableau[i] == nombre) {
            trouve = 1;
            position = i;
            break;
        }
    }

    if (trouve) {
        printf("Nombre %d trouve a l'index %d\n", nombre, position);
    } else {
        printf("Nombre %d non trouve\n", nombre);
    }

    return 0;
}
```

SOLUTION 7 : Tableau 2D - Affichage
```c

```c
#include <stdio.h>
```


```c
int main() {
    int matrice[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
```

    printf("Matrice 3x4 :\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%3d ", matrice[i][j]);  // %3d pour aligner
        }
        printf("\n");
    }

    return 0;
}
```

SOLUTION 8 : Somme par ligne
```c

```c
#include <stdio.h>
```


```c
int main() {
    int matrice[3][3] = {
        {1, 2, 3},
        {4, 5, 6},
        {7, 8, 9}
    };
```

    printf("Matrice :\n");
    for (int i = 0; i < 3; i++) {
        int somme_ligne = 0;

        for (int j = 0; j < 3; j++) {
            printf("%d ", matrice[i][j]);
            somme_ligne += matrice[i][j];
        }

        printf("  -> Somme ligne %d : %d\n", i, somme_ligne);
    }

    return 0;
}
```


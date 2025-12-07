SOLUTION EXERCICE 1 : Parcourir un tableau
```c

```c
#include <stdio.h>
```


```c
int main() {
    int tab[5] = {100, 200, 300, 400, 500};
    int *ptr = tab;
```

    printf("Parcours du tableau:\n");
    for (int i = 0; i < 5; i++) {
        printf("*ptr = %d\n", *ptr);
        ptr++;
    }

    return 0;
}
```

SOLUTION EXERCICE 2 : Trouver le maximum
```c

```c
#include <stdio.h>
```

int trouver_max(int *tableau, int taille) {
    int *ptr = tableau;
    int max = *ptr;

    for (int i = 1; i < taille; i++) {
        ptr++;
        if (*ptr > max) {
            max = *ptr;
        }
    }

    return max;
}


```c
int main() {
    int nombres[] = {45, 12, 89, 23, 67, 34};
    int taille = sizeof(nombres) / sizeof(nombres[0]);
```

    int max = trouver_max(nombres, taille);
    printf("Maximum: %d\n", max);

    return 0;
}
```

SOLUTION EXERCICE 3 : Soustraction de pointeurs
```c

```c
#include <stdio.h>
```


```c
int main() {
    int tab[10] = {0, 10, 20, 30, 40, 50, 60, 70, 80, 90};
```

    int *ptr1 = &tab[2];
    int *ptr2 = &tab[7];

    printf("ptr1 pointe vers: %d (adresse: %p)\n", *ptr1, (void*)ptr1);
    printf("ptr2 pointe vers: %d (adresse: %p)\n", *ptr2, (void*)ptr2);

    long distance = ptr2 - ptr1;
    printf("Distance entre ptr2 et ptr1: %ld éléments\n", distance);
    printf("Distance en bytes: %ld bytes\n", (char*)ptr2 - (char*)ptr1);

    return 0;
}
```

SOLUTION EXERCICE 4 : Pointeur de pointeur simple
```c

```c
#include <stdio.h>
```


```c
int main() {
    int valeur = 999;
    int *ptr1 = &valeur;
    int **ptr2 = &ptr1;
    int ***ptr3 = &ptr2;
```

    printf("Valeur originale: %d\n", valeur);
    printf("Via *ptr1: %d\n", *ptr1);
    printf("Via **ptr2: %d\n", **ptr2);
    printf("Via ***ptr3: %d\n", ***ptr3);

    printf("\nAdresses:\n");
    printf("&valeur = %p\n", (void*)&valeur);
    printf("ptr1 = %p\n", (void*)ptr1);
    printf("ptr2 = %p\n", (void*)ptr2);
    printf("ptr3 = %p\n", (void*)ptr3);

    return 0;
}
```

SOLUTION EXERCICE 5 : Tableau de chaînes
```c

```c
#include <stdio.h>
```


```c
int main() {
    char *noms[] = {
```
        "Alice",
        "Bob",
        "Charlie",
        "Diana",
        "Eve"
    };

    int nb_noms = sizeof(noms) / sizeof(noms[0]);

    printf("Liste des noms:\n");
    for (int i = 0; i < nb_noms; i++) {
        printf("%d. %s\n", i+1, noms[i]);
    }

    return 0;
}
```

SOLUTION EXERCICE 6 : Inverser un tableau
```c

```c
#include <stdio.h>
```


```c
void inverser(int *debut, int *fin) {
```
    while (debut < fin) {
        int temp = *debut;
        *debut = *fin;
        *fin = temp;
        debut++;
        fin--;
    }
}


```c
int main() {
    int tab[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int taille = sizeof(tab) / sizeof(tab[0]);
```

    printf("Avant: ");
    for (int i = 0; i < taille; i++) {
        printf("%d ", tab[i]);
    }
    printf("\n");

    inverser(tab, tab + taille - 1);

    printf("Après: ");
    for (int i = 0; i < taille; i++) {
        printf("%d ", tab[i]);
    }
    printf("\n");

    return 0;
}
```

SOLUTION EXERCICE 7 : Rechercher un élément
```c

```c
#include <stdio.h>
```

int* chercher_element(int *tableau, int taille, int valeur) {
    int *ptr = tableau;
    int *fin = tableau + taille;

    while (ptr < fin) {
        if (*ptr == valeur) {
            return ptr;
        }
        ptr++;
    }

    return NULL;
}


```c
int main() {
    int data[] = {15, 28, 7, 42, 19, 3, 56};
    int taille = sizeof(data) / sizeof(data[0]);
```

    int cherche = 42;
    int *resultat = chercher_element(data, taille, cherche);

    if (resultat != NULL) {
        printf("Trouvé %d à l'index %ld\n", cherche, resultat - data);
        printf("Adresse: %p\n", (void*)resultat);
    } else {
        printf("%d non trouvé\n", cherche);
    }

    return 0;
}
```

SOLUTION EXERCICE 8 : Matrice avec pointeurs
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


```c
    // Cast en pointeur simple pour parcours linéaire
    int *ptr = (int*)matrice;
    int taille_totale = 3 * 3;
```

    printf("Parcours linéaire de la matrice:\n");
    for (int i = 0; i < taille_totale; i++) {
        printf("%d ", *(ptr + i));
        if ((i + 1) % 3 == 0) {
            printf("\n");
        }
    }

    printf("\nAvec ptr++:\n");
    ptr = (int*)matrice;
    for (int i = 0; i < taille_totale; i++) {
        printf("%d ", *ptr);
        ptr++;
        if ((i + 1) % 3 == 0) {
            printf("\n");
        }
    }

    return 0;
}
```


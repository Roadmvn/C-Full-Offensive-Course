SOLUTION 1 : Compte de 1 à 20
```c

```c
#include <stdio.h>
```


```c
int main() {
```
    for (int i = 1; i <= 20; i++) {
        printf("%d ", i);
    }
    printf("\n");
    return 0;
}
```

SOLUTION 2 : Nombres pairs
```c

```c
#include <stdio.h>
```


```c
int main() {
    // Méthode 1 : incrément de 2
```
    for (int i = 0; i <= 30; i += 2) {
        printf("%d ", i);
    }
    printf("\n");


```c
    // Méthode 2 : condition modulo
```
    for (int i = 0; i <= 30; i++) {
        if (i % 2 == 0) {
            printf("%d ", i);
        }
    }
    printf("\n");

    return 0;
}
```

SOLUTION 3 : Compte à rebours
```c

```c
#include <stdio.h>
```


```c
int main() {
    int i = 10;
```
    while (i >= 0) {
        printf("%d ", i);
        i--;
    }
    printf("\nDecollage!\n");
    return 0;
}
```

SOLUTION 4 : Table de multiplication
```c

```c
#include <stdio.h>
```


```c
int main() {
    int nombre;
```

    printf("Entrez un nombre : ");
    scanf("%d", &nombre);

    printf("\nTable de multiplication de %d :\n", nombre);
    for (int i = 1; i <= 10; i++) {
        printf("%d x %d = %d\n", nombre, i, nombre * i);
    }

    return 0;
}
```

SOLUTION 5 : Somme des nombres
```c

```c
#include <stdio.h>
```


```c
int main() {
    int somme = 0;
```

    for (int i = 1; i <= 100; i++) {
        somme += i;  // somme = somme + i
    }

    printf("La somme de 1 a 100 = %d\n", somme);
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
    int nombre;
```

    printf("Entrez des nombres (0 pour arreter) :\n");

    while (1) {  // Boucle infinie
        printf("Nombre : ");
        scanf("%d", &nombre);

        if (nombre == 0) {
            printf("Arret du programme.\n");
            break;  // Sort de la boucle
        }

        printf("Vous avez entre : %d\n", nombre);
    }

    return 0;
}
```

SOLUTION 7 : Sauter les multiples de 3
```c

```c
#include <stdio.h>
```


```c
int main() {
```
    for (int i = 1; i <= 20; i++) {
        if (i % 3 == 0) {
            continue;  // Saute cette iteration
        }
        printf("%d ", i);
    }
    printf("\n");
    return 0;
}
```

SOLUTION 8 : Grille de nombres
```c

```c
#include <stdio.h>
```


```c
int main() {
```
    printf("Grille 5x5 :\n");

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            printf("(%d,%d) ", i, j);
        }
        printf("\n");  // Nouvelle ligne après chaque rangée
    }

    return 0;
}
```


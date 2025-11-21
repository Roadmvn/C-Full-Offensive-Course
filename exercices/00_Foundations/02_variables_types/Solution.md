EXERCICE 1 : Stocker ton profil

```c
#include <stdio.h>
int main() {
    int age = 25;
```
    float taille = 1.75;
    char initiale = 'A';

    printf("Age : %d ans\n", age);
    printf("Taille : %.2f m\n", taille);
    printf("Initiale : %c\n", initiale);
    return 0;
}

EXERCICE 2 : Calculer une somme

```c
#include <stdio.h>
int main() {
    int a = 10;
    int b = 20;
    int somme = a + b;
```

    printf("Somme : %d\n", somme);
    return 0;
}

EXERCICE 3 : Division entière vs float

```c
#include <stdio.h>
int main() {
    int x = 5, y = 2;
```
    printf("Division int : %d\n", x / y);  // 2

    float a = 5.0, b = 2.0;
    printf("Division float : %.1f\n", a / b);  // 2.5
    return 0;
}
Explication : 5/2 avec int donne 2 (partie décimale perdue).

EXERCICE 4 : Code ASCII

```c
#include <stdio.h>
int main() {
    char lettre = 'A';
```
    printf("Caractère : %c\n", lettre);
    printf("Code ASCII : %d\n", lettre);  // 65
    return 0;
}
Explication : char est stocké comme un nombre (code ASCII).

EXERCICE 5 : Taille des types

```c
#include <stdio.h>
int main() {
```
    printf("int : %zu bytes\n", sizeof(int));
    printf("char : %zu bytes\n", sizeof(char));
    printf("double : %zu bytes\n", sizeof(double));
    return 0;
}

EXERCICE 6 : Calcul IMC

```c
#include <stdio.h>
int main() {
```
    float poids = 70.0;
    float taille = 1.75;
    float imc = poids / (taille * taille);

    printf("IMC : %.2f\n", imc);
    return 0;
}
Explication : IMC = poids / taille²

EXERCICE 7 : Unsigned vs signed

```c
#include <stdio.h>
int main() {
    int signe = -1;
```
    unsigned int non_signe = -1;

    printf("Signé : %d\n", signe);         // -1
    printf("Non signé : %u\n", non_signe); // 4294967295
    return 0;
}
Explication : unsigned ne peut pas stocker de négatifs, -1 devient un très grand nombre.

EXERCICE 8 : Overflow

```c
#include <stdio.h>
int main() {
    int max = 2147483647;
```
    printf("Max : %d\n", max);
    printf("Max + 1 : %d\n", max + 1);  // -2147483648
    return 0;
}
Explication : Dépassement de capacité, la valeur "boucle" au minimum.


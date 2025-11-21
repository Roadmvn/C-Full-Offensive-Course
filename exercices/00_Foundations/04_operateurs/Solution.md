EXERCICE 1 : Calculer moyenne

```c
#include <stdio.h>
int main() {
    int a = 10, b = 20, c = 30;
```
    float moyenne = (a + b + c) / 3.0;
    printf("Moyenne : %.2f\n", moyenne);
    return 0;
}
Explication : Division par 3.0 (float) pour avoir le résultat exact.

EXERCICE 2 : Modulo

```c
#include <stdio.h>
int main() {
    int nombre = 10;
```
    if (nombre % 2 == 0) {
        printf("%d est pair\n", nombre);
    } else {
        printf("%d est impair\n", nombre);
    }
    return 0;
}
Explication : nombre % 2 donne 0 si pair, 1 si impair.

EXERCICE 3 : Incrémentation

```c
#include <stdio.h>
int main() {
    int i = 5;
```
    printf("i = %d\n", i);
    printf("i++ = %d\n", i++);  // Affiche 5, puis i devient 6
    printf("i = %d\n", i);
    printf("++i = %d\n", ++i);  // i devient 7, puis affiche 7
    return 0;
}
Explication : i++ retourne la valeur avant incrémentation, ++i après.

EXERCICE 4 : Comparaisons

```c
#include <stdio.h>
int main() {
    int a = 10, b = 20;
```
    printf("%d == %d : %d\n", a, b, a == b);  // 0 (faux)
    printf("%d != %d : %d\n", a, b, a != b);  // 1 (vrai)
    printf("%d < %d  : %d\n", a, b, a < b);   // 1 (vrai)
    printf("%d > %d  : %d\n", a, b, a > b);   // 0 (faux)
    return 0;
}

EXERCICE 5 : Opérateurs logiques

```c
#include <stdio.h>
int main() {
    int n = 15;
```
    if (n >= 10 && n <= 20) {
        printf("%d est entre 10 et 20\n", n);
    }

    if (n < 10 || n > 20) {
        printf("%d est hors de [10, 20]\n", n);
    } else {
        printf("%d est dans [10, 20]\n", n);
    }
    return 0;
}

EXERCICE 6 : Affectation composée

```c
#include <stdio.h>
int main() {
    int x = 10;
```
    printf("x = %d\n", x);

    x += 5;  // x = x + 5
    printf("Après x += 5 : %d\n", x);

    x *= 2;  // x = x * 2
    printf("Après x *= 2 : %d\n", x);

    x -= 10; // x = x - 10
    printf("Après x -= 10 : %d\n", x);

    x /= 2;  // x = x / 2
    printf("Après x /= 2 : %d\n", x);
    return 0;
}

EXERCICE 7 : Opérateurs bit à bit

```c
#include <stdio.h>
int main() {
    int a = 12;  // 1100 en binaire
    int b = 10;  // 1010 en binaire
```

    printf("%d & %d = %d\n", a, b, a & b);   // 8 (1000)
    printf("%d | %d = %d\n", a, b, a | b);   // 14 (1110)
    printf("%d ^ %d = %d\n", a, b, a ^ b);   // 6 (0110)
    printf("~%d = %d\n", a, ~a);              // Complément
    printf("%d << 1 = %d\n", a, a << 1);     // 24 (décalage gauche)
    printf("%d >> 1 = %d\n", a, a >> 1);     // 6 (décalage droite)
    return 0;
}
Explication : & (ET), | (OU), ^ (XOR), ~ (NOT), << (shift left), >> (shift right).

EXERCICE 8 : Priorité des opérateurs

```c
#include <stdio.h>
int main() {
    int r1 = 2 + 3 * 4;      // * avant +
    int r2 = (2 + 3) * 4;    // () force la priorité
```

    printf("2 + 3 * 4 = %d\n", r1);      // 14
    printf("(2 + 3) * 4 = %d\n", r2);    // 20
    return 0;
}
Explication : *, /, % ont priorité sur +, -. Utilise () pour forcer l'ordre.


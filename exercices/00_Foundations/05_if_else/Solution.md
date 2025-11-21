EXERCICE 1 : Tester la majorité

```c
#include <stdio.h>
int main() {
    int age = 20;
```
    if (age >= 18) {
        printf("Majeur\n");
    } else {
        printf("Mineur\n");
    }
    return 0;
}

EXERCICE 2 : Nombre positif/négatif

```c
#include <stdio.h>
int main() {
    int n = -5;
```
    if (n > 0) {
        printf("Positif\n");
    } else if (n < 0) {
        printf("Négatif\n");
    } else {
        printf("Nul\n");
    }
    return 0;
}

EXERCICE 3 : Calculer grade

```c
#include <stdio.h>
int main() {
    int note = 85;
```
    if (note >= 90) {
        printf("Grade : A\n");
    } else if (note >= 80) {
        printf("Grade : B\n");
    } else if (note >= 70) {
        printf("Grade : C\n");
    } else if (note >= 60) {
        printf("Grade : D\n");
    } else {
        printf("Grade : F\n");
    }
    return 0;
}

EXERCICE 4 : Maximum de deux nombres

```c
#include <stdio.h>
int main() {
    int a = 10, b = 20;
    int max = (a > b) ? a : b;
```
    printf("Max : %d\n", max);
    return 0;
}

EXERCICE 5 : Jour de la semaine

```c
#include <stdio.h>
int main() {
    int jour = 3;
```
    switch (jour) {
        case 1: printf("Lundi\n"); break;
        case 2: printf("Mardi\n"); break;
        case 3: printf("Mercredi\n"); break;
        case 4: printf("Jeudi\n"); break;
        case 5: printf("Vendredi\n"); break;
        case 6: printf("Samedi\n"); break;
        case 7: printf("Dimanche\n"); break;
        default: printf("Jour invalide\n");
    }
    return 0;
}

EXERCICE 6 : Vérifier année bissextile

```c
#include <stdio.h>
int main() {
    int annee = 2024;
```
    if ((annee % 4 == 0 && annee % 100 != 0) || (annee % 400 == 0)) {
        printf("%d est bissextile\n", annee);
    } else {
        printf("%d n'est pas bissextile\n", annee);
    }
    return 0;
}
Explication : Bissextile si divisible par 4 ET pas par 100, OU divisible par 400.

EXERCICE 7 : Calculette simple

```c
#include <stdio.h>
int main() {
```
    float a = 10, b = 3;
    char op = '/';

    switch (op) {
        case '+': printf("%.2f\n", a + b); break;
        case '-': printf("%.2f\n", a - b); break;
        case '*': printf("%.2f\n", a * b); break;
        case '/':
            if (b != 0) printf("%.2f\n", a / b);
            else printf("Erreur : division par 0\n");
            break;
        default: printf("Opérateur invalide\n");
    }
    return 0;
}

EXERCICE 8 : Menu interactif

```c
#include <stdio.h>
int main() {
    int choix = 2;
```

    printf("Menu :\n");
    printf("1. Afficher bonjour\n");
    printf("2. Afficher date\n");
    printf("3. Quitter\n");

    switch (choix) {
        case 1:
            printf("Bonjour!\n");
            break;
        case 2:
            printf("2025-01-15\n");
            break;
        case 3:
            printf("Au revoir\n");
            break;
        default:
            printf("Choix invalide\n");
    }
    return 0;
}


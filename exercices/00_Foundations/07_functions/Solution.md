SOLUTION 1 : Fonction simple
```c

```c
#include <stdio.h>
```


```c
void dire_bonjour() {
```
    printf("Bonjour!\n");
}


```c
int main() {
```
    dire_bonjour();  // Appel de la fonction
    return 0;
}
```

SOLUTION 2 : Fonction avec retour
```c

```c
#include <stdio.h>
```

int carre(int n) {
    return n * n;
}


```c
int main() {
    int nombre = 7;
    int resultat = carre(nombre);
```

    printf("Le carre de %d est %d\n", nombre, resultat);

    return 0;
}
```

SOLUTION 3 : Maximum de deux nombres
```c

```c
#include <stdio.h>
```

int maximum(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}


```c
int main() {
    int x = 15;
    int y = 23;
```

    int max = maximum(x, y);
    printf("Le maximum entre %d et %d est %d\n", x, y, max);

    return 0;
}
```

SOLUTION 4 : Factorielle
```c

```c
#include <stdio.h>
```

int factorielle(int n) {
    int resultat = 1;

    for (int i = 1; i <= n; i++) {
        resultat *= i;
    }

    return resultat;
}


```c
int main() {
    int n = 5;
    int fact = factorielle(n);
```

    printf("%d! = %d\n", n, fact);

    return 0;
}
```

SOLUTION 5 : Est premier
```c

```c
#include <stdio.h>
```

int est_premier(int n) {
    if (n <= 1) {
        return 0;  // Pas premier
    }

    for (int i = 2; i < n; i++) {
        if (n % i == 0) {
            return 0;  // Divisible, donc pas premier
        }
    }

    return 1;  // Premier
}


```c
int main() {
    int nombres[] = {7, 10, 17, 20};
```

    for (int i = 0; i < 4; i++) {
        if (est_premier(nombres[i])) {
            printf("%d est premier\n", nombres[i]);
        } else {
            printf("%d n'est pas premier\n", nombres[i]);
        }
    }

    return 0;
}
```

SOLUTION 6 : Somme d'un tableau
```c

```c
#include <stdio.h>
```

int somme_tableau(int tab[], int taille) {
    int somme = 0;

    for (int i = 0; i < taille; i++) {
        somme += tab[i];
    }

    return somme;
}


```c
int main() {
    int nombres[6] = {10, 20, 30, 40, 50, 60};
    int taille = 6;
```

    int total = somme_tableau(nombres, taille);
    printf("Somme du tableau : %d\n", total);

    return 0;
}
```

SOLUTION 7 : Convertir température
```c

```c
#include <stdio.h>
```

float celsius_to_fahrenheit(float celsius) {
    return (celsius * 9.0 / 5.0) + 32.0;
}

float fahrenheit_to_celsius(float fahrenheit) {
    return (fahrenheit - 32.0) * 5.0 / 9.0;
}


```c
int main() {
```
    float temp_c = 25.0;
    float temp_f = 77.0;

    printf("%.1f°C = %.1f°F\n", temp_c, celsius_to_fahrenheit(temp_c));
    printf("%.1f°F = %.1f°C\n", temp_f, fahrenheit_to_celsius(temp_f));

    return 0;
}
```

SOLUTION 8 : Calculatrice
```c

```c
#include <stdio.h>
```


```c
// Prototypes
```
float addition(float a, float b);
float soustraction(float a, float b);
float multiplication(float a, float b);
float division(float a, float b);

```c
void afficher_menu();
```


```c
int main() {
    int choix;
```
    float a, b, resultat;

    do {
        afficher_menu();
        printf("Votre choix : ");
        scanf("%d", &choix);

        if (choix >= 1 && choix <= 4) {
            printf("Entrez le premier nombre : ");
            scanf("%f", &a);
            printf("Entrez le deuxieme nombre : ");
            scanf("%f", &b);

            switch (choix) {
                case 1:
                    resultat = addition(a, b);
                    printf("%.2f + %.2f = %.2f\n\n", a, b, resultat);
                    break;
                case 2:
                    resultat = soustraction(a, b);
                    printf("%.2f - %.2f = %.2f\n\n", a, b, resultat);
                    break;
                case 3:
                    resultat = multiplication(a, b);
                    printf("%.2f x %.2f = %.2f\n\n", a, b, resultat);
                    break;
                case 4:
                    if (b != 0) {
                        resultat = division(a, b);
                        printf("%.2f / %.2f = %.2f\n\n", a, b, resultat);
                    } else {
                        printf("Erreur : division par zero!\n\n");
                    }
                    break;
            }
        }
    } while (choix != 5);

    printf("Au revoir!\n");
    return 0;
}


```c
void afficher_menu() {
```
    printf("=== CALCULATRICE ===\n");
    printf("1. Addition\n");
    printf("2. Soustraction\n");
    printf("3. Multiplication\n");
    printf("4. Division\n");
    printf("5. Quitter\n\n");
}

float addition(float a, float b) {
    return a + b;
}

float soustraction(float a, float b) {
    return a - b;
}

float multiplication(float a, float b) {
    return a * b;
}

float division(float a, float b) {
    return a / b;
}
```


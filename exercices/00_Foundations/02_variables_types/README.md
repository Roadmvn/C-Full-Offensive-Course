# Variables et Types

Déclarer des variables et utiliser les types de base du C.

```c
#include <stdio.h>

int main() {
    int age = 25;           // Entier
    char initiale = 'A';    // Caractère
    float taille = 1.75;    // Nombre à virgule

    printf("Age : %d\n", age);
    printf("Initiale : %c\n", initiale);
    printf("Taille : %.2f m\n", taille);

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `int` : nombres entiers (4 bytes)
- `char` : un seul caractère (1 byte)
- `float` : nombres à virgule (4 bytes)
- `double` : nombres à virgule haute précision (8 bytes)
- `sizeof()` : retourne la taille d'un type en bytes

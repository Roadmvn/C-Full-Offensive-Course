# Boucles (Loops)

Les boucles permettent de répéter du code plusieurs fois automatiquement.

```c
#include <stdio.h>

int main() {
    // Boucle for : répète 5 fois
    for (int i = 0; i < 5; i++) {
        printf("Compteur : %d\n", i);
    }

    // Boucle while : répète tant que la condition est vraie
    int j = 0;
    while (j < 3) {
        printf("While : %d\n", j);
        j++;
    }

    // Boucle do-while : exécute au moins une fois
    int k = 0;
    do {
        printf("Do-while : %d\n", k);
        k++;
    } while (k < 2);

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `for` : boucle avec compteur (initialisation; condition; incrémentation)
- `while` : boucle tant que la condition est vraie
- `do-while` : exécute le code au moins une fois puis vérifie la condition
- `break` : sort immédiatement de la boucle
- `continue` : passe directement à l'itération suivante
- Boucles imbriquées : une boucle dans une autre boucle

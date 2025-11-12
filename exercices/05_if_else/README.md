# Structures Conditionnelles (if-else)

Prendre des décisions dans le code avec if, else et switch.

```c
#include <stdio.h>

int main() {
    int age = 20;

    if (age >= 18) {
        printf("Majeur\n");
    } else {
        printf("Mineur\n");
    }

    // Opérateur ternaire (version courte)
    printf("%s\n", (age >= 18) ? "Majeur" : "Mineur");

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `if (condition)` : exécute si la condition est vraie
- `else` : exécute si la condition est fausse
- `else if` : teste une autre condition
- `condition ? vrai : faux` : opérateur ternaire
- `switch-case` : sélection multiple avec break

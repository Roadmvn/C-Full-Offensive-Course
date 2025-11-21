# Opérateurs

Utiliser les opérateurs arithmétiques, logiques et bit à bit.

```c
#include <stdio.h>

int main() {
    int a = 10, b = 3;

    printf("%d + %d = %d\n", a, b, a + b);  // 13
    printf("%d - %d = %d\n", a, b, a - b);  // 7
    printf("%d * %d = %d\n", a, b, a * b);  // 30
    printf("%d / %d = %d\n", a, b, a / b);  // 3
    printf("%d %% %d = %d\n", a, b, a % b); // 1

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `+, -, *, /, %` : opérateurs arithmétiques
- `==, !=, <, >, <=, >=` : opérateurs de comparaison
- `&&, ||, !` : opérateurs logiques (ET, OU, NON)
- `+=, -=, *=, /=` : opérateurs d'affectation composés
- `++, --` : incrémentation/décrémentation

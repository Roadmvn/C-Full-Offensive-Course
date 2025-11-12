# printf() et scanf()

Affichage formaté et lecture depuis le clavier.

```c
#include <stdio.h>

int main() {
    int age;
    printf("Age : ");
    scanf("%d", &age);  // & = adresse de la variable
    printf("Vous avez %d ans\n", age);
    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `printf("%d", x)` : affiche une variable avec format specifier
- `scanf("%d", &x)` : lit depuis le clavier (& obligatoire)
- `%d` : int, `%f` : float, `%c` : char, `%s` : string
- `%.2f` : affiche 2 décimales pour un float
- Espace avant `%c` dans scanf pour ignorer whitespace

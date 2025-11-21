# Hello World

Premier programme C : affiche du texte dans le terminal.

```c
#include <stdio.h>  // Bibliothèque pour printf()

int main() {
    printf("Hello, World!\n");  // Affiche le texte
    return 0;  // 0 = succès
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `#include <stdio.h>` : inclut les fonctions d'entrée/sortie
- `int main()` : point d'entrée du programme
- `printf()` : affiche du texte dans le terminal
- `\n` : retour à la ligne
- `return 0` : indique que le programme s'est terminé correctement

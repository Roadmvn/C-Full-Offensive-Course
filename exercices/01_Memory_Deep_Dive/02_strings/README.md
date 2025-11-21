# Chaînes de caractères (Strings)

En C, une chaîne de caractères est un tableau de char terminé par le caractère '\0'.

```c
#include <stdio.h>
#include <string.h>

int main() {
    // Déclaration et initialisation
    char nom[50] = "Alice";

    // Une string est un tableau de char avec '\0' à la fin
    // "Alice" = {'A', 'l', 'i', 'c', 'e', '\0'}

    printf("Nom : %s\n", nom);  // %s pour afficher une string

    // Longueur d'une string
    int longueur = strlen(nom);
    printf("Longueur : %d caracteres\n", longueur);

    // Copier une string
    char copie[50];
    strcpy(copie, nom);
    printf("Copie : %s\n", copie);

    // Comparer deux strings
    char nom2[50] = "Bob";
    if (strcmp(nom, nom2) == 0) {
        printf("Les noms sont identiques\n");
    } else {
        printf("Les noms sont differents\n");
    }

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- String = tableau de char terminé par `'\0'` (caractère nul)
- `char nom[50]` : déclare une string de maximum 49 caractères (+ '\0')
- `strlen(str)` : retourne la longueur (sans compter '\0')
- `strcpy(dest, src)` : copie src dans dest
- `strcmp(s1, s2)` : compare deux strings (retourne 0 si égales)
- `strcat(dest, src)` : concatène src à la fin de dest
- `fgets(str, taille, stdin)` : lecture sécurisée depuis le clavier

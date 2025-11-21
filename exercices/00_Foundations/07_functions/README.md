# Fonctions

Les fonctions permettent de diviser un programme en blocs réutilisables et organisés.

```c
#include <stdio.h>

// Déclaration de fonction (prototype)
int additionner(int a, int b);

// Fonction sans paramètres, sans retour
void afficher_message() {
    printf("Hello!\n");
}

// Fonction avec paramètres et retour
int additionner(int a, int b) {
    return a + b;  // Retourne le résultat
}

int main() {
    // Appel de fonction sans retour
    afficher_message();

    // Appel de fonction avec retour
    int resultat = additionner(5, 3);
    printf("5 + 3 = %d\n", resultat);

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- **Déclaration** (prototype) : `int addition(int a, int b);` avant main()
- **Définition** : le code complet de la fonction
- **Appel** : `resultat = addition(5, 3);`
- **return** : renvoie une valeur au code appelant
- **void** : type pour les fonctions qui ne retournent rien
- **Paramètres** : variables reçues par la fonction (passés par valeur)
- **Scope** : les variables locales n'existent que dans leur fonction

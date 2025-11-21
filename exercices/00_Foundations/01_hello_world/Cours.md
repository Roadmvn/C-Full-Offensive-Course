# Cours 01 : Hello World & Structure d'un Programme C

## 1. Introduction
Bienvenue dans le monde du C. Ce premier module est le plus important : il valide que votre environnement de travail est fonctionnel. Si vous pouvez compiler et exécuter ce code, vous avez les outils pour tout le reste.

En C, contrairement au Python ou au JavaScript, tout doit être **compilé**. Le code source (texte) est transformé en code machine (binaire) par un compilateur (GCC ou Clang).

## 2. Visualisation : La Chaîne de Compilation

```ascii
[Source (.c)]  ->  [Préprocesseur]  ->  [Compilateur]  ->  [Linker]  ->  [Exécutable]
  main.c           (Gère les #)         (Crée .o)       (Lie les lib)     a.out / .exe
```

## 3. Anatomie d'un Programme

```c
#include <stdio.h>  // 1. Directive de préprocesseur

// 2. Point d'entrée (Main function)
int main() {
    // 3. Instruction
    printf("Hello World\n");
    
    // 4. Code de retour (0 = Succès)
    return 0;
}
```

### Détails
1.  **`#include <stdio.h>`** : Dit au compilateur "J'ai besoin des outils d'entrée/sortie standard" (Standard Input/Output). C'est là que vit `printf`.
2.  **`int main()`** : La porte d'entrée. L'OS appelle cette fonction pour lancer le programme.
3.  **`{ ... }`** : Le bloc de code. Délimite le début et la fin de la fonction.
4.  **`printf(...)`** : Une fonction qui affiche du texte à l'écran.
5.  **`\n`** : Caractère spécial pour "Nouvelle Ligne" (Line Feed).
6.  **`return 0;`** : Dit à l'OS "Tout s'est bien passé". Un autre chiffre indiquerait une erreur.

## 4. Compilation et Exécution

Dans votre terminal :

```bash
# 1. Compiler (Traduire le C en binaire)
gcc example.c -o mon_programme

# 2. Exécuter (Lancer le binaire)
./mon_programme
```

## 5. Pièges Courants

*   **Oublier le `;`** : Chaque instruction DOIT finir par un point-virgule. C'est l'erreur n°1.
*   **Oublier `#include`** : Si vous utilisez `printf` sans inclure `stdio.h`, le compilateur va se plaindre (warning).
*   **Guillemets** : Utilisez des doubles guillemets `"` pour le texte. Les simples `'` sont pour un seul caractère.


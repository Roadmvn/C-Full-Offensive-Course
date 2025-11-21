# Malloc et Free

Allocation dynamique de mémoire sur le heap avec malloc, calloc, realloc et free.

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Allocation dynamique d'un tableau
    int taille = 5;
    int *tableau = malloc(taille * sizeof(int));  // Alloue 20 bytes

    if (tableau == NULL) {
        printf("Erreur d'allocation\n");
        return 1;
    }

    // Utilisation du tableau
    for (int i = 0; i < taille; i++) {
        tableau[i] = i * 10;
        printf("%d ", tableau[i]);
    }
    printf("\n");

    free(tableau);  // Libère la mémoire
    tableau = NULL;  // Bonne pratique

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `malloc(size)` : alloue size bytes sur le heap, retourne un pointeur ou NULL
- `calloc(n, size)` : alloue et initialise à zéro
- `realloc(ptr, size)` : redimensionne une allocation existante
- `free(ptr)` : libère la mémoire allouée
- Stack vs Heap : stack = automatique et limité, heap = manuel et grand
- Toujours vérifier si malloc retourne NULL

## Application Red Team

L'allocation dynamique est cruciale pour charger des payloads de taille variable. En malware dev, on utilise `VirtualAlloc()` sur Windows (équivalent de malloc mais avec contrôle des permissions mémoire) pour allouer de la mémoire exécutable où on copie le shellcode. La mémoire doit être allouée avec les flags `PAGE_EXECUTE_READWRITE` pour permettre l'exécution.

Les techniques de heap spray exploitent malloc pour remplir le heap avec des données contrôlées. En exploitation de vulnerabilités heap (use-after-free, double-free), comprendre malloc et free est essentiel. Un attaquant peut provoquer un free() prématuré puis réallouer la mémoire avec des données malveillantes avant que le programme réutilise le pointeur.

Pour l'injection de code, on alloue dynamiquement un buffer de la taille du shellcode, on y copie le payload, puis on change les permissions avec `VirtualProtect()` pour le rendre exécutable. Sans allocation dynamique, impossible d'adapter la taille aux différents payloads (reverse shell, meterpreter, etc.).

# Pointeurs Avancés

Arithmétique de pointeurs, pointeurs de pointeurs et tableaux multidimensionnels.

```c
#include <stdio.h>

int main() {
    int tab[5] = {10, 20, 30, 40, 50};
    int *ptr = tab;  // Pointe vers le premier élément

    // Arithmétique de pointeurs
    printf("*ptr = %d\n", *ptr);           // 10
    printf("*(ptr+1) = %d\n", *(ptr+1));   // 20 (avance de 4 bytes)
    printf("*(ptr+2) = %d\n", *(ptr+2));   // 30

    // Pointeur de pointeur
    int valeur = 100;
    int *ptr1 = &valeur;
    int **ptr2 = &ptr1;  // Pointeur vers un pointeur

    printf("\nValeur via **ptr2: %d\n", **ptr2);  // 100

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `ptr + n` : avance le pointeur de n éléments (pas n bytes)
- `ptr++` : avance d'un élément, `ptr--` : recule d'un élément
- `ptr2 - ptr1` : nombre d'éléments entre deux pointeurs
- `**ptr` : pointeur de pointeur (double déréférencement)
- Le nom d'un tableau est un pointeur constant vers le premier élément
- Arithmétique de pointeurs respecte la taille du type

## Application Red Team

L'arithmétique de pointeurs est essentielle pour parcourir les structures de fichiers PE (Portable Executable) sur Windows. Un attaquant doit naviguer dans les headers PE pour trouver l'Import Address Table (IAT), résoudre des adresses de fonctions, ou localiser des sections spécifiques.

En exploitation, on utilise des pointeurs de pointeurs pour manipuler la GOT (Global Offset Table) sur Linux ou l'IAT sur Windows. Par exemple, pour hooker une fonction, on obtient l'adresse de la fonction dans la table (**ptr), puis on la remplace par l'adresse de notre fonction malveillante. Les techniques de reflective DLL injection nécessitent de parser manuellement les structures PE en utilisant l'arithmétique de pointeurs.

Les shellcodes utilisent également l'arithmétique de pointeurs pour localiser dynamiquement des fonctions système sans imports statiques. On parcourt la PEB (Process Environment Block) avec des offsets calculés via pointeurs pour trouver kernel32.dll et résoudre GetProcAddress sans laisser de traces dans les imports.

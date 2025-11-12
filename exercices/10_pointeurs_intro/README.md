# Pointeurs - Introduction

Les pointeurs stockent l'adresse mémoire d'une variable. Ils permettent de manipuler directement la mémoire.

```c
#include <stdio.h>

int main() {
    int age = 25;          // Variable normale
    int *ptr = &age;       // Pointeur vers age (& = adresse de)

    printf("Valeur de age: %d\n", age);        // 25
    printf("Adresse de age: %p\n", &age);      // ex: 0x7ffeefbff5bc
    printf("Valeur de ptr: %p\n", ptr);        // même adresse
    printf("Valeur pointée: %d\n", *ptr);      // 25 (* = déréférencement)

    *ptr = 30;  // Modifie age via le pointeur
    printf("Nouvelle valeur de age: %d\n", age);  // 30

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `&variable` : retourne l'adresse mémoire de la variable
- `*ptr` : déclare un pointeur ou déréférence (accède à la valeur)
- `ptr` : contient une adresse mémoire
- Pointeur NULL : pointeur qui ne pointe vers rien (`NULL`)
- Un pointeur doit toujours être initialisé avant utilisation
- La taille d'un pointeur dépend de l'architecture (32-bit = 4 bytes, 64-bit = 8 bytes)

## Application Red Team

Les pointeurs sont fondamentaux en développement de malware et exploitation. Ils permettent de manipuler directement la mémoire d'un processus, ce qui est essentiel pour l'injection de code et la modification de comportement.

En exploitation Windows, des fonctions comme `WriteProcessMemory()` utilisent des pointeurs pour écrire dans l'espace mémoire d'un autre processus. On passe un pointeur vers le buffer contenant le shellcode et un pointeur vers l'adresse cible dans le processus distant. Sans pointeurs, impossible d'injecter du code malveillant.

Les techniques d'injection (DLL injection, process hollowing, reflective loading) reposent toutes sur la manipulation de pointeurs. Un attaquant doit comprendre comment obtenir l'adresse d'une fonction (`GetProcAddress`), comment y écrire avec un pointeur, et comment rediriger l'exécution vers du code malveillant en manipulant des pointeurs de fonctions.

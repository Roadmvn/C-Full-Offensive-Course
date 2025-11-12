# Structures

Les structures regroupent des variables de types différents sous un seul nom.

```c
#include <stdio.h>
#include <string.h>

struct Personne {
    char nom[50];
    int age;
    float taille;
};

int main() {
    // Déclaration et initialisation
    struct Personne p1;
    strcpy(p1.nom, "Alice");
    p1.age = 25;
    p1.taille = 1.65;

    printf("Nom: %s\n", p1.nom);          // Accès avec .
    printf("Age: %d ans\n", p1.age);
    printf("Taille: %.2fm\n", p1.taille);

    // Avec pointeur
    struct Personne *ptr = &p1;
    printf("\nVia pointeur: %s\n", ptr->nom);  // Accès avec ->

    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `struct` : regroupe plusieurs variables de types différents
- `.` : accède aux membres d'une structure
- `->` : accède aux membres via un pointeur (`ptr->membre` = `(*ptr).membre`)
- `typedef` : crée un alias pour éviter d'écrire `struct` à chaque fois
- Les structures peuvent contenir d'autres structures
- `sizeof(struct)` peut être plus grand que la somme des membres (padding)

## Application Red Team

Les structures sont omniprésentes dans les API Windows. Par exemple, `PROCESS_INFORMATION` stocke les handles et PIDs d'un processus créé. `STARTUPINFO` configure comment lancer un processus. En process injection, on doit manipuler ces structures correctement pour créer un processus en état suspendu puis y injecter du code.

Les structures sont essentielles pour parser les fichiers PE. `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_SECTION_HEADER` sont toutes des structures qui décrivent le format PE. Pour reflective DLL loading, on doit lire manuellement ces structures depuis la mémoire pour résoudre les imports et appliquer les relocations sans passer par LoadLibrary().

En malware dev, on crée des structures personnalisées pour organiser les données du C2 : adresses IP, ports, clés de chiffrement, configuration du beacon. Les structures permettent de sérialiser facilement ces données pour les transmettre en réseau ou les stocker chiffrées sur disque.

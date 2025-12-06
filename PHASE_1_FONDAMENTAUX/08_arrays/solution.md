==============================================
  MODULE 08 - TABLEAUX - SOLUTIONS
==============================================

Exercice 1 : Déclaration et affichage
------------------------------
#include <stdio.h>
int main() {
    int ports[5] = {80, 443, 22, 21, 3389};

    for (int i = 0; i < 5; i++) {
        printf("ports[%d] = %d\n", i, ports[i]);
    }
    return 0;
}


Exercice 2 : Taille avec sizeof
------------------------------
#include <stdio.h>
int main() {
    int data[] = {10, 20, 30, 40, 50, 60, 70};
    int size = sizeof(data) / sizeof(data[0]);

    printf("Nombre d'éléments : %d\n", size);  // 7
    return 0;
}


Exercice 3 : Somme
------------------------------
#include <stdio.h>
int main() {
    int numbers[] = {5, 10, 15, 20, 25};
    int size = sizeof(numbers) / sizeof(numbers[0]);
    int sum = 0;

    for (int i = 0; i < size; i++) {
        sum += numbers[i];
    }

    printf("Somme : %d\n", sum);  // 75
    return 0;
}


Exercice 4 : Recherche
------------------------------
#include <stdio.h>
int main() {
    int list[] = {12, 45, 67, 89, 34};
    int size = sizeof(list) / sizeof(list[0]);
    int target = 67;
    int found = 0;

    for (int i = 0; i < size; i++) {
        if (list[i] == target) {
            printf("Trouvé à l'index %d\n", i);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("Non trouvé\n");
    }
    return 0;
}


Exercice 5 : Minimum
------------------------------
#include <stdio.h>
int main() {
    int temps[] = {23, 18, 31, 15, 27, 12};
    int size = sizeof(temps) / sizeof(temps[0]);
    int min = temps[0];

    for (int i = 1; i < size; i++) {
        if (temps[i] < min) {
            min = temps[i];
        }
    }

    printf("Température minimale : %d°C\n", min);  // 12
    return 0;
}


Exercice 6 : Copie de tableau
------------------------------
#include <stdio.h>
int main() {
    int src[5] = {1, 2, 3, 4, 5};
    int dst[5];

    // Copie
    for (int i = 0; i < 5; i++) {
        dst[i] = src[i];
    }

    // Affichage
    printf("dst : ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", dst[i]);
    }
    printf("\n");

    return 0;
}


Exercice 7 : Tableau 2D
------------------------------
#include <stdio.h>
int main() {
    int matrix[2][3] = {
        {10, 20, 30},
        {40, 50, 60}
    };

    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            printf("%d ", matrix[i][j]);
        }
        printf("\n");
    }
    return 0;
}


Exercice 8 : Shellcode XOR
------------------------------
#include <stdio.h>
int main() {
    unsigned char shellcode[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    unsigned char key = 0x42;
    int size = sizeof(shellcode);

    printf("Original : ");
    for (int i = 0; i < size; i++) {
        printf("\\x%02x ", shellcode[i]);
    }
    printf("\n");

    // Encodage XOR
    for (int i = 0; i < size; i++) {
        shellcode[i] ^= key;
    }

    printf("Encodé   : ");
    for (int i = 0; i < size; i++) {
        printf("\\x%02x ", shellcode[i]);
    }
    printf("\n");

    return 0;
}

==============================================
  NOTES :
  - Les tableaux commencent à l'index 0
  - sizeof(tableau) / sizeof(tableau[0]) = nombre d'éléments
  - Pas de vérification de limites en C (attention!)
  - Copier : utiliser une boucle (pas d'opérateur =)
==============================================

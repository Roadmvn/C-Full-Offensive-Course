==============================================
  MODULE 07 - BOUCLES - SOLUTIONS
==============================================

Exercice 1 : for basique
------------------------------
#include <stdio.h>
int main() {
    for (int i = 1; i <= 10; i++) {
        printf("%d\n", i);
    }
    return 0;
}


Exercice 2 : for avec incrément personnalisé
------------------------------
#include <stdio.h>
int main() {
    for (int i = 0; i <= 50; i += 5) {
        printf("%d\n", i);
    }
    return 0;
}


Exercice 3 : while
------------------------------
#include <stdio.h>
int main() {
    int n = 1;
    while (n <= 1024) {
        printf("%d\n", n);
        n *= 2;  // n = n * 2
    }
    return 0;
}


Exercice 4 : do-while
------------------------------
#include <stdio.h>
int main() {
    int choice = 0;
    do {
        printf("1. Scan\n");
        printf("2. Exploit\n");
        printf("3. Quitter\n");
        printf("Choix : ");

        choice = 3;  // Simulation (normalement scanf)
        printf("%d\n", choice);

    } while (choice != 3);

    printf("Au revoir!\n");
    return 0;
}


Exercice 5 : break
------------------------------
#include <stdio.h>
int main() {
    for (int i = 0; i <= 100; i++) {
        if (i == 42) {
            printf("Nombre secret trouvé : 42\n");
            break;
        }
    }
    return 0;
}


Exercice 6 : continue
------------------------------
#include <stdio.h>
int main() {
    for (int i = 1; i <= 20; i++) {
        if (i % 3 == 0) {
            continue;  // Saute les multiples de 3
        }
        printf("%d\n", i);
    }
    return 0;
}


Exercice 7 : Somme (accumulateur)
------------------------------
#include <stdio.h>
int main() {
    int sum = 0;
    for (int i = 1; i <= 100; i++) {
        sum += i;
    }
    printf("Somme : %d\n", sum);  // 5050
    return 0;
}


Exercice 8 : Encodeur XOR
------------------------------
#include <stdio.h>
int main() {
    unsigned char data[] = {0x41, 0x42, 0x43, 0x44};  // "ABCD"
    unsigned char key = 0x99;
    int size = 4;

    printf("Original : ");
    for (int i = 0; i < size; i++) {
        printf("%c", data[i]);
    }
    printf("\n");

    // Encodage
    for (int i = 0; i < size; i++) {
        data[i] = data[i] ^ key;
    }

    printf("Encodé   : ");
    for (int i = 0; i < size; i++) {
        printf("\\x%02x ", data[i]);
    }
    printf("\n");

    return 0;
}

==============================================
  NOTES :
  - for : nombre d'itérations connu
  - while : condition de sortie dynamique
  - do-while : exécuté au moins 1 fois
  - break : sortie immédiate
  - continue : passe à l'itération suivante
==============================================

#include <stdio.h>

int main() {
    // if simple
    int age = 20;
    if (age >= 18) {
        printf("Vous êtes majeur\n");
    }

    // if-else
    int temperature = 15;
    if (temperature > 20) {
        printf("Il fait chaud\n");
    } else {
        printf("Il fait froid\n");
    }

    // if-else if-else
    int note = 75;
    if (note >= 90) {
        printf("Grade : A\n");
    } else if (note >= 80) {
        printf("Grade : B\n");
    } else if (note >= 70) {
        printf("Grade : C\n");
    } else {
        printf("Grade : F\n");
    }

    // Opérateur ternaire
    int x = 10, y = 20;
    int max = (x > y) ? x : y;
    printf("Max : %d\n", max);

    // switch-case
    int jour = 3;
    switch (jour) {
        case 1:
            printf("Lundi\n");
            break;
        case 2:
            printf("Mardi\n");
            break;
        case 3:
            printf("Mercredi\n");
            break;
        default:
            printf("Autre jour\n");
    }

    // Conditions imbriquées
    int a_permis = 1;
    int a_voiture = 1;
    if (age >= 18) {
        if (a_permis) {
            if (a_voiture) {
                printf("Peut conduire!\n");
            }
        }
    }

    return 0;
}

==============================================
  MODULE 10 - FONCTIONS - SOLUTIONS
==============================================

Exercice 1 : Fonction simple
------------------------------
#include <stdio.h>

int subtract(int a, int b) {
    return a - b;
}

int main() {
    int result = subtract(10, 3);
    printf("Résultat : %d\n", result);  // 7
    return 0;
}


Exercice 2 : Fonction void
------------------------------
#include <stdio.h>

void print_message() {
    printf("Bienvenue dans le Red Team!\n");
}

int main() {
    print_message();
    return 0;
}


Exercice 3 : Fonction booléenne
------------------------------
#include <stdio.h>

int is_positive(int n) {
    return (n > 0);  // Retourne 1 ou 0
}

int main() {
    printf("is_positive(5) : %d\n", is_positive(5));    // 1
    printf("is_positive(-3) : %d\n", is_positive(-3));  // 0
    printf("is_positive(0) : %d\n", is_positive(0));    // 0
    return 0;
}


Exercice 4 : Fonction avec tableau
------------------------------
#include <stdio.h>

int sum_array(int arr[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}

int main() {
    int numbers[] = {10, 20, 30, 40, 50};
    int total = sum_array(numbers, 5);
    printf("Somme : %d\n", total);  // 150
    return 0;
}


Exercice 5 : Passage par référence
------------------------------
#include <stdio.h>

void swap(int* a, int* b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main() {
    int x = 5, y = 10;
    printf("Avant : x=%d, y=%d\n", x, y);

    swap(&x, &y);

    printf("Après : x=%d, y=%d\n", x, y);  // x=10, y=5
    return 0;
}


Exercice 6 : Fonction récursive
------------------------------
#include <stdio.h>

int power(int base, int exp) {
    if (exp == 0) {
        return 1;  // Cas de base
    }
    return base * power(base, exp - 1);
}

int main() {
    printf("2^3 = %d\n", power(2, 3));  // 8
    printf("5^2 = %d\n", power(5, 2));  // 25
    return 0;
}


Exercice 7 : Fonction de validation
------------------------------
#include <stdio.h>

int is_valid_port(int port) {
    return (port >= 1 && port <= 65535);
}

int main() {
    printf("Port 80 : %s\n", is_valid_port(80) ? "Valide" : "Invalide");
    printf("Port 0 : %s\n", is_valid_port(0) ? "Valide" : "Invalide");
    printf("Port 70000 : %s\n", is_valid_port(70000) ? "Valide" : "Invalide");
    return 0;
}


Exercice 8 : Fonction d'encodage ROT13
------------------------------
#include <stdio.h>
#include <string.h>

void rot13(char* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i];

        // Minuscules
        if (c >= 'a' && c <= 'z') {
            str[i] = ((c - 'a' + 13) % 26) + 'a';
        }
        // Majuscules
        else if (c >= 'A' && c <= 'Z') {
            str[i] = ((c - 'A' + 13) % 26) + 'A';
        }
        // Autres caractères : inchangés
    }
}

int main() {
    char text[] = "Hello";
    printf("Original : %s\n", text);

    rot13(text);
    printf("ROT13    : %s\n", text);  // "Uryyb"

    rot13(text);  // Décoder
    printf("Décodé   : %s\n", text);  // "Hello"

    return 0;
}

==============================================
  NOTES :
  - Prototype : déclarer avant main ou en haut du fichier
  - Passage par valeur : copie (pas de modification)
  - Passage par référence : pointeurs (modification possible)
  - Fonction récursive : doit avoir un cas de base
  - void : fonction sans retour
==============================================

#include <stdio.h>
#include <string.h>

/*
 * Programme : Fonctions
 * Description : Démonstration des fonctions en C
 * Compilation : gcc example.c -o example
 */

// ========== PROTOTYPES ==========
int add(int a, int b);
int multiply(int a, int b);
void print_banner(char* title);
int is_even(int n);
void print_array(int arr[], int size);
void xor_encode(unsigned char* data, int size, unsigned char key);
int factorial(int n);
void increment_by_value(int x);
void increment_by_reference(int* x);
int is_valid_user(char* username);

// ========== MAIN ==========
int main() {
    printf("=== FONCTIONS EN C ===\n\n");

    // 1. Fonction simple avec retour
    printf("1. Fonction avec retour\n");
    int sum = add(5, 3);
    printf("   add(5, 3) = %d\n\n", sum);

    // 2. Fonction avec plusieurs paramètres
    printf("2. Fonction avec plusieurs paramètres\n");
    int product = multiply(4, 7);
    printf("   multiply(4, 7) = %d\n\n", product);

    // 3. Fonction void (sans retour)
    printf("3. Fonction void\n");
    print_banner("RED TEAM");
    printf("\n");

    // 4. Fonction booléenne
    printf("4. Fonction booléenne\n");
    int num = 42;
    if (is_even(num)) {
        printf("   %d est pair\n\n", num);
    } else {
        printf("   %d est impair\n\n", num);
    }

    // 5. Fonction avec tableau
    printf("5. Fonction avec tableau\n");
    int ports[] = {80, 443, 22, 21, 3389};
    printf("   Ports ouverts : ");
    print_array(ports, 5);
    printf("\n");

    // 6. Passage par valeur
    printf("6. Passage par valeur\n");
    int a = 10;
    printf("   Avant : a = %d\n", a);
    increment_by_value(a);
    printf("   Après : a = %d (inchangé)\n\n", a);

    // 7. Passage par référence (pointeur)
    printf("7. Passage par référence\n");
    int b = 10;
    printf("   Avant : b = %d\n", b);
    increment_by_reference(&b);
    printf("   Après : b = %d (modifié)\n\n", b);

    // 8. Fonction récursive
    printf("8. Fonction récursive (factorielle)\n");
    int n = 5;
    int fact = factorial(n);
    printf("   factorial(%d) = %d\n\n", n, fact);

    // 9. Fonction d'encodage XOR
    printf("9. Fonction d'encodage XOR\n");
    unsigned char shellcode[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    unsigned char key = 0x42;
    int size = sizeof(shellcode);

    printf("   Original : ");
    for (int i = 0; i < size; i++) {
        printf("%c", shellcode[i]);
    }
    printf("\n");

    xor_encode(shellcode, size, key);

    printf("   Encodé   : ");
    for (int i = 0; i < size; i++) {
        printf("\\x%02x ", shellcode[i]);
    }
    printf("\n");

    xor_encode(shellcode, size, key);  // Décoder

    printf("   Décodé   : ");
    for (int i = 0; i < size; i++) {
        printf("%c", shellcode[i]);
    }
    printf("\n\n");

    // 10. Fonction avec conditions
    printf("10. Fonction de validation\n");
    char username1[] = "admin";
    char username2[] = "guest";

    if (is_valid_user(username1)) {
        printf("   '%s' est un utilisateur valide\n", username1);
    }

    if (!is_valid_user(username2)) {
        printf("   '%s' n'est pas un utilisateur valide\n", username2);
    }

    printf("\n[+] Programme terminé avec succès.\n");
    return 0;
}

// ========== DÉFINITIONS ==========

// Addition de deux entiers
int add(int a, int b) {
    return a + b;
}

// Multiplication de deux entiers
int multiply(int a, int b) {
    return a * b;
}

// Affiche un banner stylisé
void print_banner(char* title) {
    int len = strlen(title);

    // Ligne du haut
    printf("   ");
    for (int i = 0; i < len + 4; i++) {
        printf("=");
    }
    printf("\n");

    // Titre
    printf("   | %s |\n", title);

    // Ligne du bas
    printf("   ");
    for (int i = 0; i < len + 4; i++) {
        printf("=");
    }
    printf("\n");
}

// Vérifie si un nombre est pair
int is_even(int n) {
    return (n % 2 == 0);  // Retourne 1 (vrai) ou 0 (faux)
}

// Affiche un tableau
void print_array(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

// Encode/décode un tableau avec XOR
void xor_encode(unsigned char* data, int size, unsigned char key) {
    for (int i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

// Calcul factoriel (récursif)
int factorial(int n) {
    if (n <= 1) {
        return 1;  // Cas de base
    }
    return n * factorial(n - 1);  // Récursion
}

// Passage par valeur (ne modifie pas l'original)
void increment_by_value(int x) {
    x++;
    printf("   Dans la fonction : x = %d\n", x);
}

// Passage par référence (modifie l'original)
void increment_by_reference(int* x) {
    (*x)++;
    printf("   Dans la fonction : *x = %d\n", *x);
}

// Validation d'utilisateur (Red Team)
int is_valid_user(char* username) {
    // Liste d'utilisateurs autorisés
    char* valid_users[] = {"admin", "root", "operator"};
    int count = 3;

    for (int i = 0; i < count; i++) {
        if (strcmp(username, valid_users[i]) == 0) {
            return 1;  // Valide
        }
    }
    return 0;  // Non valide
}

#include <stdio.h>
#include <string.h>

int main() {
    printf("=== CHAINES DE CARACTERES EN C ===\n\n");

    // 1. DECLARATION ET INITIALISATION
    printf("1. Declaration et initialisation :\n");
    char prenom[50] = "Alice";
    char nom[50] = "Dupont";

    printf("   Prenom : %s\n", prenom);
    printf("   Nom : %s\n", nom);

    // 2. LONGUEUR D'UNE STRING
    printf("\n2. Longueur d'une string :\n");
    int longueur = strlen(prenom);
    printf("   strlen(\"%s\") = %d caracteres\n", prenom, longueur);

    // 3. COPIER UNE STRING
    printf("\n3. Copier une string :\n");
    char copie[50];
    strcpy(copie, prenom);  // Copie prenom dans copie
    printf("   Original : %s\n", prenom);
    printf("   Copie : %s\n", copie);

    // 4. CONCATENER (JOINDRE) DES STRINGS
    printf("\n4. Concatener des strings :\n");
    char nom_complet[100] = "Alice";
    strcat(nom_complet, " ");      // Ajoute un espace
    strcat(nom_complet, "Dupont"); // Ajoute le nom
    printf("   Nom complet : %s\n", nom_complet);

    // 5. COMPARER DES STRINGS
    printf("\n5. Comparer des strings :\n");
    char mot1[50] = "hello";
    char mot2[50] = "hello";
    char mot3[50] = "world";

    if (strcmp(mot1, mot2) == 0) {
        printf("   \"%s\" == \"%s\" : identiques\n", mot1, mot2);
    }

    if (strcmp(mot1, mot3) != 0) {
        printf("   \"%s\" != \"%s\" : differents\n", mot1, mot3);
    }

    // 6. PARCOURIR UNE STRING CARACTERE PAR CARACTERE
    printf("\n6. Parcourir caractere par caractere :\n");
    char texte[50] = "Bonjour";
    printf("   Texte : %s\n", texte);
    printf("   Caracteres : ");
    for (int i = 0; texte[i] != '\0'; i++) {  // Jusqu'au caractère nul
        printf("%c ", texte[i]);
    }
    printf("\n");

    // 7. CONVERTIR EN MAJUSCULES
    printf("\n7. Convertir en majuscules :\n");
    char message[50] = "hello world";
    printf("   Original : %s\n", message);

    for (int i = 0; message[i] != '\0'; i++) {
        if (message[i] >= 'a' && message[i] <= 'z') {
            message[i] = message[i] - 32;  // Convertir en majuscule
        }
    }
    printf("   Majuscules : %s\n", message);

    // 8. LECTURE DE STRING (simulation)
    printf("\n8. Lecture de string avec fgets :\n");
    printf("   // char input[100];\n");
    printf("   // fgets(input, 100, stdin);\n");
    printf("   // input[strcspn(input, \"\\n\")] = '\\0';  // Enlever le \\n\n");

    return 0;
}

#include <stdio.h>
#include <string.h>  // Pour strcspn()

/*
 * Programme : Printf et Scanf
 * Description : Démonstration des I/O formatées
 * Compilation : gcc example.c -o example
 */

int main() {
    printf("=== PRINTF - SORTIE FORMATÉE ===\n\n");

    // Formatage basique
    int port = 4444;
    printf("Port: %d\n", port);
    printf("Port (hexa): 0x%X\n", port);
    printf("Port (octal): %o\n\n", port);

    // Formatage avec largeur
    printf("Aligné à droite  : %10d\n", 42);
    printf("Aligné à gauche  : %-10d\n", 42);
    printf("Padding avec 0   : %010d\n\n", 42);

    // Float avec précision
    float pi = 3.141592653589;
    printf("Pi (défaut)   : %f\n", pi);
    printf("Pi (2 déc)    : %.2f\n", pi);
    printf("Pi (4 déc)    : %.4f\n\n", pi);

    // Affichage d'adresses
    int secret = 1337;
    printf("Adresse de 'secret': %p\n\n", (void*)&secret);

    // ===============================
    printf("=== SCANF - ENTRÉE FORMATÉE ===\n\n");

    // Lecture d'un entier
    int age;
    printf("Entre ton âge : ");
    scanf("%d", &age);  // & = adresse de la variable
    printf("Tu as %d ans.\n\n", age);

    // Nettoyage du buffer (important !)
    while (getchar() != '\n');  // Vide le buffer

    // Lecture d'un caractère
    char grade;
    printf("Entre ta note (A-F) : ");
    scanf("%c", &grade);
    printf("Note : %c\n\n", grade);

    while (getchar() != '\n');

    // ===============================
    printf("=== FGETS - LECTURE SÉCURISÉE ===\n\n");

    // fgets() est plus sûr que scanf() pour les strings
    char name[50];
    printf("Entre ton nom : ");
    fgets(name, sizeof(name), stdin);  // Limite à 50 caractères

    // Enlève le \n à la fin
    name[strcspn(name, "\n")] = 0;

    printf("Bonjour, %s !\n\n", name);

    // ===============================
    printf("=== EXEMPLE OFFENSIF ===\n\n");

    // Affichage d'un shellcode (bytes bruts)
    unsigned char shellcode[] = {0x90, 0x90, 0x31, 0xC0, 0xFF, 0xE0};
    printf("Shellcode : ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("\\x%02X", shellcode[i]);
    }
    printf("\n");

    // Affichage de l'adresse du shellcode
    printf("Adresse du shellcode : %p\n", (void*)shellcode);

    return 0;
}

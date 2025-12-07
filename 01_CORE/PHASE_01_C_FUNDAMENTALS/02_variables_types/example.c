#include <stdio.h>

/*
 * Programme : Variables et Types
 * Description : Démonstration des types de données en C
 * Compilation : gcc example.c -o example
 */

int main() {
    printf("=== TYPES DE BASE EN C ===\n\n");

    // Entiers signés
    char c = 'A';              // 1 byte
    short s = 1000;            // 2 bytes
    int i = 100000;            // 4 bytes
    long l = 1000000000L;      // 8 bytes

    printf("char   : %c (taille: %lu bytes)\n", c, sizeof(c));
    printf("short  : %d (taille: %lu bytes)\n", s, sizeof(s));
    printf("int    : %d (taille: %lu bytes)\n", i, sizeof(i));
    printf("long   : %ld (taille: %lu bytes)\n\n", l, sizeof(l));

    // Entiers non signés (unsigned)
    unsigned char uc = 255;    // 0 à 255
    unsigned int ui = 4294967295U;  // 0 à 2^32-1

    printf("unsigned char : %u (max: 255)\n", uc);
    printf("unsigned int  : %u (max: 2^32-1)\n\n", ui);

    // Nombres à virgule
    float f = 3.14f;           // Simple précision
    double d = 3.141592653589; // Double précision

    printf("float  : %f (taille: %lu bytes)\n", f, sizeof(f));
    printf("double : %lf (taille: %lu bytes)\n\n", d, sizeof(d));

    // Constantes
    const int MAX_BUFFER = 256;
    printf("Constante MAX_BUFFER : %d\n\n", MAX_BUFFER);

    // Affichage en hexadécimal (important pour l'offensif)
    int address = 0xDEADBEEF;
    printf("Adresse en hexa : 0x%X\n", address);
    printf("Adresse en déci : %d\n\n", address);

    // Bytes bruts (shellcode style)
    unsigned char bytes[] = {0x90, 0x90, 0xCC};  // NOP NOP INT3
    printf("Bytes : ");
    for (int j = 0; j < 3; j++) {
        printf("\\x%02X ", bytes[j]);
    }
    printf("\n\n");

    // Taille des pointeurs (architecture-dépendant)
    printf("Taille d'un pointeur : %lu bytes\n", sizeof(void*));
    printf("Architecture : %lu bits\n", sizeof(void*) * 8);

    return 0;
}

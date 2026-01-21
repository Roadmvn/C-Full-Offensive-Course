#include <stdio.h>

/*
 * Programme : Opérateurs Bitwise
 * Description : Démonstration des opérations bit à bit
 * Compilation : gcc example.c -o example
 */

// Définition de flags (style Unix permissions)
#define READ    0b100  // 4
#define WRITE   0b010  // 2
#define EXECUTE 0b001  // 1

void print_binary(unsigned char n) {
    // Affiche un nombre en binaire (8 bits)
    for (int i = 7; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
        if (i == 4) printf(" ");  // Espace au milieu pour lisibilité
    }
}

int main() {
    printf("=== OPÉRATEURS BITWISE ===\n\n");

    // 1. AND bitwise (&)
    printf("1. AND bitwise (&)\n");
    unsigned char a = 0b11001100;  // 204
    unsigned char b = 0b10101010;  // 170
    unsigned char result_and = a & b;

    printf("  a     = "); print_binary(a); printf(" (%d)\n", a);
    printf("  b     = "); print_binary(b); printf(" (%d)\n", b);
    printf("  a & b = "); print_binary(result_and); printf(" (%d)\n\n", result_and);

    // 2. OR bitwise (|)
    printf("2. OR bitwise (|)\n");
    unsigned char result_or = a | b;
    printf("  a | b = "); print_binary(result_or); printf(" (%d)\n\n", result_or);

    // 3. XOR bitwise (^)
    printf("3. XOR bitwise (^)\n");
    unsigned char result_xor = a ^ b;
    printf("  a ^ b = "); print_binary(result_xor); printf(" (%d)\n\n", result_xor);

    // 4. NOT bitwise (~)
    printf("4. NOT bitwise (~)\n");
    unsigned char c = 0b00001111;  // 15
    unsigned char result_not = ~c;
    printf("  c     = "); print_binary(c); printf(" (%d)\n", c);
    printf("  ~c    = "); print_binary(result_not); printf(" (%d)\n\n", result_not);

    // 5. Left shift (<<)
    printf("5. Left Shift (<<)\n");
    unsigned char d = 0b00000101;  // 5
    printf("  d       = "); print_binary(d); printf(" (%d)\n", d);
    printf("  d << 1  = "); print_binary(d << 1); printf(" (%d) [x2]\n", d << 1);
    printf("  d << 2  = "); print_binary(d << 2); printf(" (%d) [x4]\n", d << 2);
    printf("  d << 3  = "); print_binary(d << 3); printf(" (%d) [x8]\n\n", d << 3);

    // 6. Right shift (>>)
    printf("6. Right Shift (>>)\n");
    unsigned char e = 0b10100000;  // 160
    printf("  e       = "); print_binary(e); printf(" (%d)\n", e);
    printf("  e >> 1  = "); print_binary(e >> 1); printf(" (%d) [/2]\n", e >> 1);
    printf("  e >> 2  = "); print_binary(e >> 2); printf(" (%d) [/4]\n\n", e >> 2);

    // 7. Masques : vérifier un bit
    printf("7. Masques : vérification de bits\n");
    unsigned char flags = 0b10110100;
    printf("  flags = "); print_binary(flags); printf("\n");
    printf("  Bit 0 : %s\n", (flags & (1 << 0)) ? "ON" : "OFF");
    printf("  Bit 2 : %s\n", (flags & (1 << 2)) ? "ON" : "OFF");
    printf("  Bit 5 : %s\n", (flags & (1 << 5)) ? "ON" : "OFF");
    printf("  Bit 7 : %s\n\n", (flags & (1 << 7)) ? "ON" : "OFF");

    // 8. Activer/Désactiver des bits
    printf("8. Manipulation de bits\n");
    unsigned char perms = 0b00000000;
    printf("  Initial  : "); print_binary(perms); printf("\n");

    perms = perms | (1 << 2);  // Active bit 2
    printf("  Set bit 2: "); print_binary(perms); printf("\n");

    perms = perms | (1 << 4);  // Active bit 4
    printf("  Set bit 4: "); print_binary(perms); printf("\n");

    perms = perms & ~(1 << 2); // Désactive bit 2
    printf("  Clear b2 : "); print_binary(perms); printf("\n");

    perms = perms ^ (1 << 4);  // Toggle bit 4
    printf("  Toggle 4 : "); print_binary(perms); printf("\n\n");

    // 9. Permissions Unix-style
    printf("9. Permissions (style Unix)\n");
    int user_perms = READ | WRITE;  // rw-
    printf("  User: ");
    printf("%c", (user_perms & READ) ? 'r' : '-');
    printf("%c", (user_perms & WRITE) ? 'w' : '-');
    printf("%c", (user_perms & EXECUTE) ? 'x' : '-');
    printf(" (%d)\n", user_perms);

    // 10. XOR swap (échanger sans variable temporaire)
    printf("\n10. XOR Swap (sans variable temporaire)\n");
    int x = 42, y = 100;
    printf("  Avant : x = %d, y = %d\n", x, y);
    x = x ^ y;
    y = x ^ y;  // y devient l'ancien x
    x = x ^ y;  // x devient l'ancien y
    printf("  Après : x = %d, y = %d\n", x, y);

    // 11. Encodage XOR simple (Red Team)
    printf("\n11. Encodage XOR (chiffrement simple)\n");
    unsigned char message[] = "HACK";
    unsigned char key = 0xAA;
    printf("  Message original : %s\n", message);

    // Encodage
    for (int i = 0; message[i] != '\0'; i++) {
        message[i] = message[i] ^ key;
    }
    printf("  Message encodé  : ");
    for (int i = 0; message[i] != '\0'; i++) {
        printf("\\x%02x", message[i]);
    }

    // Décodage (même opération!)
    for (int i = 0; message[i] != '\0'; i++) {
        message[i] = message[i] ^ key;
    }
    printf("\n  Message décodé  : %s\n", message);

    printf("\n[+] Programme terminé avec succès.\n");
    return 0;
}

==============================================
  MODULE 05 - BITWISE - SOLUTIONS
==============================================

Exercice 1 : AND simple
------------------------------
#include <stdio.h>
int main() {
    unsigned char a = 0b11110000;
    unsigned char b = 0b10101010;
    unsigned char result = a & b;
    printf("a & b = %d\n", result);  // 160
    return 0;
}


Exercice 2 : Masque pour extraire
------------------------------
#include <stdio.h>
int main() {
    unsigned char ip_octet = 0b11010110;
    unsigned char mask = 0b11110000;
    unsigned char result = ip_octet & mask;
    printf("4 bits de gauche : %d\n", result);  // 208
    return 0;
}


Exercice 3 : Activer un bit
------------------------------
#include <stdio.h>
int main() {
    unsigned char flags = 0b00000000;
    flags = flags | (1 << 3);  // Active bit 3
    printf("flags = %d\n", flags);  // 8 (0b00001000)
    return 0;
}


Exercice 4 : Vérifier si un bit est set
------------------------------
#include <stdio.h>
int main() {
    unsigned char status = 0b10010100;

    if (status & (1 << 4)) {
        printf("Bit 4 activé\n");
    } else {
        printf("Bit 4 désactivé\n");
    }
    return 0;
}


Exercice 5 : XOR swap
------------------------------
#include <stdio.h>
int main() {
    int x = 25, y = 75;
    printf("Avant : x = %d, y = %d\n", x, y);

    x = x ^ y;
    y = x ^ y;  // y devient 25
    x = x ^ y;  // x devient 75

    printf("Après : x = %d, y = %d\n", x, y);
    return 0;
}


Exercice 6 : Left shift (multiplication)
------------------------------
#include <stdio.h>
int main() {
    int base = 7;
    int result = base << 3;  // 7 * (2^3) = 7 * 8
    printf("7 * 8 = %d\n", result);  // 56
    return 0;
}


Exercice 7 : Right shift (division)
------------------------------
#include <stdio.h>
int main() {
    int bytes = 1024;
    int result = bytes >> 2;  // 1024 / (2^2) = 1024 / 4
    printf("1024 / 4 = %d\n", result);  // 256
    return 0;
}


Exercice 8 : Encodeur XOR
------------------------------
#include <stdio.h>
int main() {
    unsigned char data[] = {0x48, 0x45, 0x4C, 0x4C, 0x4F};  // "HELLO"
    unsigned char key = 0x13;
    int size = 5;

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

    // Décodage
    for (int i = 0; i < size; i++) {
        data[i] = data[i] ^ key;
    }

    printf("Décodé   : ");
    for (int i = 0; i < size; i++) {
        printf("%c", data[i]);
    }
    printf("\n");

    return 0;
}

==============================================
  NOTES :
  - XOR est réversible : X ^ K ^ K = X
  - Shifts : << multiplie, >> divise par puissances de 2
  - Masques : & pour extraire, | pour activer, ~ pour inverser
==============================================

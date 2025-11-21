#include <stdio.h>

// Afficher un nombre en binaire
void print_binary(unsigned int n, int bits) {
    for (int i = bits - 1; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
        if (i % 4 == 0 && i != 0) printf(" ");
    }
}

// Convertir IP en binaire
void print_ip_binary(unsigned char octets[4]) {
    for (int i = 0; i < 4; i++) {
        print_binary(octets[i], 8);
        if (i < 3) printf(".");
    }
    printf("\n");
}

// Calculer adresse réseau
void calculer_reseau(unsigned char ip[4], unsigned char masque[4], 
                     unsigned char reseau[4]) {
    for (int i = 0; i < 4; i++) {
        reseau[i] = ip[i] & masque[i];
    }
}

int main() {
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║   DÉMONSTRATION BINAIRE ET HEXADÉCIMAL             ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");
    
    // 1. COMPTAGE EN BINAIRE
    printf("1. COMPTAGE DE 0 À 15 :\n");
    printf("┌────────┬──────────┬──────┐\n");
    printf("│ Décimal│ Binaire  │ Hexa │\n");
    printf("├────────┼──────────┼──────┤\n");
    for (int i = 0; i <= 15; i++) {
        printf("│   %2d   │ ", i);
        print_binary(i, 4);
        printf("   │ 0x%X  │\n", i);
    }
    printf("└────────┴──────────┴──────┘\n\n");
    
    // 2. CONVERSIONS
    printf("2. CONVERSIONS :\n");
    unsigned char nombre = 42;
    
    printf("Nombre : %d (décimal)\n", nombre);
    printf("Binaire: ");
    print_binary(nombre, 8);
    printf("\n");
    printf("Hexa   : 0x%02X\n\n", nombre);
    
    // 3. PUISSANCES DE 2
    printf("3. PUISSANCES DE 2 :\n");
    printf("┌──────┬───────────┬──────────┐\n");
    printf("│  2^n │  Valeur   │ Binaire  │\n");
    printf("├──────┼───────────┼──────────┤\n");
    for (int i = 0; i <= 8; i++) {
        int valeur = 1 << i;
        printf("│ 2^%-2d │ %9d │ ", i, valeur);
        print_binary(valeur, 9);
        printf(" │\n");
    }
    printf("└──────┴───────────┴──────────┘\n\n");
    
    // 4. OPÉRATIONS BINAIRES
    printf("4. OPÉRATIONS BINAIRES :\n");
    unsigned char a = 0b1100;  // 12
    unsigned char b = 0b1010;  // 10
    
    printf("a = %d (0b", a);
    print_binary(a, 4);
    printf(")\n");
    
    printf("b = %d (0b", b);
    print_binary(b, 4);
    printf(")\n\n");
    
    printf("a & b  = %d (0b", a & b);
    print_binary(a & b, 4);
    printf(") - AND\n");
    
    printf("a | b  = %d (0b", a | b);
    print_binary(a | b, 4);
    printf(") - OR\n");
    
    printf("a ^ b  = %d (0b", a ^ b);
    print_binary(a ^ b, 4);
    printf(") - XOR\n\n");
    
    // 5. DÉCALAGES
    printf("5. DÉCALAGES DE BITS :\n");
    unsigned char x = 5;
    printf("x = %d (0b", x);
    print_binary(x, 8);
    printf(")\n");
    
    printf("x << 1 = %d (×2) (0b", x << 1);
    print_binary(x << 1, 8);
    printf(")\n");
    
    printf("x << 2 = %d (×4) (0b", x << 2);
    print_binary(x << 2, 8);
    printf(")\n");
    
    printf("x >> 1 = %d (÷2) (0b", x >> 1);
    print_binary(x >> 1, 8);
    printf(")\n\n");
    
    // 6. CALCULS IP
    printf("6. CALCULS RÉSEAU :\n");
    unsigned char ip[4] = {192, 168, 1, 50};
    unsigned char masque[4] = {255, 255, 255, 0};  // /24
    unsigned char reseau[4];
    
    printf("IP      : %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
    printf("Binaire : ");
    print_ip_binary(ip);
    
    printf("\nMasque  : %d.%d.%d.%d (/24)\n", 
           masque[0], masque[1], masque[2], masque[3]);
    printf("Binaire : ");
    print_ip_binary(masque);
    
    calculer_reseau(ip, masque, reseau);
    printf("\nRéseau  : %d.%d.%d.%d\n", 
           reseau[0], reseau[1], reseau[2], reseau[3]);
    printf("Binaire : ");
    print_ip_binary(reseau);
    
    // 7. MASQUES
    printf("\n7. EXTRACTION AVEC MASQUES :\n");
    unsigned short valeur = 0x1234;  // 0001 0010 0011 0100
    
    printf("Valeur : 0x%04X = ", valeur);
    print_binary(valeur, 16);
    printf("\n");
    
    unsigned char high_byte = (valeur >> 8) & 0xFF;
    unsigned char low_byte = valeur & 0xFF;
    
    printf("Byte haut  : 0x%02X = ", high_byte);
    print_binary(high_byte, 8);
    printf("\n");
    
    printf("Byte bas   : 0x%02X = ", low_byte);
    print_binary(low_byte, 8);
    printf("\n");
    
    printf("\n════════════════════════════════════════════════════\n");
    printf("Programme terminé avec succès.\n");
    
    return 0;
}


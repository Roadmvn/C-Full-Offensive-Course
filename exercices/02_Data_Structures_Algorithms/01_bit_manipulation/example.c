#include <stdio.h>

// Fonctions utilitaires
void print_binary(unsigned int n) {
    for (int i = 31; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
        if (i % 8 == 0) printf(" ");
    }
    printf("\n");
}

int check_bit(int num, int pos) {
    return (num & (1 << pos)) != 0;
}

int set_bit(int num, int pos) {
    return num | (1 << pos);
}

int clear_bit(int num, int pos) {
    return num & ~(1 << pos);
}

int toggle_bit(int num, int pos) {
    return num ^ (1 << pos);
}

int count_bits(unsigned int n) {
    int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}

int is_power_of_2(unsigned int n) {
    return n && !(n & (n - 1));
}

int main() {
    printf("=== MANIPULATION DE BITS ===\n\n");

    // 1. Opérations de base
    printf("1. Opérations de base :\n");
    unsigned int a = 12, b = 10;  // 0b1100 et 0b1010
    
    printf("a = %u (0b1100)\n", a);
    printf("b = %u (0b1010)\n", b);
    printf("a & b  = %u (AND)\n", a & b);    // 8 (0b1000)
    printf("a | b  = %u (OR)\n", a | b);     // 14 (0b1110)
    printf("a ^ b  = %u (XOR)\n", a ^ b);    // 6 (0b0110)
    printf("~a     = %u (NOT)\n\n", ~a);

    // 2. Décalages
    printf("2. Décalages :\n");
    unsigned int x = 5;  // 0b0101
    printf("x = %u\n", x);
    printf("x << 1 = %u (multiplier par 2)\n", x << 1);  // 10
    printf("x << 2 = %u (multiplier par 4)\n", x << 2);  // 20
    printf("x >> 1 = %u (diviser par 2)\n\n", x >> 1);   // 2

    // 3. Vérifier un bit
    printf("3. Vérifier un bit :\n");
    unsigned int flags = 0b1010;
    printf("flags = %u (0b1010)\n", flags);
    printf("Bit 0 : %s\n", check_bit(flags, 0) ? "ON" : "OFF");
    printf("Bit 1 : %s\n", check_bit(flags, 1) ? "ON" : "OFF");
    printf("Bit 3 : %s\n\n", check_bit(flags, 3) ? "ON" : "OFF");

    // 4. Modifier des bits
    printf("4. Modifier des bits :\n");
    int num = 0;
    printf("Initial : %d (0b%04d)\n", num, num);
    
    num = set_bit(num, 2);
    printf("Set bit 2 : %d (0b%04d)\n", num, num);
    
    num = set_bit(num, 0);
    printf("Set bit 0 : %d (0b%04d)\n", num, num);
    
    num = toggle_bit(num, 2);
    printf("Toggle bit 2 : %d (0b%04d)\n\n", num, num);

    // 5. Compter les bits
    printf("5. Compter les bits à 1 :\n");
    printf("0b1011 contient %d bits à 1\n", count_bits(0b1011));
    printf("0b11111111 contient %d bits à 1\n\n", count_bits(0xFF));

    // 6. Puissance de 2
    printf("6. Tester si puissance de 2 :\n");
    printf("16 : %s\n", is_power_of_2(16) ? "OUI" : "NON");
    printf("15 : %s\n", is_power_of_2(15) ? "OUI" : "NON");
    printf("64 : %s\n\n", is_power_of_2(64) ? "OUI" : "NON");

    // 7. Masques
    printf("7. Utilisation de masques :\n");
    unsigned int valeur = 0x12345678;
    printf("Valeur complète : 0x%08X\n", valeur);
    printf("Byte 0 (LSB)    : 0x%02X\n", valeur & 0xFF);
    printf("Byte 1          : 0x%02X\n", (valeur >> 8) & 0xFF);
    printf("Byte 2          : 0x%02X\n", (valeur >> 16) & 0xFF);
    printf("Byte 3 (MSB)    : 0x%02X\n\n", (valeur >> 24) & 0xFF);

    // 8. Swap sans variable temporaire
    printf("8. Swap avec XOR :\n");
    int p = 5, q = 10;
    printf("Avant : p=%d, q=%d\n", p, q);
    p ^= q;
    q ^= p;
    p ^= q;
    printf("Après : p=%d, q=%d\n\n", p, q);

    // 9. Permissions (style Unix)
    printf("9. Système de permissions :\n");
    #define READ    4  // 0b100
    #define WRITE   2  // 0b010
    #define EXECUTE 1  // 0b001
    
    int perms = READ | WRITE;  // 6 (rw-)
    printf("Permissions : %d (", perms);
    printf("%c", (perms & READ) ? 'r' : '-');
    printf("%c", (perms & WRITE) ? 'w' : '-');
    printf("%c)\n", (perms & EXECUTE) ? 'x' : '-');

    return 0;
}


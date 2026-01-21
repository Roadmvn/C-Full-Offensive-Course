#include "crypto.h"

// Chiffrement/Déchiffrement XOR
void xor_encrypt(unsigned char *data, size_t length, const char *key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key[i % key_len];
    }
}

void xor_decrypt(unsigned char *data, size_t length, const char *key) {
    // XOR est symétrique : déchiffrer = chiffrer
    xor_encrypt(data, length, key);
}

// Génération clé aléatoire
void generate_random_key(unsigned char *key, size_t length) {
    srand(time(NULL));
    for (size_t i = 0; i < length; i++) {
        key[i] = rand() % 256;
    }
}

// Checksum simple (somme de tous les bytes)
unsigned char calculate_checksum(const unsigned char *data, size_t length) {
    unsigned char sum = 0;
    for (size_t i = 0; i < length; i++) {
        sum += data[i];
    }
    return sum;
}

// Vérifier checksum
int verify_checksum(const unsigned char *data, size_t length, unsigned char checksum) {
    return (calculate_checksum(data, length) == checksum);
}


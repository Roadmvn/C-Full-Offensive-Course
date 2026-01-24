#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

// Chiffrement XOR simple
void xor_encrypt(unsigned char *data, size_t length, const char *key);
void xor_decrypt(unsigned char *data, size_t length, const char *key);

// Génération de clé
void generate_random_key(unsigned char *key, size_t length);

// Checksum simple
unsigned char calculate_checksum(const unsigned char *data, size_t length);
int verify_checksum(const unsigned char *data, size_t length, unsigned char checksum);

#endif // CRYPTO_H


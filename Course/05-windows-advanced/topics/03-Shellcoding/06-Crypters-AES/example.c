/**
 * AES Crypter - Exemple conceptuel
 * Nécessite OpenSSL : gcc example.c -lcrypto
 */
#include <stdio.h>
#include <string.h>

// Pseudo-code pour démonstration
// En vrai, utiliser OpenSSL EVP

int main(void) {
    printf("AES Crypter\n");
    printf("1. Générer clé et IV aléatoires\n");
    printf("2. Chiffrer shellcode avec AES-256-CBC\n");
    printf("3. Embedder shellcode chiffré + décrypteur\n");
    printf("4. Au runtime : décrypter en mémoire et exécuter\n");
    return 0;
}

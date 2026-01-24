/*
 * Lesson 01: String Obfuscation
 *
 * Obfuscate sensitive strings at compile time and deobfuscate at runtime.
 * This prevents static analysis from revealing C2 URLs, commands, etc.
 */

#include <windows.h>
#include <stdio.h>

// XOR key for obfuscation
#define XOR_KEY 0x42

/*
 * XOR encrypt/decrypt a string in place
 * Since XOR is symmetric, same function works for both
 */
VOID XorString(CHAR* str, SIZE_T len) {
    for (SIZE_T i = 0; i < len; i++) {
        str[i] ^= XOR_KEY;
    }
}

/*
 * Helper macro to obfuscate string at compile time
 * Usage: OBFUSCATE("secret") creates obfuscated version
 */
#define OBFUSCATE_CHAR(c) ((c) ^ XOR_KEY)

int main(void) {
    printf("[*] String Obfuscation Demo\n\n");

    // Original string (visible in binary)
    printf("[!] Plain string in binary:\n");
    CHAR plainStr[] = "http://malware-c2.com/beacon";
    printf("    %s\n\n", plainStr);

    // Obfuscated string (not readable in binary)
    printf("[+] Obfuscated string at compile time:\n");
    CHAR obfStr[] = {
        OBFUSCATE_CHAR('h'), OBFUSCATE_CHAR('t'), OBFUSCATE_CHAR('t'),
        OBFUSCATE_CHAR('p'), OBFUSCATE_CHAR(':'), OBFUSCATE_CHAR('/'),
        OBFUSCATE_CHAR('/'), OBFUSCATE_CHAR('m'), OBFUSCATE_CHAR('a'),
        OBFUSCATE_CHAR('l'), OBFUSCATE_CHAR('w'), OBFUSCATE_CHAR('a'),
        OBFUSCATE_CHAR('r'), OBFUSCATE_CHAR('e'), OBFUSCATE_CHAR('-'),
        OBFUSCATE_CHAR('c'), OBFUSCATE_CHAR('2'), OBFUSCATE_CHAR('.'),
        OBFUSCATE_CHAR('c'), OBFUSCATE_CHAR('o'), OBFUSCATE_CHAR('m'),
        OBFUSCATE_CHAR('/'), OBFUSCATE_CHAR('b'), OBFUSCATE_CHAR('e'),
        OBFUSCATE_CHAR('a'), OBFUSCATE_CHAR('c'), OBFUSCATE_CHAR('o'),
        OBFUSCATE_CHAR('n'), '\0'
    };

    printf("    Before decrypt: ");
    for (int i = 0; i < 10; i++) {
        printf("%02X ", (unsigned char)obfStr[i]);
    }
    printf("...\n");

    // Deobfuscate at runtime
    XorString(obfStr, sizeof(obfStr) - 1);
    printf("    After decrypt:  %s\n\n", obfStr);

    // Alternative: Stack string obfuscation
    printf("[+] Stack string obfuscation:\n");
    CHAR stackStr[32];

    // Build string on stack to avoid .data section
    stackStr[0] = 'c' ^ XOR_KEY;
    stackStr[1] = 'm' ^ XOR_KEY;
    stackStr[2] = 'd' ^ XOR_KEY;
    stackStr[3] = '.' ^ XOR_KEY;
    stackStr[4] = 'e' ^ XOR_KEY;
    stackStr[5] = 'x' ^ XOR_KEY;
    stackStr[6] = 'e' ^ XOR_KEY;
    stackStr[7] = '\0';

    XorString(stackStr, 7);
    printf("    Deobfuscated: %s\n\n", stackStr);

    // Multi-byte XOR key (stronger)
    printf("[+] Multi-byte XOR key:\n");
    CHAR multiKey[] = {0x12, 0x34, 0x56, 0x78};
    CHAR multiStr[] = "Administrator";
    SIZE_T keyLen = sizeof(multiKey);

    // Encrypt with rotating key
    for (SIZE_T i = 0; i < strlen(multiStr); i++) {
        multiStr[i] ^= multiKey[i % keyLen];
    }

    printf("    Encrypted: ");
    for (SIZE_T i = 0; i < 10; i++) {
        printf("%02X ", (unsigned char)multiStr[i]);
    }
    printf("...\n");

    // Decrypt
    for (SIZE_T i = 0; i < strlen(multiStr); i++) {
        multiStr[i] ^= multiKey[i % keyLen];
    }
    printf("    Decrypted: %s\n\n", multiStr);

    printf("[*] Key Points:\n");
    printf("    1. XOR obfuscation hides strings from static analysis\n");
    printf("    2. Compile-time obfuscation = no plaintext in binary\n");
    printf("    3. Use different keys for different string types\n");
    printf("    4. Multi-byte keys provide stronger obfuscation\n");
    printf("    5. Consider RC4/AES for critical strings\n\n");

    return 0;
}

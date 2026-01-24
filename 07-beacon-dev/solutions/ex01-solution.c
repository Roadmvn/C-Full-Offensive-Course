/*
 * Solution: Exercise 01 - String Obfuscation
 */

#include <windows.h>
#include <stdio.h>

#define XOR_KEY 0x42

// XOR deobfuscation function
VOID DeobfuscateString(CHAR* str, SIZE_T len) {
    for (SIZE_T i = 0; i < len; i++) {
        str[i] ^= XOR_KEY;
    }
}

int main(void) {
    printf("[*] Solution: String Obfuscation\n\n");

    // Task 1: Obfuscate C2 URL "http://192.168.1.100:8080/beacon"
    CHAR c2Url[] = {
        'h' ^ XOR_KEY, 't' ^ XOR_KEY, 't' ^ XOR_KEY, 'p' ^ XOR_KEY,
        ':' ^ XOR_KEY, '/' ^ XOR_KEY, '/' ^ XOR_KEY, '1' ^ XOR_KEY,
        '9' ^ XOR_KEY, '2' ^ XOR_KEY, '.' ^ XOR_KEY, '1' ^ XOR_KEY,
        '6' ^ XOR_KEY, '8' ^ XOR_KEY, '.' ^ XOR_KEY, '1' ^ XOR_KEY,
        '.' ^ XOR_KEY, '1' ^ XOR_KEY, '0' ^ XOR_KEY, '0' ^ XOR_KEY,
        ':' ^ XOR_KEY, '8' ^ XOR_KEY, '0' ^ XOR_KEY, '8' ^ XOR_KEY,
        '0' ^ XOR_KEY, '/' ^ XOR_KEY, 'b' ^ XOR_KEY, 'e' ^ XOR_KEY,
        'a' ^ XOR_KEY, 'c' ^ XOR_KEY, 'o' ^ XOR_KEY, 'n' ^ XOR_KEY,
        '\0'
    };

    printf("[*] Task 1: C2 URL\n");
    printf("    Obfuscated: ");
    for (int i = 0; i < 10; i++) {
        printf("%02X ", (unsigned char)c2Url[i]);
    }
    printf("...\n");

    DeobfuscateString(c2Url, sizeof(c2Url) - 1);
    printf("    Deobfuscated: %s\n\n", c2Url);

    // Task 2: Obfuscate "cmd.exe"
    CHAR cmdExe[] = {
        'c' ^ XOR_KEY, 'm' ^ XOR_KEY, 'd' ^ XOR_KEY, '.' ^ XOR_KEY,
        'e' ^ XOR_KEY, 'x' ^ XOR_KEY, 'e' ^ XOR_KEY, '\0'
    };

    printf("[*] Task 2: cmd.exe\n");
    printf("    Obfuscated: ");
    for (int i = 0; cmdExe[i] != '\0'; i++) {
        printf("%02X ", (unsigned char)cmdExe[i]);
    }
    printf("\n");

    DeobfuscateString(cmdExe, 7);
    printf("    Deobfuscated: %s\n\n", cmdExe);

    // Task 3: Obfuscate "powershell.exe"
    CHAR psExe[] = {
        'p' ^ XOR_KEY, 'o' ^ XOR_KEY, 'w' ^ XOR_KEY, 'e' ^ XOR_KEY,
        'r' ^ XOR_KEY, 's' ^ XOR_KEY, 'h' ^ XOR_KEY, 'e' ^ XOR_KEY,
        'l' ^ XOR_KEY, 'l' ^ XOR_KEY, '.' ^ XOR_KEY, 'e' ^ XOR_KEY,
        'x' ^ XOR_KEY, 'e' ^ XOR_KEY, '\0'
    };

    printf("[*] Task 3: powershell.exe\n");
    DeobfuscateString(psExe, 14);
    printf("    Deobfuscated: %s\n\n", psExe);

    // BONUS: Multi-byte XOR
    printf("[*] BONUS: Multi-byte XOR\n");

    CHAR multiKey[] = {0x12, 0x34, 0x56, 0x78};
    SIZE_T keyLen = sizeof(multiKey);

    CHAR secret[] = "ADMIN_PASSWORD_123";
    SIZE_T secretLen = strlen(secret);

    printf("    Original: %s\n", secret);

    // Encrypt
    for (SIZE_T i = 0; i < secretLen; i++) {
        secret[i] ^= multiKey[i % keyLen];
    }

    printf("    Encrypted: ");
    for (SIZE_T i = 0; i < secretLen; i++) {
        printf("%02X ", (unsigned char)secret[i]);
    }
    printf("\n");

    // Decrypt
    for (SIZE_T i = 0; i < secretLen; i++) {
        secret[i] ^= multiKey[i % keyLen];
    }

    printf("    Decrypted: %s\n\n", secret);

    printf("[+] All strings successfully obfuscated!\n");
    printf("[*] Verify with: strings ex01-solution.exe | grep -i http\n");
    printf("    (Should return nothing)\n\n");

    return 0;
}

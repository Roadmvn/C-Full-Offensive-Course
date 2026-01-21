/*
 * Exercise 01: Obfuscate Strings
 *
 * TASK:
 * 1. Obfuscate the C2 URL at compile time
 * 2. Obfuscate "cmd.exe" string
 * 3. Deobfuscate both at runtime
 * 4. Print the deobfuscated strings
 *
 * REQUIREMENTS:
 * - Use XOR obfuscation with key 0x42
 * - Strings should not appear in binary (use strings.exe to check)
 * - Implement both character-by-character and array methods
 */

#include <windows.h>
#include <stdio.h>

#define XOR_KEY 0x42

// TODO: Implement XOR deobfuscation function
VOID DeobfuscateString(CHAR* str, SIZE_T len) {
    // YOUR CODE HERE
    // Hint: XOR each character with XOR_KEY
}

int main(void) {
    printf("[*] Exercise 01: String Obfuscation\n\n");

    // TODO: Obfuscate C2 URL "http://192.168.1.100:8080/beacon"
    // Method 1: Character-by-character array
    CHAR c2Url[] = {
        // YOUR CODE HERE
        // Example: 'h' ^ XOR_KEY, 't' ^ XOR_KEY, ...
        '\0'
    };

    printf("[*] Task 1: Deobfuscate C2 URL\n");
    printf("    Before: ");
    for (int i = 0; i < 10; i++) {
        printf("%02X ", (unsigned char)c2Url[i]);
    }
    printf("...\n");

    // TODO: Deobfuscate the URL
    // YOUR CODE HERE

    printf("    After:  %s\n\n", c2Url);

    // TODO: Obfuscate "cmd.exe"
    printf("[*] Task 2: Deobfuscate cmd.exe\n");
    CHAR cmdExe[] = {
        // YOUR CODE HERE
        '\0'
    };

    printf("    Before: ");
    for (int i = 0; cmdExe[i] != '\0'; i++) {
        printf("%02X ", (unsigned char)cmdExe[i]);
    }
    printf("\n");

    // TODO: Deobfuscate cmd.exe
    // YOUR CODE HERE

    printf("    After:  %s\n\n", cmdExe);

    // TODO: Obfuscate "powershell.exe"
    printf("[*] Task 3: Deobfuscate powershell.exe\n");
    CHAR psExe[] = {
        // YOUR CODE HERE
        '\0'
    };

    // TODO: Deobfuscate and print
    // YOUR CODE HERE

    printf("    Result: %s\n\n", psExe);

    // Verification
    printf("[*] Verification:\n");
    printf("    Run: strings ex01-obfuscate-strings.exe\n");
    printf("    The strings should NOT appear in plain text!\n\n");

    // Bonus: Multi-byte XOR key
    printf("[*] BONUS: Multi-byte XOR\n");
    // TODO: Implement multi-byte XOR with key {0x12, 0x34, 0x56, 0x78}
    // YOUR CODE HERE

    return 0;
}

/*
 * SOLUTION APPROACH:
 *
 * 1. For each string, calculate XOR at compile time:
 *    CHAR str[] = {'h' ^ 0x42, 't' ^ 0x42, ...};
 *
 * 2. Create deobfuscation function:
 *    void DeobfuscateString(char* str, size_t len) {
 *        for (size_t i = 0; i < len; i++) {
 *            str[i] ^= 0x42;
 *        }
 *    }
 *
 * 3. Call deobfuscation before use:
 *    DeobfuscateString(str, strlen_without_null);
 *
 * 4. Verify with: strings ex01.exe | grep -i "http"
 *    Should return nothing!
 */

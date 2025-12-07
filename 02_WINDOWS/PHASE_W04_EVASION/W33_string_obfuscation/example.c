/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 29 : Code Obfuscation Techniques
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. STRING OBFUSCATION - XOR encryption
#define XOR_KEY 0x42
void xor_decrypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

// Strings obfusquées (encrypted at compile-time conceptuellement)
unsigned char obf_cmd[] = {0x21, 0x2F, 0x24, 0x00, 0x27, 0x38, 0x27};  // "cmd.exe" ^ 0x42

// 2. CONTROL FLOW FLATTENING - State machine
void control_flow_flat_demo() {
    int state = 0;
    int result = 0;

    printf("[*] Control Flow Flattening Demo\n");

    while (state != 99) {
        switch(state) {
            case 0:
                printf("[+] State 0: Init\n");
                result = 10;
                state = 1;
                break;
            case 1:
                printf("[+] State 1: Process\n");
                result *= 2;
                state = 2;
                break;
            case 2:
                printf("[+] State 2: Finalize\n");
                result += 5;
                state = 99;
                break;
            default:
                state = 99;
        }
    }

    printf("[+] Result: %d\n", result);
}

// 3. OPAQUE PREDICATES - Always true/false conditions
void opaque_predicates_demo() {
    int x = rand();

    printf("\n[*] Opaque Predicates Demo\n");

    // Toujours vrai : (x*x) >= 0
    if ((x * x) >= 0) {
        printf("[+] Real code executed (always true predicate)\n");
    } else {
        printf("[-] Dead code (never executed)\n");
    }

    // Toujours faux : (x*(x+1)) % 2 == 1
    if ((x * (x + 1)) % 2 == 1) {
        printf("[-] Dead code (never executed)\n");
    } else {
        printf("[+] Real code executed (always false predicate)\n");
    }
}

// 4. JUNK CODE INSERTION
void junk_code_demo() {
    printf("\n[*] Junk Code Demo\n");

    // Vrai calcul
    int result = 5 + 3;

    // Junk code (calculs inutiles)
    volatile int junk1 = rand() % 100;
    volatile int junk2 = junk1 * 42 / 42;
    volatile int junk3 = (junk2 << 2) >> 2;

    // Plus de vrai code
    result *= 2;

    // Plus de junk
    if (0) {
        printf("Dead code\n");
        exit(1);
    }

    printf("[+] Real result: %d\n", result);
    printf("[!] Binary contains lots of junk instructions\n");
}

// 5. INSTRUCTION SUBSTITUTION
int add_obfuscated(int a, int b) {
    // Au lieu de: return a + b;
    // Utiliser équivalent complexe
    return (a - (-b));
}

int multiply_obfuscated(int a, int b) {
    // Au lieu de: return a * b;
    int result = 0;
    for (int i = 0; i < b; i++) {
        result = add_obfuscated(result, a);
    }
    return result;
}

void instruction_substitution_demo() {
    printf("\n[*] Instruction Substitution Demo\n");
    printf("[+] 5 + 3 = %d (obfuscated add)\n", add_obfuscated(5, 3));
    printf("[+] 4 * 7 = %d (obfuscated multiply)\n", multiply_obfuscated(4, 7));
}

// 6. DEAD CODE avec fausses fonctionnalités
void fake_function_1() {
    printf("Fake crypto init\n");
}

void fake_function_2() {
    printf("Fake network conn\n");
}

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques d'obfuscation malware dev\n");
    printf("   Usage éducatif uniquement.\n\n");

    // String obfuscation test
    printf("[*] String Obfuscation Demo\n");
    xor_decrypt(obf_cmd, sizeof(obf_cmd) - 1);
    printf("[+] Decrypted string: %s\n", obf_cmd);

    control_flow_flat_demo();
    opaque_predicates_demo();
    junk_code_demo();
    instruction_substitution_demo();

    printf("\n[!] NOTES:\n");
    printf("- Strings chiffrées invisibles dans 'strings' command\n");
    printf("- Control flow compliqué pour IDA/Ghidra\n");
    printf("- Junk code augmente taille binaire\n");
    printf("- Opaque predicates trompent analyse statique\n");

    return 0;
}

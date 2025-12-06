#include <stdio.h>
#include <string.h>

void gadget_1() { printf("Gadget 1\n"); }
void gadget_2() { printf("Gadget 2\n"); }
void win() { printf("WIN!\n"); }

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable(argv[1]);
    }
    return 0;
}

/*
 * ARM64 ROP:
 * 1. Compiler: clang -arch arm64 example.c -o example
 * 2. Trouver gadgets: ROPgadget --binary example
 * 3. Chain:
 *    - Overflow buffer
 *    - Contrôler x30 (LR)
 *    - Chain gadgets
 * 
 * Gadgets utiles:
 * - ldp x29, x30, [sp], #16; ret
 * - mov x0, x1; ret
 * - blr x8
 */

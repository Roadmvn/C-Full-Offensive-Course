#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

void demo_signed_overflow() {
    printf("=== SIGNED OVERFLOW ===\n");
    int max = INT_MAX;
    printf("INT_MAX = %d\n", max);
    printf("INT_MAX + 1 = %d (overflow!)\n", max + 1);
    
    int min = INT_MIN;
    printf("INT_MIN = %d\n", min);
    printf("INT_MIN - 1 = %d (underflow!)\n", min - 1);
}

void demo_unsigned_overflow() {
    printf("\n=== UNSIGNED OVERFLOW ===\n");
    unsigned int max = UINT_MAX;
    printf("UINT_MAX = %u\n", max);
    printf("UINT_MAX + 1 = %u (wraparound to 0)\n", max + 1);
    
    unsigned int zero = 0;
    printf("0 - 1 = %u (wraparound to MAX)\n", zero - 1);
}

void demo_truncation() {
    printf("\n=== TRUNCATION ===\n");
    long long big = 0x1FFFFFFFF;
    int small = (int)big;
    printf("0x1FFFFFFFF truncated to int = 0x%X (%d)\n", small, small);
}

// Fonction vulnérable
void *vulnerable_malloc(unsigned int count, unsigned int size) {
    unsigned int total = count * size;  // Peut overflow!
    printf("Allocating %u * %u = %u bytes\n", count, size, total);
    return malloc(total);
}

// Exploitation
void exploit_malloc() {
    printf("\n=== MALLOC EXPLOIT ===\n");
    
    // Calcul normal
    void *buf1 = vulnerable_malloc(100, 100);  // 10000 bytes
    printf("Normal alloc: %p\n", buf1);
    free(buf1);
    
    // Exploitation: overflow pour petit malloc
    unsigned int count = UINT_MAX / 4 + 2;  // Cause overflow
    void *buf2 = vulnerable_malloc(count, 4);
    printf("Exploit alloc: %p (très petit!)\n", buf2);
    free(buf2);
}

int main() {
    demo_signed_overflow();
    demo_unsigned_overflow();
    demo_truncation();
    exploit_malloc();
    return 0;
}

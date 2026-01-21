/**
 * Module : Assembleur Inline - Exemples pratiques
 * 
 * Compilation : gcc -o example example.c -masm=intel
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Exemple 1 : Opérations basiques
void demo_basic(void) {
    printf("\n=== Inline ASM Basique ===\n");
    
    int a = 10, b = 20, sum;
    
    __asm__(
        "add %0, %2"
        : "=r" (sum)
        : "0" (a), "r" (b)
    );
    
    printf("%d + %d = %d\n", a, b, sum);
}

// Exemple 2 : Lecture TSC
uint64_t read_tsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__(
        "rdtsc"
        : "=a" (lo), "=d" (hi)
    );
    return ((uint64_t)hi << 32) | lo;
}

void demo_tsc(void) {
    printf("\n=== Time Stamp Counter ===\n");
    uint64_t start = read_tsc();
    
    // Faire quelque chose
    for (volatile int i = 0; i < 1000000; i++);
    
    uint64_t end = read_tsc();
    printf("Cycles: %lu\n", end - start);
}

// Exemple 3 : CPUID
void demo_cpuid(void) {
    printf("\n=== CPUID ===\n");
    
    uint32_t eax, ebx, ecx, edx;
    char vendor[13] = {0};
    
    __asm__ __volatile__(
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (0)
    );
    
    *(uint32_t*)&vendor[0] = ebx;
    *(uint32_t*)&vendor[4] = edx;
    *(uint32_t*)&vendor[8] = ecx;
    
    printf("CPU Vendor: %s\n", vendor);
    printf("Max CPUID: %u\n", eax);
}

// Exemple 4 : XOR encoder
void xor_encode(unsigned char *data, size_t len, unsigned char key) {
    __asm__ __volatile__(
        "1:\n\t"
        "test %1, %1\n\t"
        "jz 2f\n\t"
        "xor byte ptr [%0], %2\n\t"
        "inc %0\n\t"
        "dec %1\n\t"
        "jmp 1b\n\t"
        "2:"
        : "+r" (data), "+r" (len)
        : "r" (key)
        : "cc", "memory"
    );
}

void demo_xor(void) {
    printf("\n=== XOR Encoder ===\n");
    
    char msg[] = "Secret Message!";
    printf("Original: %s\n", msg);
    
    xor_encode((unsigned char*)msg, strlen(msg), 0x42);
    printf("Encoded (hex): ");
    for (size_t i = 0; i < strlen("Secret Message!"); i++)
        printf("%02x ", (unsigned char)msg[i]);
    printf("\n");
    
    xor_encode((unsigned char*)msg, strlen(msg), 0x42);
    printf("Decoded: %s\n", msg);
}

// Exemple 5 : Syscall direct
void demo_syscall(void) {
    printf("\n=== Direct Syscall ===\n");
    
    const char *msg = "Hello from syscall!\n";
    long ret;
    
    __asm__ __volatile__(
        "syscall"
        : "=a" (ret)
        : "a" ((long)1), "D" ((long)1), "S" (msg), "d" ((long)20)
        : "rcx", "r11", "memory"
    );
    
    printf("Syscall returned: %ld\n", ret);
}

int main(void) {
    printf("=== INLINE ASM DEMO ===\n");
    
    demo_basic();
    demo_tsc();
    demo_cpuid();
    demo_xor();
    demo_syscall();
    
    return 0;
}

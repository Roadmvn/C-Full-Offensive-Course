#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int main() {
    printf("=== SHELLCODE TESTER ===\n\n");
    
    // Shellcode : exit(42)
    unsigned char shellcode[] = 
        "\x40\x05\x80\xD2"      // mov x0, #42
        "\x21\x00\x80\xD2"      // mov x16, #1 (exit)
        "\x01\x10\x00\xD4";     // svc #0x80
    
    size_t len = sizeof(shellcode) - 1;
    
    printf("Shellcode length: %zu bytes\n", len);
    printf("Shellcode hex: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\n\n");
    
    // Allouer mémoire exécutable
    void *mem = mmap(NULL, len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    printf("Allocated executable memory at: %p\n", mem);
    
    // Copier shellcode
    memcpy(mem, shellcode, len);
    
    printf("Executing shellcode...\n");
    
    // Exécuter
    void (*func)() = (void(*)())mem;
    func();
    
    // Ne sera jamais atteint (exit dans shellcode)
    printf("Should not reach here\n");
    
    return 0;
}


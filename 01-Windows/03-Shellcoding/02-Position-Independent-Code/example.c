/**
 * Position Independent Code - Démonstration
 */
#include <stdio.h>
#include <string.h>

// Shellcode PIC qui affiche un message
unsigned char shellcode[] = 
    "\xeb\x1e"                  // jmp call_shellcode
    "\x5e"                      // pop rsi (adresse du message)
    "\x48\x31\xc0"              // xor rax, rax
    "\xb0\x01"                  // mov al, 1 (write)
    "\x48\x89\xc7"              // mov rdi, rax (fd=1)
    "\x48\x31\xd2"              // xor rdx, rdx
    "\xb2\x0c"                  // mov dl, 12 (len)
    "\x0f\x05"                  // syscall
    "\x48\x31\xc0"              // xor rax, rax
    "\xb0\x3c"                  // mov al, 60 (exit)
    "\x48\x31\xff"              // xor rdi, rdi
    "\x0f\x05"                  // syscall
    "\xe8\xdd\xff\xff\xff"      // call shellcode
    "Hello PIC!\n";

int main(void) {
    printf("Shellcode PIC size: %zu bytes\n", sizeof(shellcode) - 1);
    printf("Le shellcode peut être chargé à n'importe quelle adresse\n");
    
    // Pour exécuter (nécessite mémoire exécutable):
    // void (*func)() = (void(*)())shellcode;
    // func();
    
    return 0;
}

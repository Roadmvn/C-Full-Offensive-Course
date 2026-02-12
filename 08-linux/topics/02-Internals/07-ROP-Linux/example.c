/*
 * OBJECTIF  : Comprendre le Return-Oriented Programming (ROP) sous Linux
 * PREREQUIS : Bases C, stack overflow, assembleur x86_64
 * COMPILE   : gcc -o example example.c -fno-stack-protector -no-pie
 *
 * Ce programme demontre les concepts de ROP : gadgets, chaines ROP,
 * et comment contourner NX (non-executable stack) en reutilisant
 * du code existant. Demonstration pedagogique sans exploitation reelle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * Etape 1 : Pourquoi le ROP ?
 * NX (No-Execute) empeche l'execution de shellcode sur la stack.
 * ROP reutilise des fragments de code existant ("gadgets").
 */
static void explain_rop(void) {
    printf("[*] Etape 1 : Pourquoi le ROP ?\n\n");

    printf("    Probleme : La stack n'est plus executable (NX/DEP)\n");
    printf("    Solution : Reutiliser du code existant en memoire\n\n");

    printf("    Stack classique vs ROP :\n\n");
    printf("    SHELLCODE (ancien)        ROP (moderne)\n");
    printf("    ┌───────────────┐         ┌───────────────┐\n");
    printf("    │  NOP sled     │         │  gadget addr1 │ -> pop rdi; ret\n");
    printf("    │  shellcode    │         │  argument1    │ -> \"/bin/sh\"\n");
    printf("    │  ret addr     │         │  gadget addr2 │ -> pop rax; ret\n");
    printf("    │  (-> stack)   │         │  argument2    │ -> 59 (execve)\n");
    printf("    └───────────────┘         │  gadget addr3 │ -> syscall; ret\n");
    printf("    NX bloque !               └───────────────┘\n");
    printf("                              Fonctionne avec NX !\n\n");
}

/*
 * Etape 2 : Qu'est-ce qu'un gadget ?
 * Un gadget = une suite d'instructions terminee par RET
 * Exemples : "pop rdi; ret", "xor rax, rax; ret", etc.
 */

/* Fonctions qui contiennent des "gadgets" simulees */
static void gadget_pop_rdi(void) {
    /* En vrai, ce serait dans la libc ou le binaire */
    printf("      [gadget] pop rdi; ret\n");
}

static void gadget_pop_rsi(void) {
    printf("      [gadget] pop rsi; ret\n");
}

static void gadget_syscall(void) {
    printf("      [gadget] syscall; ret\n");
}

static void explain_gadgets(void) {
    printf("[*] Etape 2 : Les gadgets ROP\n\n");

    printf("    Un gadget est un bout de code se terminant par RET.\n");
    printf("    On les enchaine pour construire un programme complet.\n\n");

    printf("    Gadgets courants :\n");
    printf("      pop rdi; ret         -> Charger une valeur dans RDI\n");
    printf("      pop rsi; ret         -> Charger une valeur dans RSI\n");
    printf("      pop rax; ret         -> Charger le numero de syscall\n");
    printf("      xor rax, rax; ret    -> Mettre RAX a 0\n");
    printf("      syscall; ret         -> Executer le syscall\n");
    printf("      ret                  -> NOP slide ROP\n\n");

    printf("    Outils pour trouver des gadgets :\n");
    printf("      ROPgadget --binary ./vuln\n");
    printf("      ropper -f ./vuln\n\n");
}

/*
 * Etape 3 : Simuler une chaine ROP
 * On simule l'execution d'une chaine ROP pour execve("/bin/sh")
 */

/* Registres simules */
static struct {
    unsigned long rax, rdi, rsi, rdx, rip, rsp;
} cpu;

/* Stack simulee */
static unsigned long sim_stack[32];
static int sp;

/* Executer un gadget simule */
static void execute_gadget(const char *name) {
    if (strcmp(name, "pop_rdi_ret") == 0) {
        cpu.rdi = sim_stack[sp++];  /* pop rdi */
        cpu.rip = sim_stack[sp++];  /* ret */
        printf("      pop rdi (= 0x%lx); ret\n", cpu.rdi);
    } else if (strcmp(name, "pop_rsi_ret") == 0) {
        cpu.rsi = sim_stack[sp++];
        cpu.rip = sim_stack[sp++];
        printf("      pop rsi (= 0x%lx); ret\n", cpu.rsi);
    } else if (strcmp(name, "pop_rdx_ret") == 0) {
        cpu.rdx = sim_stack[sp++];
        cpu.rip = sim_stack[sp++];
        printf("      pop rdx (= 0x%lx); ret\n", cpu.rdx);
    } else if (strcmp(name, "pop_rax_ret") == 0) {
        cpu.rax = sim_stack[sp++];
        cpu.rip = sim_stack[sp++];
        printf("      pop rax (= 0x%lx = %lu); ret\n", cpu.rax, cpu.rax);
    } else if (strcmp(name, "syscall_ret") == 0) {
        printf("      syscall (rax=%lu, rdi=0x%lx, rsi=0x%lx, rdx=0x%lx)\n",
               cpu.rax, cpu.rdi, cpu.rsi, cpu.rdx);
        if (cpu.rax == 59) {
            printf("      -> execve(\"/bin/sh\", NULL, NULL)\n");
        }
    }
}

static void demo_rop_chain(void) {
    printf("[*] Etape 3 : Simulation d'une chaine ROP\n\n");

    printf("    Objectif : construire execve(\"/bin/sh\", NULL, NULL)\n");
    printf("    Syscall execve = 59, rdi=\"/bin/sh\", rsi=NULL, rdx=NULL\n\n");

    /* Adresses fictives de gadgets */
    unsigned long GADGET_POP_RDI  = 0x400123;
    unsigned long GADGET_POP_RSI  = 0x400456;
    unsigned long GADGET_POP_RDX  = 0x400789;
    unsigned long GADGET_POP_RAX  = 0x400abc;
    unsigned long GADGET_SYSCALL  = 0x400def;
    unsigned long BIN_SH_ADDR     = 0x601000;  /* Adresse de "/bin/sh" */

    /* Construire la chaine ROP sur la stack */
    printf("    Chaine ROP sur la stack :\n");
    printf("    ┌───────────────────────────────────┐\n");
    printf("    │ 0x%06lx  <- pop rdi; ret          │\n", GADGET_POP_RDI);
    printf("    │ 0x%06lx  <- addr \"/bin/sh\"        │\n", BIN_SH_ADDR);
    printf("    │ 0x%06lx  <- pop rsi; ret          │\n", GADGET_POP_RSI);
    printf("    │ 0x000000  <- NULL                  │\n");
    printf("    │ 0x%06lx  <- pop rdx; ret          │\n", GADGET_POP_RDX);
    printf("    │ 0x000000  <- NULL                  │\n");
    printf("    │ 0x%06lx  <- pop rax; ret          │\n", GADGET_POP_RAX);
    printf("    │ 0x00003b  <- 59 (execve)           │\n");
    printf("    │ 0x%06lx  <- syscall; ret          │\n", GADGET_SYSCALL);
    printf("    └───────────────────────────────────┘\n\n");

    /* Simuler l'execution */
    printf("    Execution simulee :\n");

    sp = 0;
    /* pop rdi; ret -> charge l'adresse de "/bin/sh" */
    sim_stack[sp++] = BIN_SH_ADDR;  /* valeur pour pop rdi */
    sim_stack[sp++] = GADGET_POP_RSI;  /* adresse de retour */
    sp = 0;
    execute_gadget("pop_rdi_ret");

    sp = 0;
    sim_stack[sp++] = 0;  /* NULL pour pop rsi */
    sim_stack[sp++] = GADGET_POP_RDX;
    sp = 0;
    execute_gadget("pop_rsi_ret");

    sp = 0;
    sim_stack[sp++] = 0;  /* NULL pour pop rdx */
    sim_stack[sp++] = GADGET_POP_RAX;
    sp = 0;
    execute_gadget("pop_rdx_ret");

    sp = 0;
    sim_stack[sp++] = 59;  /* execve pour pop rax */
    sim_stack[sp++] = GADGET_SYSCALL;
    sp = 0;
    execute_gadget("pop_rax_ret");

    execute_gadget("syscall_ret");
    printf("\n");
}

/*
 * Etape 4 : Programme vulnerable pour pratiquer
 * Compile avec : gcc -fno-stack-protector -no-pie -o vuln vuln.c
 */
static void show_vulnerable_program(void) {
    printf("[*] Etape 4 : Exemple de programme vulnerable au ROP\n\n");

    printf("    // vuln.c - compile sans protections\n");
    printf("    #include <stdio.h>\n");
    printf("    #include <string.h>\n\n");
    printf("    void vulnerable(void) {\n");
    printf("        char buf[64];\n");
    printf("        printf(\"Input: \");\n");
    printf("        gets(buf);  // Buffer overflow !\n");
    printf("    }\n\n");
    printf("    int main(void) {\n");
    printf("        vulnerable();\n");
    printf("        return 0;\n");
    printf("    }\n\n");

    printf("    Compilation : gcc -fno-stack-protector -no-pie -o vuln vuln.c\n");
    printf("    Trouver gadgets : ROPgadget --binary ./vuln\n");
    printf("    ASLR desactive  : echo 0 > /proc/sys/kernel/randomize_va_space\n\n");
}

/*
 * Etape 5 : Protections et contournements
 */
static void explain_protections(void) {
    printf("[*] Etape 5 : Protections et contournements\n\n");

    printf("    Protection        | Effet                  | Bypass\n");
    printf("    ──────────────────|────────────────────────|──────────────────\n");
    printf("    NX/DEP            | Stack non-executable   | ROP (ce module)\n");
    printf("    ASLR              | Adresses aleatoires    | Info leak, ret2plt\n");
    printf("    Stack Canary      | Detecte stack overflow | Canary leak, format string\n");
    printf("    PIE               | Code a adresse random  | Info leak\n");
    printf("    RELRO             | GOT en lecture seule   | ROP direct\n\n");

    printf("    Verifier les protections : checksec --file=./binary\n\n");

    /* Unused gadget function refs to avoid warnings */
    (void)gadget_pop_rdi;
    (void)gadget_pop_rsi;
    (void)gadget_syscall;
}

int main(void) {
    printf("[*] Demo : Return-Oriented Programming (ROP) Linux\n\n");

    explain_rop();
    explain_gadgets();
    demo_rop_chain();
    show_vulnerable_program();
    explain_protections();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

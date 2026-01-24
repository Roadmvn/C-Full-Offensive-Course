# Solutions : Opérations sur la Stack x64

## Solution Exercice 1 : PUSH/POP manuel

```c
#include <stdio.h>
#include <stdint.h>

// Variable pour stocker RSP simulé (en vrai, on manipule le vrai RSP)
void mon_push(uint64_t valeur) {
    __asm__ __volatile__ (
        "sub rsp, 8\n\t"        // Décrémenter RSP
        "mov [rsp], %0"         // Stocker la valeur
        :
        : "r" (valeur)
        : "memory"
    );
}

uint64_t mon_pop(void) {
    uint64_t valeur;
    __asm__ __volatile__ (
        "mov %0, [rsp]\n\t"     // Charger la valeur
        "add rsp, 8"            // Incrémenter RSP
        : "=r" (valeur)
        :
        : "memory"
    );
    return valeur;
}

int main() {
    printf("Test PUSH/POP manuel:\n");
    
    mon_push(0xAAAA);
    printf("Pushed 0xAAAA\n");
    
    mon_push(0xBBBB);
    printf("Pushed 0xBBBB\n");
    
    printf("Pop: 0x%lx (attendu: 0xBBBB)\n", mon_pop());
    printf("Pop: 0x%lx (attendu: 0xAAAA)\n", mon_pop());
    
    return 0;
}
```

---

## Solution Exercice 2 : Countdown récursif

```c
#include <stdio.h>

void countdown(int n) {
    if (n <= 0) {
        printf("Fin!\n");
        return;
    }
    
    // Sauvegarder n sur la stack (le compilateur le fait automatiquement,
    // mais on peut le faire explicitement)
    __asm__ __volatile__ (
        "push %0"               // Sauvegarder n
        :
        : "r" ((uint64_t)n)
        : "memory"
    );
    
    printf("%d\n", n);
    countdown(n - 1);
    
    // Restaurer (même si on ne l'utilise plus)
    uint64_t saved_n;
    __asm__ __volatile__ (
        "pop %0"
        : "=r" (saved_n)
        :
        : "memory"
    );
}

// Version plus simple sans asm (la récursion utilise naturellement la stack)
void countdown_simple(int n) {
    if (n <= 0) {
        printf("Fin!\n");
        return;
    }
    printf("%d\n", n);
    countdown_simple(n - 1);
}

int main() {
    printf("Countdown depuis 5:\n");
    countdown_simple(5);
    return 0;
}
```

---

## Solution Exercice 3 : Stack Frame Inspector

```c
#include <stdio.h>
#include <stdint.h>

void inspect_stack_frame(void) {
    void* rbp_val;
    void* rsp_val;
    void* ret_addr;
    void* saved_rbp;
    
    __asm__ __volatile__ (
        "mov %0, rbp\n\t"           // RBP actuel
        "mov %1, rsp\n\t"           // RSP actuel
        "mov rax, [rbp + 8]\n\t"    // Return address (au-dessus de RBP)
        "mov %2, rax\n\t"
        "mov rax, [rbp]\n\t"        // Saved RBP (à RBP)
        "mov %3, rax"
        : "=r" (rbp_val), "=r" (rsp_val), "=r" (ret_addr), "=r" (saved_rbp)
        :
        : "rax"
    );
    
    printf("=== Stack Frame Inspection ===\n");
    printf("RBP (frame pointer)  : %p\n", rbp_val);
    printf("RSP (stack pointer)  : %p\n", rsp_val);
    printf("Return Address       : %p\n", ret_addr);
    printf("Saved RBP (caller)   : %p\n", saved_rbp);
    printf("Frame size (RBP-RSP) : %ld bytes\n", 
           (char*)rbp_val - (char*)rsp_val);
    
    // Afficher quelques valeurs sur la stack
    printf("\nContenu du stack frame:\n");
    uint64_t* stack = (uint64_t*)rsp_val;
    for (int i = 0; i < 8; i++) {
        char* label = "";
        if (&stack[i] == (uint64_t*)rbp_val) label = " <- RBP";
        if (stack[i] == (uint64_t)ret_addr) label = " <- Return addr";
        printf("  [RSP+%2d] %p : 0x%016lx%s\n", 
               i*8, &stack[i], stack[i], label);
    }
}

int main() {
    inspect_stack_frame();
    return 0;
}
```

---

## Solution Exercice 4 : Fonction avec prologue manuel

```c
#include <stdio.h>
#include <stdint.h>

int calcul_manuel(int a, int b) {
    int resultat;
    
    __asm__ __volatile__ (
        // === PROLOGUE ===
        "push rbp\n\t"
        "mov rbp, rsp\n\t"
        "sub rsp, 16\n\t"           // Espace pour variables locales
        
        // Sauvegarder les arguments sur la stack locale
        "mov [rbp-4], %1\n\t"       // a à [rbp-4]
        "mov [rbp-8], %2\n\t"       // b à [rbp-8]
        
        // Calcul: resultat = a * 2 + b
        "mov eax, [rbp-4]\n\t"      // EAX = a
        "shl eax, 1\n\t"            // EAX = a * 2
        "add eax, [rbp-8]\n\t"      // EAX = a * 2 + b
        "mov [rbp-12], eax\n\t"     // Stocker résultat
        
        // Charger le résultat pour le retour
        "mov %0, eax\n\t"
        
        // === ÉPILOGUE ===
        "mov rsp, rbp\n\t"
        "pop rbp"
        : "=r" (resultat)
        : "r" (a), "r" (b)
        : "rax", "memory"
    );
    
    return resultat;
}

int main() {
    int a = 5, b = 3;
    int result = calcul_manuel(a, b);
    printf("calcul_manuel(%d, %d) = %d\n", a, b, result);
    printf("Attendu: %d * 2 + %d = %d\n", a, b, a * 2 + b);
    return 0;
}
```

---

## Solution Exercice 5 : Détection de Stack Canary

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void detect_canary(void) {
    char buffer[64];
    memset(buffer, 'A', 64);
    
    void* rbp;
    uint64_t* stack_ptr;
    
    __asm__ __volatile__ (
        "mov %0, rbp"
        : "=r" (rbp)
    );
    
    printf("=== Détection de Stack Canary ===\n");
    printf("Adresse buffer : %p\n", buffer);
    printf("Adresse RBP    : %p\n", rbp);
    printf("Distance       : %ld bytes\n", (char*)rbp - buffer);
    
    // Scanner la zone entre buffer et RBP pour trouver le canary
    // Le canary est généralement juste avant saved RBP
    printf("\nRecherche du canary entre buffer et RBP:\n");
    
    stack_ptr = (uint64_t*)(buffer + 64);  // Juste après le buffer
    
    while ((void*)stack_ptr < rbp) {
        uint64_t val = *stack_ptr;
        
        // Heuristique : le canary termine souvent par 0x00
        // et contient des valeurs "aléatoires"
        if ((val & 0xFF) == 0x00 && val != 0) {
            printf("  [%p] = 0x%016lx <- Canary potentiel!\n", 
                   stack_ptr, val);
        } else {
            printf("  [%p] = 0x%016lx\n", stack_ptr, val);
        }
        stack_ptr++;
    }
    
    printf("  [%p] = 0x%016lx <- Saved RBP\n", rbp, *(uint64_t*)rbp);
    printf("  [%p] = 0x%016lx <- Return Address\n", 
           (char*)rbp + 8, *((uint64_t*)rbp + 1));
}

int main() {
    detect_canary();
    return 0;
}

// Compiler avec: gcc -fstack-protector-all -o detect detect.c -masm=intel
```

---

## Solution Exercice 6 : Explication ROP Chain

```c
#include <stdio.h>
#include <stdint.h>

struct rop_chain {
    uint64_t gadget1;   // pop rdi; ret
    uint64_t arg1;      // /bin/sh
    uint64_t gadget2;   // pop rsi; ret
    uint64_t arg2;      // NULL (argv)
    uint64_t gadget3;   // pop rdx; ret
    uint64_t arg3;      // NULL (envp)
    uint64_t gadget4;   // pop rax; ret
    uint64_t syscall_nr;// 59 (execve)
    uint64_t syscall;   // syscall; ret
};

void explain_rop_chain(struct rop_chain *chain) {
    printf("=== Analyse de la ROP Chain ===\n\n");
    
    printf("Objectif : Exécuter execve(\"/bin/sh\", NULL, NULL)\n\n");
    
    printf("Étape 1 : [%p] pop rdi; ret\n", (void*)chain->gadget1);
    printf("          RDI = 0x%lx (adresse de \"/bin/sh\")\n", chain->arg1);
    printf("          -> Charge le 1er argument de execve\n\n");
    
    printf("Étape 2 : [%p] pop rsi; ret\n", (void*)chain->gadget2);
    printf("          RSI = 0x%lx (NULL)\n", chain->arg2);
    printf("          -> Charge le 2e argument (argv = NULL)\n\n");
    
    printf("Étape 3 : [%p] pop rdx; ret\n", (void*)chain->gadget3);
    printf("          RDX = 0x%lx (NULL)\n", chain->arg3);
    printf("          -> Charge le 3e argument (envp = NULL)\n\n");
    
    printf("Étape 4 : [%p] pop rax; ret\n", (void*)chain->gadget4);
    printf("          RAX = %lu (numéro syscall execve)\n", chain->syscall_nr);
    printf("          -> Configure le numéro de syscall\n\n");
    
    printf("Étape 5 : [%p] syscall\n", (void*)chain->syscall);
    printf("          -> Exécute execve(\"/bin/sh\", NULL, NULL)\n\n");
    
    printf("Résultat : Shell interactif!\n");
}

int main() {
    // Exemple avec des adresses fictives
    struct rop_chain chain = {
        .gadget1 = 0x401234,        // pop rdi; ret
        .arg1 = 0x402000,           // adresse de "/bin/sh"
        .gadget2 = 0x401238,        // pop rsi; ret
        .arg2 = 0,                  // NULL
        .gadget3 = 0x40123c,        // pop rdx; ret
        .arg3 = 0,                  // NULL
        .gadget4 = 0x401240,        // pop rax; ret
        .syscall_nr = 59,           // execve
        .syscall = 0x401244         // syscall
    };
    
    explain_rop_chain(&chain);
    
    printf("\n=== Layout sur la stack ===\n");
    printf("RSP+0x00: 0x%016lx <- gadget1 (pop rdi; ret)\n", chain.gadget1);
    printf("RSP+0x08: 0x%016lx <- arg pour RDI\n", chain.arg1);
    printf("RSP+0x10: 0x%016lx <- gadget2 (pop rsi; ret)\n", chain.gadget2);
    printf("RSP+0x18: 0x%016lx <- arg pour RSI\n", chain.arg2);
    printf("RSP+0x20: 0x%016lx <- gadget3 (pop rdx; ret)\n", chain.gadget3);
    printf("RSP+0x28: 0x%016lx <- arg pour RDX\n", chain.arg3);
    printf("RSP+0x30: 0x%016lx <- gadget4 (pop rax; ret)\n", chain.gadget4);
    printf("RSP+0x38: 0x%016lx <- syscall number\n", chain.syscall_nr);
    printf("RSP+0x40: 0x%016lx <- syscall gadget\n", chain.syscall);
    
    return 0;
}
```

---

## Points clés à retenir

1. **PUSH/POP** : Comprendre les deux opérations atomiques (modification RSP + accès mémoire)

2. **Stack Frame** : Structure standard avec saved RBP, return address, variables locales

3. **Canary** : Protection contre les buffer overflows, détectable par son pattern

4. **ROP** : Technique d'exploitation qui chaîne des gadgets pour exécuter du code arbitraire

5. **Alignement** : La stack doit être alignée sur 16 bytes avant un CALL

## Commandes utiles pour l'analyse

```bash
# Voir le code assembleur généré
objdump -d -M intel executable

# Trouver des gadgets ROP
ROPgadget --binary executable

# Debugger la stack
gdb -q executable
(gdb) break main
(gdb) run
(gdb) x/20gx $rsp    # Afficher 20 qwords depuis RSP
(gdb) info frame     # Informations sur le frame
```

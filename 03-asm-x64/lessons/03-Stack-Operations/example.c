/**
 * Module : Stack Operations x64 - Exemples pratiques
 * 
 * Démonstration des opérations sur la stack et des concepts
 * d'exploitation (buffer overflow, stack frames).
 * 
 * Compilation :
 *   gcc -o example example.c -masm=intel -fno-stack-protector -z execstack
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/**
 * Exemple 1 : PUSH et POP basiques
 */
void demo_push_pop(void) {
    printf("\n=== Démo 1 : PUSH et POP ===\n");
    
    uint64_t valeur_originale = 0xDEADBEEFCAFEBABE;
    uint64_t valeur_recuperee = 0;
    void* rsp_avant;
    void* rsp_apres_push;
    void* rsp_apres_pop;
    
    __asm__ __volatile__ (
        "mov %0, rsp\n\t"           // Sauvegarder RSP initial
        "push %4\n\t"               // Push la valeur
        "mov %1, rsp\n\t"           // RSP après push
        "pop %3\n\t"                // Pop la valeur
        "mov %2, rsp"               // RSP après pop
        : "=r" (rsp_avant), "=r" (rsp_apres_push), 
          "=r" (rsp_apres_pop), "=r" (valeur_recuperee)
        : "r" (valeur_originale)
        : "memory"
    );
    
    printf("Valeur pushée : 0x%lx\n", valeur_originale);
    printf("RSP avant push : %p\n", rsp_avant);
    printf("RSP après push : %p (delta: %ld bytes)\n", 
           rsp_apres_push, (char*)rsp_avant - (char*)rsp_apres_push);
    printf("RSP après pop  : %p\n", rsp_apres_pop);
    printf("Valeur poppée  : 0x%lx\n", valeur_recuperee);
}

/**
 * Exemple 2 : Sauvegarde et restauration de registres
 */
void demo_sauvegarde_registres(void) {
    printf("\n=== Démo 2 : Sauvegarde de registres ===\n");
    
    uint64_t val_rbx = 0x1111111111111111;
    uint64_t val_r12 = 0x2222222222222222;
    uint64_t val_r13 = 0x3333333333333333;
    uint64_t resultat_rbx, resultat_r12, resultat_r13;
    
    __asm__ __volatile__ (
        // Sauvegarder les registres callee-saved
        "push rbx\n\t"
        "push r12\n\t"
        "push r13\n\t"
        
        // Charger nos valeurs
        "mov rbx, %3\n\t"
        "mov r12, %4\n\t"
        "mov r13, %5\n\t"
        
        // "Faire quelque chose" avec les registres
        "add rbx, 1\n\t"
        "add r12, 1\n\t"
        "add r13, 1\n\t"
        
        // Sauvegarder les résultats
        "mov %0, rbx\n\t"
        "mov %1, r12\n\t"
        "mov %2, r13\n\t"
        
        // Restaurer les registres originaux
        "pop r13\n\t"
        "pop r12\n\t"
        "pop rbx"
        : "=r" (resultat_rbx), "=r" (resultat_r12), "=r" (resultat_r13)
        : "r" (val_rbx), "r" (val_r12), "r" (val_r13)
        : "memory"
    );
    
    printf("RBX: 0x%lx + 1 = 0x%lx\n", val_rbx, resultat_rbx);
    printf("R12: 0x%lx + 1 = 0x%lx\n", val_r12, resultat_r12);
    printf("R13: 0x%lx + 1 = 0x%lx\n", val_r13, resultat_r13);
}

/**
 * Exemple 3 : Analyse d'un stack frame
 */
void fonction_analysee(int a, int b, int c) {
    int local1 = 100;
    int local2 = 200;
    char buffer[32];
    
    void* rbp_val;
    void* rsp_val;
    void* ret_addr;
    
    __asm__ __volatile__ (
        "mov %0, rbp\n\t"
        "mov %1, rsp\n\t"
        "mov rax, [rbp + 8]\n\t"    // Return address
        "mov %2, rax"
        : "=r" (rbp_val), "=r" (rsp_val), "=r" (ret_addr)
        :
        : "rax"
    );
    
    printf("\n=== Démo 3 : Stack Frame ===\n");
    printf("Arguments: a=%d, b=%d, c=%d\n", a, b, c);
    printf("Locales: local1=%d, local2=%d\n", local1, local2);
    printf("RBP = %p\n", rbp_val);
    printf("RSP = %p\n", rsp_val);
    printf("Return address = %p\n", ret_addr);
    printf("Taille du frame (RBP-RSP) = %ld bytes\n", 
           (char*)rbp_val - (char*)rsp_val);
    printf("Adresse buffer = %p\n", buffer);
    printf("Offset buffer depuis RBP = %ld\n", 
           (char*)rbp_val - (char*)buffer);
}

/**
 * Exemple 4 : Simulation de prologue/épilogue
 */
void demo_prologue_epilogue(void) {
    printf("\n=== Démo 4 : Prologue/Épilogue manuel ===\n");
    
    void* rbp_avant;
    void* rbp_dans_fonction;
    void* rsp_dans_fonction;
    
    __asm__ __volatile__ (
        "mov %0, rbp\n\t"           // RBP du caller
        
        // === PROLOGUE MANUEL ===
        "push rbp\n\t"              // Sauvegarder ancien RBP
        "mov rbp, rsp\n\t"          // Nouveau frame
        "sub rsp, 64\n\t"           // Allouer 64 bytes
        
        "mov %1, rbp\n\t"           // Nouveau RBP
        "mov %2, rsp\n\t"           // Nouveau RSP
        
        // === ÉPILOGUE MANUEL ===
        "mov rsp, rbp\n\t"          // Désallouer
        "pop rbp"                   // Restaurer RBP
        : "=r" (rbp_avant), "=r" (rbp_dans_fonction), "=r" (rsp_dans_fonction)
        :
        : "memory"
    );
    
    printf("RBP avant prologue : %p\n", rbp_avant);
    printf("RBP après prologue : %p\n", rbp_dans_fonction);
    printf("RSP après allocation : %p\n", rsp_dans_fonction);
    printf("Espace alloué : %ld bytes\n", 
           (char*)rbp_dans_fonction - (char*)rsp_dans_fonction);
}

/**
 * Exemple 5 : CALL et RET - comprendre les mécanismes
 */
void fonction_cible(void) {
    printf("  -> Dans fonction_cible!\n");
}

void demo_call_ret(void) {
    printf("\n=== Démo 5 : CALL et RET ===\n");
    
    void* rsp_avant_call;
    void* rsp_apres_call;
    
    printf("Adresse de fonction_cible: %p\n", (void*)fonction_cible);
    
    __asm__ __volatile__ (
        "mov %0, rsp\n\t"
        "call %2\n\t"               // Appeler fonction_cible
        "mov %1, rsp"
        : "=r" (rsp_avant_call), "=r" (rsp_apres_call)
        : "r" (fonction_cible)
        : "memory"
    );
    
    printf("RSP avant CALL : %p\n", rsp_avant_call);
    printf("RSP après RET  : %p\n", rsp_apres_call);
    printf("RSP restauré correctement : %s\n", 
           rsp_avant_call == rsp_apres_call ? "OUI" : "NON");
}

/**
 * Exemple 6 : Lecture du contenu de la stack
 */
void demo_lecture_stack(void) {
    printf("\n=== Démo 6 : Lecture du contenu de la stack ===\n");
    
    uint64_t local1 = 0xAAAAAAAAAAAAAAAA;
    uint64_t local2 = 0xBBBBBBBBBBBBBBBB;
    uint64_t local3 = 0xCCCCCCCCCCCCCCCC;
    
    uint64_t* stack_ptr;
    
    __asm__ __volatile__ (
        "mov %0, rsp"
        : "=r" (stack_ptr)
    );
    
    printf("Contenu de la stack (depuis RSP) :\n");
    for (int i = 0; i < 10; i++) {
        printf("  [RSP + %2d] = 0x%016lx", i * 8, stack_ptr[i]);
        if (stack_ptr[i] == local1) printf(" <- local1");
        if (stack_ptr[i] == local2) printf(" <- local2");
        if (stack_ptr[i] == local3) printf(" <- local3");
        printf("\n");
    }
    
    // Éviter l'optimisation des variables
    printf("(local1=%lx, local2=%lx, local3=%lx)\n", local1, local2, local3);
}

/**
 * Exemple 7 : Comprendre l'overflow (sans l'exploiter)
 */
void demo_overflow_concept(void) {
    printf("\n=== Démo 7 : Concept de Buffer Overflow ===\n");
    
    struct {
        char buffer[16];
        uint64_t canary;
        uint64_t saved_rbp;
        uint64_t ret_addr;
    } stack_sim;
    
    // Simuler une stack vulnérable
    stack_sim.canary = 0xDEADC0DEDEADC0DE;
    stack_sim.saved_rbp = 0x7FFFFFFFE000;
    stack_sim.ret_addr = 0x401234;
    memset(stack_sim.buffer, 'A', 16);
    
    printf("Stack AVANT overflow :\n");
    printf("  buffer[16] : \"%.16s\"\n", stack_sim.buffer);
    printf("  canary     : 0x%lx\n", stack_sim.canary);
    printf("  saved_rbp  : 0x%lx\n", stack_sim.saved_rbp);
    printf("  ret_addr   : 0x%lx\n", stack_sim.ret_addr);
    
    // Simuler un overflow
    printf("\nSimulation: écriture de 40 bytes dans buffer[16]...\n");
    memset(stack_sim.buffer, 'B', 40);
    
    printf("\nStack APRÈS overflow :\n");
    printf("  buffer[16] : \"%.16s\" (déborde!)\n", stack_sim.buffer);
    printf("  canary     : 0x%lx %s\n", stack_sim.canary,
           stack_sim.canary != 0xDEADC0DEDEADC0DE ? "(ÉCRASÉ!)" : "");
    printf("  saved_rbp  : 0x%lx %s\n", stack_sim.saved_rbp,
           stack_sim.saved_rbp != 0x7FFFFFFFE000 ? "(ÉCRASÉ!)" : "");
    printf("  ret_addr   : 0x%lx %s\n", stack_sim.ret_addr,
           stack_sim.ret_addr != 0x401234 ? "(ÉCRASÉ!)" : "");
}

/**
 * Exemple 8 : Red Zone demonstration (Linux/macOS)
 */
void demo_red_zone(void) {
    printf("\n=== Démo 8 : Red Zone (System V ABI) ===\n");
    
    uint64_t valeur_dans_redzone;
    
    // Écrire dans la red zone (sous RSP) sans modifier RSP
    __asm__ __volatile__ (
        "mov qword ptr [rsp - 8], 0x1234567890ABCDEF\n\t"
        "mov %0, [rsp - 8]"
        : "=r" (valeur_dans_redzone)
        :
        : "memory"
    );
    
    printf("Valeur écrite dans red zone [RSP-8] : 0x%lx\n", valeur_dans_redzone);
    printf("(La red zone permet d'utiliser 128 bytes sous RSP\n");
    printf(" sans modifier RSP - optimisation pour fonctions leaf)\n");
}

int main(void) {
    printf("================================================\n");
    printf("      STACK OPERATIONS x64 - DÉMONSTRATIONS     \n");
    printf("================================================\n");
    
    demo_push_pop();
    demo_sauvegarde_registres();
    fonction_analysee(1, 2, 3);
    demo_prologue_epilogue();
    demo_call_ret();
    demo_lecture_stack();
    demo_overflow_concept();
    demo_red_zone();
    
    printf("\n================================================\n");
    printf("                    FIN DEMO                    \n");
    printf("================================================\n");
    
    return 0;
}

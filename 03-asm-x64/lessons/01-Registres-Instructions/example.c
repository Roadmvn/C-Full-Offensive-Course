/**
 * Module : Registres et Instructions x64 - Exemples pratiques
 * 
 * Ce fichier démontre l'utilisation de l'assembleur inline en C
 * pour comprendre les registres et instructions x64.
 * 
 * Compilation :
 *   gcc -o example example.c -masm=intel
 */

#include <stdio.h>
#include <stdint.h>

/**
 * Exemple 1 : Accès aux registres et opérations de base
 */
void demo_registres_base(void) {
    printf("\n=== Démo 1 : Registres de base ===\n");
    
    uint64_t valeur = 0;
    uint64_t resultat = 0;
    
    // Charger une valeur dans RAX puis la récupérer
    __asm__ __volatile__ (
        "mov rax, 0x1234567890ABCDEF\n\t"
        "mov %0, rax"
        : "=r" (valeur)
        :
        : "rax"
    );
    printf("Valeur chargée dans RAX : 0x%lx\n", valeur);
    
    // Démonstration des sous-registres
    uint32_t eax_val;
    uint16_t ax_val;
    uint8_t al_val;
    
    __asm__ __volatile__ (
        "mov rax, 0x1122334455667788\n\t"
        "mov %0, eax\n\t"    // 32 bits bas
        "mov %1, ax\n\t"     // 16 bits bas
        "mov %2, al"         // 8 bits bas
        : "=r" (eax_val), "=r" (ax_val), "=r" (al_val)
        :
        : "rax"
    );
    printf("RAX = 0x1122334455667788\n");
    printf("  EAX (32 bits) = 0x%x\n", eax_val);
    printf("  AX  (16 bits) = 0x%x\n", ax_val);
    printf("  AL  (8 bits)  = 0x%x\n", al_val);
}

/**
 * Exemple 2 : Instructions arithmétiques
 */
void demo_arithmetique(void) {
    printf("\n=== Démo 2 : Instructions arithmétiques ===\n");
    
    uint64_t a = 100;
    uint64_t b = 30;
    uint64_t somme, difference, produit, quotient, reste;
    
    // Addition
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "add rax, %2\n\t"
        "mov %0, rax"
        : "=r" (somme)
        : "r" (a), "r" (b)
        : "rax"
    );
    printf("ADD: %lu + %lu = %lu\n", a, b, somme);
    
    // Soustraction
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "sub rax, %2\n\t"
        "mov %0, rax"
        : "=r" (difference)
        : "r" (a), "r" (b)
        : "rax"
    );
    printf("SUB: %lu - %lu = %lu\n", a, b, difference);
    
    // Multiplication avec IMUL (version 2 opérandes)
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "imul rax, %2\n\t"
        "mov %0, rax"
        : "=r" (produit)
        : "r" (a), "r" (b)
        : "rax"
    );
    printf("IMUL: %lu * %lu = %lu\n", a, b, produit);
    
    // Division
    __asm__ __volatile__ (
        "xor rdx, rdx\n\t"   // Initialiser RDX à 0 (important!)
        "mov rax, %2\n\t"
        "div %3\n\t"
        "mov %0, rax\n\t"    // Quotient
        "mov %1, rdx"        // Reste
        : "=r" (quotient), "=r" (reste)
        : "r" (a), "r" (b)
        : "rax", "rdx"
    );
    printf("DIV: %lu / %lu = %lu (reste: %lu)\n", a, b, quotient, reste);
}

/**
 * Exemple 3 : Instructions logiques et bit manipulation
 */
void demo_logique(void) {
    printf("\n=== Démo 3 : Opérations logiques ===\n");
    
    uint64_t a = 0xFF00FF00;
    uint64_t b = 0x0F0F0F0F;
    uint64_t result_and, result_or, result_xor, result_not;
    
    // AND
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "and rax, %2\n\t"
        "mov %0, rax"
        : "=r" (result_and)
        : "r" (a), "r" (b)
        : "rax"
    );
    printf("AND: 0x%lx & 0x%lx = 0x%lx\n", a, b, result_and);
    
    // OR
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "or rax, %2\n\t"
        "mov %0, rax"
        : "=r" (result_or)
        : "r" (a), "r" (b)
        : "rax"
    );
    printf("OR:  0x%lx | 0x%lx = 0x%lx\n", a, b, result_or);
    
    // XOR
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "xor rax, %2\n\t"
        "mov %0, rax"
        : "=r" (result_xor)
        : "r" (a), "r" (b)
        : "rax"
    );
    printf("XOR: 0x%lx ^ 0x%lx = 0x%lx\n", a, b, result_xor);
    
    // NOT
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "not rax\n\t"
        "mov %0, rax"
        : "=r" (result_not)
        : "r" (a)
        : "rax"
    );
    printf("NOT: ~0x%lx = 0x%lx\n", a, result_not);
    
    // XOR pour mettre à zéro (technique courante)
    uint64_t zero;
    __asm__ __volatile__ (
        "xor rax, rax\n\t"
        "mov %0, rax"
        : "=r" (zero)
        :
        : "rax"
    );
    printf("XOR RAX, RAX = %lu (technique pour RAX = 0)\n", zero);
}

/**
 * Exemple 4 : Décalages de bits (Shifts)
 */
void demo_shifts(void) {
    printf("\n=== Démo 4 : Décalages de bits ===\n");
    
    uint64_t valeur = 0x01;
    uint64_t shl_result, shr_result;
    
    // Shift left (multiplication par puissance de 2)
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "shl rax, 4\n\t"    // Multiplier par 16 (2^4)
        "mov %0, rax"
        : "=r" (shl_result)
        : "r" (valeur)
        : "rax"
    );
    printf("SHL: 0x%lx << 4 = 0x%lx (x16)\n", valeur, shl_result);
    
    // Shift right (division par puissance de 2)
    valeur = 0x100;
    __asm__ __volatile__ (
        "mov rax, %1\n\t"
        "shr rax, 4\n\t"    // Diviser par 16 (2^4)
        "mov %0, rax"
        : "=r" (shr_result)
        : "r" (valeur)
        : "rax"
    );
    printf("SHR: 0x%lx >> 4 = 0x%lx (/16)\n", valeur, shr_result);
}

/**
 * Exemple 5 : LEA - Load Effective Address
 */
void demo_lea(void) {
    printf("\n=== Démo 5 : LEA (Load Effective Address) ===\n");
    
    uint64_t base = 100;
    uint64_t index = 10;
    uint64_t resultat;
    
    // LEA pour calcul d'adresse / calcul rapide
    __asm__ __volatile__ (
        "lea %0, [%1 + %2*4 + 8]"
        : "=r" (resultat)
        : "r" (base), "r" (index)
    );
    printf("LEA [%lu + %lu*4 + 8] = %lu\n", base, index, resultat);
    
    // LEA pour multiplication par 3
    uint64_t x = 7;
    uint64_t x_fois_3;
    __asm__ __volatile__ (
        "lea %0, [%1 + %1*2]"  // x + x*2 = x*3
        : "=r" (x_fois_3)
        : "r" (x)
    );
    printf("LEA [x + x*2] où x=%lu : %lu (x*3)\n", x, x_fois_3);
    
    // LEA pour multiplication par 5
    uint64_t x_fois_5;
    __asm__ __volatile__ (
        "lea %0, [%1 + %1*4]"  // x + x*4 = x*5
        : "=r" (x_fois_5)
        : "r" (x)
    );
    printf("LEA [x + x*4] où x=%lu : %lu (x*5)\n", x, x_fois_5);
}

/**
 * Exemple 6 : Comparaisons et flags
 */
void demo_comparaisons(void) {
    printf("\n=== Démo 6 : Comparaisons et flags ===\n");
    
    uint64_t a = 10;
    uint64_t b = 20;
    int zf, cf, sf;
    
    // CMP et lecture des flags
    __asm__ __volatile__ (
        "cmp %3, %4\n\t"
        "setz %0\n\t"       // ZF -> al
        "setc %1\n\t"       // CF -> bl
        "sets %2"           // SF -> cl
        : "=r" (zf), "=r" (cf), "=r" (sf)
        : "r" (a), "r" (b)
        : "cc"
    );
    printf("CMP %lu, %lu:\n", a, b);
    printf("  ZF (Zero Flag) = %d\n", zf);
    printf("  CF (Carry Flag) = %d\n", cf);
    printf("  SF (Sign Flag) = %d\n", sf);
    
    // TEST pour vérifier si une valeur est nulle
    uint64_t valeur = 0;
    int is_zero;
    __asm__ __volatile__ (
        "test %1, %1\n\t"
        "setz %0"
        : "=r" (is_zero)
        : "r" (valeur)
        : "cc"
    );
    printf("TEST %lu, %lu -> ZF = %d (1 = valeur nulle)\n", valeur, valeur, is_zero);
}

/**
 * Exemple 7 : Opérations sur la pile
 */
void demo_pile(void) {
    printf("\n=== Démo 7 : Opérations sur la pile ===\n");
    
    uint64_t valeur_push = 0xDEADBEEF;
    uint64_t valeur_pop;
    void* rsp_avant;
    void* rsp_apres_push;
    void* rsp_apres_pop;
    
    __asm__ __volatile__ (
        "mov %0, rsp\n\t"          // RSP avant
        "push %3\n\t"              // Push la valeur
        "mov %1, rsp\n\t"          // RSP après push
        "pop %4\n\t"               // Pop dans variable
        "mov %2, rsp"              // RSP après pop
        : "=r" (rsp_avant), "=r" (rsp_apres_push), "=r" (rsp_apres_pop), 
          "+r" (valeur_push), "=r" (valeur_pop)
    );
    
    printf("Valeur pushée : 0x%lx\n", valeur_push);
    printf("RSP avant push : %p\n", rsp_avant);
    printf("RSP après push : %p (différence: %ld bytes)\n", 
           rsp_apres_push, (char*)rsp_avant - (char*)rsp_apres_push);
    printf("RSP après pop  : %p\n", rsp_apres_pop);
    printf("Valeur récupérée : 0x%lx\n", valeur_pop);
}

/**
 * Exemple offensif : Pattern XOR decoder (shellcode)
 */
void demo_xor_decoder(void) {
    printf("\n=== Démo 8 : Pattern XOR decoder ===\n");
    
    // Données "encodées" avec XOR 0x41
    unsigned char encoded[] = {0x09, 0x24, 0x2D, 0x2D, 0x2E, 0x00}; // "Hello" ^ 0x41
    unsigned char decoded[6];
    
    // Copier pour le décodage
    for (int i = 0; i < 6; i++) {
        decoded[i] = encoded[i];
    }
    
    // Décodage avec XOR inline
    __asm__ __volatile__ (
        "mov rcx, 5\n\t"           // Longueur
        "mov rsi, %0\n\t"          // Pointeur vers les données
        "decode_loop:\n\t"
        "xor byte ptr [rsi], 0x41\n\t"  // XOR avec la clé
        "inc rsi\n\t"
        "loop decode_loop"
        :
        : "r" (decoded)
        : "rcx", "rsi", "memory"
    );
    
    printf("Données encodées (XOR 0x41): ");
    for (int i = 0; i < 5; i++) printf("0x%02x ", encoded[i]);
    printf("\nDécodé: %s\n", decoded);
}

int main(void) {
    printf("============================================\n");
    printf("   REGISTRES ET INSTRUCTIONS x64 - DEMO    \n");
    printf("============================================\n");
    
    demo_registres_base();
    demo_arithmetique();
    demo_logique();
    demo_shifts();
    demo_lea();
    demo_comparaisons();
    demo_pile();
    demo_xor_decoder();
    
    printf("\n============================================\n");
    printf("                 FIN DEMO                   \n");
    printf("============================================\n");
    
    return 0;
}

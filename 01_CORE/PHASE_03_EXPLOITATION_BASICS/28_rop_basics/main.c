/*
 * ═══════════════════════════════════════════════════════════════════
 * Module 38 : ROP Chains - Return-Oriented Programming
 * ═══════════════════════════════════════════════════════════════════
 *
 * ⚠️  AVERTISSEMENT LÉGAL STRICT ⚠️
 *
 * ROP = Technique d'exploitation avancée pour contourner DEP/NX.
 * USAGE STRICTEMENT ÉDUCATIF - VM ISOLÉE UNIQUEMENT
 *
 * INTERDIT : Exploitation de systèmes sans autorisation
 * LÉGAL : CTF, recherche académique, environnement de test personnel
 *
 * L'auteur décline toute responsabilité pour usage illégal.
 * ═══════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEPARATEUR "═══════════════════════════════════════════════════════════════════\n"

void afficher_titre(const char *titre);
void demonstrer_concept_rop();
void demonstrer_gadgets();
void demonstrer_stack_layout();
void exemple_vulnerable();

void afficher_titre(const char *titre) {
    printf("\n");
    printf(SEPARATEUR);
    printf("  %s\n", titre);
    printf(SEPARATEUR);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 1 : Concept de ROP
// ═══════════════════════════════════════════════════════════════════

void demonstrer_concept_rop() {
    afficher_titre("DÉMONSTRATION 1 : Concept de ROP");

    printf("\n[*] Return-Oriented Programming (ROP)\n\n");

    printf("PROBLÈME : DEP/NX empêche l'exécution de code sur la stack\n");
    printf("  Stack : RW-  (Read/Write, pas Execute)\n");
    printf("  .text : R-X  (Read/Execute, pas Write)\n\n");

    printf("SOLUTION : ROP - Réutiliser du code existant\n\n");

    printf("1. GADGETS : Fragments de code se terminant par 'ret'\n");
    printf("   Exemple : pop rdi ; ret\n");
    printf("             mov rax, [rsi] ; ret\n");
    printf("             add rsp, 0x10 ; ret\n\n");

    printf("2. ROP CHAIN : Enchaînement de gadgets via la stack\n");
    printf("   Stack layout :\n");
    printf("   [gadget1_addr]\n");
    printf("   [data1]\n");
    printf("   [gadget2_addr]\n");
    printf("   [data2]\n");
    printf("   ...\n\n");

    printf("3. EXÉCUTION :\n");
    printf("   - Buffer overflow → Contrôle RIP/EIP\n");
    printf("   - RIP pointe vers gadget1\n");
    printf("   - gadget1 exécuté, 'ret' → gadget2\n");
    printf("   - Répétition jusqu'à objectif atteint\n\n");

    printf("4. OBJECTIFS TYPIQUES :\n");
    printf("   - execve(\"/bin/sh\", NULL, NULL)\n");
    printf("   - system(\"/bin/sh\")\n");
    printf("   - Lecture/écriture arbitraire\n");
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 2 : Exemples de Gadgets
// ═══════════════════════════════════════════════════════════════════

void demonstrer_gadgets() {
    afficher_titre("DÉMONSTRATION 2 : Types de Gadgets");

    printf("\n[*] Gadgets couramment recherchés :\n\n");

    printf("1. POP GADGETS (charger arguments) :\n");
    printf("   pop rdi ; ret      → 1er argument\n");
    printf("   pop rsi ; ret      → 2ème argument\n");
    printf("   pop rdx ; ret      → 3ème argument\n");
    printf("   pop rax ; ret      → Numéro syscall\n\n");

    printf("2. MEMORY OPERATIONS :\n");
    printf("   mov rax, [rdi] ; ret     → Lire mémoire\n");
    printf("   mov [rdi], rax ; ret     → Écrire mémoire\n\n");

    printf("3. ARITHMETIC :\n");
    printf("   add rax, rdi ; ret\n");
    printf("   xor rax, rax ; ret\n");
    printf("   inc rax ; ret\n\n");

    printf("4. STACK PIVOTING :\n");
    printf("   xchg rsp, rax ; ret      → Changer stack\n");
    printf("   mov rsp, rbp ; ret\n");
    printf("   add rsp, 0x18 ; ret\n\n");

    printf("5. SYSCALL/CALL :\n");
    printf("   syscall ; ret\n");
    printf("   call rax ; ret\n\n");

    printf("OUTILS DE RECHERCHE :\n");
    printf("  ROPgadget --binary <file>\n");
    printf("  ropper --file <file>\n");
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 3 : Stack Layout pour ROP
// ═══════════════════════════════════════════════════════════════════

void demonstrer_stack_layout() {
    afficher_titre("DÉMONSTRATION 3 : Stack Layout");

    printf("\n[*] Exemple : execve(\"/bin/sh\", NULL, NULL)\n\n");

    printf("REGISTRES REQUIS (x64) :\n");
    printf("  rax = 59           (numéro syscall execve)\n");
    printf("  rdi = \"/bin/sh\"    (1er argument)\n");
    printf("  rsi = NULL         (2ème argument)\n");
    printf("  rdx = NULL         (3ème argument)\n\n");

    printf("ROP CHAIN :\n");
    printf("  Offset   Contenu                   Action\n");
    printf("  ───────────────────────────────────────────────────────────────\n");
    printf("  +0       [pop_rdi_ret]            pop rdi ; ret\n");
    printf("  +8       [addr_binsh]             rdi = \"/bin/sh\"\n");
    printf("  +16      [pop_rsi_ret]            pop rsi ; ret\n");
    printf("  +24      [0x0]                    rsi = NULL\n");
    printf("  +32      [pop_rdx_ret]            pop rdx ; ret\n");
    printf("  +40      [0x0]                    rdx = NULL\n");
    printf("  +48      [pop_rax_ret]            pop rax ; ret\n");
    printf("  +56      [59]                     rax = 59 (execve)\n");
    printf("  +64      [syscall_ret]            syscall\n\n");

    printf("RÉSULTAT : Shell root !\n");
}

// ═══════════════════════════════════════════════════════════════════
// Exemple de programme vulnérable (ÉDUCATIF)
// ═══════════════════════════════════════════════════════════════════

#pragma GCC push_options
#pragma GCC optimize ("O0")

void fonction_vulnerable() {
    char buffer[64];
    printf("\n[*] Fonction vulnérable (buffer overflow)\n");
    printf("    Buffer : %p (64 bytes)\n", buffer);
    printf("    RBP/EBP est à +64\n");
    printf("    Saved RIP/EIP est à +72\n\n");

    printf("Pour exploiter (DANS UN CTF) :\n");
    printf("  1. Overflow avec 72 bytes de padding\n");
    printf("  2. Écraser saved RIP avec adresse de gadget\n");
    printf("  3. Construire ROP chain sur la stack\n\n");

    printf("⚠️  NE PAS EXPLOITER CE PROGRAMME\n");
    printf("    Utilisez pwntools sur des challenges CTF\n");
}

#pragma GCC pop_options

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

int main(void) {
    printf(SEPARATEUR);
    printf("  MODULE 38 : ROP CHAINS\n");
    printf("  Return-Oriented Programming\n");
    printf(SEPARATEUR);

    printf("\n⚠️  AVERTISSEMENT LÉGAL ⚠️\n\n");
    printf("ROP = Technique d'exploitation avancée.\n");
    printf("USAGE ÉDUCATIF UNIQUEMENT - CTF, VM isolée\n\n");
    printf("INTERDIT : Exploitation de systèmes sans autorisation\n\n");
    printf("Appuyez sur ENTRÉE pour continuer...\n");
    getchar();

    demonstrer_concept_rop();
    printf("\n\nAppuyez sur ENTRÉE...\n");
    getchar();

    demonstrer_gadgets();
    printf("\n\nAppuyez sur ENTRÉE...\n");
    getchar();

    demonstrer_stack_layout();
    printf("\n\nAppuyez sur ENTRÉE...\n");
    getchar();

    fonction_vulnerable();

    printf("\n");
    afficher_titre("FIN DES DÉMONSTRATIONS");
    printf("\n[+] Pour pratiquer : ROPEmporium, pwnable.kr, HackTheBox\n");
    printf("[+] Consultez exercice.txt et solution.txt\n\n");

    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * NOTES IMPORTANTES
 * ═══════════════════════════════════════════════════════════════════
 *
 * PROTECTIONS MODERNES :
 * - DEP/NX : Stack non-exécutable → ROP bypass
 * - ASLR : Randomisation adresses → Info leak requis
 * - Stack Canaries : Détection overflow → Leak canary ou bypass
 * - CFI : Validation sauts indirects → ROP difficile
 * - Shadow Stack : Intel CET → ROP quasi impossible
 *
 * APPRENTISSAGE :
 * - ROPEmporium : Tutoriels progressifs
 * - pwnable.kr : Challenges variés
 * - Exploit Education : Phoenix, Fusion
 * - CTFtime : Compétitions CTF
 *
 * OUTILS :
 * - pwntools : Framework exploitation Python
 * - ROPgadget : Recherche de gadgets
 * - GDB + pwndbg : Debugging
 * - checksec : Vérification protections
 *
 * LÉGALITÉ :
 * - UNIQUEMENT sur challenges CTF et VM personnelles
 * - JAMAIS sur systèmes sans autorisation écrite
 * - Responsabilité pénale en cas d'abus
 *
 * ═══════════════════════════════════════════════════════════════════
 */

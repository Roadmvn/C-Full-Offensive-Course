/*
 * OBJECTIF  : Comprendre PatchGuard (Kernel Patch Protection)
 * PREREQUIS : Kernel Memory, SSDT, IDT, Driver Basics
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * PatchGuard (KPP) surveille l'integrite des structures kernel critiques.
 * Si une modification est detectee, il provoque un BSOD.
 * Introduit dans Windows XP x64.
 */

#include <windows.h>
#include <stdio.h>

void demo_patchguard_concept(void) {
    printf("[1] PatchGuard (Kernel Patch Protection)\n\n");
    printf("    PatchGuard surveille periodiquement :\n");
    printf("    - SSDT (System Service Descriptor Table)\n");
    printf("    - IDT (Interrupt Descriptor Table)\n");
    printf("    - GDT (Global Descriptor Table)\n");
    printf("    - MSR (Model Specific Registers) critiques\n");
    printf("    - Kernel code sections (ntoskrnl.exe, hal.dll)\n");
    printf("    - Kernel data sections critiques\n");
    printf("    - Processor control registers (CR0, CR4)\n\n");

    printf("    Si modification detectee :\n");
    printf("    BSOD: CRITICAL_STRUCTURE_CORRUPTION (0x109)\n");
    printf("    BugCheck parametre 0 = adresse modifiee\n");
    printf("    BugCheck parametre 1 = structure concernee\n\n");
}

void demo_how_it_works(void) {
    printf("[2] Fonctionnement interne\n\n");
    printf("    PatchGuard est un timer DPC (Deferred Procedure Call)\n");
    printf("    qui s'execute a intervalles ALEATOIRES (5-10 minutes).\n\n");

    printf("    Workflow :\n");
    printf("    1. Initialisation au boot (ntoskrnl)\n");
    printf("    2. Calcul des checksums des structures protegees\n");
    printf("    3. Timer DPC programme avec delai aleatoire\n");
    printf("    4. A l'expiration du timer :\n");
    printf("       a. Recalculer les checksums\n");
    printf("       b. Comparer avec les valeurs initiales\n");
    printf("       c. Si difference -> KeBugCheckEx(0x109)\n");
    printf("    5. Reprogrammer le timer (nouveau delai aleatoire)\n\n");

    printf("    Anti-debug :\n");
    printf("    - Le code de PatchGuard est obfusque\n");
    printf("    - Les contextes sont chiffres en memoire\n");
    printf("    - Plusieurs threads de verification\n");
    printf("    - Utilise des work items, DPCs, timers varies\n\n");
}

void demo_structures_protected(void) {
    printf("[3] Structures protegees\n\n");
    printf("    +---------------------------+-------------------------------+\n");
    printf("    | Structure                 | Impact si modifiee            |\n");
    printf("    +---------------------------+-------------------------------+\n");
    printf("    | SSDT                      | Syscall hijacking             |\n");
    printf("    | IDT                       | Interrupt hijacking           |\n");
    printf("    | GDT                       | Segment descriptor attacks    |\n");
    printf("    | ntoskrnl .text            | Inline hooks du noyau         |\n");
    printf("    | hal.dll .text             | HAL hooks                     |\n");
    printf("    | ci.dll .text              | Code Integrity bypass         |\n");
    printf("    | MSR_LSTAR                 | Syscall handler redirection   |\n");
    printf("    | MSR_CSTAR                 | Compat syscall handler        |\n");
    printf("    | CR0, CR4                  | Control register manipulation |\n");
    printf("    | Debug registers           | Hardware breakpoints          |\n");
    printf("    +---------------------------+-------------------------------+\n\n");

    printf("    Note : les CALLBACKS kernel ne sont PAS protegees par PG!\n");
    printf("    -> C'est pourquoi les EDR modernes utilisent les callbacks\n");
    printf("    -> Et c'est pourquoi les attaquants les ciblent (callback removal)\n\n");
}

void demo_bypass_history(void) {
    printf("[4] Historique des bypass PatchGuard\n\n");
    printf("    Les bypass PG sont une course entre chercheurs et MS :\n\n");

    printf("    2005 : PatchGuard v1 (Windows XP x64)\n");
    printf("    -> Bypass : trouver et desactiver le timer\n\n");

    printf("    2007 : PatchGuard v2\n");
    printf("    -> Timer obfusque, contexte chiffre\n");
    printf("    -> Bypass : exception handler hijacking\n\n");

    printf("    2011 : PatchGuard v3\n");
    printf("    -> Plus de contextes de verification\n");
    printf("    -> Bypass : GhostHook (Intel PT abuse)\n\n");

    printf("    2018+ : PatchGuard actuel\n");
    printf("    -> Tres obfusque, multiple verification threads\n");
    printf("    -> Utilise APC, work items, timer DPCs\n");
    printf("    -> Contextes dans le pool avec tags random\n\n");

    printf("    Methodes de bypass actuelles :\n");
    printf("    a) Hyperviseur custom :\n");
    printf("       Intercepter les lectures de PG via EPT\n");
    printf("       Retourner les valeurs originales\n\n");
    printf("    b) Infinity Hook :\n");
    printf("       Hooker via ETW (hal!HalPerformanceCounter)\n");
    printf("       Non protege par PG (oubli MS)\n\n");
    printf("    c) Trouver et patcher le contexte PG :\n");
    printf("       Scanner la memoire pour les contextes\n");
    printf("       Desactiver les timers avant la verification\n\n");
}

void demo_impact(void) {
    printf("[5] Impact sur l'offensif\n\n");
    printf("    Ce que PatchGuard EMPECHE :\n");
    printf("    - SSDT hooking\n");
    printf("    - IDT hooking\n");
    printf("    - Inline kernel hooks\n");
    printf("    - Modification de ci.dll (DSE bypass direct)\n\n");

    printf("    Ce que PatchGuard N'EMPECHE PAS :\n");
    printf("    - DKOM (modification d'objets kernel)\n");
    printf("    - Callback registration/removal\n");
    printf("    - BYOVD (chargement de drivers vulnerables)\n");
    printf("    - Minifilter installation\n");
    printf("    - Pool memory manipulation\n\n");

    printf("    VBS/HVCI ajoute une couche supplementaire :\n");
    printf("    - Meme avec un bypass PG, HVCI empeche :\n");
    printf("      * L'execution de code non-signe en kernel\n");
    printf("      * La modification de pages RX en RWX\n");
    printf("      * L'allocation de pages kernel executables\n\n");
}

int main(void) {
    printf("[*] Demo : PatchGuard Basics\n");
    printf("[*] ==========================================\n\n");
    demo_patchguard_concept();
    demo_how_it_works();
    demo_structures_protected();
    demo_bypass_history();
    demo_impact();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

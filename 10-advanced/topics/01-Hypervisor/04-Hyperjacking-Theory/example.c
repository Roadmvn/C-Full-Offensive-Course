/*
 * OBJECTIF  : Comprendre la theorie du hyperjacking
 * PREREQUIS : Bases C, virtualisation, VT-x, rootkits
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre la theorie du hyperjacking :
 * Blue Pill, rootkits hyperviseur, VMCS manipulation,
 * et detection.
 * Demonstration pedagogique (theorie uniquement).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Etape 1 : Concept du hyperjacking
 */
static void explain_hyperjacking(void) {
    printf("[*] Etape 1 : Concept du hyperjacking\n\n");

    printf("    Avant l'attaque :\n");
    printf("    ┌──────────────────────────────────┐\n");
    printf("    │  OS (ring 0)                      │\n");
    printf("    │  └── Applications (ring 3)        │\n");
    printf("    │                                   │\n");
    printf("    │  Hardware                         │\n");
    printf("    └──────────────────────────────────┘\n\n");

    printf("    Apres hyperjacking :\n");
    printf("    ┌──────────────────────────────────┐\n");
    printf("    │  OS (croit etre sur le hardware)  │\n");
    printf("    │  └── Applications                 │\n");
    printf("    ├──────────────────────────────────┤\n");
    printf("    │  Rootkit Hyperviseur (ring -1)    │\n");
    printf("    │  - Intercepte TOUT                │\n");
    printf("    │  - Invisible pour l'OS            │\n");
    printf("    ├──────────────────────────────────┤\n");
    printf("    │  Hardware                         │\n");
    printf("    └──────────────────────────────────┘\n\n");

    printf("    Le rootkit s'insere SOUS l'OS en utilisant\n");
    printf("    les extensions de virtualisation (VT-x/AMD-V)\n");
    printf("    pour virtualiser l'OS existant a la volee.\n\n");
}

/*
 * Etape 2 : Blue Pill
 */
static void explain_blue_pill(void) {
    printf("[*] Etape 2 : Blue Pill (Joanna Rutkowska, 2006)\n\n");

    printf("    Principe :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Le rootkit s'execute en ring 0\n");
    printf("    2. Active le mode VMX (VMXON)\n");
    printf("    3. Cree un VMCS pour l'OS actuel\n");
    printf("    4. Configure les VM Exit handlers\n");
    printf("    5. Execute VMLAUNCH\n");
    printf("    6. L'OS continue de tourner comme guest\n");
    printf("    7. Le rootkit controle tout en VMX root\n\n");

    printf("    Pseudocode :\n");
    printf("    ───────────────────────────────────\n");
    printf("    void install_hypervisor() {\n");
    printf("        // 1. Allouer la region VMXON\n");
    printf("        vmxon_region = alloc_page();\n");
    printf("        vmxon(vmxon_region);\n\n");
    printf("        // 2. Creer et configurer le VMCS\n");
    printf("        vmcs = alloc_page();\n");
    printf("        vmclear(vmcs);\n");
    printf("        vmptrld(vmcs);\n\n");
    printf("        // 3. Copier l'etat CPU actuel dans le guest state\n");
    printf("        vmwrite(GUEST_CR0, read_cr0());\n");
    printf("        vmwrite(GUEST_CR3, read_cr3());\n");
    printf("        vmwrite(GUEST_CR4, read_cr4());\n");
    printf("        vmwrite(GUEST_RSP, current_rsp);\n");
    printf("        vmwrite(GUEST_RIP, resume_point);\n\n");
    printf("        // 4. Configurer le host state\n");
    printf("        vmwrite(HOST_RIP, vmexit_handler);\n\n");
    printf("        // 5. Lancer la VM (l'OS devient guest)\n");
    printf("        vmlaunch();\n");
    printf("    }\n\n");
}

/*
 * Etape 3 : Interception des operations
 */
static void explain_interception(void) {
    printf("[*] Etape 3 : Interception des operations\n\n");

    printf("    Le rootkit peut intercepter :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Operation            | Via\n");
    printf("    ─────────────────────|──────────────────────\n");
    printf("    Acces disque         | I/O port interception\n");
    printf("    Acces reseau         | I/O port + MMIO\n");
    printf("    Acces memoire        | EPT violations\n");
    printf("    Acces registres      | MSR bitmap\n");
    printf("    Interruptions        | External-interrupt exit\n");
    printf("    Instructions priv.   | VM execution controls\n");
    printf("    Acces peripheriques  | I/O bitmap\n\n");

    printf("    Exemple : cacher un fichier :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. L'OS appelle NtQueryDirectoryFile\n");
    printf("    2. Le syscall s'execute normalement\n");
    printf("    3. Le rootkit intercepte le retour\n");
    printf("    4. Filtre le fichier cache du resultat\n");
    printf("    5. L'OS ne voit jamais le fichier\n\n");

    printf("    Exemple : cacher un processus :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Intercepter les acces a la liste des processus\n");
    printf("    -> Modifier les pages memoire via EPT\n");
    printf("    -> Presenter une vue modifiee a l'OS\n\n");
}

/*
 * Etape 4 : Rootkits hyperviseur connus
 */
static void explain_known_rootkits(void) {
    printf("[*] Etape 4 : Rootkits hyperviseur connus\n\n");

    printf("    Rootkit    | Annee | Auteur          | Technique\n");
    printf("    ───────────|───────|─────────────────|──────────────\n");
    printf("    Blue Pill  | 2006  | Rutkowska       | AMD-V (SVM)\n");
    printf("    Vitriol    | 2006  | Zovi            | VT-x\n");
    printf("    SubVirt    | 2006  | Microsoft Res.  | VMM rootkit\n");
    printf("    HyperDbg   | 2010  | Ether Project   | VT-x debugger\n");
    printf("    HyperBone  | 2016  | DarthTon        | Minimal VMM\n\n");

    printf("    Blue Pill (AMD-V) :\n");
    printf("    - Utilise Secure Virtual Machine (SVM)\n");
    printf("    - Virtualise l'OS a chaud\n");
    printf("    - Difficile a detecter depuis le guest\n\n");

    printf("    SubVirt (Microsoft Research) :\n");
    printf("    - Insere un hyperviseur sous l'OS\n");
    printf("    - Modifie le boot process\n");
    printf("    - Persistence via le secteur de boot\n\n");
}

/*
 * Etape 5 : Detection
 */
static void explain_detection(void) {
    printf("[*] Etape 5 : Detection du hyperjacking\n\n");

    printf("    Techniques de detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Timing analysis\n");
    printf("       -> RDTSC avant/apres CPUID\n");
    printf("       -> VM Exits ajoutent de la latence\n\n");

    printf("    2. Nested virtualization detection\n");
    printf("       -> Si deja dans un hyperviseur,\n");
    printf("       -> les instructions VMX echouent\n\n");

    printf("    3. TLB analysis\n");
    printf("       -> Les VM Exits flushent le TLB\n");
    printf("       -> Patterns de cache anormaux\n\n");

    printf("    4. Hardware-based detection\n");
    printf("       -> Intel SMM (System Management Mode)\n");
    printf("       -> Firmware-level checks\n");
    printf("       -> TPM attestation\n\n");

    printf("    5. Red Pill (historique, peu fiable) :\n");
    printf("       -> SIDT retourne une adresse decalee en VM\n");
    printf("       -> Facile a contourner par l'hyperviseur\n\n");
}

/*
 * Etape 6 : Mitigations
 */
static void explain_mitigations(void) {
    printf("[*] Etape 6 : Mitigations\n\n");

    printf("    Prevenir le hyperjacking :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Secure Boot : verifier la chaine de boot\n");
    printf("    - TPM : attestation d'integrite\n");
    printf("    - UEFI Secure Boot + Measured Boot\n");
    printf("    - Hypervisor-protected Code Integrity (HVCI)\n");
    printf("    - VBS (Virtualization Based Security, Windows)\n\n");

    printf("    Windows VBS/HVCI :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Windows utilise Hyper-V pour se proteger\n");
    printf("    -> Credential Guard : isoler les secrets\n");
    printf("    -> HVCI : empecher le code non signe en kernel\n");
    printf("    -> Le rootkit ne peut pas s'inserer sous Hyper-V\n\n");

    printf("    Bonnes pratiques :\n");
    printf("    - Activer Secure Boot\n");
    printf("    - Activer VBS/HVCI (Windows)\n");
    printf("    - Verifier l'integrite du boot regulierement\n");
    printf("    - Utiliser un TPM pour l'attestation\n\n");
}

int main(void) {
    printf("[*] Demo : Hyperjacking Theory\n\n");

    explain_hyperjacking();
    explain_blue_pill();
    explain_interception();
    explain_known_rootkits();
    explain_detection();
    explain_mitigations();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

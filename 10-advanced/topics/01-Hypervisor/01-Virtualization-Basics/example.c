/*
 * OBJECTIF  : Comprendre les fondamentaux de la virtualisation
 * PREREQUIS : Bases C, architecture x86, systemes d'exploitation
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les concepts de virtualisation :
 * types d'hyperviseurs, VT-x/AMD-V, VMCS, vCPU,
 * memoire virtuelle, et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/stat.h>
#endif

/*
 * Etape 1 : Architecture de la virtualisation
 */
static void explain_virtualization(void) {
    printf("[*] Etape 1 : Architecture de la virtualisation\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Type 1 (Bare-metal)                      │\n");
    printf("    │  ┌────────┐ ┌────────┐ ┌────────┐       │\n");
    printf("    │  │ VM 1   │ │ VM 2   │ │ VM 3   │       │\n");
    printf("    │  │ Guest  │ │ Guest  │ │ Guest  │       │\n");
    printf("    │  └───┬────┘ └───┬────┘ └───┬────┘       │\n");
    printf("    │  ┌───┴──────────┴──────────┴────┐       │\n");
    printf("    │  │  Hyperviseur (VMM)            │       │\n");
    printf("    │  │  ESXi, Xen, KVM, Hyper-V      │       │\n");
    printf("    │  └──────────────┬───────────────┘       │\n");
    printf("    │  ┌──────────────v───────────────┐       │\n");
    printf("    │  │  Hardware (CPU, RAM, I/O)     │       │\n");
    printf("    │  └──────────────────────────────┘       │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Type 2 (Hosted)                          │\n");
    printf("    │  ┌────────┐ ┌────────┐                   │\n");
    printf("    │  │ VM 1   │ │ VM 2   │                   │\n");
    printf("    │  └───┬────┘ └───┬────┘                   │\n");
    printf("    │  ┌───┴──────────┴────┐                   │\n");
    printf("    │  │  Hyperviseur       │ (VirtualBox,      │\n");
    printf("    │  │  (application)     │  VMware Workstation│\n");
    printf("    │  └──────────┬────────┘                   │\n");
    printf("    │  ┌──────────v────────────────┐           │\n");
    printf("    │  │  OS Hote (Linux, Windows)  │           │\n");
    printf("    │  └──────────┬────────────────┘           │\n");
    printf("    │  ┌──────────v────────────────┐           │\n");
    printf("    │  │  Hardware                  │           │\n");
    printf("    │  └───────────────────────────┘           │\n");
    printf("    └──────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Extensions de virtualisation CPU
 */
static void explain_vt_extensions(void) {
    printf("[*] Etape 2 : Extensions de virtualisation CPU\n\n");

    printf("    Intel VT-x / AMD-V :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Ajoutent un nouveau mode CPU :\n");
    printf("    - VMX root    : l'hyperviseur (ring -1)\n");
    printf("    - VMX non-root: la VM (ring 0-3 virtualise)\n\n");

    printf("    Transitions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    VM Entry : hote -> guest (VMLAUNCH/VMRESUME)\n");
    printf("    VM Exit  : guest -> hote (instructions sensibles)\n\n");

    printf("    Instructions VMX (Intel) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    VMXON     : activer le mode VMX\n");
    printf("    VMXOFF    : desactiver VMX\n");
    printf("    VMLAUNCH  : lancer une VM\n");
    printf("    VMRESUME  : reprendre une VM\n");
    printf("    VMREAD    : lire le VMCS\n");
    printf("    VMWRITE   : ecrire dans le VMCS\n");
    printf("    VMCALL    : hypercall (guest -> host)\n\n");

    printf("    VMCS (Virtual Machine Control Structure) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Guest state area  : etat CPU du guest\n");
    printf("    - Host state area   : etat CPU de l'hote\n");
    printf("    - VM-execution ctrl : quelles ops causent VM Exit\n");
    printf("    - VM-exit ctrl      : comment gerer les exits\n");
    printf("    - VM-entry ctrl     : comment entrer dans la VM\n\n");

#ifdef __linux__
    /* Verifier le support VT-x */
    printf("    Support virtualisation CPU :\n");
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        int vmx = 0, svm = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "vmx")) vmx = 1;
            if (strstr(line, "svm")) svm = 1;
        }
        fclose(fp);
        if (vmx) printf("      Intel VT-x : supporte\n");
        else if (svm) printf("      AMD-V (SVM) : supporte\n");
        else printf("      Pas de support virtualisation detecte\n");
    }
    printf("\n");
#endif
}

/*
 * Etape 3 : Memoire virtuelle et EPT
 */
static void explain_memory_virtualization(void) {
    printf("[*] Etape 3 : Virtualisation memoire\n\n");

    printf("    Sans EPT (Shadow Page Tables) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Guest VA -> Guest PA -> Host PA\n");
    printf("    (lent, l'hyperviseur doit intercepter)\n\n");

    printf("    Avec EPT / NPT :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Guest VA -> Guest PA (guest page tables)\n");
    printf("    Guest PA -> Host PA  (EPT, en hardware)\n");
    printf("    (rapide, traduction en hardware)\n\n");

    printf("    ┌──────────────────────────────────┐\n");
    printf("    │  Guest                            │\n");
    printf("    │  VA -> PA (CR3 du guest)          │\n");
    printf("    │         │                         │\n");
    printf("    │         v                         │\n");
    printf("    │  EPT (Extended Page Tables)       │\n");
    printf("    │  Guest PA -> Host PA              │\n");
    printf("    │  (geree par l'hyperviseur)        │\n");
    printf("    └──────────────────────────────────┘\n\n");

    printf("    EPT violations :\n");
    printf("    - Acces a une page non mappee -> VM Exit\n");
    printf("    - L'hyperviseur peut intercepter tout acces memoire\n");
    printf("    - Utilise pour le monitoring et la securite\n\n");
}

/*
 * Etape 4 : Virtualisation I/O
 */
static void explain_io_virtualization(void) {
    printf("[*] Etape 4 : Virtualisation I/O\n\n");

    printf("    Methodes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Methode         | Performance | Complexite\n");
    printf("    ────────────────|─────────────|──────────\n");
    printf("    Emulation       | Faible      | Faible\n");
    printf("    Paravirtualise  | Bonne       | Moyenne\n");
    printf("    Passthrough     | Native      | Elevee\n");
    printf("    SR-IOV          | Native      | Elevee\n\n");

    printf("    Emulation : peripheriques virtuels\n");
    printf("    -> e1000 (reseau), IDE/AHCI (disque)\n");
    printf("    -> Chaque acces I/O = VM Exit\n\n");

    printf("    Paravirtualisation (virtio) :\n");
    printf("    -> Le guest sait qu'il est virtualise\n");
    printf("    -> Drivers optimises (virtio-net, virtio-blk)\n");
    printf("    -> Shared memory entre host et guest\n\n");

    printf("    Passthrough (VFIO / VT-d) :\n");
    printf("    -> Le peripherique physique est assigne a la VM\n");
    printf("    -> Acces direct, performance native\n");
    printf("    -> IOMMU pour l'isolation DMA\n\n");
}

/*
 * Etape 5 : Hyperviseurs principaux
 */
static void explain_hypervisors(void) {
    printf("[*] Etape 5 : Hyperviseurs principaux\n\n");

    printf("    Hyperviseur    | Type | Usage\n");
    printf("    ───────────────|──────|────────────────────\n");
    printf("    KVM            | 1    | Linux, cloud\n");
    printf("    Xen            | 1    | AWS (historique)\n");
    printf("    ESXi (VMware)  | 1    | Entreprise\n");
    printf("    Hyper-V        | 1    | Microsoft Azure\n");
    printf("    QEMU           | 2    | Emulation + KVM\n");
    printf("    VirtualBox     | 2    | Desktop\n");
    printf("    VMware WS      | 2    | Desktop\n");
    printf("    Parallels      | 2    | macOS\n");
    printf("    AWS Nitro      | 1    | Cloud AWS\n\n");

#ifdef __linux__
    /* Verifier KVM */
    printf("    Detection KVM sur ce systeme :\n");
    struct stat st;
    if (stat("/dev/kvm", &st) == 0)
        printf("      /dev/kvm : present (KVM disponible)\n");
    else
        printf("      /dev/kvm : absent\n");

    /* Verifier les modules */
    FILE *fp = fopen("/proc/modules", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "kvm_intel") || strstr(line, "kvm_amd") ||
                strstr(line, "kvm ")) {
                line[strcspn(line, "\n")] = '\0';
                printf("      Module : %s\n", line);
            }
        }
        fclose(fp);
    }
    printf("\n");
#endif
}

/*
 * Etape 6 : Implications securite
 */
static void explain_security(void) {
    printf("[*] Etape 6 : Implications securite\n\n");

    printf("    Surface d'attaque :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - VM Escape : sortir de la VM vers l'hote\n");
    printf("    - Hyperjacking : installer un rootkit hyperviseur\n");
    printf("    - Side-channel : Spectre/Meltdown entre VMs\n");
    printf("    - DoS : epuiser les ressources de l'hote\n\n");

    printf("    Protections :\n");
    printf("    - Isolation memoire (EPT/NPT)\n");
    printf("    - IOMMU pour l'isolation DMA\n");
    printf("    - Hyperviseur minimal (microkernel)\n");
    printf("    - Secure Boot pour l'hyperviseur\n");
    printf("    - Mise a jour reguliere du firmware\n\n");
}

int main(void) {
    printf("[*] Demo : Virtualization Basics\n\n");

    explain_virtualization();
    explain_vt_extensions();
    explain_memory_virtualization();
    explain_io_virtualization();
    explain_hypervisors();
    explain_security();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

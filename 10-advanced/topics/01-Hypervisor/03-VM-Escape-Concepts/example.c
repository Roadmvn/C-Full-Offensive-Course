/*
 * OBJECTIF  : Comprendre les concepts d'evasion de VM
 * PREREQUIS : Bases C, virtualisation, architecture hyperviseur
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les concepts d'evasion de VM :
 * surface d'attaque, CVE historiques, techniques,
 * et mitigations.
 * Demonstration pedagogique (theorie uniquement).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Etape 1 : Surface d'attaque d'un hyperviseur
 */
static void explain_attack_surface(void) {
    printf("[*] Etape 1 : Surface d'attaque\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  VM (Guest)                               │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ Attaquant dans la VM              │    │\n");
    printf("    │  └──┬───────┬────────┬──────┬──────┘    │\n");
    printf("    │     │       │        │      │            │\n");
    printf("    │     v       v        v      v            │\n");
    printf("    │  Reseau  Disque  Affichage  USB          │\n");
    printf("    │  virtuel virtuel  virtuel  virtuel       │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  Hyperviseur (VMM)                       │\n");
    printf("    │  - Emulation peripheriques               │\n");
    printf("    │  - Gestion memoire (EPT)                 │\n");
    printf("    │  - Gestion interruptions                 │\n");
    printf("    │  - Paravirtualisation                    │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  Hote / Hardware                         │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Vecteurs d'attaque principaux :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Emulation de peripheriques\n");
    printf("       -> Carte reseau, disque, USB, GPU\n");
    printf("    2. Traitement des VM Exits\n");
    printf("       -> Instructions privilegiees mal gerees\n");
    printf("    3. Memoire partagee\n");
    printf("       -> Clipboard, dossiers partages\n");
    printf("    4. Guest tools / additions\n");
    printf("       -> Services qui tournent en root\n\n");
}

/*
 * Etape 2 : CVE historiques
 */
static void explain_historical_cves(void) {
    printf("[*] Etape 2 : CVE historiques de VM Escape\n\n");

    printf("    CVE              | Produit      | Description\n");
    printf("    ─────────────────|──────────────|──────────────────────\n");
    printf("    CVE-2015-3456   | QEMU         | VENOM (floppy driver)\n");
    printf("    CVE-2017-4901   | VMware       | DnD/CopyPaste heap OOB\n");
    printf("    CVE-2018-3646   | Intel        | L1TF (foreshadow)\n");
    printf("    CVE-2019-5183   | VirtualBox   | NAT (slirp) RCE\n");
    printf("    CVE-2020-3962   | VMware       | SVGA heap OOB\n");
    printf("    CVE-2021-22045  | VMware       | CD-ROM heap overflow\n");
    printf("    CVE-2023-20858  | VMware       | VMX process escape\n\n");

    printf("    VENOM (CVE-2015-3456) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Floppy Disk Controller (FDC) emule dans QEMU\n");
    printf("    - Buffer overflow dans le traitement des commandes\n");
    printf("    - Permet execution de code dans le processus QEMU\n");
    printf("    - Affecte : QEMU, KVM, Xen, VirtualBox\n\n");

    printf("    VMware DnD (CVE-2017-4901) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Drag and Drop / Copy-Paste entre guest et host\n");
    printf("    - Heap out-of-bounds dans vmware-vmx\n");
    printf("    - Exploite au Pwn2Own 2017\n");
    printf("    - RCE dans le processus VMX sur l'hote\n\n");
}

/*
 * Etape 3 : Techniques d'exploitation
 */
static void explain_exploitation(void) {
    printf("[*] Etape 3 : Techniques d'exploitation\n\n");

    printf("    1. Buffer overflow dans l'emulation :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Le guest envoie des donnees au peripherique virtuel\n");
    printf("    -> Le code d'emulation (QEMU/VMware) a un bug\n");
    printf("    -> Overflow dans le processus de l'hyperviseur\n");
    printf("    -> RCE sur l'hote\n\n");

    printf("    2. Use-after-free dans le VMM :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Le guest declenche la creation/destruction\n");
    printf("    -> d'objets dans l'hyperviseur\n");
    printf("    -> Race condition -> UAF\n");
    printf("    -> Controle du flux d'execution\n\n");

    printf("    3. Confused deputy via shared resources :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Le guest abuse d'une fonctionnalite partagee\n");
    printf("    -> (clipboard, drag-drop, dossiers partages)\n");
    printf("    -> Pour ecrire/lire sur l'hote\n\n");

    printf("    4. Side-channel attacks :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Spectre/Meltdown entre VMs\n");
    printf("    -> L1TF (Foreshadow) : lire le cache L1\n");
    printf("    -> MDS : lire les buffers microarchitecturaux\n\n");
}

/*
 * Etape 4 : QEMU/KVM attack surface
 */
static void explain_qemu_surface(void) {
    printf("[*] Etape 4 : Surface d'attaque QEMU/KVM\n\n");

    printf("    Peripheriques emules vulnerables :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Peripherique | Risque | Bugs historiques\n");
    printf("    ─────────────|────────|─────────────────\n");
    printf("    e1000/rtl8139| Eleve  | Multiples OOB\n");
    printf("    virtio-net   | Moyen  | Integer overflow\n");
    printf("    USB (UHCI)   | Eleve  | Buffer overflow\n");
    printf("    IDE/AHCI     | Moyen  | OOB write\n");
    printf("    VGA/SVGA     | Eleve  | Heap overflow\n");
    printf("    Floppy (FDC) | Eleve  | VENOM\n");
    printf("    Sound (AC97) | Moyen  | Integer overflow\n\n");

    printf("    Architecture QEMU :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - QEMU tourne en userspace sur l'hote\n");
    printf("    - Chaque VM = un processus QEMU\n");
    printf("    - RCE dans QEMU = code sur l'hote\n");
    printf("    - Souvent lance en root (ou avec capabilities)\n\n");

    printf("    Mitigations QEMU :\n");
    printf("    - seccomp sandbox\n");
    printf("    - SELinux/AppArmor confinement\n");
    printf("    - Memory ballooning limits\n");
    printf("    - Desactiver les peripheriques non necessaires\n\n");
}

/*
 * Etape 5 : Protections et mitigations
 */
static void explain_mitigations(void) {
    printf("[*] Etape 5 : Protections et mitigations\n\n");

    printf("    Reduire la surface d'attaque :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Desactiver les peripheriques inutiles\n");
    printf("    - Utiliser virtio (moins de code d'emulation)\n");
    printf("    - Desactiver clipboard/drag-drop\n");
    printf("    - Pas de dossiers partages en production\n\n");

    printf("    Isolation :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - SELinux/AppArmor pour confiner QEMU\n");
    printf("    - seccomp pour limiter les syscalls\n");
    printf("    - Namespaces/cgroups\n");
    printf("    - IOMMU pour l'isolation DMA\n\n");

    printf("    Architecture securisee :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - microVMs (Firecracker, Cloud Hypervisor)\n");
    printf("    - Minimal hypervisor (moins de code)\n");
    printf("    - Hardware-backed isolation (Intel TDX, AMD SEV)\n");
    printf("    - Confidential computing\n\n");
}

/*
 * Etape 6 : Detection d'une evasion
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection\n\n");

    printf("    Indicateurs d'une tentative d'evasion :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Acces anormaux aux peripheriques emules\n");
    printf("    - Crash du processus QEMU/VMware\n");
    printf("    - Ecriture dans des zones memoire interdites\n");
    printf("    - Tentatives de communication host-guest anormales\n\n");

    printf("    Monitoring :\n");
    printf("    - Logs de l'hyperviseur\n");
    printf("    - Audit des appels hypercall\n");
    printf("    - Surveillance des crashes QEMU\n");
    printf("    - Analyse des core dumps\n\n");
}

int main(void) {
    printf("[*] Demo : VM Escape Concepts\n\n");

    explain_attack_surface();
    explain_historical_cves();
    explain_exploitation();
    explain_qemu_surface();
    explain_mitigations();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

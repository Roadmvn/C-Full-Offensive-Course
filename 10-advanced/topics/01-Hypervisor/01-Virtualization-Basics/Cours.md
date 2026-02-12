# Module A01 : Bases de la Virtualisation

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre les concepts fondamentaux de la virtualisation matérielle
- [ ] Maîtriser les extensions VT-x/VMX d'Intel
- [ ] Identifier les différents types d'hyperviseurs
- [ ] Détecter et exploiter les capacités de virtualisation en C
- [ ] Appliquer ces connaissances dans un contexte offensif (rootkits hyperviseur)

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Architecture x86/x64 (registres, modes CPU)
- Notions de systèmes d'exploitation (Ring 0/Ring 3)
- Assembleur x86 de base

## Introduction

La virtualisation permet d'exécuter plusieurs systèmes d'exploitation sur une même machine physique. Comprendre son fonctionnement est essentiel pour la sécurité offensive, notamment pour développer des rootkits hyperviseurs (hyperjacking) ou échapper aux sandboxes.

### Pourquoi ce sujet est important ?

Imaginez une maison (le système d'exploitation) construite sur un terrain (le matériel). La virtualisation, c'est comme construire plusieurs maisons sur le même terrain en utilisant un architecte spécial (l'hyperviseur) qui gère l'espace et les ressources.

Pour un Red Teamer :
- **Persistance ultime** : Un rootkit hyperviseur s'exécute sous l'OS (plus furtif que Ring 0)
- **Évasion de détection** : Comprendre la virtualisation permet de détecter les sandboxes
- **Attaques avancées** : VM escape, hyperjacking, blue pill

## 1. Concepts fondamentaux

### 1.1 Qu'est-ce que la virtualisation matérielle ?

La virtualisation matérielle est une technologie CPU qui permet d'exécuter un système invité (guest) isolé du système hôte (host).

```
┌─────────────────────────────────────────────────┐
│                Applications                      │ Ring 3
├─────────────────────────────────────────────────┤
│            Guest OS (Linux/Windows)              │ Ring 0 (virtualisé)
├─────────────────────────────────────────────────┤
│         Hyperviseur (KVM, Xen, ESXi)            │ VMX Root Mode
├─────────────────────────────────────────────────┤
│    CPU avec VT-x/AMD-V + Matériel physique      │ Hardware
└─────────────────────────────────────────────────┘
```

**Analogie** : C'est comme une pièce de théâtre :
- Le CPU est la scène
- L'hyperviseur est le metteur en scène
- Les VMs sont les acteurs qui croient jouer seuls sur scène
- Le hardware est le bâtiment du théâtre

### 1.2 Les extensions VT-x (Intel) et AMD-V

**VT-x** (Virtualization Technology) ajoute deux nouveaux modes au CPU :
- **VMX Root Mode** : Où s'exécute l'hyperviseur (plus puissant que Ring 0)
- **VMX Non-Root Mode** : Où s'exécute le guest OS (croit être en Ring 0)

```
Mode CPU classique:
Ring 3 (User) → Ring 0 (Kernel) → Hardware

Mode VMX:
Guest Ring 3 → Guest Ring 0 (VMX Non-Root)
                      ↓ (VM Exit)
                Hyperviseur (VMX Root)
                      ↓
                  Hardware
```

**Instructions clés VT-x** :
- `VMXON` : Active le mode VMX
- `VMLAUNCH` / `VMRESUME` : Lance/reprend une VM
- `VMCALL` : Hypercall (appel depuis le guest vers l'hyperviseur)
- `VMXOFF` : Désactive le mode VMX

### 1.3 EPT (Extended Page Tables)

EPT est une technique de virtualisation de la mémoire qui permet de traduire les adresses du guest sans intervention logicielle.

```
Guest Virtual Address (GVA)
        ↓
Guest Page Tables (gérées par le guest OS)
        ↓
Guest Physical Address (GPA)
        ↓
EPT Tables (gérées par l'hyperviseur)
        ↓
Host Physical Address (HPA)
```

**Avantage pour Red Team** : L'EPT permet de cacher du code en créant des vues mémoire différentes (read vs execute).

## 2. Types d'hyperviseurs

### 2.1 Type 1 (Bare Metal)

L'hyperviseur s'exécute directement sur le hardware, sans OS hôte.

```
┌──────────┬──────────┬──────────┐
│  VM 1    │  VM 2    │  VM 3    │
│ (Linux)  │ (Windows)│ (BSD)    │
├──────────┴──────────┴──────────┤
│   Hyperviseur Type 1            │
│   (ESXi, Xen, Hyper-V)         │
├─────────────────────────────────┤
│         Hardware                │
└─────────────────────────────────┘
```

**Exemples** : VMware ESXi, Xen, Microsoft Hyper-V, KVM

### 2.2 Type 2 (Hosted)

L'hyperviseur s'exécute comme une application sur un OS hôte.

```
┌──────────┬──────────┐
│  VM 1    │  VM 2    │
├──────────┴──────────┤
│  Hyperviseur Type 2  │
│  (VirtualBox, VMware)│
├──────────────────────┤
│    OS Hôte (Linux)   │
├──────────────────────┤
│      Hardware        │
└──────────────────────┘
```

**Exemples** : VirtualBox, VMware Workstation, QEMU

### 2.3 Hyperviseur léger (Blue Pill)

Un hyperviseur minimal qui s'installe sous un OS déjà en cours d'exécution.

```
Avant Blue Pill:          Après Blue Pill:
┌────────────┐            ┌────────────┐
│     OS     │            │     OS     │ (devient un guest)
├────────────┤            ├────────────┤
│  Hardware  │            │ Blue Pill  │ (hyperviseur furtif)
└────────────┘            ├────────────┤
                          │  Hardware  │
                          └────────────┘
```

**Usage offensif** : Rootkit hyperviseur totalement furtif.

## 3. Détection des capacités VT-x en C

### 3.1 Vérifier le support VT-x avec CPUID

```c
#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>

int check_vmx_support(void) {
    uint32_t eax, ebx, ecx, edx;

    // CPUID.1:ECX.VMX[bit 5] indique le support VT-x
    __cpuid(1, eax, ebx, ecx, edx);

    if (ecx & (1 << 5)) {
        printf("[+] VT-x est supporté par le CPU\n");
        return 1;
    } else {
        printf("[-] VT-x n'est pas supporté\n");
        return 0;
    }
}

int check_vmx_enabled_in_bios(void) {
    uint32_t eax, edx;

    // Lire le MSR IA32_FEATURE_CONTROL (0x3A)
    // Nécessite Ring 0
    asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(0x3A));

    // Bit 0: Lock bit
    // Bit 2: Enable VMX outside SMX
    if ((eax & 0x5) == 0x5) {
        printf("[+] VT-x est activé dans le BIOS\n");
        return 1;
    } else {
        printf("[-] VT-x est désactivé dans le BIOS\n");
        return 0;
    }
}
```

### 3.2 Détecter si on est dans une VM

```c
#include <stdio.h>
#include <string.h>

int detect_hypervisor(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13];

    // CPUID.1:ECX.Hypervisor[bit 31]
    __cpuid(1, eax, ebx, ecx, edx);

    if (ecx & (1 << 31)) {
        printf("[+] Hyperviseur détecté\n");

        // CPUID.0x40000000 : Vendor ID de l'hyperviseur
        __cpuid(0x40000000, eax, ebx, ecx, edx);

        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);
        vendor[12] = '\0';

        printf("[+] Hyperviseur : %s\n", vendor);
        // VMwareVMware = VMware
        // KVMKVMKVM = KVM
        // Microsoft Hv = Hyper-V

        return 1;
    }

    printf("[-] Pas d'hyperviseur détecté\n");
    return 0;
}
```

## 4. VMCS (Virtual Machine Control Structure)

Le VMCS est une structure de données en mémoire qui contrôle le comportement d'une VM.

```
┌─────────────────────────────────────┐
│        VMCS (4 KB aligné)           │
├─────────────────────────────────────┤
│ Guest State Area                    │
│  - Registres CPU (RIP, RSP, etc.)  │
│  - Registres de contrôle (CR0, CR3)│
│  - Registres segment (CS, DS, etc.) │
├─────────────────────────────────────┤
│ Host State Area                     │
│  - État où revenir après VM Exit    │
├─────────────────────────────────────┤
│ VM Execution Control Fields         │
│  - Quelles instructions causent Exit│
│  - Configuration EPT                │
├─────────────────────────────────────┤
│ VM Exit Control Fields              │
│  - Que faire lors d'un VM Exit      │
└─────────────────────────────────────┘
```

**Instructions pour manipuler le VMCS** :
- `VMPTRLD` : Charge un VMCS
- `VMREAD` : Lit un champ du VMCS
- `VMWRITE` : Écrit un champ du VMCS
- `VMCLEAR` : Désactive un VMCS

## 5. VM Exit et VM Entry

### 5.1 Qu'est-ce qu'un VM Exit ?

Un **VM Exit** est un événement qui suspend l'exécution du guest et transfert le contrôle à l'hyperviseur.

```
Guest exécute:          VM Exit déclenché:       Hyperviseur traite:
┌─────────────┐         ┌─────────────┐         ┌──────────────┐
│   mov cr3   │ ───────>│  Sauvegarde │ ───────>│ Gère l'event │
│             │         │  état guest │         │ (ex: émule)  │
└─────────────┘         └─────────────┘         └──────────────┘
                                                        │
                                                        v
                                                  VM Entry (VMRESUME)
                                                  Retour au guest
```

**Causes communes de VM Exit** :
- Accès à des registres de contrôle (CR3, CR4)
- Instructions privilégiées (CPUID, RDMSR, WRMSR)
- Exceptions (page fault)
- Interruptions externes
- Instructions configurées (VMCALL)

### 5.2 Exemple de flux

```
1. Guest exécute CPUID
2. CPU déclenche VM Exit (car CPUID configuré pour exit)
3. Hyperviseur :
   - Lit la raison (VMCS Exit Reason)
   - Émule CPUID (modifie les valeurs de retour)
   - Incrémente RIP du guest
4. VMRESUME : retour au guest
5. Guest reçoit les valeurs CPUID modifiées
```

## 6. Applications Offensives

### 6.1 Blue Pill - Rootkit Hyperviseur

Un rootkit hyperviseur s'installe sous l'OS en cours d'exécution :

```c
// Concept simplifié - NE PAS UTILISER tel quel
void install_bluepill(void) {
    // 1. Activer VMX
    asm volatile("vmxon %0" : : "m"(vmxon_region));

    // 2. Initialiser le VMCS
    asm volatile("vmclear %0" : : "m"(vmcs));
    asm volatile("vmptrld %0" : : "m"(vmcs));

    // 3. Configurer Guest State = état actuel du CPU
    vmwrite(GUEST_RIP, read_rip());
    vmwrite(GUEST_RSP, read_rsp());
    // ... (tous les registres)

    // 4. Configurer Host State = handler VM Exit
    vmwrite(HOST_RIP, (uint64_t)vmexit_handler);

    // 5. Lancer la VM (l'OS actuel devient un guest)
    asm volatile("vmlaunch");

    // À partir d'ici, l'OS s'exécute en VMX non-root
}
```

**Avantages offensifs** :
- Invisible depuis le guest (même pour le kernel)
- Peut intercepter toutes les opérations (CPUID, MSR, I/O)
- Persistance extrême (survit au reboot si installé dans le bootloader)

### 6.2 Hooking furtif avec EPT

L'EPT permet de créer des "split pages" : une page qui apparaît différente en lecture vs exécution.

```
Page contenant NtCreateFile():

Vue en lecture (EPT Read):     Vue en exécution (EPT Execute):
┌──────────────────┐          ┌──────────────────┐
│  Code original   │          │  Code trojan     │
│  NtCreateFile    │          │  + hook malware  │
└──────────────────┘          └──────────────────┘

Résultat :
- Antivirus lit le code original (clean)
- CPU exécute le code trojan (hooked)
```

### 6.3 Évasion de sandbox

Détecter qu'on est dans une VM pour éviter l'analyse :

```c
#include <stdio.h>
#include <time.h>

int evade_sandbox(void) {
    uint32_t ecx;
    clock_t start, end;

    // 1. Test CPUID Hypervisor bit
    __cpuid(1, eax, ebx, ecx, edx);
    if (ecx & (1 << 31)) {
        printf("[-] VM détectée (CPUID), abort\n");
        return 0;
    }

    // 2. Test timing (VMs sont plus lentes)
    start = clock();
    for (int i = 0; i < 1000000; i++) {
        asm volatile("nop");
    }
    end = clock();

    if ((end - start) > THRESHOLD) {
        printf("[-] VM détectée (timing), abort\n");
        return 0;
    }

    // 3. Continuer l'exécution malveillante
    printf("[+] Bare metal détecté, exécution\n");
    return 1;
}
```

## 7. Mise en pratique

### Étape 1 : Vérifier le support VT-x

Créez `check_vtx.c` :

```c
#include <stdio.h>
#include <cpuid.h>

int main(void) {
    uint32_t eax, ebx, ecx, edx;

    __cpuid(1, eax, ebx, ecx, edx);

    printf("=== Vérification VT-x ===\n");
    printf("VT-x supporté : %s\n", (ecx & (1 << 5)) ? "OUI" : "NON");
    printf("Hyperviseur présent : %s\n", (ecx & (1 << 31)) ? "OUI" : "NON");

    if (ecx & (1 << 31)) {
        __cpuid(0x40000000, eax, ebx, ecx, edx);
        char vendor[13];
        *(uint32_t*)&vendor[0] = ebx;
        *(uint32_t*)&vendor[4] = ecx;
        *(uint32_t*)&vendor[8] = edx;
        vendor[12] = '\0';
        printf("Vendor hyperviseur : %s\n", vendor);
    }

    return 0;
}
```

Compilez et exécutez :
```bash
gcc -o check_vtx check_vtx.c
./check_vtx
```

### Étape 2 : Expérimenter avec KVM

KVM (Kernel-based Virtual Machine) est un hyperviseur Linux accessible via `/dev/kvm`.

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>

int main(void) {
    int kvm_fd, vm_fd, vcpu_fd;

    // Ouvrir /dev/kvm
    kvm_fd = open("/dev/kvm", O_RDWR);
    if (kvm_fd < 0) {
        perror("[-] Impossible d'ouvrir /dev/kvm");
        return 1;
    }

    // Vérifier la version de l'API
    int api_version = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    printf("[+] KVM API version : %d\n", api_version);

    // Créer une VM
    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    printf("[+] VM créée : fd=%d\n", vm_fd);

    // Créer un vCPU
    vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    printf("[+] vCPU créé : fd=%d\n", vcpu_fd);

    return 0;
}
```

## 8. Considérations OPSEC

### 8.1 Détection d'un rootkit hyperviseur

**Indicateurs** :
- Performance dégradée (VM Exits fréquents)
- Timing anormal sur certaines instructions
- Incohérences dans les MSRs
- CPUID modifié

**Mitigation** :
- Minimiser les VM Exits (configuration fine du VMCS)
- Émuler parfaitement le hardware
- Utiliser des techniques anti-forensics

### 8.2 Contre-mesures défensives

- **Nested virtualization** : Exécuter dans une VM déjà virtualisée (empêche VMX)
- **SMM lock** : Verrouiller le mode System Management
- **Measured boot** : TPM vérifie l'intégrité du boot

## Résumé

- La virtualisation matérielle (VT-x/AMD-V) permet d'exécuter des VMs avec isolation
- VMX introduit deux modes : Root (hyperviseur) et Non-Root (guest)
- EPT permet de virtualiser la mémoire efficacement
- VMCS contrôle le comportement d'une VM
- VM Exit transfère le contrôle du guest vers l'hyperviseur
- Applications offensives : Blue Pill, hooking EPT, évasion sandbox
- Type 1 (bare metal) vs Type 2 (hosted) hyperviseurs
- CPUID permet de détecter VT-x et les hyperviseurs

## Checklist

- [ ] Comprendre la différence entre VMX Root et Non-Root
- [ ] Savoir ce qu'est le VMCS et son rôle
- [ ] Connaître les causes principales de VM Exit
- [ ] Savoir détecter VT-x avec CPUID en C
- [ ] Comprendre le concept de Blue Pill
- [ ] Savoir comment EPT permet le hooking furtif
- [ ] Identifier les techniques d'évasion de VM

## Exercices

Voir `exercice.md` pour les défis pratiques :
1. Implémenter une détection multi-méthodes de VM
2. Créer un timer de détection de sandbox
3. Expérimenter avec l'API KVM

## Ressources complémentaires

- Intel SDM Volume 3C : VMX (Software Developer Manual)
- "BluePill" par Joanna Rutkowska (2006) : https://theinvisiblethings.blogspot.com/
- Linux KVM Documentation : https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt
- "Hardware-Assisted Virtualization" (phrack)

---

**Navigation**
- [Retour au sommaire HYPERVISOR](../)
- [Module suivant : VM Detection](../02-VM-Detection/)

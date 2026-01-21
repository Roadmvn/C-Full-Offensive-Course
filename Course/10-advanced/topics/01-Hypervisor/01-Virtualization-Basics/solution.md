# Solutions - Virtualization Basics

## Solution Exercice 1 : Découverte (Très facile)

### Objectif
Se familiariser avec la détection des capacités de virtualisation du CPU.

### Code complet

```c
#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>
#include <string.h>

/*
 * Vérifie si le CPU supporte VT-x (Intel) ou AMD-V
 * Utilise l'instruction CPUID pour interroger les capacités du processeur
 */
int check_vmx_support(void) {
    uint32_t eax, ebx, ecx, edx;

    // CPUID fonction 1 : Feature Information
    // Le bit 5 de ECX indique le support VMX (Virtual Machine Extensions)
    __cpuid(1, eax, ebx, ecx, edx);

    if (ecx & (1 << 5)) {
        printf("[+] VT-x est supporté par ce CPU\n");
        return 1;
    } else {
        printf("[-] VT-x n'est PAS supporté\n");
        return 0;
    }
}

/*
 * Détecte si le système s'exécute actuellement dans un hyperviseur
 * Le bit 31 de ECX (CPUID.1) est le "Hypervisor Present Bit"
 */
int detect_hypervisor(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13];

    // CPUID fonction 1
    __cpuid(1, eax, ebx, ecx, edx);

    if (ecx & (1 << 31)) {
        printf("[+] Hyperviseur détecté !\n");

        // CPUID fonction 0x40000000 : Hypervisor Vendor ID
        // Cette fonction retourne l'identité de l'hyperviseur
        __cpuid(0x40000000, eax, ebx, ecx, edx);

        // Construire la chaîne vendor à partir des registres
        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);
        vendor[12] = '\0';

        printf("[+] Type d'hyperviseur : %s\n", vendor);

        // Identification des hyperviseurs courants
        if (strcmp(vendor, "VMwareVMware") == 0)
            printf("    -> VMware Workstation/ESXi\n");
        else if (strcmp(vendor, "KVMKVMKVM") == 0)
            printf("    -> KVM (Kernel-based Virtual Machine)\n");
        else if (strcmp(vendor, "Microsoft Hv") == 0)
            printf("    -> Microsoft Hyper-V\n");
        else if (strcmp(vendor, "VBoxVBoxVBox") == 0)
            printf("    -> Oracle VirtualBox\n");
        else if (strcmp(vendor, "XenVMMXenVMM") == 0)
            printf("    -> Xen Hypervisor\n");

        return 1;
    }

    printf("[-] Pas d'hyperviseur détecté (bare metal)\n");
    return 0;
}

int main(void) {
    printf("=== Détection des capacités de virtualisation ===\n\n");

    // Test 1 : Support matériel de la virtualisation
    check_vmx_support();

    printf("\n");

    // Test 2 : Détection d'hyperviseur
    detect_hypervisor();

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o virtualization_check solution1.c
./virtualization_check
```

### Résultat attendu

Sur un système bare metal avec VT-x :
```
=== Détection des capacités de virtualisation ===

[+] VT-x est supporté par ce CPU

[-] Pas d'hyperviseur détecté (bare metal)
```

Sur une VM VirtualBox :
```
=== Détection des capacités de virtualisation ===

[+] VT-x est supporté par ce CPU

[+] Hyperviseur détecté !
[+] Type d'hyperviseur : VBoxVBoxVBox
    -> Oracle VirtualBox
```

### Explications

**CPUID** est une instruction x86 qui permet d'interroger le CPU sur ses capacités. Elle fonctionne ainsi :
- On place un numéro de fonction dans EAX
- On exécute CPUID
- Le CPU retourne les informations dans EAX, EBX, ECX, EDX

**Bit 5 de ECX (CPUID.1)** : VMX support
**Bit 31 de ECX (CPUID.1)** : Hypervisor present

---

## Solution Exercice 2 : Détection multi-méthodes (Facile)

### Objectif
Combiner plusieurs techniques de détection pour plus de fiabilité.

### Code complet

```c
#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>
#include <time.h>

/*
 * Méthode 1 : CPUID Hypervisor Bit
 */
int detect_via_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx & (1 << 31)) ? 1 : 0;
}

/*
 * Méthode 2 : Timing Attack avec RDTSC
 * Les VMs introduisent de la latence lors des VM Exits
 */
int detect_via_timing(void) {
    uint64_t start, end;
    uint64_t total = 0;

    // Fonction inline pour lire le Time Stamp Counter
    static inline uint64_t rdtsc(void) {
        uint32_t lo, hi;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        return ((uint64_t)hi << 32) | lo;
    }

    // Mesurer 10 fois pour avoir une moyenne
    for (int i = 0; i < 10; i++) {
        start = rdtsc();

        // CPUID cause un VM Exit dans une VM
        uint32_t eax, ebx, ecx, edx;
        __cpuid(0, eax, ebx, ecx, edx);

        end = rdtsc();
        total += (end - start);
    }

    uint64_t average = total / 10;

    printf("[*] Latence CPUID moyenne : %llu cycles\n", average);

    // Sur bare metal : < 100 cycles
    // Sur VM : > 1000 cycles
    if (average > 500) {
        return 1;
    }

    return 0;
}

/*
 * Méthode 3 : Vérifier le nombre de CPUs
 * Les VMs ont souvent peu de vCPUs
 */
int detect_via_cpu_count(void) {
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

    printf("[*] Nombre de CPUs : %ld\n", cpu_count);

    // Suspect si <= 2 CPUs
    return (cpu_count <= 2) ? 1 : 0;
}

int main(void) {
    printf("=== Détection multi-méthodes ===\n\n");

    int score = 0;

    // Test 1 : CPUID
    printf("[Test 1] CPUID Hypervisor Bit\n");
    if (detect_via_cpuid()) {
        printf("  [+] VM détectée\n");
        score++;
    } else {
        printf("  [-] Bare metal\n");
    }

    printf("\n[Test 2] Timing Attack\n");
    if (detect_via_timing()) {
        printf("  [+] VM détectée\n");
        score++;
    } else {
        printf("  [-] Bare metal\n");
    }

    printf("\n[Test 3] CPU Count\n");
    if (detect_via_cpu_count()) {
        printf("  [+] VM suspectée\n");
        score++;
    } else {
        printf("  [-] Bare metal probable\n");
    }

    printf("\n========================================\n");
    printf("Score de détection : %d/3\n", score);

    if (score >= 2) {
        printf("VERDICT : Machine Virtuelle détectée\n");
    } else {
        printf("VERDICT : Probablement Bare Metal\n");
    }

    return 0;
}
```

### Compilation

```bash
gcc -o multidetect solution2.c
./multidetect
```

---

## Solution Exercice 3 : Exploration de /dev/kvm (Moyen)

### Objectif
Interagir avec l'API KVM pour créer une VM basique.

### Code complet

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <string.h>

int main(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    void *mem;
    struct kvm_userspace_memory_region region;
    struct kvm_run *run;

    printf("=== Création d'une VM avec KVM ===\n\n");

    // Étape 1 : Ouvrir /dev/kvm
    kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) {
        perror("[-] Impossible d'ouvrir /dev/kvm");
        printf("    Installez kvm ou exécutez en tant que root\n");
        return 1;
    }

    printf("[+] /dev/kvm ouvert : fd=%d\n", kvm_fd);

    // Vérifier la version de l'API KVM
    int api_version = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    if (api_version < 0) {
        perror("[-] KVM_GET_API_VERSION");
        return 1;
    }

    printf("[+] KVM API version : %d\n", api_version);
    if (api_version != 12) {
        fprintf(stderr, "[-] Version KVM non supportée\n");
        return 1;
    }

    // Étape 2 : Créer une VM
    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0) {
        perror("[-] KVM_CREATE_VM");
        return 1;
    }

    printf("[+] VM créée : fd=%d\n", vm_fd);

    // Étape 3 : Allouer de la mémoire pour la VM (1 MB)
    mem = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("[-] mmap");
        return 1;
    }

    printf("[+] Mémoire VM allouée : %p (1 MB)\n", mem);

    // Configurer la région mémoire de la VM
    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = 1 << 20;
    region.userspace_addr = (uint64_t)mem;

    if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("[-] KVM_SET_USER_MEMORY_REGION");
        return 1;
    }

    printf("[+] Région mémoire configurée\n");

    // Étape 4 : Créer un vCPU
    vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu_fd < 0) {
        perror("[-] KVM_CREATE_VCPU");
        return 1;
    }

    printf("[+] vCPU créé : fd=%d\n", vcpu_fd);

    // Mapper la structure kvm_run
    int run_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (run_size < 0) {
        perror("[-] KVM_GET_VCPU_MMAP_SIZE");
        return 1;
    }

    run = mmap(NULL, run_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, vcpu_fd, 0);
    if (run == MAP_FAILED) {
        perror("[-] mmap kvm_run");
        return 1;
    }

    printf("[+] Structure kvm_run mappée : %p\n", run);

    printf("\n[+] VM créée avec succès !\n");
    printf("    Pour exécuter du code, il faudrait :\n");
    printf("    1. Copier du code machine dans 'mem'\n");
    printf("    2. Initialiser les registres du vCPU (RIP, etc.)\n");
    printf("    3. Appeler ioctl(vcpu_fd, KVM_RUN, 0)\n");

    // Nettoyage
    munmap(run, run_size);
    munmap(mem, 1 << 20);
    close(vcpu_fd);
    close(vm_fd);
    close(kvm_fd);

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o kvm_test solution3.c
sudo ./kvm_test
```

### Résultat attendu

```
=== Création d'une VM avec KVM ===

[+] /dev/kvm ouvert : fd=3
[+] KVM API version : 12
[+] VM créée : fd=4
[+] Mémoire VM allouée : 0x7f... (1 MB)
[+] Région mémoire configurée
[+] vCPU créé : fd=5
[+] Structure kvm_run mappée : 0x7f...

[+] VM créée avec succès !
```

---

## Solution Exercice 4 : VM Minimal Hypervisor (Difficile)

### Objectif
Exécuter du code assembleur simple dans une VM KVM.

### Code complet

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <string.h>

/*
 * Code machine x86-64 à exécuter dans la VM
 *
 * Assembleur :
 *   mov rax, 42    ; Mettre 42 dans RAX
 *   hlt            ; Arrêter le CPU
 *
 * Opcodes :
 *   48 c7 c0 2a 00 00 00  ; mov rax, 42
 *   f4                     ; hlt
 */
const uint8_t guest_code[] = {
    0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00,  // mov rax, 42
    0xf4                                         // hlt
};

int main(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    void *mem;
    struct kvm_userspace_memory_region region;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    struct kvm_run *run;
    int run_size;

    printf("=== Hyperviseur minimal KVM ===\n\n");

    // Ouvrir KVM
    kvm_fd = open("/dev/kvm", O_RDWR);
    if (kvm_fd < 0) {
        perror("open /dev/kvm");
        return 1;
    }

    // Créer une VM
    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);

    // Allouer mémoire
    mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    // Copier le code guest dans la mémoire
    memcpy(mem, guest_code, sizeof(guest_code));

    printf("[+] Code guest copié en mémoire :\n");
    printf("    ");
    for (size_t i = 0; i < sizeof(guest_code); i++) {
        printf("%02x ", guest_code[i]);
    }
    printf("\n\n");

    // Configurer la région mémoire
    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0x1000;
    region.memory_size = 0x1000;
    region.userspace_addr = (uint64_t)mem;
    ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region);

    // Créer vCPU
    vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);

    // Mapper kvm_run
    run_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    run = mmap(NULL, run_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, vcpu_fd, 0);

    // Initialiser les registres spéciaux
    ioctl(vcpu_fd, KVM_GET_SREGS, &sregs);
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    ioctl(vcpu_fd, KVM_SET_SREGS, &sregs);

    // Initialiser les registres généraux
    memset(&regs, 0, sizeof(regs));
    regs.rip = 0x1000;  // Commencer à l'adresse 0x1000
    regs.rflags = 0x2;
    ioctl(vcpu_fd, KVM_SET_REGS, &regs);

    printf("[+] vCPU initialisé, RIP=0x%llx\n", regs.rip);
    printf("[+] Exécution du code guest...\n\n");

    // Exécuter la VM
    while (1) {
        ioctl(vcpu_fd, KVM_RUN, 0);

        switch (run->exit_reason) {
            case KVM_EXIT_HLT:
                printf("[+] VM arrêtée (HLT)\n");

                // Lire les registres finaux
                ioctl(vcpu_fd, KVM_GET_REGS, &regs);

                printf("\n[+] État final des registres :\n");
                printf("    RAX = %lld (0x%llx)\n", regs.rax, regs.rax);
                printf("    RIP = 0x%llx\n", regs.rip);

                if (regs.rax == 42) {
                    printf("\n[+] Succès ! RAX contient bien 42\n");
                }

                goto cleanup;

            case KVM_EXIT_IO:
                printf("[*] I/O operation\n");
                break;

            case KVM_EXIT_FAIL_ENTRY:
                printf("[-] VM Entry failed\n");
                goto cleanup;

            default:
                printf("[-] Exit reason inattendu : %d\n", run->exit_reason);
                goto cleanup;
        }
    }

cleanup:
    munmap(run, run_size);
    munmap(mem, 0x1000);
    close(vcpu_fd);
    close(vm_fd);
    close(kvm_fd);

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o minimal_hypervisor solution4.c
sudo ./minimal_hypervisor
```

### Résultat attendu

```
=== Hyperviseur minimal KVM ===

[+] Code guest copié en mémoire :
    48 c7 c0 2a 00 00 00 f4

[+] vCPU initialisé, RIP=0x1000
[+] Exécution du code guest...

[+] VM arrêtée (HLT)

[+] État final des registres :
    RAX = 42 (0x2a)
    RIP = 0x1008

[+] Succès ! RAX contient bien 42
```

### Explications

Ce programme démontre les concepts fondamentaux d'un hyperviseur :

1. **Création de la VM** : Allocation d'une machine virtuelle via KVM
2. **Mémoire guest** : Allocation et mapping de la mémoire pour la VM
3. **Code guest** : Injection de code machine à exécuter
4. **Configuration vCPU** : Initialisation des registres (RIP, segments)
5. **VM Execution Loop** : Boucle qui exécute le guest et gère les VM Exits

---

## Points clés à retenir

1. **CPUID** est l'outil principal pour détecter les capacités de virtualisation
2. **VT-x** (Intel) et **AMD-V** sont les extensions matérielles nécessaires
3. **KVM** expose une API simple via `/dev/kvm` pour créer des VMs
4. Un hyperviseur minimal nécessite : mémoire, vCPU, et une boucle d'exécution
5. Les **VM Exits** transfèrent le contrôle du guest vers l'hyperviseur

## Cas d'usage offensif

- **Blue Pill** : Installer un hyperviseur sous l'OS pour créer un rootkit furtif
- **Sandbox evasion** : Détecter les VMs pour éviter l'analyse
- **VM introspection** : Analyser la mémoire d'une VM depuis l'hyperviseur

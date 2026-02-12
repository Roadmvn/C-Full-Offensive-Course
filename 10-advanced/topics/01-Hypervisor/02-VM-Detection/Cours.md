# Module A02 : Détection de Machines Virtuelles

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre les différentes techniques de détection de VM
- [ ] Implémenter des checks anti-VM en C
- [ ] Identifier les artifacts laissés par les hyperviseurs
- [ ] Utiliser le timing pour détecter la virtualisation
- [ ] Contourner la détection (pour les défenseurs/analystes)

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Module A01 : Virtualisation basics
- Instructions CPUID et manipulation de registres
- Notions de système de fichiers et registre Windows

## Introduction

La détection de VM est cruciale pour les malwares modernes qui veulent éviter l'analyse dans des sandboxes. À l'inverse, les défenseurs doivent masquer les traces de virtualisation pour tromper les malwares.

### Pourquoi ce sujet est important ?

Imaginez un cambrioleur qui vérifie s'il est filmé avant d'agir. Les malwares font pareil : ils vérifient s'ils sont dans un environnement d'analyse (VM) avant d'exécuter leur payload.

Pour un Red Teamer :
- **Évasion de sandbox** : 90% des sandboxes utilisent des VMs
- **Anti-forensics** : Ne pas laisser de traces dans les environnements de test
- **OPSEC** : Détecter si votre implant est analysé

Pour un Blue Teamer :
- **Masquer la VM** : Rendre l'environnement d'analyse invisible
- **Honeypot** : Créer des faux positifs pour tromper les attaquants

## 1. Catégories de détection

### 1.1 Vue d'ensemble

```
┌─────────────────────────────────────────────────┐
│         Techniques de détection VM              │
├─────────────────┬───────────────────────────────┤
│ CPU/Hardware    │ - CPUID (hypervisor bit)      │
│                 │ - Instructions invalides      │
│                 │ - MSRs (Model Specific Reg)   │
├─────────────────┼───────────────────────────────┤
│ Timing          │ - RDTSC (Time Stamp Counter)  │
│                 │ - Latence des opérations      │
├─────────────────┼───────────────────────────────┤
│ Artifacts       │ - Fichiers système            │
│ Système         │ - Processus (VMwareTools)     │
│                 │ - Drivers (vmmouse, vmhgfs)   │
├─────────────────┼───────────────────────────────┤
│ Hardware        │ - MAC address                 │
│ Virtuel         │ - Disque (VBOX, VMware)       │
│                 │ - BIOS/SMBIOS strings         │
├─────────────────┼───────────────────────────────┤
│ Comportemental  │ - RAM/CPU anormaux            │
│                 │ - Ressources limitées         │
└─────────────────┴───────────────────────────────┘
```

## 2. Détection via CPUID

### 2.1 Le Hypervisor Bit

Le bit 31 de ECX (CPUID leaf 1) indique la présence d'un hyperviseur.

```
CPUID Function 0x1:
┌────────────────────────────────────────┐
│  EAX: Version Information              │
│  EBX: Additional Information           │
│  ECX: Feature Information              │
│       Bit 31: Hypervisor Present       │  <--- Detection
│  EDX: Feature Information              │
└────────────────────────────────────────┘
```

**Code de détection** :

```c
#include <stdio.h>
#include <cpuid.h>

int detect_vm_cpuid_hypervisor_bit(void) {
    uint32_t eax, ebx, ecx, edx;

    __cpuid(1, eax, ebx, ecx, edx);

    if (ecx & (1 << 31)) {
        printf("[!] VM détectée : Hypervisor bit activé\n");
        return 1;
    }

    printf("[+] Pas de VM détectée (hypervisor bit)\n");
    return 0;
}
```

### 2.2 Vendor ID de l'hyperviseur

Les hyperviseurs exposent leur identité via CPUID leaf 0x40000000.

```c
#include <string.h>

void detect_vm_vendor(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13];

    // Vérifier si hypervisor présent
    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx & (1 << 31))) {
        printf("[+] Pas d'hyperviseur\n");
        return;
    }

    // Lire le vendor ID
    __cpuid(0x40000000, eax, ebx, ecx, edx);

    *(uint32_t*)&vendor[0] = ebx;
    *(uint32_t*)&vendor[4] = ecx;
    *(uint32_t*)&vendor[8] = edx;
    vendor[12] = '\0';

    printf("[!] Hyperviseur détecté : %s\n", vendor);

    // Identifications connues
    if (strcmp(vendor, "VMwareVMware") == 0)
        printf("    -> VMware Workstation/ESXi\n");
    else if (strcmp(vendor, "KVMKVMKVM") == 0)
        printf("    -> KVM\n");
    else if (strcmp(vendor, "Microsoft Hv") == 0)
        printf("    -> Hyper-V\n");
    else if (strcmp(vendor, "VBoxVBoxVBox") == 0)
        printf("    -> VirtualBox\n");
    else if (strcmp(vendor, "XenVMMXenVMM") == 0)
        printf("    -> Xen\n");
}
```

### 2.3 Instructions invalides spécifiques

Certaines instructions ne fonctionnent que dans un contexte virtualisé.

```c
int detect_vmware_backdoor(void) {
    uint32_t eax, ebx, ecx, edx;

    // VMware backdoor : IN instruction sur port 0x5658 ('VX')
    // Fonctionne seulement sous VMware
    __try {
        asm volatile(
            "mov $0x564D5868, %%eax\n"  // Magic number
            "mov $0xA, %%ecx\n"         // Command (get version)
            "mov $0x5658, %%dx\n"       // Port 'VX'
            "in %%dx, %%eax\n"
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            :
            : "memory"
        );

        if (ebx == 0x564D5868) {
            printf("[!] VMware détecté (backdoor I/O)\n");
            return 1;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Exception = pas VMware
    }

    return 0;
}
```

## 3. Détection par Timing

### 3.1 RDTSC (Read Time Stamp Counter)

Les VMs introduisent de la latence. Mesurer le temps d'exécution révèle la virtualisation.

```
Bare Metal:                    VM:
┌──────────────┐              ┌──────────────┐
│ RDTSC        │              │ RDTSC        │
│ cycles: 100  │              │ cycles: 100  │
├──────────────┤              ├──────────────┤
│ CPUID        │              │ CPUID        │
│ +50 cycles   │              │ +5000 cycles │ <-- VM Exit coûteux
├──────────────┤              ├──────────────┤
│ RDTSC        │              │ RDTSC        │
│ cycles: 150  │              │ cycles: 5100 │
└──────────────┘              └──────────────┘
```

**Implémentation** :

```c
#include <stdint.h>

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int detect_vm_timing(void) {
    uint64_t start, end;
    uint64_t avg = 0;

    // Mesurer le coût de CPUID (déclenche VM Exit)
    for (int i = 0; i < 10; i++) {
        start = rdtsc();
        __cpuid(0, eax, ebx, ecx, edx);
        end = rdtsc();
        avg += (end - start);
    }

    avg /= 10;

    printf("[*] CPUID latence moyenne : %llu cycles\n", avg);

    // Seuil arbitraire (à calibrer)
    if (avg > 1000) {
        printf("[!] VM détectée (timing anormal)\n");
        return 1;
    }

    printf("[+] Pas de VM détectée (timing)\n");
    return 0;
}
```

### 3.2 Timing sur opérations mémoire

```c
int detect_vm_memory_timing(void) {
    uint64_t start, end;
    volatile int data[1000];

    // Écriture mémoire (peut déclencher EPT violations)
    start = rdtsc();
    for (int i = 0; i < 1000; i++) {
        data[i] = i;
    }
    end = rdtsc();

    uint64_t latency = end - start;
    printf("[*] Memory write latency : %llu cycles\n", latency);

    if (latency > 10000) {
        printf("[!] VM détectée (memory timing)\n");
        return 1;
    }

    return 0;
}
```

## 4. Détection via Artifacts Système

### 4.1 Fichiers et répertoires (Linux)

```c
#include <stdio.h>
#include <unistd.h>

int detect_vm_files_linux(void) {
    const char *vm_files[] = {
        "/sys/class/dmi/id/product_name",      // Contient "VirtualBox" ou "VMware"
        "/sys/class/dmi/id/sys_vendor",
        "/proc/scsi/scsi",                      // Disques VBOX, VMware
        "/dev/vboxguest",                       // VirtualBox Guest Additions
        "/dev/vboxuser",
        NULL
    };

    for (int i = 0; vm_files[i] != NULL; i++) {
        if (access(vm_files[i], F_OK) == 0) {
            printf("[!] VM artifact trouvé : %s\n", vm_files[i]);
            return 1;
        }
    }

    return 0;
}
```

### 4.2 Contenu DMI/SMBIOS

```c
#include <stdio.h>
#include <string.h>

int detect_vm_dmi(void) {
    FILE *fp;
    char buffer[256];
    const char *vm_strings[] = {
        "VMware", "VirtualBox", "QEMU", "Xen", "Bochs", "KVM", NULL
    };

    // Lire product_name
    fp = fopen("/sys/class/dmi/id/product_name", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            for (int i = 0; vm_strings[i] != NULL; i++) {
                if (strstr(buffer, vm_strings[i])) {
                    printf("[!] VM détectée : %s dans DMI\n", vm_strings[i]);
                    fclose(fp);
                    return 1;
                }
            }
        }
        fclose(fp);
    }

    return 0;
}
```

### 4.3 Processus suspects (Windows)

```c
#include <windows.h>
#include <tlhelp32.h>

int detect_vm_processes_windows(void) {
    const char *vm_processes[] = {
        "vmtoolsd.exe",      // VMware Tools
        "VBoxService.exe",   // VirtualBox
        "vmusrvc.exe",
        "vmsrvc.exe",
        "qemu-ga.exe",       // QEMU Guest Agent
        NULL
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            for (int i = 0; vm_processes[i] != NULL; i++) {
                if (strcasecmp(pe32.szExeFile, vm_processes[i]) == 0) {
                    printf("[!] Processus VM détecté : %s\n", vm_processes[i]);
                    CloseHandle(snapshot);
                    return 1;
                }
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return 0;
}
```

## 5. Détection Hardware Virtuel

### 5.1 MAC Address

Les VMs utilisent des plages MAC spécifiques.

```c
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

int detect_vm_mac(void) {
    const char *vm_mac_prefixes[] = {
        "00:05:69",  // VMware
        "00:0C:29",  // VMware
        "00:1C:14",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "52:54:00",  // QEMU/KVM
        NULL
    };

    struct ifaddrs *ifaddr, *ifa;
    char mac[18];

    if (getifaddrs(&ifaddr) == -1) {
        return 0;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x",
                     s->sll_addr[0], s->sll_addr[1], s->sll_addr[2]);

            for (int i = 0; vm_mac_prefixes[i] != NULL; i++) {
                if (strncasecmp(mac, vm_mac_prefixes[i], 8) == 0) {
                    printf("[!] VM MAC détectée : %s (prefix %s)\n",
                           mac, vm_mac_prefixes[i]);
                    freeifaddrs(ifaddr);
                    return 1;
                }
            }
        }
    }

    freeifaddrs(ifaddr);
    return 0;
}
```

### 5.2 Nom de disque/SCSI

```c
int detect_vm_disk(void) {
    FILE *fp = fopen("/proc/scsi/scsi", "r");
    if (!fp) return 0;

    char line[256];
    const char *vm_disks[] = {
        "VBOX", "VMware", "QEMU", "Virtual", NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; vm_disks[i] != NULL; i++) {
            if (strstr(line, vm_disks[i])) {
                printf("[!] Disque VM détecté : %s\n", line);
                fclose(fp);
                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}
```

## 6. Techniques avancées

### 6.1 CPU Core Count

Les VMs ont souvent peu de CPU.

```c
#include <unistd.h>

int detect_vm_cpu_count(void) {
    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("[*] CPUs disponibles : %ld\n", ncpus);

    if (ncpus <= 2) {
        printf("[!] VM suspectée (peu de CPUs)\n");
        return 1;
    }

    return 0;
}
```

### 6.2 RAM totale

```c
int detect_vm_ram(void) {
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long ram_mb = (pages * page_size) / (1024 * 1024);

    printf("[*] RAM totale : %ld MB\n", ram_mb);

    if (ram_mb < 2048) {  // Moins de 2GB
        printf("[!] VM suspectée (RAM faible)\n");
        return 1;
    }

    return 0;
}
```

## 7. Outil de détection complet

### 7.1 Framework multi-checks

```c
#include <stdio.h>

typedef struct {
    const char *name;
    int (*check)(void);
} vm_check_t;

vm_check_t vm_checks[] = {
    {"CPUID Hypervisor Bit", detect_vm_cpuid_hypervisor_bit},
    {"CPUID Vendor", detect_vm_vendor},
    {"Timing RDTSC", detect_vm_timing},
    {"Fichiers système", detect_vm_files_linux},
    {"DMI/SMBIOS", detect_vm_dmi},
    {"MAC Address", detect_vm_mac},
    {"Disque virtuel", detect_vm_disk},
    {"CPU Count", detect_vm_cpu_count},
    {"RAM", detect_vm_ram},
    {NULL, NULL}
};

int main(void) {
    int vm_score = 0;
    int total_checks = 0;

    printf("=== Détection de VM ===\n\n");

    for (int i = 0; vm_checks[i].name != NULL; i++) {
        printf("[*] Test : %s\n", vm_checks[i].name);
        if (vm_checks[i].check()) {
            vm_score++;
        }
        total_checks++;
        printf("\n");
    }

    printf("========================================\n");
    printf("Score : %d/%d checks positifs\n", vm_score, total_checks);

    if (vm_score >= 3) {
        printf("[!] VERDICT : Machine Virtuelle détectée\n");
        return 1;
    } else {
        printf("[+] VERDICT : Probablement Bare Metal\n");
        return 0;
    }
}
```

## 8. Applications Offensives

### 8.1 Malware anti-sandbox

```c
int main(void) {
    // Détection VM
    if (detect_vm_cpuid_hypervisor_bit() ||
        detect_vm_timing() ||
        detect_vm_mac()) {

        printf("[*] Sandbox détectée, mode furtif\n");

        // Comportement bénin
        printf("Hello World!\n");
        return 0;
    }

    // Payload malveillant (seulement sur bare metal)
    printf("[*] Bare metal détecté, exécution payload\n");
    // ... code malveillant ...

    return 0;
}
```

### 8.2 Sleep evasion

Les sandboxes accélèrent le temps. Détecter cette accélération :

```c
#include <time.h>
#include <unistd.h>

int detect_accelerated_time(void) {
    time_t start, end;
    uint64_t tsc_start, tsc_end;

    start = time(NULL);
    tsc_start = rdtsc();

    sleep(5);  // 5 secondes

    end = time(NULL);
    tsc_end = rdtsc();

    time_t elapsed_real = end - start;
    uint64_t elapsed_cycles = tsc_end - tsc_start;

    printf("[*] Temps réel : %ld s\n", elapsed_real);
    printf("[*] Cycles CPU : %llu\n", elapsed_cycles);

    // Si le temps réel < demandé, sandbox accélère
    if (elapsed_real < 4) {
        printf("[!] Temps accéléré détecté (sandbox)\n");
        return 1;
    }

    return 0;
}
```

## 9. Contournement de la détection

### 9.1 Masquer le hypervisor bit (défenseur)

Sur KVM, utiliser l'option `-cpu host,-hypervisor` :

```bash
qemu-system-x86_64 -cpu host,-hypervisor ...
```

### 9.2 Patcher les artifacts

```bash
# Modifier SMBIOS
qemu-system-x86_64 \
  -smbios type=0,vendor="American Megatrends Inc." \
  -smbios type=1,manufacturer="ASUS",product="ROG"
```

### 9.3 Randomiser MAC

```bash
# VirtualBox
VBoxManage modifyvm "VM" --macaddress1 auto

# Changer vers un vrai OUI (Organizational Unique Identifier)
VBoxManage modifyvm "VM" --macaddress1 001B638B2417
```

## 10. Considérations OPSEC

### 10.1 Pour l'attaquant

- **Multi-layer checks** : Combiner plusieurs méthodes (pas une seule)
- **Faux positifs** : Certains bare metal peuvent ressembler à des VMs
- **Timing calibration** : Adapter les seuils selon le CPU cible

### 10.2 Pour le défenseur

- **Masquer tous les artifacts** : DMI, MAC, processus, fichiers
- **Nested virtualization** : Rendre la détection inutile
- **Hardware passthrough** : Passer un vrai GPU pour éviter détection

## Résumé

- CPUID Hypervisor Bit (leaf 1, ECX bit 31) est la méthode la plus simple
- CPUID leaf 0x40000000 révèle l'identité de l'hyperviseur
- Timing avec RDTSC détecte la latence des VM Exits
- Artifacts système : fichiers, processus, drivers révèlent la VM
- Hardware virtuel : MAC, disques ont des signatures spécifiques
- Un malware robuste utilise plusieurs checks combinés
- Les défenseurs doivent masquer TOUS les indicators

## Checklist

- [ ] Implémenter un check CPUID hypervisor bit
- [ ] Détecter le vendor de l'hyperviseur
- [ ] Utiliser RDTSC pour mesurer la latence
- [ ] Scanner les artifacts système (fichiers, processus)
- [ ] Vérifier les MAC addresses suspectes
- [ ] Combiner plusieurs checks pour réduire les faux positifs
- [ ] Comprendre comment masquer une VM (défense)

## Exercices

Voir `exercice.md` pour les défis pratiques :
1. Créer un détecteur de VM multi-méthodes avec score
2. Implémenter un timing attack robuste
3. Bypass : configurer une VM indétectable

## Ressources complémentaires

- "Pafish" (Paranoid Fish) : https://github.com/a0rtega/pafish
- Al-Khaser : https://github.com/LordNoteworthy/al-khaser
- "Evasions Encyclopedia" : https://evasions.checkpoint.com/
- Papier "Tick Tock, Timeout: Timing Channels in Sandboxes"

---

**Navigation**
- [Module précédent : Virtualization Basics](../01-Virtualization-Basics/)
- [Module suivant : VM Escape Concepts](../03-VM-Escape-Concepts/)

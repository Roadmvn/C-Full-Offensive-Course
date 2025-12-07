# Solutions - VM Detection

## Solution Exercice 1 : Détection CPUID basique (Très facile)

### Objectif
Implémenter une détection de VM simple via CPUID.

### Code complet

```c
#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>
#include <string.h>

/*
 * Détecte la présence d'un hyperviseur via le bit 31 de ECX
 * Cette méthode est rapide mais peut être contournée
 */
int detect_hypervisor_bit(void) {
    uint32_t eax, ebx, ecx, edx;

    // CPUID fonction 1 : Feature Information
    __cpuid(1, eax, ebx, ecx, edx);

    // Bit 31 de ECX = Hypervisor Present Bit
    if (ecx & (1 << 31)) {
        printf("[!] Hyperviseur détecté (CPUID bit 31)\n");
        return 1;
    }

    printf("[+] Pas d'hyperviseur détecté\n");
    return 0;
}

/*
 * Récupère et affiche le vendor ID de l'hyperviseur
 */
void get_hypervisor_vendor(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13] = {0};

    // CPUID fonction 0x40000000 : Hypervisor CPUID Information
    __cpuid(0x40000000, eax, ebx, ecx, edx);

    // Construire la chaîne vendor
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);

    printf("[+] Hyperviseur vendor : '%s'\n", vendor);

    // Identification
    if (strcmp(vendor, "VMwareVMware") == 0)
        printf("    Type : VMware (Workstation/ESXi)\n");
    else if (strcmp(vendor, "KVMKVMKVM") == 0)
        printf("    Type : KVM (Linux)\n");
    else if (strcmp(vendor, "Microsoft Hv") == 0)
        printf("    Type : Microsoft Hyper-V\n");
    else if (strcmp(vendor, "VBoxVBoxVBox") == 0)
        printf("    Type : Oracle VirtualBox\n");
    else if (strcmp(vendor, "XenVMMXenVMM") == 0)
        printf("    Type : Xen Hypervisor\n");
    else if (strcmp(vendor, "prl hyperv  ") == 0)
        printf("    Type : Parallels\n");
    else
        printf("    Type : Inconnu ou custom\n");
}

int main(void) {
    printf("=== Détection VM via CPUID ===\n\n");

    if (detect_hypervisor_bit()) {
        get_hypervisor_vendor();
    }

    return 0;
}
```

### Compilation et test

```bash
gcc -o detect_cpuid solution1.c
./detect_cpuid
```

### Résultat sur VirtualBox

```
=== Détection VM via CPUID ===

[!] Hyperviseur détecté (CPUID bit 31)
[+] Hyperviseur vendor : 'VBoxVBoxVBox'
    Type : Oracle VirtualBox
```

---

## Solution Exercice 2 : Détection par timing (Facile)

### Objectif
Utiliser RDTSC pour détecter la latence anormale des VMs.

### Code complet

```c
#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>

/*
 * Lit le Time Stamp Counter (nombre de cycles CPU)
 */
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/*
 * Mesure la latence de l'instruction CPUID
 * Les VMs ont une latence plus élevée à cause des VM Exits
 */
int detect_vm_timing_cpuid(void) {
    uint64_t start, end, latency;
    uint64_t total = 0;
    const int iterations = 100;

    printf("[*] Mesure de la latence CPUID (%d itérations)...\n", iterations);

    // Warmup (éviter le cache miss initial)
    for (int i = 0; i < 10; i++) {
        uint32_t eax, ebx, ecx, edx;
        __cpuid(0, eax, ebx, ecx, edx);
    }

    // Mesures
    for (int i = 0; i < iterations; i++) {
        uint32_t eax, ebx, ecx, edx;

        start = rdtsc();
        __cpuid(0, eax, ebx, ecx, edx);  // Provoque VM Exit dans une VM
        end = rdtsc();

        latency = end - start;
        total += latency;
    }

    uint64_t average = total / iterations;

    printf("[*] Latence moyenne : %llu cycles\n", average);

    // Seuils empiriques (à ajuster selon le CPU)
    if (average < 100) {
        printf("[+] Bare metal probable (latence faible)\n");
        return 0;
    } else if (average < 1000) {
        printf("[?] Indéterminé (peut être bare metal rapide ou VM optimisée)\n");
        return 0;
    } else {
        printf("[!] VM détectée (latence élevée : VM Exit overhead)\n");
        return 1;
    }
}

/*
 * Mesure la latence des accès mémoire
 * Les VMs avec EPT peuvent avoir des latences différentes
 */
int detect_vm_timing_memory(void) {
    uint64_t start, end, latency;
    volatile int data[10000];

    printf("\n[*] Mesure de la latence mémoire...\n");

    start = rdtsc();
    for (int i = 0; i < 10000; i++) {
        data[i] = i;  // Écritures mémoire
    }
    end = rdtsc();

    latency = end - start;

    printf("[*] Latence écriture mémoire : %llu cycles\n", latency);

    // Sur bare metal : ~20000-50000 cycles
    // Sur VM : peut être plus élevé
    if (latency > 100000) {
        printf("[!] VM suspectée (latence mémoire élevée)\n");
        return 1;
    }

    printf("[+] Latence mémoire normale\n");
    return 0;
}

/*
 * Test de timing sur des instructions privilégiées
 */
int detect_vm_timing_rdtsc(void) {
    uint64_t t1, t2, t3;
    uint64_t delta1, delta2;

    printf("\n[*] Mesure de cohérence RDTSC...\n");

    t1 = rdtsc();
    t2 = rdtsc();
    t3 = rdtsc();

    delta1 = t2 - t1;
    delta2 = t3 - t2;

    printf("[*] Delta 1 : %llu cycles\n", delta1);
    printf("[*] Delta 2 : %llu cycles\n", delta2);

    // Sur bare metal, les deltas sont très petits et cohérents
    // Sur VM, RDTSC peut être intercepté et avoir des deltas plus grands
    if (delta1 > 100 || delta2 > 100) {
        printf("[!] Deltas anormaux, possible interception RDTSC\n");
        return 1;
    }

    printf("[+] RDTSC cohérent\n");
    return 0;
}

int main(void) {
    printf("=== Détection VM par Timing ===\n\n");

    int score = 0;

    if (detect_vm_timing_cpuid()) score++;
    if (detect_vm_timing_memory()) score++;
    if (detect_vm_timing_rdtsc()) score++;

    printf("\n========================================\n");
    printf("Score de détection timing : %d/3\n", score);

    if (score >= 2) {
        printf("VERDICT : VM détectée avec haute confiance\n");
    } else if (score == 1) {
        printf("VERDICT : VM possible, tests supplémentaires requis\n");
    } else {
        printf("VERDICT : Probablement bare metal\n");
    }

    return 0;
}
```

### Compilation et test

```bash
gcc -O0 -o detect_timing solution2.c
./detect_timing
```

### Résultat sur VM

```
=== Détection VM par Timing ===

[*] Mesure de la latence CPUID (100 itérations)...
[*] Latence moyenne : 3521 cycles
[!] VM détectée (latence élevée : VM Exit overhead)

[*] Mesure de la latence mémoire...
[*] Latence écriture mémoire : 45231 cycles
[+] Latence mémoire normale

[*] Mesure de cohérence RDTSC...
[*] Delta 1 : 42 cycles
[*] Delta 2 : 38 cycles
[+] RDTSC cohérent

========================================
Score de détection timing : 1/3
VERDICT : VM possible, tests supplémentaires requis
```

---

## Solution Exercice 3 : Détection via artifacts système (Moyen)

### Objectif
Scanner le système pour trouver des traces d'hyperviseur.

### Code complet

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

/*
 * Vérifie la présence de fichiers caractéristiques des VMs
 */
int check_vm_files(void) {
    const char *vm_files[] = {
        // VirtualBox
        "/dev/vboxguest",
        "/dev/vboxuser",
        "/sys/bus/pci/drivers/vboxguest",

        // VMware
        "/dev/vmci",
        "/proc/scsi/scsi",  // Contient "VMware" dans une VM VMware

        // General
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/bios_vendor",

        NULL
    };

    int detected = 0;

    printf("[*] Scan des fichiers système...\n");

    for (int i = 0; vm_files[i] != NULL; i++) {
        if (access(vm_files[i], F_OK) == 0) {
            printf("  [+] Trouvé : %s\n", vm_files[i]);

            // Lire le contenu si c'est un fichier DMI
            if (strstr(vm_files[i], "dmi/id")) {
                FILE *fp = fopen(vm_files[i], "r");
                if (fp) {
                    char buffer[256];
                    if (fgets(buffer, sizeof(buffer), fp)) {
                        buffer[strcspn(buffer, "\n")] = 0;  // Enlever \n
                        printf("      Contenu : %s\n", buffer);

                        // Chercher des mots-clés VM
                        const char *vm_keywords[] = {
                            "VMware", "VirtualBox", "QEMU", "KVM",
                            "Xen", "Bochs", "Parallels", "innotek",
                            NULL
                        };

                        for (int j = 0; vm_keywords[j] != NULL; j++) {
                            if (strstr(buffer, vm_keywords[j])) {
                                printf("      [!] Keyword VM trouvé : %s\n", vm_keywords[j]);
                                detected = 1;
                            }
                        }
                    }
                    fclose(fp);
                }
            } else {
                detected = 1;
            }
        }
    }

    return detected;
}

/*
 * Vérifie les périphériques PCI pour des vendors VM
 */
int check_pci_devices(void) {
    FILE *fp;
    char line[512];
    int detected = 0;

    printf("\n[*] Scan des périphériques PCI...\n");

    fp = fopen("/proc/bus/pci/devices", "r");
    if (!fp) {
        // Essayer une autre méthode
        fp = popen("lspci 2>/dev/null", "r");
        if (!fp) {
            printf("  [-] Impossible de lister les périphériques PCI\n");
            return 0;
        }
    }

    const char *vm_pci_keywords[] = {
        "VMware", "VirtualBox", "QEMU", "Red Hat", "Virtio",
        "Bochs", "Cirrus Logic", NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; vm_pci_keywords[i] != NULL; i++) {
            if (strcasestr(line, vm_pci_keywords[i])) {
                printf("  [!] Périphérique VM : %s", line);
                detected = 1;
                break;
            }
        }
    }

    pclose(fp);
    return detected;
}

/*
 * Vérifie les adresses MAC suspectes
 */
int check_mac_addresses(void) {
    FILE *fp;
    char line[256];
    int detected = 0;

    printf("\n[*] Vérification des adresses MAC...\n");

    fp = popen("ip link show 2>/dev/null", "r");
    if (!fp) {
        printf("  [-] Impossible de lire les interfaces réseau\n");
        return 0;
    }

    const char *vm_mac_prefixes[] = {
        "00:05:69",  // VMware
        "00:0c:29",  // VMware
        "00:1c:14",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "52:54:00",  // QEMU/KVM
        "00:16:3e",  // Xen
        NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        // Chercher les lignes avec "link/ether"
        if (strstr(line, "link/ether")) {
            char *mac = strstr(line, "link/ether") + 11;
            printf("  [*] MAC trouvée : %.17s\n", mac);

            for (int i = 0; vm_mac_prefixes[i] != NULL; i++) {
                if (strncasecmp(mac, vm_mac_prefixes[i], 8) == 0) {
                    printf("      [!] Prefix VM détecté : %s\n", vm_mac_prefixes[i]);
                    detected = 1;
                }
            }
        }
    }

    pclose(fp);
    return detected;
}

/*
 * Vérifie les modules kernel chargés
 */
int check_kernel_modules(void) {
    FILE *fp;
    char line[256];
    int detected = 0;

    printf("\n[*] Vérification des modules kernel...\n");

    fp = fopen("/proc/modules", "r");
    if (!fp) {
        printf("  [-] Impossible de lire /proc/modules\n");
        return 0;
    }

    const char *vm_modules[] = {
        "vboxguest", "vboxsf", "vboxvideo",  // VirtualBox
        "vmw_", "vmware", "vmxnet",          // VMware
        "virtio", "kvm",                      // KVM
        NULL
    };

    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; vm_modules[i] != NULL; i++) {
            if (strstr(line, vm_modules[i])) {
                printf("  [!] Module VM chargé : %s", line);
                detected = 1;
                break;
            }
        }
    }

    fclose(fp);
    return detected;
}

int main(void) {
    printf("=== Détection VM par Artifacts Système ===\n\n");

    int score = 0;

    if (check_vm_files()) score++;
    if (check_pci_devices()) score++;
    if (check_mac_addresses()) score++;
    if (check_kernel_modules()) score++;

    printf("\n========================================\n");
    printf("Score d'artifacts : %d/4\n", score);

    if (score >= 2) {
        printf("VERDICT : Machine Virtuelle détectée\n");
    } else if (score == 1) {
        printf("VERDICT : Indices de VM, vérification manuelle recommandée\n");
    } else {
        printf("VERDICT : Probablement Bare Metal\n");
    }

    return 0;
}
```

### Compilation et test

```bash
gcc -o detect_artifacts solution3.c
./detect_artifacts
```

---

## Solution Exercice 4 : Framework de détection complet (Difficile)

### Objectif
Combiner toutes les techniques dans un framework robuste.

### Code complet

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <cpuid.h>

// Structure pour stocker les résultats
typedef struct {
    int cpuid_hypervisor_bit;
    int cpuid_vendor_match;
    int timing_cpuid_anomaly;
    int timing_memory_anomaly;
    int files_vm_artifacts;
    int mac_address_vm;
    int cpu_count_low;
    int ram_size_low;
} detection_results_t;

// Prototypes
static inline uint64_t rdtsc(void);
int test_cpuid(detection_results_t *results);
int test_timing(detection_results_t *results);
int test_system(detection_results_t *results);
void print_report(detection_results_t *results);

/*
 * Lit le Time Stamp Counter
 */
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/*
 * Tests CPUID
 */
int test_cpuid(detection_results_t *results) {
    uint32_t eax, ebx, ecx, edx;

    printf("[*] Tests CPUID...\n");

    // Test hypervisor bit
    __cpuid(1, eax, ebx, ecx, edx);
    if (ecx & (1 << 31)) {
        printf("  [+] Hypervisor bit activé\n");
        results->cpuid_hypervisor_bit = 1;

        // Vérifier le vendor
        char vendor[13] = {0};
        __cpuid(0x40000000, eax, ebx, ecx, edx);
        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);

        printf("  [+] Vendor : %s\n", vendor);

        const char *known_vendors[] = {
            "VMwareVMware", "KVMKVMKVM", "Microsoft Hv",
            "VBoxVBoxVBox", "XenVMMXenVMM", NULL
        };

        for (int i = 0; known_vendors[i] != NULL; i++) {
            if (strcmp(vendor, known_vendors[i]) == 0) {
                results->cpuid_vendor_match = 1;
                break;
            }
        }
    }

    return results->cpuid_hypervisor_bit || results->cpuid_vendor_match;
}

/*
 * Tests de timing
 */
int test_timing(detection_results_t *results) {
    uint64_t start, end, total = 0;

    printf("\n[*] Tests de timing...\n");

    // Test CPUID latency
    for (int i = 0; i < 50; i++) {
        uint32_t eax, ebx, ecx, edx;
        start = rdtsc();
        __cpuid(0, eax, ebx, ecx, edx);
        end = rdtsc();
        total += (end - start);
    }

    uint64_t avg = total / 50;
    printf("  [*] CPUID latence : %llu cycles\n", avg);

    if (avg > 1000) {
        printf("  [+] Latence anormale détectée\n");
        results->timing_cpuid_anomaly = 1;
    }

    // Test memory latency
    volatile int data[1000];
    start = rdtsc();
    for (int i = 0; i < 1000; i++) data[i] = i;
    end = rdtsc();

    printf("  [*] Memory latence : %llu cycles\n", end - start);

    if ((end - start) > 50000) {
        results->timing_memory_anomaly = 1;
    }

    return results->timing_cpuid_anomaly || results->timing_memory_anomaly;
}

/*
 * Tests système
 */
int test_system(detection_results_t *results) {
    printf("\n[*] Tests système...\n");

    // Vérifier fichiers
    const char *files[] = {
        "/dev/vboxguest", "/sys/class/dmi/id/product_name", NULL
    };

    for (int i = 0; files[i] != NULL; i++) {
        if (access(files[i], F_OK) == 0) {
            results->files_vm_artifacts = 1;
            printf("  [+] Artifact trouvé : %s\n", files[i]);
        }
    }

    // CPU count
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("  [*] CPUs : %ld\n", cpus);
    if (cpus <= 2) {
        results->cpu_count_low = 1;
    }

    // RAM
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long ram_mb = (pages * page_size) / (1024 * 1024);
    printf("  [*] RAM : %ld MB\n", ram_mb);
    if (ram_mb < 2048) {
        results->ram_size_low = 1;
    }

    return results->files_vm_artifacts ||
           results->cpu_count_low ||
           results->ram_size_low;
}

/*
 * Génère le rapport final
 */
void print_report(detection_results_t *results) {
    int total_score = results->cpuid_hypervisor_bit +
                      results->cpuid_vendor_match +
                      results->timing_cpuid_anomaly +
                      results->timing_memory_anomaly +
                      results->files_vm_artifacts +
                      results->mac_address_vm +
                      results->cpu_count_low +
                      results->ram_size_low;

    printf("\n");
    printf("================== RAPPORT DE DÉTECTION ==================\n");
    printf("\n");
    printf("Tests CPUID :\n");
    printf("  Hypervisor bit         : %s\n", results->cpuid_hypervisor_bit ? "DÉTECTÉ" : "NON");
    printf("  Vendor match           : %s\n", results->cpuid_vendor_match ? "DÉTECTÉ" : "NON");
    printf("\n");
    printf("Tests Timing :\n");
    printf("  CPUID anomalie         : %s\n", results->timing_cpuid_anomaly ? "DÉTECTÉ" : "NON");
    printf("  Memory anomalie        : %s\n", results->timing_memory_anomaly ? "DÉTECTÉ" : "NON");
    printf("\n");
    printf("Tests Système :\n");
    printf("  Artifacts VM           : %s\n", results->files_vm_artifacts ? "DÉTECTÉ" : "NON");
    printf("  CPU count faible       : %s\n", results->cpu_count_low ? "DÉTECTÉ" : "NON");
    printf("  RAM faible             : %s\n", results->ram_size_low ? "DÉTECTÉ" : "NON");
    printf("\n");
    printf("==========================================================\n");
    printf("SCORE TOTAL : %d/8\n", total_score);
    printf("\n");

    if (total_score >= 3) {
        printf("VERDICT FINAL : Machine Virtuelle DÉTECTÉE (haute confiance)\n");
        printf("\nRecommandation :\n");
        printf("  - Arrêt de l'exécution si malware anti-sandbox\n");
        printf("  - Comportement alternatif en environnement VM\n");
    } else if (total_score >= 1) {
        printf("VERDICT FINAL : VM possible (confiance moyenne)\n");
        printf("\nRecommandation :\n");
        printf("  - Tests supplémentaires recommandés\n");
        printf("  - Prudence dans l'exécution\n");
    } else {
        printf("VERDICT FINAL : Probablement Bare Metal\n");
        printf("\nRecommandation :\n");
        printf("  - Environnement sûr pour exécution\n");
    }

    printf("==========================================================\n");
}

int main(void) {
    detection_results_t results = {0};

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     FRAMEWORK DE DÉTECTION VM - Version 1.0              ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");

    test_cpuid(&results);
    test_timing(&results);
    test_system(&results);

    print_report(&results);

    return (results.cpuid_hypervisor_bit || results.cpuid_vendor_match) ? 1 : 0;
}
```

### Compilation et test

```bash
gcc -O2 -o vm_detector solution4.c
./vm_detector
```

### Résultat sur VirtualBox

```
╔══════════════════════════════════════════════════════════╗
║     FRAMEWORK DE DÉTECTION VM - Version 1.0              ║
╚══════════════════════════════════════════════════════════╝

[*] Tests CPUID...
  [+] Hypervisor bit activé
  [+] Vendor : VBoxVBoxVBox

[*] Tests de timing...
  [*] CPUID latence : 2547 cycles
  [+] Latence anormale détectée
  [*] Memory latence : 8234 cycles

[*] Tests système...
  [+] Artifact trouvé : /dev/vboxguest
  [*] CPUs : 2
  [*] RAM : 4096 MB

================== RAPPORT DE DÉTECTION ==================

Tests CPUID :
  Hypervisor bit         : DÉTECTÉ
  Vendor match           : DÉTECTÉ

Tests Timing :
  CPUID anomalie         : DÉTECTÉ
  Memory anomalie        : NON

Tests Système :
  Artifacts VM           : DÉTECTÉ
  CPU count faible       : DÉTECTÉ
  RAM faible             : NON

==========================================================
SCORE TOTAL : 5/8

VERDICT FINAL : Machine Virtuelle DÉTECTÉE (haute confiance)

Recommandation :
  - Arrêt de l'exécution si malware anti-sandbox
  - Comportement alternatif en environnement VM
==========================================================
```

---

## Points clés à retenir

1. **CPUID** est la méthode la plus fiable mais peut être spoofée
2. **Timing attacks** détectent les VM Exits mais nécessitent calibration
3. **Artifacts système** sont nombreux mais dépendent de la configuration
4. **Combiner plusieurs méthodes** augmente la fiabilité
5. Un **score de confiance** permet de prendre des décisions robustes

## Application offensive

Un malware utiliserait ce framework pour :
- **Détecter les sandboxes** d'analyse (Cuckoo, ANY.RUN)
- **Adapter son comportement** : bénin en VM, malveillant sur bare metal
- **Évasion de détection** : ne pas révéler ses capacités en environnement d'analyse

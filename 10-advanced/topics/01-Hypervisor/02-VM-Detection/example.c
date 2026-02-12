/*
 * OBJECTIF  : Comprendre la detection de machines virtuelles
 * PREREQUIS : Bases C, CPUID, architecture x86, virtualisation
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de detection de VM :
 * CPUID, timing, artefacts systeme, registres speciaux,
 * et contre-mesures.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#ifdef __linux__
#include <sys/stat.h>
#endif

/*
 * Etape 1 : Pourquoi detecter une VM
 */
static void explain_vm_detection(void) {
    printf("[*] Etape 1 : Detection de machines virtuelles\n\n");

    printf("    Pourquoi detecter une VM :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Malware : eviter l'analyse en sandbox\n");
    printf("    - Red team : adapter le comportement\n");
    printf("    - DRM : detecter la virtualisation\n");
    printf("    - Forensics : identifier l'environnement\n\n");

    printf("    Techniques de detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. CPUID          : hypervisor brand string\n");
    printf("    2. Timing         : RDTSC, latence I/O\n");
    printf("    3. Artefacts      : fichiers, registres, MAC\n");
    printf("    4. Materiels      : DMI/SMBIOS, ACPI\n");
    printf("    5. Processus      : guest tools processes\n");
    printf("    6. Instructions   : comportement non standard\n\n");
}

/*
 * Etape 2 : Detection CPUID
 */
static void demo_cpuid_detection(void) {
    printf("[*] Etape 2 : Detection via CPUID\n\n");

#if defined(__x86_64__) || defined(__i386__)
    /* CPUID leaf 1 : hypervisor bit */
    unsigned int eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1));

    int hypervisor_bit = (ecx >> 31) & 1;
    printf("    CPUID leaf 1, ECX bit 31 (hypervisor) : %d\n",
           hypervisor_bit);
    printf("    -> %s\n\n",
           hypervisor_bit ? "HYPERVISEUR DETECTE" : "Pas d'hyperviseur");

    if (hypervisor_bit) {
        /* CPUID leaf 0x40000000 : hypervisor brand */
        __asm__ volatile("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(0x40000000));

        char brand[13] = {0};
        memcpy(brand + 0, &ebx, 4);
        memcpy(brand + 4, &ecx, 4);
        memcpy(brand + 8, &edx, 4);
        printf("    Hypervisor brand : \"%s\"\n", brand);

        /* Decoder le brand */
        if (strcmp(brand, "VMwareVMware") == 0)
            printf("    -> VMware detecte\n");
        else if (strcmp(brand, "KVMKVMKVM") == 0)
            printf("    -> KVM detecte\n");
        else if (strcmp(brand, "Microsoft Hv") == 0)
            printf("    -> Hyper-V detecte\n");
        else if (strcmp(brand, "XenVMMXenVMM") == 0)
            printf("    -> Xen detecte\n");
        else if (strcmp(brand, "VBoxVBoxVBox") == 0)
            printf("    -> VirtualBox detecte\n");
        else
            printf("    -> Hyperviseur inconnu\n");
    }
    printf("\n");
#else
    printf("    CPUID non disponible (non-x86)\n\n");

    /* Detection alternative via sysctl (macOS/ARM) */
    printf("    Detection alternative :\n");
    FILE *fp = popen("sysctl -n machdep.cpu.features 2>/dev/null | "
                     "grep -i VMM || echo '(pas de VMM flag)'", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
#endif

    printf("    Code de detection CPUID :\n");
    printf("    ───────────────────────────────────\n");
    printf("    unsigned int ecx;\n");
    printf("    __asm__(\"cpuid\" : \"=c\"(ecx) : \"a\"(1));\n");
    printf("    if ((ecx >> 31) & 1)\n");
    printf("        printf(\"VM detectee !\\n\");\n\n");
}

/*
 * Etape 3 : Detection par timing
 */
static void demo_timing_detection(void) {
    printf("[*] Etape 3 : Detection par timing\n\n");

    printf("    Les VM ont une latence plus elevee\n");
    printf("    sur certaines operations :\n\n");

    struct timespec start, end;

    /* Mesurer la latence d'un appel systeme */
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 1000; i++) {
        getpid();
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    long ns = (end.tv_sec - start.tv_sec) * 1000000000L +
              (end.tv_nsec - start.tv_nsec);
    long avg_ns = ns / 1000;

    printf("    1000x getpid() : %ld ns total, %ld ns/appel\n",
           ns, avg_ns);
    if (avg_ns > 500)
        printf("    [!] Latence elevee (possible VM)\n");
    else
        printf("    [OK] Latence normale\n");
    printf("\n");

    printf("    RDTSC timing (x86) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    uint64_t start = __rdtsc();\n");
    printf("    cpuid();  // instruction qui cause VM Exit\n");
    printf("    uint64_t end = __rdtsc();\n");
    printf("    if ((end - start) > 500)\n");
    printf("        // Possible VM (CPUID = ~100 cycles natif)\n\n");
}

/*
 * Etape 4 : Artefacts systeme
 */
static void demo_artifact_detection(void) {
    printf("[*] Etape 4 : Detection par artefacts\n\n");

#ifdef __linux__
    /* DMI/SMBIOS */
    printf("    DMI/SMBIOS :\n");
    const char *dmi_files[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        NULL
    };

    for (int i = 0; dmi_files[i]; i++) {
        FILE *fp = fopen(dmi_files[i], "r");
        if (fp) {
            char val[128] = {0};
            fgets(val, sizeof(val), fp);
            val[strcspn(val, "\n")] = '\0';
            fclose(fp);
            printf("      %s : %s\n", dmi_files[i], val);

            if (strstr(val, "VMware") || strstr(val, "VirtualBox") ||
                strstr(val, "QEMU") || strstr(val, "KVM") ||
                strstr(val, "Xen") || strstr(val, "Microsoft")) {
                printf("        [!] VM detectee !\n");
            }
        }
    }
    printf("\n");

    /* Fichiers specifiques aux VMs */
    printf("    Fichiers specifiques :\n");
    struct stat st;
    const char *vm_files[] = {
        "/sys/hypervisor/type",
        "/proc/scsi/scsi",
        "/sys/bus/pci/devices/0000:00:05.0",
        NULL
    };

    for (int i = 0; vm_files[i]; i++) {
        if (stat(vm_files[i], &st) == 0)
            printf("      %s : present\n", vm_files[i]);
    }
    printf("\n");
#endif

    printf("    Artefacts communs par hyperviseur :\n");
    printf("    ───────────────────────────────────\n");
    printf("    VMware     : vmtoolsd, vmware-rpctool\n");
    printf("    VirtualBox : VBoxService, VBoxClient\n");
    printf("    QEMU/KVM   : qemu-ga, virtio devices\n");
    printf("    Hyper-V    : hv_*, vmbus\n");
    printf("    Xen        : xenbus, xen-*\n\n");
}

/*
 * Etape 5 : Detection avancee
 */
static void explain_advanced_detection(void) {
    printf("[*] Etape 5 : Detection avancee\n\n");

    printf("    MAC address prefixes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    00:0C:29  : VMware\n");
    printf("    00:50:56  : VMware\n");
    printf("    08:00:27  : VirtualBox\n");
    printf("    52:54:00  : QEMU/KVM\n");
    printf("    00:15:5D  : Hyper-V\n\n");

    printf("    Registres speciaux :\n");
    printf("    ───────────────────────────────────\n");
    printf("    IDT/GDT/LDT base address :\n");
    printf("    - Sur un systeme natif : adresses classiques\n");
    printf("    - En VM : adresses decalees (technique Red Pill)\n\n");

    printf("    Port I/O VMware (backdoor) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Port 0x5658 (\"VX\") avec magic value\n");
    printf("    mov eax, 0x564D5868  // 'VMXh'\n");
    printf("    mov ecx, 0x0A        // get version\n");
    printf("    mov edx, 0x5658      // 'VX'\n");
    printf("    in eax, dx\n");
    printf("    // Si pas de crash -> VMware\n\n");
}

/*
 * Etape 6 : Contre-mesures et evasion
 */
static void explain_countermeasures(void) {
    printf("[*] Etape 6 : Contre-mesures\n\n");

    printf("    Masquer une VM :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Modifier le CPUID (hypervisor leaf)\n");
    printf("    - Changer les DMI/SMBIOS strings\n");
    printf("    - Modifier les MAC addresses\n");
    printf("    - Supprimer les guest tools\n");
    printf("    - Ajouter de la latence realiste\n\n");

    printf("    Outils anti-detection :\n");
    printf("    - VirtualBox : VBoxHarden\n");
    printf("    - VMware : vmx config (cpuid.0.eax = ...)\n");
    printf("    - KVM : cpu host mode\n");
    printf("    - al-khaser : test anti-VM/anti-debug\n\n");

    printf("    Detection pour les defenseurs :\n");
    printf("    - Les malwares qui detectent les VMs\n");
    printf("      sont suspects par defaut\n");
    printf("    - Analyse statique des checks VM\n");
    printf("    - Forcer l'execution avec les checks patched\n\n");
}

int main(void) {
    printf("[*] Demo : VM Detection\n\n");

    explain_vm_detection();
    demo_cpuid_detection();
    demo_timing_detection();
    demo_artifact_detection();
    explain_advanced_detection();
    explain_countermeasures();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

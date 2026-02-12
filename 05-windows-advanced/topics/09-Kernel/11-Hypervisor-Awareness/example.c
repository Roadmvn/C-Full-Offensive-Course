/*
 * OBJECTIF  : Detection et interaction avec les hyperviseurs
 * PREREQUIS : Architecture CPU, VT-x/AMD-V, CPUID
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les hyperviseurs (Hyper-V, VMware, VirtualBox) sont detectables.
 * Important pour les malwares (anti-sandbox) et les rootkits
 * (certains utilisent un hyperviseur custom).
 */

#include <windows.h>
#include <stdio.h>
#include <intrin.h>

void demo_cpuid_detection(void) {
    printf("[1] Detection hyperviseur via CPUID\n\n");

    /* CPUID leaf 1 : bit 31 de ECX = hyperviseur present */
    int regs[4] = {0};
    __cpuid(regs, 1);
    int hypervisor_present = (regs[2] >> 31) & 1;
    printf("    CPUID(1).ECX bit 31 : %d (%s)\n\n",
           hypervisor_present,
           hypervisor_present ? "HYPERVISEUR DETECTE" : "Bare metal");

    if (hypervisor_present) {
        /* CPUID leaf 0x40000000 : hyperviseur vendor string */
        __cpuid(regs, 0x40000000);
        char vendor[13] = {0};
        memcpy(vendor, &regs[1], 4);
        memcpy(vendor + 4, &regs[2], 4);
        memcpy(vendor + 8, &regs[3], 4);
        printf("    Vendor string : %s\n", vendor);

        /* Identifier l'hyperviseur */
        const char* name = "Inconnu";
        if (strncmp(vendor, "Microsoft Hv", 12) == 0) name = "Hyper-V / WSL2";
        else if (strncmp(vendor, "VMwareVMware", 12) == 0) name = "VMware";
        else if (strncmp(vendor, "VBoxVBoxVBox", 12) == 0) name = "VirtualBox";
        else if (strncmp(vendor, "KVMKVMKVM", 9) == 0) name = "KVM";
        else if (strncmp(vendor, "XenVMMXenVMM", 12) == 0) name = "Xen";
        printf("    Hyperviseur   : %s\n\n", name);

        /* CPUID leaf 0x40000001 : interface version (Hyper-V) */
        __cpuid(regs, 0x40000001);
        printf("    Interface ID  : %c%c%c%c\n\n",
               regs[0] & 0xFF, (regs[0] >> 8) & 0xFF,
               (regs[0] >> 16) & 0xFF, (regs[0] >> 24) & 0xFF);
    }
}

void demo_hardware_detection(void) {
    printf("[2] Detection VM via hardware\n\n");

    /* MAC address (premiers 3 octets = OUI du fabricant) */
    printf("    OUI des adaptateurs VM :\n");
    printf("    00:0C:29 / 00:50:56 - VMware\n");
    printf("    08:00:27             - VirtualBox\n");
    printf("    00:15:5D             - Hyper-V\n");
    printf("    52:54:00             - QEMU/KVM\n\n");

    /* Verifier le registre pour VMware */
    HKEY hKey;
    printf("    Artefacts registre :\n");
    const char* vm_keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\CurrentControlSet\\Services\\vmci",
        NULL
    };
    int i;
    for (i = 0; vm_keys[i]; i++) {
        LONG ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, vm_keys[i],
                                 0, KEY_READ, &hKey);
        printf("    [%c] %s\n", ret == ERROR_SUCCESS ? '+' : '-', vm_keys[i]);
        if (ret == ERROR_SUCCESS) RegCloseKey(hKey);
    }
    printf("\n");
}

void demo_timing_detection(void) {
    printf("[3] Detection par timing\n\n");
    printf("    Les instructions privilegiees sont plus lentes en VM\n");
    printf("    car elles causent un VM exit.\n\n");

    /* Mesurer le temps de CPUID */
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    /* CPUID timing */
    QueryPerformanceCounter(&start);
    int regs[4];
    int j;
    for (j = 0; j < 10000; j++)
        __cpuid(regs, 0);
    QueryPerformanceCounter(&end);

    double cpuid_us = (double)(end.QuadPart - start.QuadPart) * 1000000.0
                      / freq.QuadPart / 10000.0;
    printf("    CPUID moyen    : %.2f us\n", cpuid_us);

    /* RDTSC timing */
    QueryPerformanceCounter(&start);
    for (j = 0; j < 10000; j++)
        __rdtsc();
    QueryPerformanceCounter(&end);

    double rdtsc_us = (double)(end.QuadPart - start.QuadPart) * 1000000.0
                      / freq.QuadPart / 10000.0;
    printf("    RDTSC moyen    : %.2f us\n\n", rdtsc_us);

    printf("    Seuils typiques :\n");
    printf("    CPUID < 1 us  : probablement bare metal\n");
    printf("    CPUID > 5 us  : probablement VM\n");
    printf("    (les seuils varient selon le CPU)\n\n");
}

void demo_vbs(void) {
    printf("[4] VBS et l'hyperviseur Hyper-V\n\n");
    printf("    Windows 10/11 utilise Hyper-V pour la securite :\n\n");
    printf("    VTL1 (Secure World)     VTL0 (Normal World)\n");
    printf("    +------------------+    +------------------+\n");
    printf("    | Secure Kernel    |    | ntoskrnl.exe     |\n");
    printf("    | (securekernel)   |    | (noyau normal)   |\n");
    printf("    | Credential Guard |    | Drivers          |\n");
    printf("    | Code Integrity   |    | Applications     |\n");
    printf("    +------------------+    +------------------+\n");
    printf("              Hyper-V Hypervisor\n\n");

    printf("    Impact sur l'offensive :\n");
    printf("    - Credential Guard : LSASS isole dans VTL1\n");
    printf("    - HVCI : pages kernel non-modifiables\n");
    printf("    - g_CiOptions protege en VTL1\n");
    printf("    - Meme un rootkit kernel ne peut pas contourner VBS\n\n");

    /* Verifier VBS */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD vbs = 0, size = sizeof(vbs);
        RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity",
                         NULL, NULL, (BYTE*)&vbs, &size);
        printf("    VBS configure : %s\n", vbs ? "OUI" : "NON");
        RegCloseKey(hKey);
    }
    printf("\n");
}

void demo_anti_vm(void) {
    printf("[5] Anti-VM et evasion de sandbox\n\n");
    printf("    Les malwares detectent les VMs pour eviter l'analyse.\n");
    printf("    Les sandboxes contre-attaquent :\n\n");

    printf("    Techniques anti-detection :\n");
    printf("    - Masquer le CPUID hypervisor bit\n");
    printf("    - Changer les MAC addresses\n");
    printf("    - Supprimer les artefacts registre\n");
    printf("    - Ajuster les timings (RDTSC patching)\n");
    printf("    - Ajouter des fichiers/programmes realistes\n\n");

    printf("    Techniques de detection avancees :\n");
    printf("    - Nombre de fichiers recents\n");
    printf("    - Historique navigateur\n");
    printf("    - Taille du disque (< 60GB = suspect)\n");
    printf("    - RAM (< 4GB = suspect)\n");
    printf("    - Resolution ecran atypique\n\n");
}

int main(void) {
    printf("[*] Demo : Hypervisor Awareness\n");
    printf("[*] ==========================================\n\n");
    demo_cpuid_detection();
    demo_hardware_detection();
    demo_timing_detection();
    demo_vbs();
    demo_anti_vm();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

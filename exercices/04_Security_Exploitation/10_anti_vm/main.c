/*
 * ═══════════════════════════════════════════════════════════════════════
 * MODULE 31 : ANTI-VM ET ANTI-SANDBOX
 * ═══════════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT LÉGAL :
 *   Ces techniques sont présentées UNIQUEMENT à des fins éducatives.
 *   L'utilisateur est SEUL RESPONSABLE de l'usage qu'il en fait.
 *   Toute utilisation malveillante est STRICTEMENT INTERDITE.
 *
 * ═══════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 1 : DÉTECTION CPUID
 * ═══════════════════════════════════════════════════════════════════════ */

int check_cpuid_hypervisor(void) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
    unsigned int ecx = 0;

    #ifdef _MSC_VER
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    ecx = cpuInfo[2];
    #else
    __asm__ volatile (
        "mov $1, %%eax\n\t"
        "cpuid\n\t"
        : "=c"(ecx)
        :
        : "eax", "ebx", "edx"
    );
    #endif

    return (ecx >> 31) & 1;
#else
    return 0;
#endif
}

void demo_cpuid_check(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("1. DÉTECTION CPUID HYPERVISOR BIT\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Vérification du bit hypervisor (CPUID.0x1.ECX[31])...\n");

    if (check_cpuid_hypervisor()) {
        printf("[!] HYPERVISOR DÉTECTÉ via CPUID\n");
    } else {
        printf("[✓] Pas d'hypervisor détecté\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 2 : DÉTECTION PAR FICHIERS ET REGISTRE
 * ═══════════════════════════════════════════════════════════════════════ */

#ifdef _WIN32
int check_vmware_registry(void) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}

int check_vbox_registry(void) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}
#else
int check_vm_files(void) {
    const char* vm_files[] = {
        "/proc/scsi/scsi",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        NULL
    };

    for (int i = 0; vm_files[i]; i++) {
        FILE* f = fopen(vm_files[i], "r");
        if (f) {
            char buf[256];
            if (fgets(buf, sizeof(buf), f)) {
                if (strstr(buf, "VMware") || strstr(buf, "VirtualBox") ||
                    strstr(buf, "QEMU") || strstr(buf, "Bochs")) {
                    fclose(f);
                    return 1;
                }
            }
            fclose(f);
        }
    }
    return 0;
}
#endif

void demo_vm_detection(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("2. DÉTECTION DE VM PAR ARTEFACTS SYSTÈME\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

#ifdef _WIN32
    printf("Vérification registre VMware... ");
    if (check_vmware_registry()) {
        printf("[!] VMWARE DÉTECTÉ\n");
    } else {
        printf("[✓] Non détecté\n");
    }

    printf("Vérification registre VirtualBox... ");
    if (check_vbox_registry()) {
        printf("[!] VIRTUALBOX DÉTECTÉ\n");
    } else {
        printf("[✓] Non détecté\n");
    }
#else
    printf("Vérification fichiers VM Linux... ");
    if (check_vm_files()) {
        printf("[!] VM DÉTECTÉE\n");
    } else {
        printf("[✓] Non détecté\n");
    }
#endif
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 3 : SLEEP ACCELERATION
 * ═══════════════════════════════════════════════════════════════════════ */

int check_sleep_acceleration(void) {
    time_t start = time(NULL);

#ifdef _WIN32
    Sleep(5000);  // 5 secondes
#else
    sleep(5);
#endif

    time_t end = time(NULL);
    int elapsed = (int)(end - start);

    printf("  Temps attendu: 5 secondes\n");
    printf("  Temps mesuré: %d secondes\n", elapsed);

    if (elapsed < 4) {
        return 1;  // Sandbox détectée (temps accéléré)
    }
    return 0;
}

void demo_sleep_acceleration(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("3. DÉTECTION SLEEP ACCELERATION\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Test de sleep acceleration...\n");
    if (check_sleep_acceleration()) {
        printf("[!] SANDBOX DÉTECTÉE (temps accéléré)\n");
    } else {
        printf("[✓] Timing normal\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 4 : DÉTECTION SANDBOX PAR INDICATEURS
 * ═══════════════════════════════════════════════════════════════════════ */

int check_sandbox_indicators(void) {
    int score = 0;

#ifdef _WIN32
    char computername[256];
    DWORD size = sizeof(computername);

    if (GetComputerNameA(computername, &size)) {
        const char* sandbox_names[] = {
            "SANDBOX", "MALWARE", "VIRUS", "SAMPLE", "CUCKOO", NULL
        };

        for (int i = 0; sandbox_names[i]; i++) {
            if (strstr(computername, sandbox_names[i])) {
                score += 30;
                break;
            }
        }
    }

    // Vérifier RAM (< 2GB suspect)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        DWORDLONG totalRAM = memInfo.ullTotalPhys / (1024 * 1024 * 1024);
        if (totalRAM < 2) {
            score += 20;
        }
    }
#endif

    return score;
}

void demo_sandbox_indicators(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("4. DÉTECTION PAR INDICATEURS SANDBOX\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    int score = check_sandbox_indicators();
    printf("Score de suspicion: %d%%\n", score);

    if (score > 50) {
        printf("[!] SANDBOX PROBABLEMENT DÉTECTÉE\n");
    } else {
        printf("[✓] Environnement normal probable\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║          MODULE 31 : ANTI-VM ET ANTI-SANDBOX                  ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\nAVERTISSEMENT LÉGAL : Usage éducatif uniquement.\n");

    demo_cpuid_check();
    demo_vm_detection();
    demo_sleep_acceleration();
    demo_sandbox_indicators();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Programme terminé.\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    return 0;
}

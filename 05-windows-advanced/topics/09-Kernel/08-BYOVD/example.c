/*
 * OBJECTIF  : Comprendre BYOVD (Bring Your Own Vulnerable Driver)
 * PREREQUIS : Driver Basics, IOCTL, Kernel Memory
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * BYOVD exploite des drivers legitimes et signes qui contiennent
 * des vulnerabilites (arbitrary read/write, code exec kernel).
 * L'attaquant charge le driver vulnerable pour obtenir un acces kernel.
 */

#include <windows.h>
#include <stdio.h>

void demo_byovd_concept(void) {
    printf("[1] Concept BYOVD\n\n");
    printf("    Probleme : charger un driver custom necessite une signature\n");
    printf("    Solution : utiliser un driver DEJA signe mais VULNERABLE\n\n");

    printf("    Flux d'attaque :\n");
    printf("    1. Deposer le driver .sys vulnerable sur la cible\n");
    printf("    2. sc create VulnDrv type= kernel binPath= vuln.sys\n");
    printf("    3. sc start VulnDrv\n");
    printf("    4. CreateFile(\"\\\\\\\\.\\\\VulnDevice\")\n");
    printf("    5. DeviceIoControl(IOCTL_READ_KERNEL, ...)\n");
    printf("    6. Lire/ecrire la memoire kernel a volonte\n");
    printf("    7. Desactiver les protections EDR\n\n");
}

void demo_vulnerable_drivers(void) {
    printf("[2] Drivers vulnerables connus\n\n");
    printf("    +---------------------+----------------------+------------------+\n");
    printf("    | Driver              | Editeur              | Capacite         |\n");
    printf("    +---------------------+----------------------+------------------+\n");
    printf("    | RTCore64.sys        | MSI Afterburner      | R/W kernel       |\n");
    printf("    | dbutil_2_3.sys      | Dell BIOS Utility    | R/W kernel       |\n");
    printf("    | gdrv.sys            | Gigabyte             | R/W physique     |\n");
    printf("    | iqvw64e.sys         | Intel                | R/W physique     |\n");
    printf("    | AsIO64.sys          | ASUS                 | R/W I/O ports    |\n");
    printf("    | ProcExp.sys         | Sysinternals (old)   | Kill process     |\n");
    printf("    | WinRing0.sys        | Diverse              | R/W MSR          |\n");
    printf("    +---------------------+----------------------+------------------+\n\n");

    printf("    Catalogue complet : loldrivers.io\n\n");
}

void demo_attack_chain(void) {
    printf("[3] Chaine d'attaque detaillee\n\n");
    printf("    Objectif : desactiver l'EDR via BYOVD\n\n");

    printf("    Etape 1 : Charger le driver\n");
    printf("    SC_HANDLE hSvc = CreateServiceA(hSCM,\n");
    printf("        \"VulnDrv\", \"Vulnerable Driver\",\n");
    printf("        SERVICE_ALL_ACCESS,\n");
    printf("        SERVICE_KERNEL_DRIVER,\n");
    printf("        SERVICE_DEMAND_START,\n");
    printf("        SERVICE_ERROR_NORMAL,\n");
    printf("        \"C:\\\\Temp\\\\vuln.sys\", ...);\n\n");

    printf("    Etape 2 : Obtenir read/write kernel\n");
    printf("    HANDLE hDev = CreateFileA(\"\\\\\\\\.\\\\VulnDevice\", ...);\n");
    printf("    DeviceIoControl(hDev, IOCTL_READ_PHYSICAL,\n");
    printf("        &address, 8, buffer, size, ...);\n\n");

    printf("    Etape 3 : Localiser et patcher\n");
    printf("    - Trouver l'EPROCESS de l'EDR\n");
    printf("    - Supprimer les kernel callbacks\n");
    printf("    - Desactiver les minifilters\n");
    printf("    - Modifier les tokens pour elevation\n\n");
}

void demo_loldrivers_check(void) {
    printf("[4] Verification des drivers charges\n\n");

    /* Enumerer les drivers et chercher des signatures connues */
    LPVOID drivers[512];
    DWORD needed;

    /* Drivers vulnerables connus */
    const char* vuln_drivers[] = {
        "RTCore64.sys", "dbutil_2_3.sys", "gdrv.sys",
        "iqvw64e.sys", "AsIO64.sys", "WinRing0x64.sys",
        "ProcExp152.sys", "cpuz141.sys", NULL
    };

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        int count = needed / sizeof(LPVOID);
        int vulns = 0;
        int i;

        for (i = 0; i < count; i++) {
            char name[256] = {0};
            GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));

            int j;
            for (j = 0; vuln_drivers[j]; j++) {
                if (_stricmp(name, vuln_drivers[j]) == 0) {
                    printf("    [!] VULNERABLE : %s a 0x%p\n",
                           name, drivers[i]);
                    vulns++;
                }
            }
        }

        if (vulns == 0)
            printf("    [+] Aucun driver vulnerable connu detecte (%d scannes)\n",
                   count);
        printf("\n");
    }
}

void demo_defense(void) {
    printf("[5] Defenses contre BYOVD\n\n");
    printf("    a) Microsoft Vulnerable Driver Blocklist :\n");
    printf("    - Liste de hashes de drivers bloques\n");
    printf("    - Active via WDAC ou Defender\n");
    printf("    - Mise a jour reguliere\n\n");

    printf("    b) HVCI (Hypervisor-Enforced Code Integrity) :\n");
    printf("    - Le hyperviseur verifie les pages kernel\n");
    printf("    - Empeche l'allocation RWX en kernel\n");
    printf("    - Complique l'exploitation meme avec R/W\n\n");

    printf("    c) WDAC (Windows Defender Application Control) :\n");
    printf("    - Politique de controle des drivers\n");
    printf("    - Whitelist stricte des drivers autorises\n\n");

    printf("    d) Monitoring :\n");
    printf("    - Sysmon Event ID 6 (Driver Loaded)\n");
    printf("    - Verifier le hash et le signataire\n");
    printf("    - Alerter sur les drivers non-standard\n\n");

    /* Verifier si HVCI est active */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enabled = 0, size = sizeof(enabled);
        RegQueryValueExA(hKey, "Enabled", NULL, NULL, (BYTE*)&enabled, &size);
        printf("    HVCI : %s\n\n", enabled ? "ACTIVE" : "INACTIF");
        RegCloseKey(hKey);
    } else {
        printf("    HVCI : Non configure\n\n");
    }
}

int main(void) {
    printf("[*] Demo : BYOVD (Bring Your Own Vulnerable Driver)\n");
    printf("[*] ==========================================\n\n");
    demo_byovd_concept();
    demo_vulnerable_drivers();
    demo_attack_chain();
    demo_loldrivers_check();
    demo_defense();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

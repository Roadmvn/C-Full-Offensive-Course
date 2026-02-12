/*
 * OBJECTIF  : Comprendre le Driver Signature Enforcement (DSE) et ses bypass
 * PREREQUIS : Driver Basics, BYOVD, Secure Boot
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Depuis Windows Vista x64, tous les drivers doivent etre signes.
 * Le DSE empeche le chargement de drivers non-signes.
 * Plusieurs techniques permettent de le contourner.
 */

#include <windows.h>
#include <stdio.h>

void demo_dse_concept(void) {
    printf("[1] Driver Signature Enforcement (DSE)\n\n");
    printf("    Windows exige une signature pour les drivers kernel :\n");
    printf("    - Certificat WHQL (Windows Hardware Quality Labs)\n");
    printf("    - Certificat EV (Extended Validation)\n");
    printf("    - Cross-signed certificate (deprecie)\n\n");

    printf("    Verification :\n");
    printf("    1. Le noyau verifie la signature Authenticode\n");
    printf("    2. ci.dll (Code Integrity) valide le certificat\n");
    printf("    3. g_CiOptions controle le comportement\n");
    printf("       0x0 = DSE desactive\n");
    printf("       0x6 = DSE active (defaut)\n");
    printf("       0x8 = DSE + WHQL only\n\n");
}

void demo_test_signing(void) {
    printf("[2] Test Signing Mode\n\n");
    printf("    Methode officielle pour le developpement :\n");
    printf("    bcdedit /set testsigning on\n");
    printf("    -> Reboot necessaire\n");
    printf("    -> Watermark visible sur le bureau\n");
    printf("    -> Accepte les drivers auto-signes\n\n");

    /* Verifier si le test signing est actif */
    HKEY hKey;
    LONG ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\CI",
        0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        DWORD policy = 0, size = sizeof(policy);
        if (RegQueryValueExA(hKey, "UMCIAuditMode", NULL, NULL,
                             (BYTE*)&policy, &size) == ERROR_SUCCESS) {
            printf("    CI UMCIAuditMode: %lu\n", policy);
        }
        RegCloseKey(hKey);
    }

    printf("\n    Verification via NtQuerySystemInformation :\n");
    printf("    SystemCodeIntegrityInformation (0x67)\n");
    printf("    -> CodeIntegrityOptions contient les flags CI\n\n");
}

void demo_bypass_techniques(void) {
    printf("[3] Techniques de bypass DSE\n\n");

    printf("    a) BYOVD -> patch g_CiOptions :\n");
    printf("       1. Charger un driver vulnerable signe\n");
    printf("       2. Utiliser le R/W arbitraire kernel\n");
    printf("       3. Localiser ci.dll!g_CiOptions\n");
    printf("       4. Ecrire 0x0 (desactiver DSE)\n");
    printf("       5. Charger notre driver non-signe\n");
    printf("       6. Restaurer g_CiOptions\n\n");

    printf("    b) EFI bootkit :\n");
    printf("       - Modifier le bootloader EFI\n");
    printf("       - Patcher le noyau avant le demarrage\n");
    printf("       - Necessite de desactiver Secure Boot\n\n");

    printf("    c) KDU (Kernel Driver Utility) :\n");
    printf("       - Outil open-source automatisant le bypass\n");
    printf("       - Utilise plusieurs drivers vulnerables\n");
    printf("       - github.com/hfiref0x/KDU\n\n");

    printf("    d) Leak/steal de certificat :\n");
    printf("       - Utiliser un certificat vole\n");
    printf("       - Exemples : HackingTeam, Stuxnet\n\n");
}

void demo_secure_boot(void) {
    printf("[4] Secure Boot et VBS\n\n");
    printf("    Secure Boot :\n");
    printf("    - Verifie le bootloader AVANT le demarrage\n");
    printf("    - Empeche les bootkits\n");
    printf("    - Active dans le BIOS/UEFI\n\n");

    /* Verifier Secure Boot */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enabled = 0, size = sizeof(enabled);
        if (RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, NULL,
                             (BYTE*)&enabled, &size) == ERROR_SUCCESS) {
            printf("    Secure Boot : %s\n", enabled ? "ACTIVE" : "INACTIF");
        }
        RegCloseKey(hKey);
    }

    printf("\n    VBS (Virtualization-Based Security) :\n");
    printf("    - Le hyperviseur protege ci.dll\n");
    printf("    - g_CiOptions est en memoire protegee par VTL1\n");
    printf("    - Meme avec R/W kernel, impossible de patcher!\n");
    printf("    - Necessaire pour une protection complete\n\n");

    /* Verifier VBS */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD vbs = 0, size = sizeof(vbs);
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity",
                             NULL, NULL, (BYTE*)&vbs, &size) == ERROR_SUCCESS) {
            printf("    VBS : %s\n", vbs ? "ACTIVE" : "INACTIF");
        }
        RegCloseKey(hKey);
    }
    printf("\n");
}

void demo_detection(void) {
    printf("[5] Detection des bypass DSE\n\n");
    printf("    Indicateurs :\n");
    printf("    - Driver non-signe charge (Event ID 7045)\n");
    printf("    - Driver signe mais sur la vulnerable list\n");
    printf("    - g_CiOptions modifie (monitorer via CI callbacks)\n");
    printf("    - Test signing active (bcdedit)\n");
    printf("    - Nouveau service kernel cree (Event ID 4697)\n\n");

    printf("    Best practices defenseurs :\n");
    printf("    - Activer HVCI + Secure Boot\n");
    printf("    - Activer la Vulnerable Driver Blocklist\n");
    printf("    - Monitorer Sysmon Event ID 6\n");
    printf("    - Politique WDAC stricte\n");
    printf("    - Alerter sur les changements bcdedit\n\n");
}

int main(void) {
    printf("[*] Demo : DSE Bypass\n");
    printf("[*] ==========================================\n\n");
    demo_dse_concept();
    demo_test_signing();
    demo_bypass_techniques();
    demo_secure_boot();
    demo_detection();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

/*
 * OBJECTIF  : Fondamentaux des rootkits kernel
 * PREREQUIS : DKOM, SSDT, Callbacks, BYOVD
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Un rootkit kernel est un driver qui se cache et cache
 * l'activite d'un attaquant au niveau le plus bas de l'OS.
 * Ce module presente les concepts sans code malveillant.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

void demo_rootkit_types(void) {
    printf("[1] Types de rootkits\n\n");
    printf("    +---------------------+---------------------------+-----------+\n");
    printf("    | Type                | Technique                 | Ring      |\n");
    printf("    +---------------------+---------------------------+-----------+\n");
    printf("    | Usermode rootkit    | IAT/EAT hook, LD_PRELOAD | Ring 3    |\n");
    printf("    | Kernel rootkit      | DKOM, callbacks, SSDT    | Ring 0    |\n");
    printf("    | Bootkit             | MBR/VBR/UEFI mod         | Pre-boot  |\n");
    printf("    | Hypervisor rootkit  | VMX/SVM interception     | Ring -1   |\n");
    printf("    | Firmware rootkit    | BIOS/UEFI flash           | Firmware  |\n");
    printf("    +---------------------+---------------------------+-----------+\n\n");
}

void demo_capabilities(void) {
    printf("[2] Capacites d'un rootkit kernel\n\n");
    printf("    a) Process Hiding (DKOM) :\n");
    printf("       - Retirer de ActiveProcessLinks\n");
    printf("       - Invisible dans Task Manager / ps\n\n");

    printf("    b) File Hiding :\n");
    printf("       - Hook NtQueryDirectoryFile\n");
    printf("       - Filtrer les resultats (supprimer nos fichiers)\n");
    printf("       - Invisible dans dir / Explorer\n\n");

    printf("    c) Network Hiding :\n");
    printf("       - Hook NtDeviceIoControlFile\n");
    printf("       - Filtrer les connexions TCP/UDP\n");
    printf("       - Invisible dans netstat\n\n");

    printf("    d) Registry Hiding :\n");
    printf("       - Hook NtEnumerateValueKey\n");
    printf("       - Filtrer nos cles de persistance\n");
    printf("       - Invisible dans regedit\n\n");

    printf("    e) Privilege Escalation :\n");
    printf("       - Token stealing via DKOM\n");
    printf("       - Modifier les ACL en memoire\n\n");
}

void demo_communication(void) {
    printf("[3] Communication rootkit <-> usermode\n\n");
    printf("    Le rootkit a besoin de recevoir des commandes\n");
    printf("    et d'envoyer des resultats.\n\n");

    printf("    Methodes de communication :\n\n");
    printf("    a) IOCTL via device cache :\n");
    printf("       - Device non liste dans \\Device\\\n");
    printf("       - Nom aleatoire ou obfusque\n\n");

    printf("    b) Shared memory :\n");
    printf("       - Section kernel-user partagee\n");
    printf("       - ZwCreateSection + ZwMapViewOfSection\n\n");

    printf("    c) Network filtering :\n");
    printf("       - Intercepter un protocole specifique\n");
    printf("       - Magic bytes dans les paquets\n\n");

    printf("    d) Hypercalls (hypervisor rootkit) :\n");
    printf("       - VMCALL avec un numero specifique\n");
    printf("       - Invisible pour le systeme\n\n");
}

void demo_persistence(void) {
    printf("[4] Persistance d'un rootkit kernel\n\n");
    printf("    Le rootkit doit survivre au reboot.\n\n");

    printf("    a) Service kernel :\n");
    printf("       - Entree dans HKLM\\SYSTEM\\CurrentControlSet\\Services\n");
    printf("       - Type = SERVICE_KERNEL_DRIVER\n");
    printf("       - Se cache en memoire mais visible dans le registre\n\n");

    printf("    b) Boot Start driver :\n");
    printf("       - Start = SERVICE_BOOT_START (0)\n");
    printf("       - Charge tres tot dans le processus de boot\n");
    printf("       - Avant les EDR/AV\n\n");

    printf("    c) Bootkit :\n");
    printf("       - Modifier le boot loader EFI\n");
    printf("       - Patcher le noyau au boot\n");
    printf("       - Persiste meme apres reinstall OS\n");
    printf("       - Secure Boot protege contre ca\n\n");

    /* Lister les drivers boot-start */
    printf("    Drivers boot-start sur ce systeme :\n");
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char name[256];
        DWORD nameLen, i = 0;
        int boot_count = 0;
        while (1) {
            nameLen = sizeof(name);
            if (RegEnumKeyExA(hKey, i, name, &nameLen,
                              NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY hSubKey;
            if (RegOpenKeyExA(hKey, name, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                DWORD start = 99, type = 99, sz = sizeof(DWORD);
                RegQueryValueExA(hSubKey, "Start", NULL, NULL, (BYTE*)&start, &sz);
                sz = sizeof(DWORD);
                RegQueryValueExA(hSubKey, "Type", NULL, NULL, (BYTE*)&type, &sz);
                if (start == 0 && type == 1) { /* BOOT_START + KERNEL_DRIVER */
                    if (boot_count < 5)
                        printf("    [%d] %s\n", boot_count, name);
                    boot_count++;
                }
                RegCloseKey(hSubKey);
            }
            i++;
        }
        RegCloseKey(hKey);
        if (boot_count > 5) printf("    ... (%d total)\n", boot_count);
        printf("\n");
    }
}

void demo_detection(void) {
    printf("[5] Detection des rootkits\n\n");
    printf("    Cross-view detection :\n");
    printf("    - Comparer les APIs haut niveau vs bas niveau\n");
    printf("    - Ex: EnumProcesses vs PspCidTable scan\n");
    printf("    - Differences = hiding detecte\n\n");

    printf("    Outils :\n");
    printf("    - Volatility (analyse memoire offline)\n");
    printf("    - GMER (scanner rootkit live)\n");
    printf("    - WinDbg (analyse kernel debugger)\n");
    printf("    - Microsoft Defender Offline\n\n");

    printf("    Memory forensics :\n");
    printf("    - Pool tag scanning (chercher les objets caches)\n");
    printf("    - Integrity check des structures kernel\n");
    printf("    - Verification des callbacks enregistres\n");
    printf("    - Comparaison driver list vs memory scan\n\n");
}

int main(void) {
    printf("[*] Demo : Kernel Rootkit Basics\n");
    printf("[*] ==========================================\n\n");
    demo_rootkit_types();
    demo_capabilities();
    demo_communication();
    demo_persistence();
    demo_detection();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

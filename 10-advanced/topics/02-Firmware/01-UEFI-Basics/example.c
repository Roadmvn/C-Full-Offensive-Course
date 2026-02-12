/*
 * OBJECTIF  : Comprendre les fondamentaux UEFI
 * PREREQUIS : Bases C, architecture x86, boot process
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les concepts UEFI :
 * architecture, boot process, protocoles, variables,
 * et surface d'attaque.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/stat.h>
#endif

/*
 * Etape 1 : Architecture UEFI
 */
static void explain_uefi_architecture(void) {
    printf("[*] Etape 1 : Architecture UEFI\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Boot Process UEFI                        │\n");
    printf("    │                                          │\n");
    printf("    │  ┌────────────┐                          │\n");
    printf("    │  │ SEC Phase  │ Security (premier code)  │\n");
    printf("    │  └─────┬──────┘                          │\n");
    printf("    │  ┌─────v──────┐                          │\n");
    printf("    │  │ PEI Phase  │ Pre-EFI Initialization   │\n");
    printf("    │  └─────┬──────┘                          │\n");
    printf("    │  ┌─────v──────┐                          │\n");
    printf("    │  │ DXE Phase  │ Driver Execution Env.    │\n");
    printf("    │  └─────┬──────┘                          │\n");
    printf("    │  ┌─────v──────┐                          │\n");
    printf("    │  │ BDS Phase  │ Boot Device Selection    │\n");
    printf("    │  └─────┬──────┘                          │\n");
    printf("    │  ┌─────v──────┐                          │\n");
    printf("    │  │ TSL Phase  │ Transient System Load    │\n");
    printf("    │  └─────┬──────┘                          │\n");
    printf("    │  ┌─────v──────┐                          │\n");
    printf("    │  │ RT Phase   │ OS Running               │\n");
    printf("    │  └────────────┘                          │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    UEFI vs BIOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Caracteristique | BIOS          | UEFI\n");
    printf("    ────────────────|───────────────|──────────────\n");
    printf("    Mode CPU        | 16-bit real   | 32/64-bit\n");
    printf("    Adressage       | 1 MB          | Illimite\n");
    printf("    Partition       | MBR           | GPT\n");
    printf("    Drivers         | ROM options   | .efi modules\n");
    printf("    Interface       | Texte         | GUI possible\n");
    printf("    Secure Boot     | Non           | Oui\n\n");
}

/*
 * Etape 2 : Partition EFI System
 */
static void explain_esp(void) {
    printf("[*] Etape 2 : EFI System Partition (ESP)\n\n");

    printf("    Structure de l'ESP :\n");
    printf("    ───────────────────────────────────\n");
    printf("    /EFI/\n");
    printf("    ├── BOOT/\n");
    printf("    │   └── BOOTX64.EFI    (bootloader par defaut)\n");
    printf("    ├── Microsoft/\n");
    printf("    │   └── Boot/\n");
    printf("    │       └── bootmgfw.efi\n");
    printf("    ├── ubuntu/\n");
    printf("    │   ├── grubx64.efi\n");
    printf("    │   └── shimx64.efi\n");
    printf("    └── (autres OS)\n\n");

#ifdef __linux__
    /* Verifier l'ESP */
    printf("    EFI System Partition sur ce systeme :\n");
    struct stat st;
    if (stat("/boot/efi", &st) == 0 || stat("/sys/firmware/efi", &st) == 0) {
        printf("      Systeme UEFI detecte\n");

        FILE *fp = popen("ls /boot/efi/EFI/ 2>/dev/null", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = '\0';
                printf("      /boot/efi/EFI/%s\n", line);
            }
            pclose(fp);
        }
    } else {
        printf("      UEFI non detecte (ou pas /boot/efi)\n");
    }
    printf("\n");
#endif
}

/*
 * Etape 3 : Variables UEFI
 */
static void explain_uefi_variables(void) {
    printf("[*] Etape 3 : Variables UEFI\n\n");

    printf("    Les variables UEFI persistent dans la NVRAM :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Variable         | Description\n");
    printf("    ─────────────────|──────────────────────────\n");
    printf("    BootOrder        | Ordre de boot\n");
    printf("    Boot0001         | Entree de boot\n");
    printf("    SecureBoot       | Secure Boot active\n");
    printf("    SetupMode        | Mode setup (enrollment)\n");
    printf("    PK               | Platform Key\n");
    printf("    KEK              | Key Exchange Key\n");
    printf("    db               | Signature database\n");
    printf("    dbx              | Revocation database\n\n");

#ifdef __linux__
    /* Lister les variables UEFI */
    printf("    Variables UEFI accessibles :\n");
    FILE *fp = popen("ls /sys/firmware/efi/efivars/ 2>/dev/null | head -10", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    } else {
        printf("      (non disponible)\n");
    }
    printf("\n");

    /* Verifier Secure Boot */
    printf("    Statut Secure Boot :\n");
    fp = popen("mokutil --sb-state 2>/dev/null || "
               "cat /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | "
               "xxd | head -1", "r");
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
}

/*
 * Etape 4 : UEFI Runtime Services
 */
static void explain_runtime_services(void) {
    printf("[*] Etape 4 : UEFI Runtime Services\n\n");

    printf("    Services disponibles apres le boot :\n");
    printf("    ───────────────────────────────────\n");
    printf("    GetVariable()     : lire une variable NVRAM\n");
    printf("    SetVariable()     : ecrire une variable NVRAM\n");
    printf("    GetTime()         : horloge temps reel\n");
    printf("    SetTime()         : modifier l'heure\n");
    printf("    ResetSystem()     : reboot/shutdown\n");
    printf("    GetNextVariableName() : enumerer les variables\n\n");

    printf("    Acces depuis Linux :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Lire une variable\n");
    printf("    efivar -l  # lister les variables\n");
    printf("    efivar -p -n GUID-Name  # afficher\n\n");
    printf("    # Modifier (dangereux !)\n");
    printf("    efibootmgr -v  # voir les entrees de boot\n");
    printf("    efibootmgr -o 0001,0002  # changer l'ordre\n\n");
}

/*
 * Etape 5 : Surface d'attaque UEFI
 */
static void explain_uefi_attacks(void) {
    printf("[*] Etape 5 : Surface d'attaque UEFI\n\n");

    printf("    Attaques firmware connues :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Attaque        | Annee | Technique\n");
    printf("    ───────────────|───────|─────────────────────\n");
    printf("    Hacking Team   | 2015  | UEFI rootkit\n");
    printf("    LoJax           | 2018  | SPI flash write\n");
    printf("    MosaicRegressor | 2020  | UEFI bootkit\n");
    printf("    ESPecter        | 2021  | ESP manipulation\n");
    printf("    BlackLotus      | 2023  | Secure Boot bypass\n");
    printf("    CosmicStrand    | 2022  | Firmware rootkit\n\n");

    printf("    Vecteurs d'attaque :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. SPI flash write\n");
    printf("       -> Ecrire un module DXE malveillant\n");
    printf("       -> Persiste au reinstall de l'OS\n\n");
    printf("    2. ESP manipulation\n");
    printf("       -> Modifier les bootloaders sur l'ESP\n");
    printf("       -> Plus simple mais moins persistant\n\n");
    printf("    3. Variable NVRAM abuse\n");
    printf("       -> Modifier les variables de boot\n");
    printf("       -> Contourner Secure Boot\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - CHIPSEC : outil d'audit firmware Intel\n");
    printf("    - LVFS/fwupd : verification des mises a jour\n");
    printf("    - UEFITool : analyse des images firmware\n");
    printf("    - Binwalk : extraction de firmware\n\n");

    printf("    Commandes utiles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Verifier le firmware\n");
    printf("    sudo chipsec_main -m common.bios_wp\n");
    printf("    sudo chipsec_main -m common.spi_lock\n\n");
    printf("    # Verifier les mises a jour\n");
    printf("    fwupdmgr get-devices\n");
    printf("    fwupdmgr get-updates\n\n");

    printf("    Protection :\n");
    printf("    - Activer Secure Boot\n");
    printf("    - Activer le BIOS write protect\n");
    printf("    - Mettre a jour le firmware regulierement\n");
    printf("    - Utiliser TPM pour mesurer le boot\n");
    printf("    - SPI flash lock (BIOS_CNTL)\n\n");
}

int main(void) {
    printf("[*] Demo : UEFI Basics\n\n");

    explain_uefi_architecture();
    explain_esp();
    explain_uefi_variables();
    explain_runtime_services();
    explain_uefi_attacks();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

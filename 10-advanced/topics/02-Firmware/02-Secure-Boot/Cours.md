# Module A07 : Secure Boot - La chaîne de confiance et ses failles

## Objectifs pédagogiques

À la fin de ce module, tu seras capable de :
- Comprendre le mécanisme de Secure Boot et la chaîne de confiance UEFI
- Identifier les points de bypass possibles dans la chaîne de démarrage
- Analyser les certificats et signatures utilisés dans Secure Boot
- Comprendre les attaques contre Secure Boot (shim, bootkit UEFI)

## Prérequis

Avant de commencer ce module, assure-toi de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- La structure UEFI (Module A06)
- Les concepts de cryptographie asymétrique (RSA, signatures)
- L'architecture du boot (BIOS/UEFI)

---

## Introduction

### Qu'est-ce que Secure Boot ?

Imagine que tu veuilles entrer dans un bâtiment ultra-sécurisé. À chaque porte, un garde vérifie ton badge. Si ton badge est valide, tu passes. Si non, tu es bloqué. **Secure Boot, c'est exactement ça pour ton ordinateur au démarrage.**

À chaque étape du boot, le composant actuel vérifie la signature cryptographique du composant suivant avant de l'exécuter. Si la signature est invalide ou manquante, le boot s'arrête.

```
┌─────────────────────────────────────────────────────────────┐
│              Chaîne de confiance Secure Boot                │
└─────────────────────────────────────────────────────────────┘

Firmware UEFI (Platform Key = PK)
      │ Vérifie signature avec KEK
      ├─> Shim / Bootloader (signé Microsoft ou OEM)
      │   Vérifie signature avec db
      ├─> GRUB / Windows Boot Manager
      │   Vérifie signature avec db
      ├─> Kernel (Linux / Windows)
      │   Vérifie signature des modules
      └─> Modules / Drivers signés

Légende:
PK  = Platform Key (clé racine)
KEK = Key Exchange Key (clés intermédiaires)
db  = Signature Database (clés autorisées)
dbx = Forbidden Signature Database (clés révoquées)
```

**Pourquoi c'est important en Red Team ?**

Secure Boot est l'un des principaux mécanismes de défense contre :
- Les bootkits (malwares qui infectent le bootloader)
- Les rootkits UEFI (malwares dans le firmware)
- L'exécution de binaires non signés au démarrage

Si tu peux bypass Secure Boot, tu peux :
- Installer un bootkit persistant
- Exécuter du code avant le kernel
- Contourner les protections kernel (Secure Kernel, VBS sur Windows)

---

## Partie 1 : Les fondations de Secure Boot

### La cryptographie asymétrique - Rappel express

Secure Boot repose sur la **signature numérique** avec cryptographie asymétrique.

**Principe :**
1. Tu as une **clé privée** (secrète) et une **clé publique** (partageable)
2. Tu **signes** un fichier avec ta clé privée → crée une signature
3. N'importe qui peut **vérifier** la signature avec ta clé publique
4. Si le fichier est modifié, la signature devient invalide

```
┌─────────────────────────────────────────────────────────┐
│                Signature d'un bootloader                │
└─────────────────────────────────────────────────────────┘

[OEM/Vendor]
    │
    ├─> Clé privée (secrète, stockée chez l'OEM)
    │   Hash(bootloader.efi) → Signature
    │
    └─> Clé publique → Stockée dans la db UEFI

[Boot time]
    Firmware UEFI lit bootloader.efi
    ├─> Calcule Hash(bootloader.efi)
    ├─> Vérifie la signature avec clé publique de la db
    └─> Si valide → Exécute
        Si invalide → BLOQUE ("Secure Boot Violation")
```

### Les bases de données Secure Boot

Secure Boot utilise **4 bases de données** stockées dans les variables UEFI (NVRAM) :

| Base | Nom complet | Rôle | Signataire typique |
|------|-------------|------|-------------------|
| **PK** | Platform Key | Clé racine du système (1 seule clé) | OEM (Dell, HP, Lenovo...) |
| **KEK** | Key Exchange Keys | Clés pour modifier db/dbx | OEM + Microsoft |
| **db** | Signature Database | Clés autorisées à signer bootloaders/drivers | Microsoft, OEM, Linux distros |
| **dbx** | Forbidden Signatures | Hashes/clés révoquées (bootloaders compromis) | Microsoft UEFI CA |

**Hiérarchie :**
```
PK (Platform Key)
  │
  ├─> Signe les KEK
  │
KEK (Key Exchange Keys)
  │
  ├─> Signe les modifications de db et dbx
  │
db (Authorized Signatures)
  │
  ├─> Vérifie les bootloaders, kernels, drivers
  │
dbx (Forbidden Signatures)
  │
  └─> Liste noire de hashes/certificats compromis
```

### Variables UEFI Secure Boot

Sur Linux, tu peux lire les variables UEFI dans `/sys/firmware/efi/efivars/` :

```bash
# Vérifier si Secure Boot est activé
mokutil --sb-state
# ou
dmesg | grep -i secure

# Lire les certificats de la db
efi-readvar -v db

# Lister les variables UEFI
ls /sys/firmware/efi/efivars/
```

Sur Windows :
```powershell
# PowerShell
Confirm-SecureBootUEFI
# Retourne True si Secure Boot est actif
```

---

## Partie 2 : Le flux de boot avec Secure Boot

### Étape par étape

```
┌────────────────────────────────────────────────────────────────┐
│            Séquence complète de boot avec Secure Boot          │
└────────────────────────────────────────────────────────────────┘

1. Power On
   └─> CPU exécute le code dans la ROM du firmware

2. SEC Phase (Security)
   └─> Initialisation minimale du CPU
   └─> Vérification intégrité du firmware (Intel Boot Guard, AMD PSB)

3. PEI Phase (Pre-EFI Initialization)
   └─> Initialisation de la RAM
   └─> Mesures TPM (si activé)

4. DXE Phase (Driver Execution Environment)
   └─> Chargement des drivers UEFI
   └─> Initialisation des variables Secure Boot (PK, KEK, db, dbx)

5. BDS Phase (Boot Device Selection)
   └─> Lecture des entrées de boot (BootOrder UEFI)
   └─> Secure Boot ACTIVÉ ici

6. Chargement du bootloader (ex: shimx64.efi, bootx64.efi)
   ┌─────────────────────────────────────────────┐
   │ VÉRIFICATION SECURE BOOT                    │
   ├─────────────────────────────────────────────┤
   │ 1. Firmware UEFI lit le fichier .efi        │
   │ 2. Parse le PE/COFF header                  │
   │ 3. Extrait la signature Authenticode        │
   │ 4. Vérifie contre db (clés autorisées)      │
   │ 5. Vérifie contre dbx (clés interdites)     │
   │ 6. Si OK → Exécute                          │
   │    Si KO → Affiche "Secure Boot Violation"  │
   └─────────────────────────────────────────────┘

7. Bootloader charge le kernel
   └─> Le bootloader vérifie AUSSI la signature du kernel
   └─> Même processus (db/dbx)

8. Kernel charge les modules/drivers
   └─> Sur Windows : Driver Signature Enforcement
   └─> Sur Linux : module signature verification (si activé)

9. Système d'exploitation opérationnel
```

### Exemple concret : Linux avec shim

Sur la plupart des distributions Linux modernes :

```
UEFI Firmware
  │
  ├─> Charge shimx64.efi (signé par Microsoft)
  │   └─> La clé Microsoft est dans db par défaut
  │
shimx64.efi
  │
  ├─> Contient une seconde db (MOK = Machine Owner Keys)
  │   └─> Permet d'ajouter des clés custom sans modifier la db UEFI
  │
  ├─> Charge grubx64.efi (signé par Ubuntu/Fedora/etc.)
  │   └─> Vérifié avec la clé dans MOK ou db
  │
grubx64.efi
  │
  ├─> Charge vmlinuz (kernel Linux signé)
  │   └─> Vérifié avec MOK ou db
  │
Kernel Linux
  │
  └─> Charge les modules signés
```

**Pourquoi shim ?**

Microsoft ne signe pas tous les bootloaders Linux. Au lieu de ça :
1. Chaque distro signe son GRUB avec sa propre clé
2. Mais shim est signé par Microsoft
3. Shim contient une db secondaire (MOK) avec les clés des distros
4. Résultat : Secure Boot fonctionne sans que chaque PC ait la clé de chaque distro

**C'est une surface d'attaque.**

---

## Partie 3 : Analyser les signatures Secure Boot

### Format des binaires UEFI

Les bootloaders UEFI sont au format **PE/COFF** (Portable Executable), le même format que les .exe Windows.

Ils contiennent une section spéciale : **Authenticode Signature**.

```
┌────────────────────────────────────────────────────────┐
│               Structure PE/COFF d'un .efi              │
└────────────────────────────────────────────────────────┘

[DOS Header]                MZ signature
[PE Header]                 PE\0\0 signature
[Optional Header]
  ├─> Data Directories
      └─> Certificate Table ──> Pointe vers la signature

[Section .text]             Code exécutable
[Section .data]             Données
[Section .reloc]            Relocations
...
[Certificate Table]         Signature Authenticode (PKCS#7)
  ├─> Certificate
  ├─> Signature (hash signé)
  └─> Signer info (qui a signé)
```

### Extraire et analyser une signature

**Sur Linux :**

```bash
# Extraire la signature d'un .efi
sbverify --list shimx64.efi

# Vérifier la signature contre la db système
sbverify --cert /path/to/cert.pem shimx64.efi

# Avec openssl
objcopy -O binary -j .signature shimx64.efi signature.pkcs7
openssl pkcs7 -inform DER -in signature.pkcs7 -print_certs -text
```

**Exemple de sortie :**

```
Signature verification OK
Signer:
    CN=Microsoft Corporation UEFI CA 2011
    O=Microsoft Corporation
    L=Redmond
    ST=Washington
    C=US
Issuer:
    CN=Microsoft Corporation Third Party Marketplace Root
```

**Sur Windows :**

```powershell
# PowerShell - Vérifier la signature
Get-AuthenticodeSignature bootx64.efi

# Afficher les détails du certificat
Get-AuthenticodeSignature bootx64.efi | Select-Object -ExpandProperty SignerCertificate | Format-List
```

### Code C pour parser une signature UEFI

Voici comment extraire la signature d'un binaire PE/COFF en C :

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Structures PE/COFF simplifiées
typedef struct {
    uint16_t e_magic;    // "MZ"
    uint8_t  e_pad[58];
    uint32_t e_lfanew;   // Offset vers PE header
} DOS_HEADER;

typedef struct {
    uint32_t Signature;  // "PE\0\0"
    uint16_t Machine;
    uint16_t NumberOfSections;
    // ... (simplifié)
} PE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DATA_DIRECTORY;

void extract_signature(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return;
    }

    // Lire DOS header
    DOS_HEADER dos;
    fread(&dos, sizeof(dos), 1, f);
    if (dos.e_magic != 0x5A4D) { // "MZ"
        printf("Pas un fichier PE valide\n");
        fclose(f);
        return;
    }

    // Aller au PE header
    fseek(f, dos.e_lfanew, SEEK_SET);

    uint32_t pe_sig;
    fread(&pe_sig, 4, 1, f);
    if (pe_sig != 0x00004550) { // "PE\0\0"
        printf("Signature PE invalide\n");
        fclose(f);
        return;
    }

    // Sauter COFF header (20 bytes) et lire Optional Header
    fseek(f, dos.e_lfanew + 24, SEEK_SET);

    uint16_t magic;
    fread(&magic, 2, 1, f);

    int dd_offset;
    if (magic == 0x010B) { // PE32
        dd_offset = dos.e_lfanew + 24 + 92;
    } else if (magic == 0x020B) { // PE32+
        dd_offset = dos.e_lfanew + 24 + 108;
    } else {
        printf("Format PE inconnu\n");
        fclose(f);
        return;
    }

    // Certificate Table = Data Directory #4
    fseek(f, dd_offset + (4 * 8), SEEK_SET);

    DATA_DIRECTORY cert_dir;
    fread(&cert_dir, sizeof(cert_dir), 1, f);

    if (cert_dir.Size == 0) {
        printf("Aucune signature trouvée\n");
    } else {
        printf("Signature trouvée:\n");
        printf("  Offset: 0x%X\n", cert_dir.VirtualAddress);
        printf("  Taille: %u bytes\n", cert_dir.Size);

        // Extraire la signature
        uint8_t* sig = malloc(cert_dir.Size);
        fseek(f, cert_dir.VirtualAddress, SEEK_SET);
        fread(sig, cert_dir.Size, 1, f);

        printf("  Premiers bytes: ");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", sig[i]);
        }
        printf("\n");

        free(sig);
    }

    fclose(f);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <bootloader.efi>\n", argv[0]);
        return 1;
    }

    extract_signature(argv[1]);
    return 0;
}
```

**Compilation et test :**

```bash
gcc -o parse_sig parse_signature.c
./parse_sig /boot/efi/EFI/ubuntu/shimx64.efi
```

---

## Partie 4 : Attaques contre Secure Boot

### 4.1 - Boothole (CVE-2020-10713)

**Contexte :**
En juillet 2020, une vulnérabilité critique dans GRUB2 a permis de bypass Secure Boot.

**Le bug :**
GRUB2 parse les fichiers de configuration (`grub.cfg`) sans vérification suffisante. Un attaquant avec accès root peut modifier `grub.cfg` pour exploiter un buffer overflow dans le parser.

**Impact :**
- Exécution de code arbitraire dans le bootloader
- Avant le kernel (donc avant toute protection kernel)
- Contourne Secure Boot car GRUB2 est déjà vérifié et chargé

**Exploitation (simplifié) :**

```bash
# En tant que root, modifier grub.cfg
echo "setparams 'AAAA...AAAA' <shellcode>" >> /boot/grub/grub.cfg

# Au prochain reboot, le shellcode s'exécute dans GRUB2
# → Peut charger un kernel non signé
# → Bypasse Secure Boot
```

**Mitigation :**
Microsoft a ajouté les anciens binaires GRUB2 dans la **dbx** (liste noire). Les firmwares à jour refusent désormais de booter ces versions.

**Leçon Red Team :**
Même avec Secure Boot, des vulnérabilités dans les composants signés (shim, GRUB) peuvent tout compromettre.

---

### 4.2 - Attaque sur shim et MOK

**Concept :**

Shim utilise une base de données secondaire appelée **MOK** (Machine Owner Keys) pour permettre aux utilisateurs d'ajouter leurs propres clés de signature.

**Workflow légitime :**

```bash
# Générer une clé personnelle
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.key -out MOK.crt

# Signer un bootloader custom
sbsign --key MOK.key --cert MOK.crt my_bootloader.efi

# Importer la clé dans MOK
mokutil --import MOK.crt

# Au reboot, shim demande confirmation et ajoute la clé
# Maintenant my_bootloader.efi est accepté par shim
```

**Attaque :**

Si un attaquant obtient un accès root :

1. **Importer sa propre clé dans MOK**
   ```bash
   mokutil --import attacker.crt
   # Demande un mot de passe, mais l'attaquant choisit le mot de passe
   ```

2. **Au reboot, entrer le mot de passe dans l'interface MOK**

3. **La clé de l'attaquant est maintenant de confiance**
   - Il peut signer n'importe quel bootloader/kernel
   - Secure Boot ne bloque plus rien
   - Installation d'un bootkit possible

**Défense :**

- **Password pour MOK enrollment** : Force l'interaction physique
- **TPM + Measured Boot** : Détecte les modifications de la chaîne de boot
- **UEFI password** : Empêche de booter sur un autre device

---

### 4.3 - Fake Secure Boot / Setup Mode

**Le concept :**

Secure Boot peut être dans différents états :

| État | Description | db/PK | Conséquence |
|------|-------------|-------|-------------|
| **User Mode** | Mode normal, Secure Boot actif | Présent | Vérification active |
| **Setup Mode** | Mode configuration, Secure Boot INACTIF | Absent | Aucune vérification ! |
| **Audit Mode** | Mode test, log violations sans bloquer | Présent | Vérifications loggées |

**L'attaque :**

Si un attaquant peut effacer la **PK** (Platform Key) :

```bash
# Effacer la PK (root requis + accès aux efivars)
chattr -i /sys/firmware/efi/efivars/PK-*
rm /sys/firmware/efi/efivars/PK-*
```

**Résultat :**

- Le système entre en **Setup Mode**
- Secure Boot est désactivé
- N'importe quel bootloader non signé peut démarrer
- L'attaquant peut installer sa propre PK et reconstruire une chaîne de confiance malveillante

**Indicateur :**

```bash
mokutil --sb-state
# Setup Mode = Secure Boot désactivé

dmesg | grep -i "secure boot"
# Cherche "Setup Mode" ou "SecureBoot disabled"
```

**Défense :**

- **Protéger les efivars** : `chattr +i` ou `mount -o ro,remount`
- **UEFI password** : Empêche les modifications dans le BIOS
- **TPM + Attestation** : Détecte le passage en Setup Mode

---

### 4.4 - BlackLotus : UEFI Bootkit réel

**Contexte :**

En 2023, BlackLotus est le premier bootkit UEFI capable de **contourner Secure Boot** sur des systèmes Windows 11 à jour.

**Comment ça fonctionne :**

1. **Exploite CVE-2022-21894** : Vulnérabilité dans le Windows Boot Manager
2. **Installe un bootkit UEFI** dans l'ESP (EFI System Partition)
3. **Désactive les vérifications Secure Boot** en patchant le bootmgr
4. **Charge un driver kernel non signé** pour établir la persistance

**Schéma d'infection :**

```
Malware initial (userland)
  │
  ├─> Élève privilèges → SYSTEM
  │
  ├─> Monte l'ESP (EFI System Partition)
  │   └─> Normalement sur \EFI\Microsoft\Boot\
  │
  ├─> Installe bootkit.efi dans l'ESP
  │   └─> Patch bootmgfw.efi (Windows Boot Manager)
  │
  ├─> Modifie BootOrder UEFI pour charger bootkit.efi en premier
  │
  └─> Reboot

Au boot suivant :
  UEFI Firmware
    │
    ├─> Charge bootkit.efi (exploite CVE-2022-21894)
    │   └─> Désactive les vérifications Secure Boot
    │
    ├─> Charge le vrai bootmgfw.efi (patché)
    │   └─> Charge un driver kernel malveillant (non signé)
    │
    └─> Windows démarre, compromis dès le kernel
```

**Persistence :**

- Le bootkit est dans l'ESP, qui n'est pas scannée par les antivirus
- Survit à une réinstallation de Windows
- Fonctionne même avec Secure Boot activé (bypass)

**Détection :**

```powershell
# Vérifier l'intégrité du Boot Manager
Get-FileHash C:\Windows\Boot\EFI\bootmgfw.efi
# Comparer avec le hash officiel de Microsoft

# Analyser l'ESP
mountvol S: /S
dir S:\EFI\Microsoft\Boot\
# Chercher des .efi suspects
```

**Mitigation :**

- **Installer les patchs** : Microsoft a ajouté les bootmgfw.efi vulnérables à la dbx
- **UEFI Secure Boot avec dernières updates dbx**
- **Mesures TPM + Windows Defender System Guard**
- **Monitorer l'ESP** avec un EDR avancé

---

## Partie 5 : Développer un bootloader UEFI (légitime)

Pour comprendre les attaques, il faut savoir créer un bootloader UEFI basique.

### Structure minimale

```c
#include <efi.h>
#include <efilib.h>

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    // Initialiser la bibliothèque GNU-EFI
    InitializeLib(ImageHandle, SystemTable);

    // Afficher un message
    Print(L"Hello from UEFI Bootloader!\n");
    Print(L"Secure Boot Status: ");

    // Vérifier si Secure Boot est actif
    UINT8 SecureBoot = 0;
    UINTN Size = sizeof(SecureBoot);
    EFI_GUID GlobalVar = EFI_GLOBAL_VARIABLE;

    EFI_STATUS Status = uefi_call_wrapper(
        SystemTable->RuntimeServices->GetVariable,
        5,
        L"SecureBoot",
        &GlobalVar,
        NULL,
        &Size,
        &SecureBoot
    );

    if (Status == EFI_SUCCESS && SecureBoot == 1) {
        Print(L"ENABLED\n");
    } else {
        Print(L"DISABLED\n");
    }

    // Attendre une touche
    Print(L"\nPress any key to continue boot...\n");
    SystemTable->ConIn->Reset(SystemTable->ConIn, FALSE);
    EFI_INPUT_KEY Key;
    while (SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &Key) == EFI_NOT_READY);

    return EFI_SUCCESS;
}
```

**Compilation (Linux) :**

```bash
# Installer gnu-efi
sudo apt install gnu-efi

# Compiler
gcc -I/usr/include/efi -I/usr/include/efi/x86_64 \
    -fno-stack-protector -fpic -fshort-wchar -mno-red-zone \
    -DEFI_FUNCTION_WRAPPER -c bootloader.c -o bootloader.o

# Linker
ld -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds -shared \
   -Bsymbolic -L /usr/lib /usr/lib/crt0-efi-x86_64.o bootloader.o \
   -o bootloader.so -lefi -lgnuefi

# Convertir en .efi
objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
        -j .rela -j .reloc --target=efi-app-x86_64 bootloader.so bootloader.efi
```

**Test dans QEMU :**

```bash
# Créer une image disque avec ESP
dd if=/dev/zero of=disk.img bs=1M count=100
mkfs.vfat disk.img

# Monter et copier le bootloader
mkdir /tmp/esp
sudo mount disk.img /tmp/esp
sudo mkdir -p /tmp/esp/EFI/BOOT
sudo cp bootloader.efi /tmp/esp/EFI/BOOT/BOOTX64.EFI
sudo umount /tmp/esp

# Lancer QEMU avec UEFI (OVMF)
qemu-system-x86_64 -enable-kvm -m 512M \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=/usr/share/OVMF/OVMF_VARS.fd \
    -drive format=raw,file=disk.img
```

---

## Partie 6 : Contournements avancés

### 6.1 - Implant dans le firmware UEFI

Au lieu d'attaquer le bootloader, pourquoi ne pas attaquer le firmware lui-même ?

**Prérequis :**

- Accès physique ou kernel exploit pour écrire dans la SPI flash
- Connaissance de la structure du firmware (voir module A08_spi_flash)

**Technique :**

1. Dumper le firmware UEFI depuis la SPI flash
2. Injecter un DXE driver malveillant
3. Reflasher le firmware modifié

**Code conceptuel (injection DXE) :**

```c
// Voir module A08_spi_flash pour les détails de manipulation SPI

// Pseudo-code DXE malveillant
EFI_STATUS EFIAPI MaliciousDxeEntry(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
) {
    // S'exécute AVANT le bootloader
    // Peut patcher la db/dbx en mémoire
    // Peut désactiver les vérifications Secure Boot

    // Exemple: Patcher la fonction de vérification de signature
    VOID* VerifySignatureFunc = FindPattern(SystemTable, signature_pattern);
    if (VerifySignatureFunc) {
        // Remplacer par "return EFI_SUCCESS;"
        PatchMemory(VerifySignatureFunc, "\xB8\x00\x00\x00\x00\xC3", 6);
        // MOV EAX, 0 ; RET (x86-64)
    }

    return EFI_SUCCESS;
}
```

**Persistance :**

- Survit à TOUT (réinstallation OS, formatage disque)
- Invisible pour l'OS
- Détection extrêmement difficile

---

### 6.2 - Exploitation de shim (théorique)

**Scénario :**

Trouver un bug dans shim pour exécuter du code arbitraire avant la vérification MOK.

**Surfaces d'attaque :**

1. **Parser PE/COFF** : Buffer overflow dans le parsing des headers
2. **Vérification de signature** : Cryptographic flaw
3. **MOK enrollment** : Race condition lors de l'ajout de clés

**Exemple de bug hypothétique :**

```c
// Code vulnérable dans shim (exemple fictif)
CHAR16 user_input[256];
ReadUserInput(user_input); // Pas de vérification de longueur !

CHAR16 buffer[128];
StrCpy(buffer, user_input); // Buffer overflow !

// Exploitation : user_input = "AAAA..." (> 128 chars)
// → Écrase l'adresse de retour
// → ROP chain pour désactiver Secure Boot
```

---

## Partie 7 : Détection et défense

### Détection d'un boot compromis

**1. Mesures TPM (Trusted Platform Module)**

Le TPM mesure chaque étape du boot et stocke les hashes dans des **PCR** (Platform Configuration Registers).

```bash
# Lire les PCR du TPM
sudo tpm2_pcrread

# PCR 0-7 = Firmware et bootloader
# PCR 8-9 = OS loader
```

Si un composant est modifié, le hash dans les PCR change.

**Utilisation en défense :**

- **BitLocker / LUKS avec TPM** : Déverrouille seulement si les PCR correspondent
- **Remote Attestation** : Envoyer les PCR à un serveur pour vérification

**2. UEFI Secure Boot avec dbx à jour**

```bash
# Vérifier la version de la dbx
efi-readvar -v dbx | grep -i version

# Mettre à jour avec fwupdmgr (Linux)
sudo fwupdmgr refresh
sudo fwupdmgr get-updates
sudo fwupdmgr update
```

**3. Intégrité de l'ESP**

```bash
# Générer des hashes de l'ESP
sudo find /boot/efi -type f -exec sha256sum {} \; > esp_hashes.txt

# Comparer régulièrement
sudo find /boot/efi -type f -exec sha256sum {} \; > esp_current.txt
diff esp_hashes.txt esp_current.txt
```

**4. Monitorer les modifications UEFI**

```bash
# Logger les modifications des variables UEFI
auditctl -w /sys/firmware/efi/efivars -p wa -k uefi_changes

# Voir les logs
ausearch -k uefi_changes
```

---

## Résumé

| Concept | Points clés |
|---------|-------------|
| **Secure Boot** | Vérifie la signature de chaque composant de boot (bootloader → kernel → drivers) |
| **Chaîne de confiance** | PK → KEK → db/dbx → Vérification des signatures Authenticode |
| **Bypass** | Boothole (GRUB), MOK manipulation, Setup Mode, bugs firmware, implants DXE |
| **Défense** | dbx à jour, TPM + Measured Boot, monitoring ESP, UEFI password |
| **Red Team** | Bootkits UEFI = persistance maximale, pré-kernel, invisible de l'OS |

**Progression logique :**

1. **A06_uefi_basics** : Comprendre l'architecture UEFI
2. **A07_secure_boot** (ce module) : Comprendre la chaîne de confiance et ses failles
3. **A08_spi_flash** : Attaquer directement le firmware
4. **A09_bootkit_concepts** : Implémenter un bootkit MBR/UEFI
5. **A10_smm_basics** : Ring -2, attaques SMM

---

## Ressources complémentaires

- **UEFI Spec** : https://uefi.org/specifications
- **Shim source code** : https://github.com/rhboot/shim
- **BootHole advisory** : https://eclypsium.com/2020/07/29/theres-a-hole-in-the-boot/
- **BlackLotus analysis** : https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit/
- **Microsoft UEFI CA** : https://docs.microsoft.com/en-us/windows-hardware/drivers/install/uefi-signing
- **GNU-EFI** : https://sourceforge.net/projects/gnu-efi/
- **EDK II (UEFI dev kit)** : https://github.com/tianocore/edk2

---

**Module suivant** : [SPI Flash & BIOS Attacks](../03-SPI-Flash/)

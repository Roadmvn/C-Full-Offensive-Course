# Module A06 : Fondamentaux UEFI

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre l'architecture UEFI et son rôle dans le boot
- [ ] Identifier les phases de démarrage UEFI
- [ ] Analyser des variables UEFI depuis l'OS
- [ ] Comprendre les protocoles UEFI essentiels
- [ ] Appliquer ces connaissances pour le développement de bootkits

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (structures, pointeurs)
- Architecture x86/x64 (modes CPU, mémoire)
- Notions de BIOS legacy
- Concepts de bootloaders (MBR, GPT)

## Introduction

UEFI (Unified Extensible Firmware Interface) est le successeur moderne du BIOS legacy. C'est un firmware qui initialise le hardware et lance l'OS. Comprendre UEFI est essentiel pour créer des implants firmware (bootkits, rootkits UEFI).

### Pourquoi ce sujet est important ?

Imaginez que le démarrage d'un ordinateur soit comme le réveil d'une ville :
- **BIOS legacy** = Une seule personne (maire) réveille tout manuellement
- **UEFI** = Une équipe organisée (gouvernement) avec des protocoles et processus

Pour un Red Teamer :
- **Persistance ultime** : Un bootkit UEFI survit à la réinstallation de l'OS
- **Furtivité** : S'exécute avant l'OS et les antivirus
- **Attaques firmware** : Exploiter les vulnérabilités UEFI (LogoFAIL, BootHole)
- **Secure Boot bypass** : Comprendre UEFI est requis pour bypass Secure Boot

## 1. UEFI vs BIOS Legacy

### 1.1 Comparaison

```
BIOS Legacy                    UEFI
┌─────────────────┐           ┌──────────────────────┐
│ ROM (1-2 MB)    │           │ Flash (16+ MB)       │
│ 16-bit code     │           │ 32/64-bit code       │
│ MBR boot        │           │ GPT boot             │
│ Pas d'interface │           │ GUI possible         │
│ Drivers limités │           │ Drivers modulaires   │
│ Pas de sécurité │           │ Secure Boot          │
└─────────────────┘           └──────────────────────┘

Capacités:
- Max disk: 2 TB               - Max disk: 9.4 ZB
- Max partitions: 4            - Max partitions: 128
- Boot time: lent              - Boot time: rapide
- Réseau: non                  - Réseau: oui (PXE)
```

### 1.2 Avantages UEFI pour l'attaquant

**Avantages** :
- Plus de surface d'attaque (code complexe, drivers)
- Modules chargeables (facile d'injecter du code)
- Accès réseau (PXE boot = exfiltration dès le boot)
- Variables persistantes (stockage de config malveillante)

**Inconvénients** :
- Secure Boot (si activé, signatures requises)
- Protections firmware (Intel Boot Guard, AMD PSP)

## 2. Architecture UEFI

### 2.1 Composants principaux

```
┌─────────────────────────────────────────────────────┐
│                 Operating System                     │
├─────────────────────────────────────────────────────┤
│            UEFI Boot Services / Runtime              │
│  ┌────────────────────┬──────────────────────┐      │
│  │  Boot Services     │  Runtime Services    │      │
│  │  - Memory alloc    │  - Variables (nvram) │      │
│  │  - Protocols       │  - Time/Date         │      │
│  │  - Drivers load    │  - Reset system      │      │
│  └────────────────────┴──────────────────────┘      │
├─────────────────────────────────────────────────────┤
│              UEFI Drivers (Protocols)                │
│  ┌──────────┬──────────┬──────────┬────────┐        │
│  │ Disk I/O │ Graphics │ Network  │ USB    │        │
│  └──────────┴──────────┴──────────┴────────┘        │
├─────────────────────────────────────────────────────┤
│         Platform Initialization (PI)                 │
│  SEC → PEI → DXE → BDS → TSL → RT                   │
├─────────────────────────────────────────────────────┤
│                  Hardware                            │
└─────────────────────────────────────────────────────┘
```

**Boot Services** : Disponibles uniquement avant ExitBootServices()
**Runtime Services** : Disponibles même après le boot de l'OS

## 3. Phases de boot UEFI (PI)

### 3.1 Les 6 phases

```
Power On
   │
   ↓
┌──────────────────────────────────────────┐
│ 1. SEC (Security)                         │
│    - CPU init                             │
│    - Vérifier intégrité firmware         │
│    - Passer à PEI                        │
│    Durée: ~10ms                          │
└──────────────────────────────────────────┘
   │
   ↓
┌──────────────────────────────────────────┐
│ 2. PEI (Pre-EFI Initialization)          │
│    - Init RAM temporaire (CAR)           │
│    - Détecter RAM principale             │
│    - Charger PEIMs (modules)             │
│    Point d'injection possible            │
└──────────────────────────────────────────┘
   │
   ↓
┌──────────────────────────────────────────┐
│ 3. DXE (Driver Execution Environment)    │
│    - Charger DXE drivers                 │
│    - Initialiser protocoles              │
│    - Setup hardware (GPU, disk, etc.)    │
│    Phase la plus riche en code           │
│    Point d'injection populaire           │
└──────────────────────────────────────────┘
   │
   ↓
┌──────────────────────────────────────────┐
│ 4. BDS (Boot Device Selection)           │
│    - Lire Boot#### variables             │
│    - Afficher menu boot                  │
│    - Charger bootloader OS               │
│    Point d'interception bootloader       │
└──────────────────────────────────────────┘
   │
   ↓
┌──────────────────────────────────────────┐
│ 5. TSL (Transient System Load)           │
│    - Exécuter bootloader (GRUB, Windows) │
│    - ExitBootServices() appelé           │
│    - Boot services désactivés            │
└──────────────────────────────────────────┘
   │
   ↓
┌──────────────────────────────────────────┐
│ 6. RT (Runtime)                           │
│    - OS en contrôle                      │
│    - Runtime services seulement          │
│    - Variables UEFI accessibles          │
└──────────────────────────────────────────┘
```

### 3.2 Points d'injection pour Red Team

```
Phase      Complexité  Détection  Persistance  Use Case
─────────────────────────────────────────────────────────
SEC        Très haute  Très basse Maximale     APT nation-state
PEI        Haute       Basse      Très haute   Rootkit avancé
DXE        Moyenne     Moyenne    Haute        Bootkit typique
BDS        Basse       Haute      Moyenne      Hook bootloader
TSL        Très basse  Très haute Faible       Patch bootloader
```

## 4. Variables UEFI

### 4.1 Qu'est-ce qu'une variable UEFI ?

Les variables UEFI sont des paires clé-valeur stockées dans la NVRAM (flash).

```
Variable UEFI:
┌────────────────────────────────────────┐
│ Name: "Boot0001"                       │
│ GUID: 8BE4DF61-93CA-11d2-AA0D-00E098032B8C │
│ Attributes: BS | RT | NV               │
│ Data: [bootloader path, options]      │
└────────────────────────────────────────┘

Attributes:
- NV  = Non-Volatile (persistant)
- BS  = Boot Services (accessible avant OS)
- RT  = Runtime (accessible depuis OS)
- RO  = Read-Only
```

### 4.2 Lire les variables UEFI en C (Linux)

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// Path vers les variables UEFI sous Linux
#define EFIVARFS_PATH "/sys/firmware/efi/efivars"

void list_efi_variables(void) {
    DIR *dir;
    struct dirent *entry;

    dir = opendir(EFIVARFS_PATH);
    if (!dir) {
        perror("[-] Impossible d'ouvrir /sys/firmware/efi/efivars");
        printf("    Système non-UEFI ou efivarfs non monté\n");
        return;
    }

    printf("[+] Variables UEFI détectées:\n\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        // Format: VarName-GUID
        printf("  - %s\n", entry->d_name);
    }

    closedir(dir);
}

int read_efi_variable(const char *name) {
    char path[512];
    uint8_t buffer[4096];
    int fd;
    ssize_t size;

    snprintf(path, sizeof(path), "%s/%s", EFIVARFS_PATH, name);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("[-] Erreur lecture variable");
        return -1;
    }

    // Les 4 premiers bytes = attributes
    size = read(fd, buffer, sizeof(buffer));
    close(fd);

    if (size < 4) {
        printf("[-] Variable vide ou erreur\n");
        return -1;
    }

    uint32_t attributes = *(uint32_t *)buffer;

    printf("[+] Variable: %s\n", name);
    printf("    Attributes: 0x%08x\n", attributes);
    printf("    Size: %ld bytes\n", size - 4);

    printf("    Data (hex): ");
    for (int i = 4; i < (size < 68 ? size : 68); i++) {
        printf("%02x ", buffer[i]);
    }
    printf("%s\n", size > 68 ? "..." : "");

    return 0;
}

int main(void) {
    printf("=== UEFI Variables Reader ===\n\n");

    list_efi_variables();

    printf("\n[*] Lecture de Boot0000...\n");
    read_efi_variable("Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c");

    return 0;
}
```

### 4.3 Variables importantes

```
Variable           GUID (partiel)        Usage
─────────────────────────────────────────────────────────
Boot####          8be4df61-...          Ordre de boot
BootCurrent       8be4df61-...          Entry actuel
BootOrder         8be4df61-...          Liste boot
SecureBoot        8be4df61-...          État Secure Boot
SetupMode         8be4df61-...          Mode setup (0/1)
PK                8be4df61-...          Platform Key
KEK               8be4df61-...          Key Exchange Key
db                d719b2cb-...          Allowed signatures
dbx               d719b2cb-...          Forbidden signatures
OsIndications     8be4df61-...          Flags OS→firmware
```

## 5. Protocoles UEFI

### 5.1 Concept de protocole

Un protocole UEFI est une interface (comme une classe en POO) qui expose des fonctions.

```
Protocol = Interface + GUID

Exemple: EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
  GUID: 964e5b22-6459-11d2-8e39-00a0c969723b
  Fonctions:
    - OpenVolume()
```

### 5.2 Protocoles essentiels

```c
// 1. Loaded Image Protocol (infos sur l'image chargée)
EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

gBS->HandleProtocol(
    ImageHandle,
    &loaded_image_guid,
    (void **)&loaded_image
);

// 2. Simple File System Protocol (accès filesystem)
EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

gBS->LocateProtocol(&fs_guid, NULL, (void **)&fs);

// 3. Graphics Output Protocol (affichage)
EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

gBS->LocateProtocol(&gop_guid, NULL, (void **)&gop);
```

## 6. Application UEFI simple

### 6.1 Hello World UEFI

```c
#include <efi.h>
#include <efilib.h>

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle,
                            EFI_SYSTEM_TABLE *SystemTable) {
    // Initialiser la lib GNU-EFI
    InitializeLib(ImageHandle, SystemTable);

    // Afficher un message
    Print(L"Hello from UEFI!\n");
    Print(L"Firmware Vendor: %s\n", SystemTable->FirmwareVendor);
    Print(L"UEFI Version: %d.%d\n",
          SystemTable->Hdr.Revision >> 16,
          SystemTable->Hdr.Revision & 0xFFFF);

    // Attendre une touche
    Print(L"\nPress any key to exit...\n");

    EFI_INPUT_KEY Key;
    while (SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &Key)
           == EFI_NOT_READY);

    return EFI_SUCCESS;
}
```

**Compilation** (avec GNU-EFI) :
```bash
gcc -I/usr/include/efi -I/usr/include/efi/x86_64 \
    -fno-stack-protector -fpic -fshort-wchar \
    -mno-red-zone -DEFI_FUNCTION_WRAPPER \
    -c hello.c -o hello.o

ld -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds \
   -shared -Bsymbolic -L /usr/lib /usr/lib/crt0-efi-x86_64.o \
   hello.o -o hello.so -lefi -lgnuefi

objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
        -j .rel -j .rela -j .reloc --target=efi-app-x86_64 \
        hello.so hello.efi
```

### 6.2 Lire un fichier depuis UEFI

```c
#include <efi.h>
#include <efilib.h>

EFI_STATUS read_file(EFI_FILE_PROTOCOL *root, CHAR16 *filename) {
    EFI_FILE_PROTOCOL *file;
    EFI_STATUS status;
    CHAR8 buffer[1024];
    UINTN size = sizeof(buffer);

    // Ouvrir le fichier
    status = root->Open(root, &file, filename, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        Print(L"[-] Impossible d'ouvrir %s\n", filename);
        return status;
    }

    // Lire le contenu
    status = file->Read(file, &size, buffer);
    if (!EFI_ERROR(status)) {
        Print(L"[+] Contenu (%d bytes):\n", size);
        for (UINTN i = 0; i < size; i++) {
            Print(L"%c", buffer[i]);
        }
        Print(L"\n");
    }

    file->Close(file);
    return status;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle,
                            EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
    EFI_FILE_PROTOCOL *root;
    EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    // Obtenir le filesystem
    gBS->LocateProtocol(&fs_guid, NULL, (void **)&fs);
    fs->OpenVolume(fs, &root);

    // Lire un fichier
    read_file(root, L"\\EFI\\BOOT\\grub.cfg");

    root->Close(root);

    return EFI_SUCCESS;
}
```

## 7. Applications offensives

### 7.1 Bootkit UEFI - Concept

Un bootkit UEFI s'installe dans la partition ESP (EFI System Partition) et se charge avant le bootloader légitime.

```
Partition ESP (/boot/efi)
┌─────────────────────────────────────┐
│ /EFI/BOOT/                           │
│   ├── BOOTX64.EFI (légitime)        │
│   ├── BOOTX64_ORIG.EFI (backup)     │ <-- Bootkit renomme
│   └── BOOTKIT.EFI                   │ <-- Malware
│                                      │
│ /EFI/Microsoft/Boot/                 │
│   └── bootmgfw.efi                   │
└─────────────────────────────────────┘

Flux d'exécution:
1. UEFI charge BOOTX64.EFI (bootkit)
2. Bootkit exécute payload (keylogger, backdoor)
3. Bootkit chainload BOOTX64_ORIG.EFI (légitime)
4. Boot normal (invisible pour l'utilisateur)
```

### 7.2 Exemple de bootkit minimaliste

```c
#include <efi.h>
#include <efilib.h>

// Payload malveillant
void evil_payload(void) {
    Print(L"[BOOTKIT] Payload executed!\n");
    // En pratique:
    // - Hooker ExitBootServices pour persister en RAM
    // - Installer un hyperviseur (blue pill)
    // - Patcher le kernel au chargement
}

EFI_STATUS chainload_original_bootloader(EFI_HANDLE ImageHandle) {
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
    EFI_DEVICE_PATH_PROTOCOL *device_path;
    EFI_HANDLE new_image_handle;
    EFI_STATUS status;

    // Charger le bootloader original
    // (renommé en BOOTX64_ORIG.EFI)

    // Simplified: en pratique, construire le device path
    Print(L"[BOOTKIT] Chainloading original bootloader...\n");

    // LoadImage() + StartImage() sur BOOTX64_ORIG.EFI

    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle,
                            EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);

    Print(L"[BOOTKIT] Initializing...\n");

    // Exécuter le payload malveillant
    evil_payload();

    // Charger le bootloader légitime (transparence)
    chainload_original_bootloader(ImageHandle);

    return EFI_SUCCESS;
}
```

### 7.3 Hooking Runtime Services

```c
// Technique pour persister après ExitBootServices
EFI_GET_VARIABLE original_get_variable = NULL;

EFI_STATUS EFIAPI hooked_get_variable(
    CHAR16 *VariableName,
    EFI_GUID *VendorGuid,
    UINT32 *Attributes,
    UINTN *DataSize,
    VOID *Data) {

    // Intercepter les lectures de variables
    Print(L"[HOOK] GetVariable called: %s\n", VariableName);

    // Appeler l'original
    return original_get_variable(VariableName, VendorGuid,
                                  Attributes, DataSize, Data);
}

void install_hooks(EFI_SYSTEM_TABLE *SystemTable) {
    // Sauvegarder l'original
    original_get_variable = SystemTable->RuntimeServices->GetVariable;

    // Installer le hook
    SystemTable->RuntimeServices->GetVariable = hooked_get_variable;

    // Recalculer le CRC32 de la table (sinon UEFI détecte)
    SystemTable->RuntimeServices->Hdr.CRC32 = 0;
    gBS->CalculateCrc32(SystemTable->RuntimeServices,
                        SystemTable->RuntimeServices->Hdr.HeaderSize,
                        &SystemTable->RuntimeServices->Hdr.CRC32);
}
```

## 8. Détection de bootkits UEFI

### 8.1 Indicateurs depuis l'OS

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vérifier les checksums des binaires UEFI
int check_efi_integrity(void) {
    FILE *fp;
    unsigned char hash[32];
    const char *known_good_hash = "a1b2c3d4..."; // Hash connu

    // Calculer SHA256 de /boot/efi/EFI/BOOT/BOOTX64.EFI
    fp = popen("sha256sum /boot/efi/EFI/BOOT/BOOTX64.EFI", "r");
    if (!fp) return -1;

    fscanf(fp, "%s", hash);
    pclose(fp);

    if (strcmp(hash, known_good_hash) != 0) {
        printf("[!] BOOTKIT DÉTECTÉ: hash mismatch\n");
        return 1;
    }

    printf("[+] Bootloader légitime\n");
    return 0;
}

// Vérifier les variables UEFI suspectes
int check_suspicious_variables(void) {
    // Chercher des variables custom ou modifiées
    system("ls -la /sys/firmware/efi/efivars/ | grep -v '8be4df61'");
    return 0;
}
```

## 9. Considérations OPSEC

### 9.1 Détection d'un bootkit UEFI

**Indicateurs** :
- Hash modifié des binaires ESP
- Variables UEFI suspectes
- Temps de boot anormal
- Secure Boot désactivé
- Logs TPM/Measured Boot

**Mitigation pour l'attaquant** :
- Re-signer avec certificat volé (si Secure Boot)
- Minimiser les modifications (in-memory hooks)
- Utiliser un implant firmware (plus furtif)

### 9.2 Défenses

- **Secure Boot** : Vérifier signatures
- **Intel Boot Guard** : Hardware root of trust
- **TPM Measured Boot** : Log de l'intégrité
- **BIOS/UEFI updates** : Patcher les vulnérabilités

## Résumé

- UEFI remplace BIOS legacy avec architecture moderne
- 6 phases de boot: SEC → PEI → DXE → BDS → TSL → RT
- Variables UEFI stockées en NVRAM (persistance)
- Protocoles UEFI = interfaces pour hardware/services
- Boot Services (avant OS) vs Runtime Services (après OS)
- Applications UEFI écrites en C, compilées en .efi
- Bootkit UEFI = payload dans ESP, chainload bootloader
- Hooking Runtime Services pour persistance post-boot
- Détection: checksums, variables, Secure Boot

## Checklist

- [ ] Comprendre les 6 phases de boot UEFI
- [ ] Savoir lire les variables UEFI depuis Linux
- [ ] Connaître les protocoles essentiels (FS, GOP, LoadedImage)
- [ ] Compiler une application UEFI simple
- [ ] Comprendre le concept de bootkit UEFI
- [ ] Identifier les points d'injection dans le boot
- [ ] Connaître les techniques de détection

## Exercices

Voir `exercice.md` pour les défis pratiques.

## Ressources complémentaires

- UEFI Specification 2.10: https://uefi.org/specifications
- GNU-EFI Library: https://sourceforge.net/projects/gnu-efi/
- Tianocore EDK II: https://github.com/tianocore/edk2
- "UEFI Firmware Bootkits" (BlackHat): https://www.blackhat.com/
- CHIPSEC (UEFI security tool): https://github.com/chipsec/chipsec

---

**Navigation**
- [Retour au sommaire FIRMWARE](../)
- [Module suivant : Secure Boot](../02-Secure-Boot/)

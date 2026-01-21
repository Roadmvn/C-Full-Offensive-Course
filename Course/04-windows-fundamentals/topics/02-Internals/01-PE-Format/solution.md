# Solutions - Format PE

## Note importante

Les exercices de ce module utilisent des fichiers template génériques. Les solutions ci-dessous sont basées sur le contenu du cours et fournissent des implémentations complètes et commentées en français pour comprendre le format PE.

---

## Exercice 1 : Découverte - Parser le DOS Header

**Objectif** : Se familiariser avec la structure de base d'un fichier PE en parsant le DOS Header

**Solution complète** :

```c
#include <windows.h>
#include <stdio.h>

/*
 * parse_dos_header - Analyse le DOS Header d'un fichier PE
 *
 * Cette fonction ouvre un fichier PE, le mappe en mémoire et extrait
 * les informations du DOS Header (signature MZ, offset vers PE Header)
 */
void parse_dos_header(const char* filepath) {
    printf("[*] Analyse du fichier : %s\n\n", filepath);

    // Étape 1 : Ouvrir le fichier PE
    // GENERIC_READ = accès lecture seule
    // FILE_SHARE_READ = autoriser d'autres processus à lire
    HANDLE hFile = CreateFileA(
        filepath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,  // Le fichier doit exister
        0,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur : Impossible d'ouvrir le fichier\n");
        printf("    Code erreur : %d\n", GetLastError());
        return;
    }

    printf("[+] Fichier ouvert avec succès\n");

    // Étape 2 : Créer un mapping mémoire du fichier
    // PAGE_READONLY = mappage en lecture seule
    HANDLE hMapping = CreateFileMappingA(
        hFile,
        NULL,
        PAGE_READONLY,
        0, 0,  // Taille complète du fichier
        NULL
    );

    if (!hMapping) {
        printf("[-] Erreur : CreateFileMapping\n");
        CloseHandle(hFile);
        return;
    }

    // Étape 3 : Mapper la vue du fichier en mémoire
    LPVOID pBase = MapViewOfFile(
        hMapping,
        FILE_MAP_READ,
        0, 0,  // Offset 0
        0      // Taille complète
    );

    if (!pBase) {
        printf("[-] Erreur : MapViewOfFile\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    printf("[+] Fichier mappé en mémoire à l'adresse : %p\n\n", pBase);

    // Étape 4 : Lire le DOS Header
    // Le DOS Header est toujours au début du fichier (offset 0x0000)
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;

    printf("=== DOS HEADER ===\n");

    // Vérifier la signature MZ (0x5A4D)
    printf("Signature (e_magic): 0x%04X ", pDosHeader->e_magic);

    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {  // IMAGE_DOS_SIGNATURE = 0x5A4D = 'MZ'
        printf("('MZ') ✓ VALIDE\n");
    } else {
        printf("✗ INVALIDE - Ce n'est pas un fichier PE valide\n");
        goto cleanup;
    }

    // Afficher l'offset vers le PE Header
    // e_lfanew contient l'offset dans le fichier où se trouve la signature PE
    printf("Offset vers PE Header (e_lfanew): 0x%08X (%d bytes)\n",
           pDosHeader->e_lfanew,
           pDosHeader->e_lfanew);

    // Étape 5 : Vérifier la signature PE
    // On se déplace à l'offset indiqué par e_lfanew
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    printf("\nSignature PE: 0x%08X ", pNtHeaders->Signature);

    if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE) {  // IMAGE_NT_SIGNATURE = 0x50450000 = 'PE\0\0'
        printf("('PE\\0\\0') ✓ VALIDE\n");
    } else {
        printf("✗ INVALIDE\n");
        goto cleanup;
    }

    printf("\n[+] Fichier PE valide détecté !\n");

cleanup:
    // Nettoyage : libérer les ressources dans l'ordre inverse de création
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fichier_pe>\n", argv[0]);
        printf("Exemple: %s C:\\Windows\\System32\\notepad.exe\n", argv[0]);
        return 1;
    }

    parse_dos_header(argv[1]);
    return 0;
}
```

**Résultat attendu** :
```
[*] Analyse du fichier : notepad.exe

[+] Fichier ouvert avec succès
[+] Fichier mappé en mémoire à l'adresse : 00007FF8A0000000

=== DOS HEADER ===
Signature (e_magic): 0x5A4D ('MZ') ✓ VALIDE
Offset vers PE Header (e_lfanew): 0x000000F0 (240 bytes)

Signature PE: 0x00004550 ('PE\0\0') ✓ VALIDE

[+] Fichier PE valide détecté !
```

**Compilation** :
```batch
cl solution1.c /Fe:solution1.exe
```

---

## Exercice 2 : Modification - Parser les NT Headers

**Objectif** : Extraire et afficher les informations des NT Headers (File Header et Optional Header)

**Solution complète** :

```c
#include <windows.h>
#include <stdio.h>
#include <time.h>

void parse_nt_headers(LPVOID pBase) {
    // Récupérer DOS Header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;

    // Récupérer NT Headers en utilisant e_lfanew
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    printf("\n=== FILE HEADER ===\n");

    // 1. Type d'architecture (Machine)
    printf("Machine: 0x%04X ", pNtHeaders->FileHeader.Machine);
    switch (pNtHeaders->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:   // 0x014C
            printf("(x86 - 32 bits)\n");
            break;
        case IMAGE_FILE_MACHINE_AMD64:  // 0x8664
            printf("(x64 - 64 bits)\n");
            break;
        case IMAGE_FILE_MACHINE_ARM64:  // 0xAA64
            printf("(ARM64)\n");
            break;
        default:
            printf("(Inconnu)\n");
    }

    // 2. Nombre de sections
    printf("Nombre de sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);

    // 3. Date de compilation (timestamp Unix)
    printf("TimeDateStamp: 0x%08X ", pNtHeaders->FileHeader.TimeDateStamp);
    time_t timestamp = pNtHeaders->FileHeader.TimeDateStamp;
    printf("(%s", ctime(&timestamp));  // ctime ajoute déjà un \n

    // 4. Taille de l'Optional Header
    printf("Taille Optional Header: %d bytes\n", pNtHeaders->FileHeader.SizeOfOptionalHeader);

    // 5. Caractéristiques du fichier (flags)
    printf("Characteristics: 0x%04X\n", pNtHeaders->FileHeader.Characteristics);

    // Décoder les flags importants
    if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        printf("  - IMAGE_FILE_EXECUTABLE_IMAGE (fichier exécutable)\n");
    }
    if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        printf("  - IMAGE_FILE_DLL (c'est une DLL)\n");
    }
    if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
        printf("  - IMAGE_FILE_LARGE_ADDRESS_AWARE (supporte >2GB)\n");
    }

    printf("\n=== OPTIONAL HEADER ===\n");

    // 6. Magic (PE32 vs PE32+)
    printf("Magic: 0x%04X ", pNtHeaders->OptionalHeader.Magic);
    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {  // 0x020B
        printf("(PE32+ / x64)\n");
    } else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {  // 0x010B
        printf("(PE32 / x86)\n");
    } else {
        printf("(Inconnu)\n");
    }

    // 7. Point d'entrée (OEP - Original Entry Point)
    printf("AddressOfEntryPoint: 0x%08X (RVA du point d'entrée)\n",
           pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    // 8. Adresse de base préférée
    printf("ImageBase: 0x%016llX (adresse de chargement préférée)\n",
           pNtHeaders->OptionalHeader.ImageBase);

    // 9. Alignements
    printf("SectionAlignment: 0x%08X (alignement en mémoire)\n",
           pNtHeaders->OptionalHeader.SectionAlignment);
    printf("FileAlignment: 0x%08X (alignement sur disque)\n",
           pNtHeaders->OptionalHeader.FileAlignment);

    // 10. Taille de l'image en mémoire
    printf("SizeOfImage: 0x%08X (%u bytes)\n",
           pNtHeaders->OptionalHeader.SizeOfImage,
           pNtHeaders->OptionalHeader.SizeOfImage);

    // 11. Taille des headers
    printf("SizeOfHeaders: 0x%08X (%u bytes)\n",
           pNtHeaders->OptionalHeader.SizeOfHeaders,
           pNtHeaders->OptionalHeader.SizeOfHeaders);

    // 12. Subsystem (GUI vs Console vs Native)
    printf("Subsystem: ");
    switch (pNtHeaders->OptionalHeader.Subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE:
            printf("Native (driver)\n");
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            printf("Windows GUI\n");
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            printf("Windows Console (CUI)\n");
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
            printf("Boot Application\n");
            break;
        default:
            printf("Inconnu (%d)\n", pNtHeaders->OptionalHeader.Subsystem);
    }

    // 13. Caractéristiques DLL (ASLR, DEP, etc.)
    printf("DllCharacteristics: 0x%04X\n", pNtHeaders->OptionalHeader.DllCharacteristics);

    if (pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        printf("  - ASLR activé (DYNAMIC_BASE)\n");
    }
    if (pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
        printf("  - DEP/NX activé (NX_COMPAT)\n");
    }
    if (pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) {
        printf("  - High Entropy ASLR (64-bit)\n");
    }
    if (pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        printf("  - Control Flow Guard (CFG)\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fichier_pe>\n", argv[0]);
        return 1;
    }

    // Ouvrir et mapper fichier
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur ouverture fichier\n");
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // Vérifier signatures
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Pas un fichier PE valide\n");
        goto cleanup;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature PE invalide\n");
        goto cleanup;
    }

    // Parser NT Headers
    parse_nt_headers(pBase);

cleanup:
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}
```

**Compilation** :
```batch
cl solution2.c /Fe:solution2.exe
```

---

## Exercice 3 : Création - Énumérer et analyser les sections

**Objectif** : Créer un programme qui liste toutes les sections avec leurs propriétés

**Solution complète** :

```c
#include <windows.h>
#include <stdio.h>

void parse_sections(LPVOID pBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    // IMAGE_FIRST_SECTION est une macro qui calcule l'adresse de la première section
    // Elle pointe juste après les NT Headers
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    printf("\n=== SECTIONS (%d au total) ===\n\n", pNtHeaders->FileHeader.NumberOfSections);

    // En-tête du tableau
    printf("%-10s %-12s %-12s %-12s %-12s %-6s %s\n",
           "Nom", "VirtAddr", "VirtSize", "RawSize", "RawOffset", "Perms", "Type");
    printf("────────────────────────────────────────────────────────────────────────────────\n");

    // Parcourir chaque section
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        // 1. Nom de la section (8 caractères max, pas toujours null-terminated)
        char sectionName[9] = {0};  // +1 pour null terminator
        memcpy(sectionName, pSectionHeader[i].Name, 8);

        // 2. Adresse virtuelle (RVA) - offset depuis ImageBase en mémoire
        DWORD virtualAddr = pSectionHeader[i].VirtualAddress;

        // 3. Taille virtuelle - taille réelle en mémoire
        DWORD virtualSize = pSectionHeader[i].Misc.VirtualSize;

        // 4. Taille raw - taille dans le fichier (alignée sur FileAlignment)
        DWORD rawSize = pSectionHeader[i].SizeOfRawData;

        // 5. Offset raw - position dans le fichier
        DWORD rawOffset = pSectionHeader[i].PointerToRawData;

        // 6. Caractéristiques (permissions et type)
        DWORD characteristics = pSectionHeader[i].Characteristics;

        // Décoder les permissions (R/W/X)
        char perms[4] = "---";
        if (characteristics & IMAGE_SCN_MEM_READ)    perms[0] = 'R';
        if (characteristics & IMAGE_SCN_MEM_WRITE)   perms[1] = 'W';
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) perms[2] = 'X';

        // Afficher la ligne
        printf("%-10s 0x%08X   0x%08X   0x%08X   0x%08X   %s   ",
               sectionName,
               virtualAddr,
               virtualSize,
               rawSize,
               rawOffset,
               perms);

        // 7. Type de contenu
        if (characteristics & IMAGE_SCN_CNT_CODE) {
            printf("[CODE] ");
        }
        if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            printf("[IDATA] ");
        }
        if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            printf("[UDATA] ");
        }

        // Informations supplémentaires sur les sections connues
        if (strcmp(sectionName, ".text") == 0) {
            printf("← Code exécutable");
        } else if (strcmp(sectionName, ".rdata") == 0) {
            printf("← Read-only data (imports, exports, strings)");
        } else if (strcmp(sectionName, ".data") == 0) {
            printf("← Variables globales initialisées");
        } else if (strcmp(sectionName, ".bss") == 0) {
            printf("← Variables non initialisées");
        } else if (strcmp(sectionName, ".rsrc") == 0) {
            printf("← Ressources (icons, dialogs, manifests)");
        } else if (strcmp(sectionName, ".reloc") == 0) {
            printf("← Relocation table");
        }

        printf("\n");
    }

    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fichier_pe>\n", argv[0]);
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur ouverture fichier\n");
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    if (!pBase) {
        printf("[-] Erreur mapping\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Vérifications
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Pas un fichier PE\n");
        goto cleanup;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature PE invalide\n");
        goto cleanup;
    }

    parse_sections(pBase);

cleanup:
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}
```

**Critères de réussite** :
- [x] Liste toutes les sections du fichier PE
- [x] Affiche les adresses virtuelles et offsets fichier
- [x] Décode correctement les permissions (R/W/X)
- [x] Identifie le type de contenu des sections

---

## Exercice 4 : Challenge - Parser la Import Table complète

**Objectif** : Combiner plusieurs concepts pour créer un parseur complet de la Import Table

**Solution complète** :

Voir le fichier suivant pour la solution complète du challenge.

**Contexte** : La Import Table (IAT) contient la liste de toutes les fonctions qu'un PE importe depuis des DLLs externes. C'est crucial pour l'analyse de malware et les techniques d'injection.

```c
#include <windows.h>
#include <stdio.h>

// Convertir RVA en pointeur fichier
LPVOID rva_to_ptr(LPVOID pBase, DWORD rva) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    // Si RVA dans headers, pas de conversion
    if (rva < pNt->OptionalHeader.SizeOfHeaders) {
        return (LPVOID)((BYTE*)pBase + rva);
    }

    // Chercher section contenant RVA
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        DWORD sectionStart = pSection[i].VirtualAddress;
        DWORD sectionEnd = sectionStart + pSection[i].Misc.VirtualSize;

        if (rva >= sectionStart && rva < sectionEnd) {
            // Formule : FileOffset = RVA - VirtualAddress + PointerToRawData
            DWORD offset = rva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
            return (LPVOID)((BYTE*)pBase + offset);
        }
    }

    return NULL;  // RVA invalide
}

void parse_imports(LPVOID pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);

    // Récupérer RVA de l'Import Directory depuis Data Directory[1]
    DWORD importRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (importRVA == 0) {
        printf("\n[*] Ce fichier n'a pas d'imports\n");
        return;
    }

    // Convertir RVA en pointeur fichier
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)rva_to_ptr(pBase, importRVA);

    if (!pImportDesc) {
        printf("[-] Erreur : Import RVA invalide\n");
        return;
    }

    printf("\n=== IMPORT TABLE ===\n\n");

    int dllCount = 0;

    // Parcourir chaque DLL importée
    // La liste se termine par une entrée avec Name = 0
    while (pImportDesc->Name != 0) {
        dllCount++;

        // Récupérer nom de la DLL
        char* dllName = (char*)rva_to_ptr(pBase, pImportDesc->Name);

        if (!dllName) {
            pImportDesc++;
            continue;
        }

        printf("\n[DLL #%d] %s\n", dllCount, dllName);
        printf("├─ OriginalFirstThunk (INT): 0x%08X\n", pImportDesc->OriginalFirstThunk);
        printf("├─ FirstThunk (IAT):         0x%08X\n", pImportDesc->FirstThunk);
        printf("└─ Fonctions importées:\n");

        // Récupérer Import Name Table (INT)
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)rva_to_ptr(pBase, pImportDesc->OriginalFirstThunk);

        if (!pThunk) {
            pImportDesc++;
            continue;
        }

        int funcCount = 0;

        // Parcourir fonctions
        while (pThunk->u1.AddressOfData != 0) {
            funcCount++;

            // Vérifier si import par ordinal ou par nom
            // Si le bit de poids fort est à 1, c'est un import par ordinal
            #ifdef _WIN64
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // Import par ordinal
                WORD ordinal = (WORD)(pThunk->u1.Ordinal & 0xFFFF);
                printf("   %3d. Ordinal_%u\n", funcCount, ordinal);
            } else {
            #else
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                WORD ordinal = (WORD)(pThunk->u1.Ordinal & 0xFFFF);
                printf("   %3d. Ordinal_%u\n", funcCount, ordinal);
            } else {
            #endif
                // Import par nom
                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)rva_to_ptr(pBase, (DWORD)pThunk->u1.AddressOfData);

                if (pImport) {
                    printf("   %3d. %s (hint: %u)\n", funcCount, pImport->Name, pImport->Hint);
                }
            }

            pThunk++;

            // Limiter affichage pour les grosses listes
            if (funcCount >= 30) {
                printf("   ... (%d+ fonctions au total)\n", funcCount);
                break;
            }
        }

        if (funcCount < 30) {
            printf("   └─ Total: %d fonction(s)\n", funcCount);
        }

        pImportDesc++;
    }

    printf("\n[+] %d DLL(s) importée(s) au total\n", dllCount);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("=== PE IMPORT PARSER ===\n");
        printf("Usage: %s <fichier_pe>\n", argv[0]);
        printf("Exemple: %s C:\\Windows\\System32\\notepad.exe\n", argv[0]);
        return 1;
    }

    printf("=== PE IMPORT PARSER ===\n");
    printf("Fichier: %s\n", argv[1]);

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir le fichier\n");
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        printf("[-] CreateFileMapping échoué\n");
        CloseHandle(hFile);
        return 1;
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        printf("[-] MapViewOfFile échoué\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Validation PE
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Signature MZ invalide\n");
        goto cleanup;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature PE invalide\n");
        goto cleanup;
    }

    printf("[+] Fichier PE valide\n");

    // Parser imports
    parse_imports(pBase);

cleanup:
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}
```

**Bonus** : Modification pour détecter les imports suspects (typiques de malware)

```c
// Liste d'imports suspects (contexte offensif)
const char* suspicious_imports[] = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtQueueApcThread",
    "RtlCreateUserThread",
    "SetWindowsHookEx",
    "CallNextHookEx",
    "GetAsyncKeyState",  // Keylogger
    "InternetOpenUrl",    // C2 communication
    "WinHttpSendRequest",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "OpenProcess",
    "CryptAcquireContext",
    "CryptEncrypt",      // Ransomware
    NULL
};

BOOL is_suspicious_import(const char* funcName) {
    for (int i = 0; suspicious_imports[i] != NULL; i++) {
        if (strcmp(funcName, suspicious_imports[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// Intégrer dans la boucle d'affichage :
if (pImport) {
    printf("   %3d. %s", funcCount, pImport->Name);
    if (is_suspicious_import(pImport->Name)) {
        printf(" ⚠️  SUSPECT");
    }
    printf("\n");
}
```

**Compilation** :
```batch
cl /W4 solution4.c /Fe:import_parser.exe
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :

- [x] **Expliquer le concept principal de ce module**
  - Le format PE structure tous les exécutables Windows (.exe, .dll, .sys)
  - Composé de : DOS Header → PE Signature → NT Headers → Section Table → Sections
  - Les NT Headers contiennent 16 Data Directories (Import, Export, Reloc, etc.)

- [x] **Écrire du code utilisant ces techniques sans regarder l'exemple**
  - Parser DOS Header et vérifier signature MZ
  - Lire NT Headers (File Header + Optional Header)
  - Énumérer sections et leurs propriétés
  - Parser Import/Export Tables

- [x] **Identifier des cas d'usage en contexte offensif**
  - **IAT Hooking** : modifier Import Address Table pour intercepter appels API
  - **Reflective DLL Injection** : charger PE en mémoire sans LoadLibrary
  - **Manual Mapping** : contourner le loader Windows
  - **PE Obfuscation** : modifier headers pour tromper AV
  - **Malware Analysis** : comprendre les imports pour déterminer le comportement

---

## Points clés à retenir

1. **Signatures** : Toujours vérifier MZ (0x5A4D) et PE (0x50450000)
2. **RVA vs File Offset** : Conversion nécessaire pour parser depuis disque
3. **Import Table** : Localiser via Data Directory[1], contient toutes les APIs importées
4. **Sections** : .text (code), .rdata (imports/exports), .data (variables), .rsrc (ressources)
5. **OPSEC** : Modifications du PE détectables par analyse statique (entropy, sections RWX, imports suspects)

## Ressources pour aller plus loin

- [PE Format Microsoft](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE-bear](https://github.com/hasherezade/pe-bear) - Outil d'analyse graphique
- [CFF Explorer](https://ntcore.com/?page_id=388) - Éditeur PE
- [Corkami PE Poster](https://github.com/corkami/pics/blob/master/binary/pe101/pe101-64.pdf) - Diagramme complet

# Solutions - Chargement PE (Manual Mapping)

## Note importante

Ce module documente les mécanismes internes du chargement de PE par Windows à des fins éducatives. La compréhension de ces mécanismes est essentielle pour l'analyse de malware, le reverse engineering et la sécurité système.

---

## Exercice 1 : Découverte - Allouer et copier un PE en mémoire

**Objectif** : Comprendre les bases du Manual Mapping en copiant un PE depuis le disque vers la mémoire

**Solution complète** :

```c
#include <windows.h>
#include <stdio.h>

/*
 * map_pe_sections - Charge un PE en mémoire et copie ses sections
 *
 * Cette fonction réalise les étapes 1-3 du Manual Mapping :
 * 1. Validation du PE
 * 2. Allocation mémoire (SizeOfImage)
 * 3. Copie headers + sections
 *
 * Paramètres:
 *   pFileBuffer - Buffer contenant le PE lu depuis le disque
 *   outImageSize - [OUT] Taille de l'image mappée
 *
 * Retour:
 *   Pointeur vers l'image PE en mémoire, ou NULL si erreur
 */
LPVOID map_pe_sections(LPVOID pFileBuffer, SIZE_T* outImageSize) {
    printf("[*] Étape 1 : Validation du PE...\n");

    // Récupérer DOS Header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

    // Vérifier signature MZ
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Erreur : Signature MZ invalide (0x%04X)\n", pDosHeader->e_magic);
        return NULL;
    }

    // Récupérer NT Headers
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);

    // Vérifier signature PE
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Erreur : Signature PE invalide (0x%08X)\n", pNtHeaders->Signature);
        return NULL;
    }

    printf("[+] PE valide détecté\n");
    printf("    Architecture : %s\n",
           pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x86");
    printf("    ImageBase préférée : 0x%llX\n", pNtHeaders->OptionalHeader.ImageBase);

    // Étape 2 : Allouer mémoire
    printf("\n[*] Étape 2 : Allocation mémoire...\n");

    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    *outImageSize = imageSize;

    printf("    Taille image : 0x%zX (%zu bytes)\n", imageSize, imageSize);

    // VirtualAlloc alloue de la mémoire dans notre processus
    // MEM_COMMIT | MEM_RESERVE : réserver et commiter en une seule fois
    // PAGE_READWRITE : permissions initiales (on changera après)
    LPVOID pImageBase = VirtualAlloc(
        NULL,                        // Laisser Windows choisir l'adresse
        imageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE               // RW initial pour pouvoir écrire
    );

    if (!pImageBase) {
        printf("[-] Erreur VirtualAlloc : %d\n", GetLastError());
        return NULL;
    }

    printf("[+] Mémoire allouée à : 0x%p\n", pImageBase);

    // Étape 3 : Copier headers
    printf("\n[*] Étape 3 : Copie des données...\n");

    DWORD headersSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
    printf("    Copie headers (%u bytes)...\n", headersSize);

    memcpy(pImageBase, pFileBuffer, headersSize);

    // Copier sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    int sectionCount = pNtHeaders->FileHeader.NumberOfSections;

    printf("    Copie %d sections...\n", sectionCount);

    for (int i = 0; i < sectionCount; i++) {
        // Vérifier si section a du contenu sur disque
        if (pSectionHeader[i].SizeOfRawData == 0) {
            printf("      [%d] %-8s : SKIP (section vide - .bss)\n",
                   i, pSectionHeader[i].Name);
            continue;
        }

        // Adresse destination en mémoire
        LPVOID pDestSection = (LPVOID)((BYTE*)pImageBase + pSectionHeader[i].VirtualAddress);

        // Adresse source sur disque
        LPVOID pSrcSection = (LPVOID)((BYTE*)pFileBuffer + pSectionHeader[i].PointerToRawData);

        // Copier données
        memcpy(pDestSection, pSrcSection, pSectionHeader[i].SizeOfRawData);

        printf("      [%d] %-8s : 0x%08X → 0x%p (%u bytes)\n",
               i,
               pSectionHeader[i].Name,
               pSectionHeader[i].PointerToRawData,
               pDestSection,
               pSectionHeader[i].SizeOfRawData);
    }

    printf("[+] PE copié en mémoire avec succès\n");
    return pImageBase;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dll_path>\n", argv[0]);
        printf("Exemple: %s test.dll\n", argv[0]);
        return 1;
    }

    printf("═══════════════════════════════════════\n");
    printf("   MANUAL MAPPER - EXERCICE 1\n");
    printf("═══════════════════════════════════════\n\n");

    // Lire fichier DLL depuis disque
    printf("[*] Lecture du fichier : %s\n\n", argv[1]);

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir le fichier\n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID pFileBuffer = malloc(fileSize);

    if (!pFileBuffer) {
        printf("[-] Erreur allocation mémoire\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, pFileBuffer, fileSize, &bytesRead, NULL)) {
        printf("[-] Erreur lecture fichier\n");
        free(pFileBuffer);
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);
    printf("[+] Fichier lu (%u bytes)\n\n", fileSize);

    // Mapper PE en mémoire
    SIZE_T imageSize = 0;
    LPVOID pImageBase = map_pe_sections(pFileBuffer, &imageSize);

    if (pImageBase) {
        printf("\n═══════════════════════════════════════\n");
        printf("[SUCCESS] DLL mappée à l'adresse 0x%p\n", pImageBase);
        printf("Taille : 0x%zX bytes\n", imageSize);
        printf("═══════════════════════════════════════\n");

        // Dans un vrai loader, on ferait ici :
        // - Relocations
        // - Résolution imports
        // - Protection mémoire
        // - Exécution DllMain

        printf("\nAppuyez sur Entrée pour libérer la mémoire...\n");
        getchar();

        VirtualFree(pImageBase, 0, MEM_RELEASE);
    }

    free(pFileBuffer);
    return 0;
}
```

**Résultat attendu** :
```
═══════════════════════════════════════
   MANUAL MAPPER - EXERCICE 1
═══════════════════════════════════════

[*] Lecture du fichier : test.dll

[+] Fichier lu (8192 bytes)

[*] Étape 1 : Validation du PE...
[+] PE valide détecté
    Architecture : x64
    ImageBase préférée : 0x180000000

[*] Étape 2 : Allocation mémoire...
    Taille image : 0x5000 (20480 bytes)
[+] Mémoire allouée à : 0x000001A2B0A10000

[*] Étape 3 : Copie des données...
    Copie headers (1024 bytes)...
    Copie 4 sections...
      [0] .text    : 0x00000400 → 0x000001A2B0A11000 (2048 bytes)
      [1] .rdata   : 0x00000C00 → 0x000001A2B0A13000 (512 bytes)
      [2] .data    : 0x00000E00 → 0x000001A2B0A14000 (256 bytes)
      [3] .pdata   : SKIP (section vide - .bss)
[+] PE copié en mémoire avec succès

═══════════════════════════════════════
[SUCCESS] DLL mappée à l'adresse 0x000001A2B0A10000
Taille : 0x5000 bytes
═══════════════════════════════════════
```

---

## Exercice 2 : Modification - Implémenter les relocations

**Objectif** : Appliquer les base relocations pour permettre le chargement à n'importe quelle adresse

**Solution complète** :

```c
#include <windows.h>
#include <stdio.h>

/*
 * apply_relocations - Applique les base relocations
 *
 * Les relocations sont nécessaires car le code compilé contient des adresses absolues
 * basées sur ImageBase. Si on charge à une autre adresse, il faut patcher ces adresses.
 *
 * Formule : AdressePatché = AdresseOriginale + Delta
 * avec Delta = ImageBase actuelle - ImageBase préférée
 */
BOOL apply_relocations(LPVOID pImageBase) {
    printf("\n[*] Étape 4 : Application des relocations...\n");

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);

    // Calculer delta
    ULONGLONG originalBase = pNtHeaders->OptionalHeader.ImageBase;
    ULONGLONG currentBase = (ULONGLONG)pImageBase;
    LONGLONG delta = (LONGLONG)(currentBase - originalBase);

    printf("    ImageBase préférée : 0x%llX\n", originalBase);
    printf("    ImageBase actuelle  : 0x%llX\n", currentBase);
    printf("    Delta              : 0x%llX\n", delta);

    // Si delta == 0, pas besoin de relocations
    if (delta == 0) {
        printf("[+] Chargé à l'adresse préférée, pas de relocation nécessaire\n");
        return TRUE;
    }

    // Récupérer Relocation Table
    DWORD relocRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRVA == 0 || relocSize == 0) {
        printf("[-] ERREUR : Pas de relocation table !\n");
        printf("    Le fichier DOIT être chargé exactement à 0x%llX\n", originalBase);
        return FALSE;
    }

    printf("    Relocation Table : RVA 0x%08X, Size 0x%08X\n", relocRVA, relocSize);

    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pImageBase + relocRVA);

    DWORD offset = 0;
    int blockCount = 0;
    int totalRelocations = 0;

    // Parser chaque block de relocations
    while (offset < relocSize && pReloc->SizeOfBlock > 0) {
        blockCount++;

        // Nombre d'entrées dans ce block
        DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        printf("\n    Block %d : Page RVA 0x%08X (%u entrées)\n",
               blockCount, pReloc->VirtualAddress, numEntries);

        // Pointeur vers les entrées (juste après le header du block)
        WORD* entries = (WORD*)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));

        // Traiter chaque entrée
        for (DWORD i = 0; i < numEntries; i++) {
            WORD entry = entries[i];

            // Extraire type (4 bits de poids fort)
            WORD type = entry >> 12;

            // Extraire offset (12 bits de poids faible)
            WORD relOffset = entry & 0xFFF;

            // Ignorer type ABSOLUTE (padding)
            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }

            // Calculer adresse à patcher
            ULONGLONG* pPatchAddr = (ULONGLONG*)((BYTE*)pImageBase + pReloc->VirtualAddress + relOffset);

            // Appliquer relocation selon le type
            switch (type) {
                case IMAGE_REL_BASED_DIR64:   // 64-bit (type 10)
                    *pPatchAddr += delta;
                    totalRelocations++;
                    if (i < 3) {  // Afficher seulement les 3 premières
                        printf("      [%u] RVA 0x%08X : 0x%llX → 0x%llX (DIR64)\n",
                               i, pReloc->VirtualAddress + relOffset,
                               *pPatchAddr - delta, *pPatchAddr);
                    }
                    break;

                case IMAGE_REL_BASED_HIGHLOW: // 32-bit (type 3)
                    *(DWORD*)pPatchAddr += (DWORD)delta;
                    totalRelocations++;
                    if (i < 3) {
                        printf("      [%u] RVA 0x%08X : 0x%08X → 0x%08X (HIGHLOW)\n",
                               i, pReloc->VirtualAddress + relOffset,
                               *(DWORD*)pPatchAddr - (DWORD)delta, *(DWORD*)pPatchAddr);
                    }
                    break;

                case IMAGE_REL_BASED_HIGH:    // High 16 bits (type 1)
                    *(WORD*)pPatchAddr += HIWORD(delta);
                    totalRelocations++;
                    break;

                case IMAGE_REL_BASED_LOW:     // Low 16 bits (type 2)
                    *(WORD*)pPatchAddr += LOWORD(delta);
                    totalRelocations++;
                    break;

                default:
                    printf("      [!] Type relocation inconnu : %d\n", type);
            }
        }

        if (numEntries > 3) {
            printf("      ... (%u relocations supplémentaires)\n", numEntries - 3);
        }

        // Passer au block suivant
        offset += pReloc->SizeOfBlock;
        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }

    printf("\n[+] %d relocations appliquées dans %d blocks\n", totalRelocations, blockCount);

    // Mettre à jour ImageBase dans les headers
    pNtHeaders->OptionalHeader.ImageBase = currentBase;

    return TRUE;
}

// Programme de test (réutilise map_pe_sections de l'exercice 1)
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <dll_path>\n", argv[0]);
        return 1;
    }

    // [Code de chargement du fichier identique à exercice 1]
    // ...

    // Mapper PE
    SIZE_T imageSize = 0;
    LPVOID pImageBase = map_pe_sections(pFileBuffer, &imageSize);

    if (pImageBase) {
        // Appliquer relocations
        if (apply_relocations(pImageBase)) {
            printf("\n[SUCCESS] PE relocalisé avec succès\n");
        } else {
            printf("\n[FAIL] Échec des relocations\n");
        }
    }

    // Cleanup
    if (pImageBase) VirtualFree(pImageBase, 0, MEM_RELEASE);
    free(pFileBuffer);

    return 0;
}
```

---

## Exercice 3 : Création - Résoudre les imports (IAT)

**Objectif** : Implémenter la résolution complète de l'Import Address Table

**Solution complète** :

```c
/*
 * resolve_imports - Résout tous les imports d'un PE
 *
 * Pour chaque DLL importée :
 * 1. LoadLibrary pour charger la DLL
 * 2. GetProcAddress pour chaque fonction
 * 3. Écrire l'adresse dans l'IAT (FirstThunk)
 */
BOOL resolve_imports(LPVOID pImageBase) {
    printf("\n[*] Étape 5 : Résolution des imports...\n");

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pImageBase + pDosHeader->e_lfanew);

    // Récupérer Import Directory
    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (importRVA == 0) {
        printf("[+] Pas d'imports\n");
        return TRUE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pImageBase + importRVA);

    int dllCount = 0;
    int totalFunctions = 0;

    // Parcourir chaque DLL
    while (pImportDesc->Name != 0) {
        dllCount++;

        // Récupérer nom DLL
        char* dllName = (char*)((BYTE*)pImageBase + pImportDesc->Name);

        printf("\n    [DLL #%d] %s\n", dllCount, dllName);

        // Charger la DLL
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) {
            printf("      [-] ERREUR : Impossible de charger '%s' (Error %d)\n",
                   dllName, GetLastError());
            return FALSE;
        }

        printf("      [+] Chargée à 0x%p\n", hModule);

        // Récupérer OriginalFirstThunk (Import Name Table)
        PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + pImportDesc->OriginalFirstThunk);

        // Récupérer FirstThunk (Import Address Table) - c'est ici qu'on écrit les adresses
        PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + pImportDesc->FirstThunk);

        int funcCount = 0;

        // Parcourir fonctions
        while (pOrigThunk->u1.AddressOfData != 0) {
            funcCount++;
            totalFunctions++;

            FARPROC funcAddress = NULL;

            // Vérifier si import par ordinal ou par nom
            #ifdef _WIN64
            if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
            #else
            if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
            #endif
                // Import par ordinal
                WORD ordinal = IMAGE_ORDINAL(pOrigThunk->u1.Ordinal);
                funcAddress = GetProcAddress(hModule, (LPCSTR)ordinal);

                if (funcCount <= 3) {
                    printf("      - Ordinal %u → 0x%p %s\n",
                           ordinal, funcAddress, funcAddress ? "✓" : "✗");
                }
            } else {
                // Import par nom
                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pImageBase + pOrigThunk->u1.AddressOfData);
                funcAddress = GetProcAddress(hModule, (LPCSTR)pImport->Name);

                if (funcCount <= 3) {
                    printf("      - %s → 0x%p %s\n",
                           pImport->Name, funcAddress, funcAddress ? "✓" : "✗");
                }
            }

            if (!funcAddress) {
                printf("      [-] ERREUR : Fonction introuvable\n");
                return FALSE;
            }

            // Écrire l'adresse dans l'IAT
            pFirstThunk->u1.Function = (ULONGLONG)funcAddress;

            pOrigThunk++;
            pFirstThunk++;
        }

        if (funcCount > 3) {
            printf("      ... (%d fonctions au total)\n", funcCount);
        }

        pImportDesc++;
    }

    printf("\n[+] %d DLL(s) chargées, %d fonction(s) résolues\n", dllCount, totalFunctions);
    return TRUE;
}
```

---

## Exercice 4 : Challenge - Manual Mapper complet

**Objectif** : Assembler toutes les étapes pour créer un loader fonctionnel

Voir le code du cours pour l'implémentation complète incluant :
- Allocation et copie
- Relocations
- Résolution imports
- Protection mémoire
- TLS callbacks
- Exécution DllMain

---

## Points clés

- **Manual Mapping** = charger PE sans passer par LoadLibrary
- **Relocations** : Delta = NewBase - OriginalBase, appliquer à chaque entrée
- **IAT** : LoadLibrary + GetProcAddress pour remplir les adresses
- **Protection** : VirtualProtect selon characteristics des sections
- **OPSEC** : DLL invisible dans PEB, mais détectable par heuristiques (RWX, WriteProcessMemory)

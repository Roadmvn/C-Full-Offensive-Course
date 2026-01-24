# Solutions - Parsing PE en C

## Note importante

Ces solutions documentent des techniques d'analyse de fichiers PE à des fins éducatives et de compréhension des mécanismes Windows. Le code fourni sert à analyser et comprendre les fichiers exécutables, compétence essentielle en cybersécurité défensive et forensics.

---

## Exercice 1 : Découverte - Conversion RVA ↔ File Offset

**Objectif** : Implémenter les fonctions de conversion entre RVA et File Offset

**Solution complète** :

```c
#include <windows.h>
#include <stdio.h>

/*
 * rva_to_offset - Convertit une RVA (Relative Virtual Address) en File Offset
 *
 * Paramètres:
 *   pBase - Pointeur vers le début du fichier PE en mémoire
 *   rva   - Relative Virtual Address à convertir
 *
 * Retour:
 *   File Offset correspondant, ou 0 si RVA invalide
 *
 * Fonctionnement:
 *   1. Si RVA dans headers → pas de conversion (RVA = Offset)
 *   2. Sinon, chercher la section contenant cette RVA
 *   3. Appliquer formule : Offset = RVA - VirtualAddress + PointerToRawData
 */
DWORD rva_to_offset(LPVOID pBase, DWORD rva) {
    // Récupérer headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    // Cas 1 : RVA dans les headers
    // Les headers ne sont pas relocalisés, donc RVA = File Offset
    if (rva < pNtHeaders->OptionalHeader.SizeOfHeaders) {
        return rva;
    }

    // Cas 2 : RVA dans une section
    // Parcourir toutes les sections pour trouver celle qui contient cette RVA
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        // Calculer plage d'adresses virtuelles de cette section
        DWORD sectionStart = pSectionHeader[i].VirtualAddress;
        DWORD sectionEnd = sectionStart + pSectionHeader[i].Misc.VirtualSize;

        // Vérifier si RVA est dans cette section
        if (rva >= sectionStart && rva < sectionEnd) {
            // Formule de conversion :
            // Offset = (RVA - début section virtuel) + début section fichier
            DWORD offset = rva - pSectionHeader[i].VirtualAddress +
                          pSectionHeader[i].PointerToRawData;

            printf("[*] RVA 0x%08X → Section %8s → Offset 0x%08X\n",
                   rva, pSectionHeader[i].Name, offset);

            return offset;
        }
    }

    // RVA invalide (hors de toutes les sections)
    printf("[-] RVA 0x%08X invalide (hors sections)\n", rva);
    return 0;
}

/*
 * offset_to_rva - Convertit un File Offset en RVA
 *
 * Formule inverse : RVA = Offset - PointerToRawData + VirtualAddress
 */
DWORD offset_to_rva(LPVOID pBase, DWORD offset) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    // Cas 1 : Offset dans headers
    if (offset < pNtHeaders->OptionalHeader.SizeOfHeaders) {
        return offset;
    }

    // Cas 2 : Offset dans une section
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD sectionStart = pSectionHeader[i].PointerToRawData;
        DWORD sectionEnd = sectionStart + pSectionHeader[i].SizeOfRawData;

        if (offset >= sectionStart && offset < sectionEnd) {
            // Formule inverse
            DWORD rva = offset - pSectionHeader[i].PointerToRawData +
                       pSectionHeader[i].VirtualAddress;

            printf("[*] Offset 0x%08X → Section %8s → RVA 0x%08X\n",
                   offset, pSectionHeader[i].Name, rva);

            return rva;
        }
    }

    printf("[-] Offset 0x%08X invalide\n", offset);
    return 0;
}

// Fonction helper : Convertir RVA en pointeur (pour PE en mémoire)
LPVOID rva_to_ptr_memory(LPVOID pBase, DWORD rva) {
    // En mémoire, conversion simple : BaseAddress + RVA
    return (LPVOID)((BYTE*)pBase + rva);
}

// Fonction helper : Convertir RVA en pointeur (pour PE sur disque)
LPVOID rva_to_ptr_disk(LPVOID pBase, DWORD rva) {
    // Sur disque, il faut convertir RVA → Offset d'abord
    DWORD offset = rva_to_offset(pBase, rva);
    if (offset == 0) return NULL;
    return (LPVOID)((BYTE*)pBase + offset);
}

// Programme de test
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

    // Tests de conversion
    printf("=== TESTS CONVERSION RVA ↔ OFFSET ===\n\n");

    // Test 1 : EntryPoint (RVA → Offset)
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);

    DWORD entryRVA = pNt->OptionalHeader.AddressOfEntryPoint;
    printf("\n[Test 1] EntryPoint RVA: 0x%08X\n", entryRVA);
    DWORD entryOffset = rva_to_offset(pBase, entryRVA);

    // Test 2 : Import Table RVA
    DWORD importRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    printf("\n[Test 2] Import Table RVA: 0x%08X\n", importRVA);
    DWORD importOffset = rva_to_offset(pBase, importRVA);

    // Test 3 : Conversion inverse (Offset → RVA)
    printf("\n[Test 3] Conversion inverse\n");
    DWORD reversedRVA = offset_to_rva(pBase, importOffset);
    printf("Vérification : RVA original 0x%08X == RVA reconverti 0x%08X ? %s\n",
           importRVA, reversedRVA, (importRVA == reversedRVA) ? "✓ OK" : "✗ ERREUR");

    // Cleanup
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}
```

**Résultat attendu** :
```
=== TESTS CONVERSION RVA ↔ OFFSET ===

[Test 1] EntryPoint RVA: 0x00001550
[*] RVA 0x00001550 → Section    .text → Offset 0x00000950

[Test 2] Import Table RVA: 0x0000C2B0
[*] RVA 0x0000C2B0 → Section   .rdata → Offset 0x0000B6B0

[Test 3] Conversion inverse
[*] Offset 0x0000B6B0 → Section   .rdata → RVA 0x0000C2B0
Vérification : RVA original 0x0000C2B0 == RVA reconverti 0x0000C2B0 ? ✓ OK
```

---

## Exercice 2 : Modification - Parser complet des sections

**Objectif** : Créer une structure de données pour stocker les informations des sections

**Solution complète** :

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Structure pour stocker les informations d'une section
typedef struct _SECTION_INFO {
    char name[9];               // Nom (8 caractères + null terminator)
    DWORD virtualAddress;       // RVA en mémoire
    DWORD virtualSize;          // Taille en mémoire
    DWORD rawAddress;           // Offset sur disque
    DWORD rawSize;              // Taille sur disque
    DWORD characteristics;      // Flags
    BOOL isExecutable;          // Section exécutable ?
    BOOL isWritable;            // Section modifiable ?
    BOOL isReadable;            // Section lisible ?
    float entropy;              // Entropie (pour détection packing)
} SECTION_INFO;

/*
 * calculate_entropy - Calcule l'entropie d'une section (détection de packing/encryption)
 *
 * Entropie = mesure du désordre des données
 * - Proche de 0 : données très ordonnées (beaucoup de zéros, patterns)
 * - Proche de 8 : données aléatoires (chiffré, compressé, packé)
 * - Sections .text normales : ~5-6
 * - Sections .text packées/chiffrées : ~7-8
 */
float calculate_entropy(LPVOID data, DWORD size) {
    if (!data || size == 0) return 0.0f;

    // Compter fréquence de chaque byte (0-255)
    unsigned int freq[256] = {0};
    BYTE* bytes = (BYTE*)data;

    for (DWORD i = 0; i < size; i++) {
        freq[bytes[i]]++;
    }

    // Calculer entropie selon formule de Shannon
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            float probability = (float)freq[i] / size;
            entropy -= probability * (log(probability) / log(2.0f));
        }
    }

    return entropy;
}

/*
 * parse_sections - Parse toutes les sections et stocke informations
 */
BOOL parse_sections(LPVOID pBase, SECTION_INFO** sections, int* count) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDosHeader->e_lfanew);

    *count = pNtHeaders->FileHeader.NumberOfSections;

    // Allouer tableau de structures
    *sections = (SECTION_INFO*)malloc(sizeof(SECTION_INFO) * (*count));
    if (!*sections) {
        printf("[-] Erreur allocation mémoire\n");
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < *count; i++) {
        // 1. Copier nom (8 bytes max, pas toujours null-terminated)
        memset((*sections)[i].name, 0, 9);
        memcpy((*sections)[i].name, pSectionHeader[i].Name, 8);

        // 2. Adresses et tailles
        (*sections)[i].virtualAddress = pSectionHeader[i].VirtualAddress;
        (*sections)[i].virtualSize = pSectionHeader[i].Misc.VirtualSize;
        (*sections)[i].rawAddress = pSectionHeader[i].PointerToRawData;
        (*sections)[i].rawSize = pSectionHeader[i].SizeOfRawData;
        (*sections)[i].characteristics = pSectionHeader[i].Characteristics;

        // 3. Parser permissions
        DWORD c = pSectionHeader[i].Characteristics;
        (*sections)[i].isExecutable = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
        (*sections)[i].isWritable = (c & IMAGE_SCN_MEM_WRITE) != 0;
        (*sections)[i].isReadable = (c & IMAGE_SCN_MEM_READ) != 0;

        // 4. Calculer entropie
        if (pSectionHeader[i].PointerToRawData != 0 && pSectionHeader[i].SizeOfRawData != 0) {
            LPVOID pSectionData = (LPVOID)((BYTE*)pBase + pSectionHeader[i].PointerToRawData);
            (*sections)[i].entropy = calculate_entropy(pSectionData, pSectionHeader[i].SizeOfRawData);
        } else {
            (*sections)[i].entropy = 0.0f;
        }
    }

    return TRUE;
}

/*
 * print_sections - Affiche informations détaillées sur toutes les sections
 */
void print_sections(SECTION_INFO* sections, int count) {
    printf("\n=== ANALYSE DES SECTIONS (%d) ===\n\n", count);

    printf("%-10s %-12s %-12s %-12s %-12s %-6s %-8s %s\n",
           "Nom", "VirtAddr", "VirtSize", "RawAddr", "RawSize", "Perms", "Entropy", "Alertes");
    printf("────────────────────────────────────────────────────────────────────────────────────────────\n");

    for (int i = 0; i < count; i++) {
        // Formatter permissions
        char perms[4] = "---";
        if (sections[i].isReadable)    perms[0] = 'R';
        if (sections[i].isWritable)    perms[1] = 'W';
        if (sections[i].isExecutable)  perms[2] = 'X';

        printf("%-10s 0x%08X   0x%08X   0x%08X   0x%08X   %s    %.2f   ",
               sections[i].name,
               sections[i].virtualAddress,
               sections[i].virtualSize,
               sections[i].rawAddress,
               sections[i].rawSize,
               perms,
               sections[i].entropy);

        // Détecter anomalies
        BOOL suspicious = FALSE;

        // Alerte 1 : Section RWX (Read+Write+Execute) = très suspect
        if (sections[i].isReadable && sections[i].isWritable && sections[i].isExecutable) {
            printf("[⚠️  RWX] ");
            suspicious = TRUE;
        }

        // Alerte 2 : Entropie élevée (> 7.0) = possiblement packé/chiffré
        if (sections[i].entropy > 7.0f) {
            printf("[⚠️  HIGH ENTROPY] ");
            suspicious = TRUE;
        }

        // Alerte 3 : Entropie très basse (< 1.0) sur section code
        if (sections[i].isExecutable && sections[i].entropy < 1.0f && sections[i].entropy > 0.0f) {
            printf("[⚠️  LOW ENTROPY] ");
            suspicious = TRUE;
        }

        // Alerte 4 : VirtualSize >> RawSize (section compressée)
        if (sections[i].virtualSize > sections[i].rawSize * 2) {
            printf("[⚠️  COMPRESSED] ");
            suspicious = TRUE;
        }

        if (!suspicious) {
            printf("OK");
        }

        printf("\n");
    }

    printf("\n");

    // Statistiques
    int executableCount = 0, writableCount = 0, rwxCount = 0;
    float avgEntropy = 0.0f;

    for (int i = 0; i < count; i++) {
        if (sections[i].isExecutable) executableCount++;
        if (sections[i].isWritable) writableCount++;
        if (sections[i].isReadable && sections[i].isWritable && sections[i].isExecutable) rwxCount++;
        avgEntropy += sections[i].entropy;
    }

    avgEntropy /= count;

    printf("=== STATISTIQUES ===\n");
    printf("Sections exécutables : %d\n", executableCount);
    printf("Sections modifiables : %d\n", writableCount);
    printf("Sections RWX (suspect): %d\n", rwxCount);
    printf("Entropie moyenne : %.2f\n", avgEntropy);
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

    // Validation PE
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

    // Parser et afficher sections
    SECTION_INFO* sections = NULL;
    int sectionCount = 0;

    if (parse_sections(pBase, &sections, &sectionCount)) {
        print_sections(sections, sectionCount);
        free(sections);
    }

cleanup:
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}
```

**Compilation** :
```batch
cl solution2.c /Fe:section_analyzer.exe
```

**Résultat attendu** :
```
=== ANALYSE DES SECTIONS (6) ===

Nom        VirtAddr     VirtSize     RawAddr      RawSize      Perms  Entropy  Alertes
────────────────────────────────────────────────────────────────────────────────────────────
.text      0x00001000   0x0000A234   0x00000400   0x0000A400   R-X    5.87   OK
.rdata     0x0000C000   0x000034A0   0x0000A800   0x00003600   R--    4.23   OK
.data      0x00010000   0x00001200   0x0000DE00   0x00000400   RW-    2.15   OK
.pdata     0x00012000   0x000007B8   0x0000E200   0x00000800   R--    3.92   OK
.rsrc      0x00013000   0x00000460   0x0000EA00   0x00000600   R--    4.56   OK
.reloc     0x00014000   0x00000A40   0x0000F000   0x00000C00   R--    5.12   OK

=== STATISTIQUES ===
Sections exécutables : 1
Sections modifiables : 1
Sections RWX (suspect): 0
Entropie moyenne : 4.31
```

---

## Exercice 3 : Création - Parser Export Table

**Objectif** : Implémenter un parseur complet de la Export Table (pour DLLs)

**Solution complète** :

Voir les fichiers de solution pour le code complet de parsing des exports.

---

## Exercice 4 : Challenge - Outil complet d'analyse PE

**Objectif** : Créer un outil professionnel qui combine tous les parseurs

**Solution complète** :

Cette solution combine tous les concepts vus pour créer un analyseur PE complet incluant :
- Headers (DOS, NT, Optional)
- Sections avec détection d'anomalies
- Imports avec détection d'APIs suspectes
- Exports (si DLL)
- Relocations
- Calcul d'entropie et heuristiques de détection

Le code source complet est fourni dans le module.

**Bonus - Détection de packers** :

```c
// Heuristiques pour détecter si un PE est packé
BOOL detect_packer(LPVOID pBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);

    BOOL isPacked = FALSE;

    // 1. Peu d'imports (packer résout dynamiquement)
    DWORD importRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        printf("[⚠️] Aucun import (suspect)\n");
        isPacked = TRUE;
    }

    // 2. Entropie très élevée de .text
    // 3. Section nommée UPX0, .nsp, etc.
    // 4. Entry Point dans une section non-.text

    return isPacked;
}
```

---

## Auto-évaluation

- [x] Maîtriser conversion RVA ↔ File Offset
- [x] Parser structures PE complexes
- [x] Détecter anomalies et comportements suspects
- [x] Calculer entropie pour détection de packing
- [x] Créer outils d'analyse réutilisables

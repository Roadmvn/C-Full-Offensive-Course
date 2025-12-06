/*
 * ═══════════════════════════════════════════════════════════════════
 * Module 37 : Reflective Loading - Chargement réflexif de DLL
 * ═══════════════════════════════════════════════════════════════════
 *
 * ⚠️  AVERTISSEMENT LÉGAL STRICT ⚠️
 *
 * Cette technique est utilisée par des malwares avancés.
 * Usage STRICTEMENT éducatif et éthique UNIQUEMENT.
 *
 * ILLÉGAL : Injection dans processus sans autorisation, malware
 * LÉGAL : Pentest autorisé, recherche académique, VM isolée
 *
 * L'auteur décline toute responsabilité pour usage illégal.
 * ═══════════════════════════════════════════════════════════════════
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define SEPARATEUR "═══════════════════════════════════════════════════════════════════\n"

// ═══════════════════════════════════════════════════════════════════
// Prototypes
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre);
void demonstrer_pe_parsing();
void demonstrer_section_headers();
void demonstrer_import_table();
void demonstrer_relocation_concept();

// ═══════════════════════════════════════════════════════════════════
// Utilitaires
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre) {
    printf("\n");
    printf(SEPARATEUR);
    printf("  %s\n", titre);
    printf(SEPARATEUR);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 1 : Parsing des headers PE
// ═══════════════════════════════════════════════════════════════════

void demonstrer_pe_parsing() {
    afficher_titre("DÉMONSTRATION 1 : PE Header Parsing");

    printf("\n[*] Analyse du fichier kernel32.dll...\n");

    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Échec GetModuleHandle\n");
        return;
    }

    printf("[+] kernel32.dll chargé à : %p\n", hKernel32);

    // DOS Header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hKernel32;

    printf("\n[*] DOS Header :\n");
    printf("    e_magic : 0x%04X (%c%c)\n", dosHeader->e_magic,
           dosHeader->e_magic & 0xFF, (dosHeader->e_magic >> 8) & 0xFF);
    printf("    e_lfanew : 0x%08X (offset vers PE header)\n", dosHeader->e_lfanew);

    // NT Headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hKernel32 + dosHeader->e_lfanew);

    printf("\n[*] NT Headers :\n");
    printf("    Signature : 0x%08X (%.4s)\n", ntHeaders->Signature, (char*)&ntHeaders->Signature);

    // File Header
    printf("\n[*] File Header :\n");
    printf("    Machine : 0x%04X ", ntHeaders->FileHeader.Machine);
    switch (ntHeaders->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: printf("(x86)\n"); break;
        case IMAGE_FILE_MACHINE_AMD64: printf("(x64)\n"); break;
        default: printf("(Unknown)\n");
    }
    printf("    NumberOfSections : %d\n", ntHeaders->FileHeader.NumberOfSections);
    printf("    TimeDateStamp : 0x%08X\n", ntHeaders->FileHeader.TimeDateStamp);

    // Optional Header
    printf("\n[*] Optional Header :\n");
    printf("    Magic : 0x%04X ", ntHeaders->OptionalHeader.Magic);
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        printf("(PE32)\n");
    else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        printf("(PE32+)\n");

    printf("    ImageBase : 0x%p\n", (void*)ntHeaders->OptionalHeader.ImageBase);
    printf("    SizeOfImage : 0x%08X (%u bytes)\n",
           ntHeaders->OptionalHeader.SizeOfImage, ntHeaders->OptionalHeader.SizeOfImage);
    printf("    AddressOfEntryPoint : 0x%08X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 2 : Section Headers
// ═══════════════════════════════════════════════════════════════════

void demonstrer_section_headers() {
    afficher_titre("DÉMONSTRATION 2 : Section Headers");

    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hKernel32;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hKernel32 + dosHeader->e_lfanew);

    printf("\n[*] Sections de kernel32.dll :\n\n");
    printf("%-10s %-12s %-12s %-12s %s\n", "Nom", "VirtAddr", "VirtSize", "RawSize", "Caractéristiques");
    printf("────────────────────────────────────────────────────────────────────────\n");

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, section[i].Name, 8);

        printf("%-10s 0x%08X   0x%08X   0x%08X   ",
               name,
               section[i].VirtualAddress,
               section[i].Misc.VirtualSize,
               section[i].SizeOfRawData);

        // Caractéristiques
        if (section[i].Characteristics & IMAGE_SCN_CNT_CODE)
            printf("CODE ");
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            printf("X");
        if (section[i].Characteristics & IMAGE_SCN_MEM_READ)
            printf("R");
        if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            printf("W");

        printf("\n");
    }
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 3 : Import Table
// ═══════════════════════════════════════════════════════════════════

void demonstrer_import_table() {
    afficher_titre("DÉMONSTRATION 3 : Import Table");

    HMODULE hNotepad = LoadLibrary("notepad.exe");
    if (!hNotepad) {
        printf("[-] Échec chargement notepad.exe : %lu\n", GetLastError());
        printf("    (Normal si notepad.exe n'est pas dans le PATH)\n");
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNotepad;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNotepad + dosHeader->e_lfanew);

    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (importRVA == 0) {
        printf("[-] Pas d'import table\n");
        FreeLibrary(hNotepad);
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hNotepad + importRVA);

    printf("\n[*] DLL importées par notepad.exe :\n\n");

    int count = 0;
    while (importDesc->Name != 0) {
        char *dllName = (char*)((BYTE*)hNotepad + importDesc->Name);
        printf("  [%d] %s\n", count++, dllName);

        // Afficher quelques fonctions importées
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hNotepad + importDesc->OriginalFirstThunk);

        if (thunk && count <= 3) {  // Limiter affichage
            printf("      Fonctions importées :\n");
            int funcCount = 0;
            while (thunk->u1.AddressOfData != 0 && funcCount < 5) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hNotepad + thunk->u1.AddressOfData);
                    printf("        - %s\n", import->Name);
                }
                thunk++;
                funcCount++;
            }
            if (funcCount == 5) printf("        - ...\n");
        }

        importDesc++;
    }

    FreeLibrary(hNotepad);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 4 : Concept de Relocation
// ═══════════════════════════════════════════════════════════════════

void demonstrer_relocation_concept() {
    afficher_titre("DÉMONSTRATION 4 : Concept de Relocation");

    printf("\n[*] Explication de la relocation...\n\n");

    printf("Scénario :\n");
    printf("  1. DLL compilée avec base address préférée : 0x10000000\n");
    printf("  2. Au chargement, cette adresse est occupée\n");
    printf("  3. Chargeur Windows place la DLL à : 0x50000000\n");
    printf("  4. Delta = 0x50000000 - 0x10000000 = 0x40000000\n\n");

    printf("Relocation nécessaire car :\n");
    printf("  - Code contient des adresses absolues\n");
    printf("  - Ces adresses doivent être ajustées\n\n");

    printf("Exemple :\n");
    printf("  Instruction originale : MOV EAX, [0x10001234]\n");
    printf("  Après relocation :      MOV EAX, [0x50001234]\n");
    printf("                                     ^^^^ Ajusté par delta\n\n");

    printf("Table de relocation (.reloc) :\n");
    printf("  - Contient tous les offsets à corriger\n");
    printf("  - Appliqué automatiquement par LoadLibrary\n");
    printf("  - Manuel pour reflective loading\n\n");

    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hKernel32;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hKernel32 + dosHeader->e_lfanew);

    DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    printf("kernel32.dll :\n");
    printf("  Base address préférée : 0x%p\n", (void*)ntHeaders->OptionalHeader.ImageBase);
    printf("  Base address actuelle : %p\n", hKernel32);
    printf("  Delta : 0x%IX\n", (UINT_PTR)hKernel32 - ntHeaders->OptionalHeader.ImageBase);
    printf("  Relocation table size : %lu bytes\n", relocSize);
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

int main(void) {
    printf(SEPARATEUR);
    printf("  MODULE 37 : REFLECTIVE LOADING\n");
    printf("  Chargement réflexif de DLL Windows\n");
    printf(SEPARATEUR);

    printf("\n⚠️  AVERTISSEMENT LÉGAL ⚠️\n\n");
    printf("Cette technique est utilisée par des malwares avancés.\n");
    printf("USAGE ÉDUCATIF ET ÉTHIQUE UNIQUEMENT.\n\n");
    printf("Appuyez sur ENTRÉE pour continuer...\n");
    getchar();

    demonstrer_pe_parsing();
    printf("\n\nAppuyez sur ENTRÉE...\n");
    getchar();

    demonstrer_section_headers();
    printf("\n\nAppuyez sur ENTRÉE...\n");
    getchar();

    demonstrer_import_table();
    printf("\n\nAppuyez sur ENTRÉE...\n");
    getchar();

    demonstrer_relocation_concept();

    printf("\n");
    afficher_titre("FIN DES DÉMONSTRATIONS");
    printf("\n[+] Consultez exercice.txt pour défis avancés\n\n");

    return 0;
}

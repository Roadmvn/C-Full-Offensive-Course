/*
 * OBJECTIF  : Comprendre comment Windows charge un PE en memoire (Manual Mapping simplifie)
 * PREREQUIS : Modules 01-PE-Format et 02-PE-Parsing
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Ce programme demontre le chargement manuel d'une DLL en memoire :
 * 1. Lire le fichier DLL depuis le disque
 * 2. Allouer de la memoire et copier les sections
 * 3. Appliquer les relocations
 * 4. Resoudre les imports
 * 5. Appeler DllMain
 *
 * Pour des raisons pedagogiques, on explique chaque etape avec des commentaires
 * et on travaille sur notre propre processus (pas d'injection distante).
 */

#include <windows.h>
#include <stdio.h>

/* Convertir RVA en offset fichier */
DWORD rva_to_offset(PIMAGE_SECTION_HEADER sec, WORD count, DWORD rva) {
    for (WORD i = 0; i < count; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
        }
    }
    return rva;
}

/*
 * Etape de demonstration : Simuler un manual mapping de DLL
 * On ne va PAS executer de code arbitraire, mais montrer la logique.
 */
void demo_manual_mapping_steps(const char* dll_path) {
    printf("[1] Lecture du fichier DLL depuis le disque\n");
    HANDLE hFile = CreateFileA(dll_path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    [-] Impossible d'ouvrir : %s (err %lu)\n", dll_path, GetLastError());
        printf("    [*] Utilisation d'une DLL systeme pour la demo\n\n");

        /* Fallback : utiliser une DLL systeme pour la demo */
        char sys_dll[MAX_PATH];
        GetSystemDirectoryA(sys_dll, MAX_PATH);
        strcat_s(sys_dll, MAX_PATH, "\\version.dll");

        hFile = CreateFileA(sys_dll, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("    [-] Echec aussi avec version.dll\n");
            return;
        }
        printf("    [+] Ouverture de %s\n", sys_dll);
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE* raw = (BYTE*)malloc(file_size);
    DWORD bytesRead;
    ReadFile(hFile, raw, file_size, &bytesRead, NULL);
    CloseHandle(hFile);
    printf("    [+] Lu %lu octets\n\n", bytesRead);

    /* Valider les headers */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("    [-] Fichier PE invalide\n");
        free(raw);
        return;
    }

    printf("[2] Allocation memoire (VirtualAlloc)\n");
    printf("    SizeOfImage demande : 0x%lX octets\n", nt->OptionalHeader.SizeOfImage);

    /*
     * VirtualAlloc reserve de la memoire avec la taille SizeOfImage.
     * En manual mapping reel, on utiliserait VirtualAllocEx dans un processus distant.
     * Ici on alloue dans notre propre processus pour la demo.
     */
    BYTE* mapped = (BYTE*)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mapped) {
        printf("    [-] VirtualAlloc echoue\n");
        free(raw);
        return;
    }
    printf("    [+] Memoire allouee a : %p\n\n", mapped);

    printf("[3] Copie des headers PE\n");
    memcpy(mapped, raw, nt->OptionalHeader.SizeOfHeaders);
    printf("    [+] %lu octets de headers copies\n\n", nt->OptionalHeader.SizeOfHeaders);

    printf("[4] Copie des sections\n");
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);

        if (sections[i].SizeOfRawData > 0) {
            memcpy(mapped + sections[i].VirtualAddress,
                   raw + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
            printf("    [+] %-8s -> RVA 0x%08lX (%lu octets)\n",
                   name, sections[i].VirtualAddress, sections[i].SizeOfRawData);
        } else {
            printf("    [*] %-8s -> RVA 0x%08lX (pas de raw data)\n",
                   name, sections[i].VirtualAddress);
        }
    }
    printf("\n");

    printf("[5] Relocations (base relocation)\n");
    /*
     * Si l'image n'est pas chargee a son ImageBase preferee,
     * il faut ajuster toutes les adresses absolues dans le code.
     * Delta = adresse_reelle - ImageBase_preferee
     */
    ULONGLONG delta = (ULONGLONG)mapped - nt->OptionalHeader.ImageBase;
    printf("    ImageBase preferee : 0x%p\n", (void*)(ULONG_PTR)nt->OptionalHeader.ImageBase);
    printf("    Adresse reelle     : %p\n", mapped);
    printf("    Delta              : 0x%llX\n", delta);

    DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (reloc_rva && reloc_size && delta != 0) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(mapped + reloc_rva);
        int block_count = 0;

        while ((BYTE*)reloc < mapped + reloc_rva + reloc_size && reloc->SizeOfBlock > 0) {
            DWORD num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < num_entries; i++) {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0x0FFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* addr = (ULONGLONG*)(mapped + reloc->VirtualAddress + offset);
                    *addr += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* addr = (DWORD*)(mapped + reloc->VirtualAddress + offset);
                    *addr += (DWORD)delta;
                }
            }
            block_count++;
            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
        printf("    [+] %d blocs de relocation traites\n\n", block_count);
    } else {
        printf("    [*] Pas de relocations necessaires (delta=0 ou pas de table)\n\n");
    }

    printf("[6] Resolution des imports (IAT)\n");
    /*
     * Pour chaque DLL importee, on charge la DLL avec LoadLibrary,
     * puis on resout chaque fonction avec GetProcAddress
     * et on ecrit l'adresse dans l'IAT.
     */
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(mapped + import_rva);
        int dll_count = 0;

        while (imp->Name) {
            char* dll_name = (char*)(mapped + imp->Name);
            HMODULE hDll = LoadLibraryA(dll_name);
            printf("    [+] %s -> %p\n", dll_name, hDll);

            if (hDll) {
                PIMAGE_THUNK_DATA thunk_ilt = (PIMAGE_THUNK_DATA)(mapped +
                    (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                PIMAGE_THUNK_DATA thunk_iat = (PIMAGE_THUNK_DATA)(mapped + imp->FirstThunk);

                while (thunk_ilt->u1.AddressOfData) {
                    FARPROC func;
                    if (IMAGE_SNAP_BY_ORDINAL(thunk_ilt->u1.Ordinal)) {
                        func = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(thunk_ilt->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(mapped + thunk_ilt->u1.AddressOfData);
                        func = GetProcAddress(hDll, ibn->Name);
                    }
                    thunk_iat->u1.Function = (ULONGLONG)func;
                    thunk_ilt++;
                    thunk_iat++;
                }
            }
            dll_count++;
            imp++;
        }
        printf("    [+] %d DLLs resolues\n\n", dll_count);
    }

    printf("[7] Protection memoire des sections\n");
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        DWORD ch = sections[i].Characteristics;

        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE))
            protect = PAGE_EXECUTE_READWRITE;
        else if (ch & IMAGE_SCN_MEM_EXECUTE)
            protect = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)
            protect = PAGE_READWRITE;

        DWORD old;
        VirtualProtect(mapped + sections[i].VirtualAddress,
                       sections[i].Misc.VirtualSize, protect, &old);

        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        printf("    %-8s -> protection 0x%lX\n", name, protect);
    }
    printf("\n");

    printf("[8] DllMain (non appelee dans cette demo pour securite)\n");
    printf("    EntryPoint RVA : 0x%lX\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("    Adresse reelle : %p\n", mapped + nt->OptionalHeader.AddressOfEntryPoint);
    printf("    [!] En manual mapping reel, on appellerait :\n");
    printf("        typedef BOOL (WINAPI *DllEntry)(HINSTANCE, DWORD, LPVOID);\n");
    printf("        DllEntry entry = (DllEntry)(mapped + entrypoint);\n");
    printf("        entry((HINSTANCE)mapped, DLL_PROCESS_ATTACH, NULL);\n\n");

    /* Nettoyage */
    VirtualFree(mapped, 0, MEM_RELEASE);
    free(raw);
}

int main(void) {
    printf("[*] Demo : Chargement PE / Manual Mapping\n");
    printf("[*] ==========================================\n\n");

    printf("[*] Ce programme demontre les etapes d'un manual mapping :\n");
    printf("    1. Lire la DLL depuis le disque\n");
    printf("    2. Allouer memoire avec VirtualAlloc\n");
    printf("    3. Copier les headers et sections\n");
    printf("    4. Appliquer les relocations (delta rebase)\n");
    printf("    5. Resoudre les imports (remplir IAT)\n");
    printf("    6. Proteger les sections (RX, RW, R)\n");
    printf("    7. Appeler DllMain (desactive pour securite)\n\n");

    demo_manual_mapping_steps("test.dll");

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

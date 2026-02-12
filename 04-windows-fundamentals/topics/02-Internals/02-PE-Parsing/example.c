/*
 * OBJECTIF  : Parser un fichier PE depuis le disque et extraire ses informations
 * PREREQUIS : Module 01-PE-Format (comprendre les structures PE)
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Ce programme lit un fichier PE (par defaut lui-meme) et effectue un parsing
 * complet : headers, sections, imports (DLLs + fonctions), exports.
 * Utile pour comprendre le reverse engineering et creer des outils d'analyse.
 */

#include <windows.h>
#include <stdio.h>

/* Convertir un RVA en offset fichier */
DWORD rva_to_offset(PIMAGE_SECTION_HEADER sections, WORD num_sections, DWORD rva) {
    for (WORD i = 0; i < num_sections; i++) {
        DWORD start = sections[i].VirtualAddress;
        DWORD end = start + sections[i].Misc.VirtualSize;
        if (rva >= start && rva < end) {
            return rva - start + sections[i].PointerToRawData;
        }
    }
    return 0;
}

/* Afficher la table des imports */
void parse_imports(BYTE* base, PIMAGE_NT_HEADERS nt, PIMAGE_SECTION_HEADER sections) {
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva == 0) {
        printf("    (aucune import table)\n");
        return;
    }

    DWORD import_offset = rva_to_offset(sections, nt->FileHeader.NumberOfSections, import_rva);
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + import_offset);

    int dll_count = 0;
    while (imp->Name != 0) {
        DWORD name_offset = rva_to_offset(sections, nt->FileHeader.NumberOfSections, imp->Name);
        char* dll_name = (char*)(base + name_offset);
        printf("\n    DLL : %s\n", dll_name);

        /* Lire les fonctions importees via l'ILT (Import Lookup Table) */
        DWORD thunk_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        DWORD thunk_offset = rva_to_offset(sections, nt->FileHeader.NumberOfSections, thunk_rva);

        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            PIMAGE_THUNK_DATA64 thunk = (PIMAGE_THUNK_DATA64)(base + thunk_offset);
            int func_count = 0;
            while (thunk->u1.AddressOfData != 0 && func_count < 10) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    DWORD hint_offset = rva_to_offset(sections, nt->FileHeader.NumberOfSections,
                                                       (DWORD)thunk->u1.AddressOfData);
                    PIMAGE_IMPORT_BY_NAME hint = (PIMAGE_IMPORT_BY_NAME)(base + hint_offset);
                    printf("      [%04X] %s\n", hint->Hint, hint->Name);
                } else {
                    printf("      [Ordinal] #%llu\n", thunk->u1.Ordinal & 0xFFFF);
                }
                thunk++;
                func_count++;
            }
            if (func_count >= 10) printf("      ... (tronque)\n");
        } else {
            PIMAGE_THUNK_DATA32 thunk = (PIMAGE_THUNK_DATA32)(base + thunk_offset);
            int func_count = 0;
            while (thunk->u1.AddressOfData != 0 && func_count < 10) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                    DWORD hint_offset = rva_to_offset(sections, nt->FileHeader.NumberOfSections,
                                                       thunk->u1.AddressOfData);
                    PIMAGE_IMPORT_BY_NAME hint = (PIMAGE_IMPORT_BY_NAME)(base + hint_offset);
                    printf("      [%04X] %s\n", hint->Hint, hint->Name);
                } else {
                    printf("      [Ordinal] #%lu\n", thunk->u1.Ordinal & 0xFFFF);
                }
                thunk++;
                func_count++;
            }
            if (func_count >= 10) printf("      ... (tronque)\n");
        }

        dll_count++;
        imp++;
    }
    printf("\n    Total DLLs importees : %d\n", dll_count);
}

/* Afficher la table des exports (si presente) */
void parse_exports(BYTE* base, PIMAGE_NT_HEADERS nt, PIMAGE_SECTION_HEADER sections) {
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_rva == 0) {
        printf("    (aucune export table - normal pour un .exe)\n");
        return;
    }

    DWORD export_offset = rva_to_offset(sections, nt->FileHeader.NumberOfSections, export_rva);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + export_offset);

    DWORD name_off = rva_to_offset(sections, nt->FileHeader.NumberOfSections, exp->Name);
    printf("    Module : %s\n", (char*)(base + name_off));
    printf("    Nombre de fonctions  : %lu\n", exp->NumberOfFunctions);
    printf("    Nombre de noms       : %lu\n", exp->NumberOfNames);

    DWORD names_off = rva_to_offset(sections, nt->FileHeader.NumberOfSections, exp->AddressOfNames);
    DWORD* names = (DWORD*)(base + names_off);

    int display = exp->NumberOfNames > 20 ? 20 : exp->NumberOfNames;
    for (int i = 0; i < display; i++) {
        DWORD fn_off = rva_to_offset(sections, nt->FileHeader.NumberOfSections, names[i]);
        printf("      [%d] %s\n", i, (char*)(base + fn_off));
    }
    if (exp->NumberOfNames > 20)
        printf("      ... (%lu de plus)\n", exp->NumberOfNames - 20);
}

int main(int argc, char* argv[]) {
    printf("[*] Demo : Parsing PE depuis le disque\n");
    printf("[*] ==========================================\n\n");

    /* Le fichier a parser : par defaut, notre propre executable */
    const char* target = (argc > 1) ? argv[1] : argv[0];
    printf("[*] Fichier cible : %s\n\n", target);

    /* Etape 1 : Lire le fichier entier en memoire */
    HANDLE hFile = CreateFileA(target, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir le fichier (erreur %lu)\n", GetLastError());
        return 1;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)malloc(file_size);
    if (!buffer) {
        printf("[-] malloc echoue\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytes_read;
    ReadFile(hFile, buffer, file_size, &bytes_read, NULL);
    CloseHandle(hFile);
    printf("[+] Fichier lu : %lu octets\n\n", bytes_read);

    /* Etape 2 : Valider le DOS Header */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Ce n'est pas un fichier PE (pas de signature MZ)\n");
        free(buffer);
        return 1;
    }

    /* Etape 3 : Acceder au NT Headers */
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature PE invalide\n");
        free(buffer);
        return 1;
    }

    printf("[+] Format : %s\n",
           nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE32+ (64-bit)" : "PE32 (32-bit)");
    printf("[+] EntryPoint RVA : 0x%08lX\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("[+] ImageBase      : 0x%p\n", (void*)(ULONG_PTR)nt->OptionalHeader.ImageBase);
    printf("[+] Sections       : %d\n\n", nt->FileHeader.NumberOfSections);

    /* Etape 4 : Afficher les sections */
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    printf("[*] --- Sections ---\n");
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        printf("    %-8s  VA=0x%08lX  Size=0x%08lX  Raw=0x%08lX\n",
               name, sections[i].VirtualAddress,
               sections[i].Misc.VirtualSize,
               sections[i].PointerToRawData);
    }

    /* Etape 5 : Parser les imports */
    printf("\n[*] --- Import Table ---\n");
    parse_imports(buffer, nt, sections);

    /* Etape 6 : Parser les exports */
    printf("\n[*] --- Export Table ---\n");
    parse_exports(buffer, nt, sections);

    free(buffer);
    printf("\n[+] Parsing termine avec succes\n");
    return 0;
}

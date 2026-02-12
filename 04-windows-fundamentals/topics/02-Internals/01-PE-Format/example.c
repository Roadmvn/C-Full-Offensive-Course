/*
 * OBJECTIF  : Comprendre la structure du format Portable Executable (PE)
 * PREREQUIS : Bases du C (structures, pointeurs), notions d'hexadecimal
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Ce programme ouvre son propre executable et affiche les headers PE :
 * DOS Header, NT Headers (File Header + Optional Header), et les sections.
 * C'est la base pour comprendre comment Windows charge un .exe ou .dll.
 */

#include <windows.h>
#include <stdio.h>

/* Affiche les informations du DOS Header */
void print_dos_header(PIMAGE_DOS_HEADER dos) {
    printf("[1] DOS Header\n");
    printf("    e_magic  : 0x%04X", dos->e_magic);
    if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        printf(" (MZ - valide)\n");
    else
        printf(" (INVALIDE!)\n");
    printf("    e_lfanew : 0x%08lX (offset vers PE Header)\n\n", dos->e_lfanew);
}

/* Affiche les informations du File Header */
void print_file_header(PIMAGE_FILE_HEADER fh) {
    printf("[2] File Header (COFF)\n");
    printf("    Machine          : 0x%04X", fh->Machine);
    if (fh->Machine == IMAGE_FILE_MACHINE_AMD64)
        printf(" (x64)\n");
    else if (fh->Machine == IMAGE_FILE_MACHINE_I386)
        printf(" (x86)\n");
    else
        printf(" (autre)\n");
    printf("    NumberOfSections : %d\n", fh->NumberOfSections);
    printf("    TimeDateStamp    : 0x%08lX\n", fh->TimeDateStamp);
    printf("    Characteristics  : 0x%04X", fh->Characteristics);
    if (fh->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        printf(" [EXECUTABLE]");
    if (fh->Characteristics & IMAGE_FILE_DLL)
        printf(" [DLL]");
    if (fh->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        printf(" [LARGE_ADDR]");
    printf("\n\n");
}

/* Affiche les informations de l'Optional Header (PE32+) */
void print_optional_header(PIMAGE_OPTIONAL_HEADER opt) {
    printf("[3] Optional Header\n");
    printf("    Magic                : 0x%04X", opt->Magic);
    if (opt->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        printf(" (PE32+ / 64-bit)\n");
    else if (opt->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        printf(" (PE32 / 32-bit)\n");
    else
        printf(" (inconnu)\n");
    printf("    AddressOfEntryPoint  : 0x%08lX (RVA du point d'entree)\n", opt->AddressOfEntryPoint);
    printf("    ImageBase            : 0x%p\n", (void*)(ULONG_PTR)opt->ImageBase);
    printf("    SectionAlignment     : 0x%08lX\n", opt->SectionAlignment);
    printf("    FileAlignment        : 0x%08lX\n", opt->FileAlignment);
    printf("    SizeOfImage          : 0x%08lX\n", opt->SizeOfImage);
    printf("    SizeOfHeaders        : 0x%08lX\n", opt->SizeOfHeaders);
    printf("    Subsystem            : %d", opt->Subsystem);
    if (opt->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
        printf(" (Console)\n");
    else if (opt->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
        printf(" (GUI)\n");
    else
        printf("\n");
    printf("    NumberOfRvaAndSizes  : %lu\n", opt->NumberOfRvaAndSizes);

    /* Afficher les Data Directories non-vides */
    const char* dir_names[] = {
        "Export", "Import", "Resource", "Exception",
        "Security", "BaseReloc", "Debug", "Architecture",
        "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
        "IAT", "DelayImport", "CLR", "Reserved"
    };
    printf("\n    Data Directories (non-vides) :\n");
    for (DWORD i = 0; i < opt->NumberOfRvaAndSizes && i < 16; i++) {
        if (opt->DataDirectory[i].VirtualAddress != 0) {
            printf("      [%2lu] %-12s  RVA=0x%08lX  Size=0x%08lX\n",
                   i, dir_names[i],
                   opt->DataDirectory[i].VirtualAddress,
                   opt->DataDirectory[i].Size);
        }
    }
    printf("\n");
}

/* Affiche la table des sections */
void print_sections(PIMAGE_SECTION_HEADER sec, WORD count) {
    printf("[4] Section Table (%d sections)\n", count);
    printf("    %-8s  %-10s  %-10s  %-10s  %-10s  Flags\n",
           "Name", "VirtAddr", "VirtSize", "RawOffset", "RawSize");
    printf("    %-8s  %-10s  %-10s  %-10s  %-10s  -----\n",
           "--------", "----------", "----------", "----------", "----------");

    for (WORD i = 0; i < count; i++) {
        char name[9] = {0};
        memcpy(name, sec[i].Name, 8);

        printf("    %-8s  0x%08lX  0x%08lX  0x%08lX  0x%08lX ",
               name,
               sec[i].VirtualAddress,
               sec[i].Misc.VirtualSize,
               sec[i].PointerToRawData,
               sec[i].SizeOfRawData);

        /* Decoder les flags de la section */
        DWORD ch = sec[i].Characteristics;
        if (ch & IMAGE_SCN_MEM_EXECUTE)  printf("X");
        if (ch & IMAGE_SCN_MEM_READ)     printf("R");
        if (ch & IMAGE_SCN_MEM_WRITE)    printf("W");
        if (ch & IMAGE_SCN_CNT_CODE)     printf(" [CODE]");
        if (ch & IMAGE_SCN_CNT_INITIALIZED_DATA) printf(" [IDATA]");
        if (ch & IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf(" [UDATA]");
        printf("\n");
    }
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Structure du format PE\n");
    printf("[*] ==========================================\n\n");

    /*
     * Etape 1 : Obtenir l'adresse de base de notre propre executable
     * GetModuleHandle(NULL) retourne l'ImageBase du processus courant.
     * En memoire, le PE est deja mappe, donc on peut lire directement les headers.
     */
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        printf("[-] GetModuleHandle echoue\n");
        return 1;
    }
    printf("[+] ImageBase du processus : %p\n\n", hModule);

    /* Etape 2 : Parser le DOS Header (debut du PE) */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    print_dos_header(dos);

    /* Etape 3 : Acceder au NT Headers via e_lfanew */
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature PE invalide!\n");
        return 1;
    }
    printf("[+] Signature PE : 0x%08lX (PE\\0\\0 - valide)\n\n", nt->Signature);

    /* Etape 4 : File Header et Optional Header */
    print_file_header(&nt->FileHeader);
    print_optional_header(&nt->OptionalHeader);

    /* Etape 5 : Table des sections */
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    print_sections(sections, nt->FileHeader.NumberOfSections);

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

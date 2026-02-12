/*
 * OBJECTIF  : Comprendre le fonctionnement interne de ntdll.dll
 * PREREQUIS : Module 05-System-Calls-NTAPI (syscalls, Native API)
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * ntdll.dll est la premiere DLL chargee dans tout processus Windows.
 * Elle contient les stubs syscall (transition user->kernel) et la Native API.
 * Ce programme explore ntdll en memoire : exports, stubs syscall, detection de hooks.
 */

#include <windows.h>
#include <stdio.h>

/* Afficher les premiers octets d'une fonction pour identifier le stub syscall */
void dump_bytes(const char* name, BYTE* addr, int count) {
    printf("    %-35s : ", name);
    for (int i = 0; i < count; i++)
        printf("%02X ", addr[i]);
    printf("\n");
}

/* Verifier si un stub ntdll est dans son etat normal (non-hooke) */
BOOL is_stub_clean(BYTE* func) {
    /*
     * Pattern normal d'un stub syscall ntdll en x64 :
     * 4C 8B D1       mov r10, rcx
     * B8 XX XX 00 00  mov eax, SSN
     * ...
     * 0F 05          syscall
     * C3             ret
     *
     * Si les premiers octets sont differents (ex: E9 = JMP),
     * c'est qu'un EDR/AV a place un hook.
     */
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8)
        return TRUE;
    return FALSE;
}

/* Extraire le SSN (System Service Number) d'un stub ntdll */
DWORD extract_ssn(BYTE* func) {
    if (func[0] == 0x4C && func[3] == 0xB8)
        return *(DWORD*)(func + 4);
    return 0xFFFFFFFF;
}

/* Enumerer les exports de ntdll qui commencent par "Nt" (Native API) */
void enumerate_nt_functions(HMODULE ntdll) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)ntdll + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);

    printf("[*] Fonctions Nt* exportees par ntdll.dll :\n\n");
    printf("    %-35s  %-6s  %-8s  %s\n", "Fonction", "SSN", "Status", "Premiers octets");
    printf("    %-35s  %-6s  %-8s  %s\n", "-----------------------------------",
           "------", "--------", "---------------");

    int nt_count = 0;
    int hooked = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && nt_count < 30; i++) {
        char* name = (char*)((BYTE*)ntdll + names[i]);

        /* Filtrer : garder seulement les fonctions Nt* (pas Rtl*, Ldr*, etc.) */
        if (name[0] == 'N' && name[1] == 't' && name[2] >= 'A' && name[2] <= 'Z') {
            BYTE* func = (BYTE*)ntdll + functions[ordinals[i]];
            BOOL clean = is_stub_clean(func);
            DWORD ssn = extract_ssn(func);

            printf("    %-35s  ", name);
            if (ssn != 0xFFFFFFFF)
                printf("0x%04X", ssn);
            else
                printf("  N/A ");
            printf("  %-8s  ", clean ? "[CLEAN]" : "[HOOK!]");

            for (int j = 0; j < 8; j++)
                printf("%02X ", func[j]);
            printf("\n");

            if (!clean) hooked++;
            nt_count++;
        }
    }

    printf("\n    [+] Affiche : %d fonctions Nt*\n", nt_count);
    if (hooked > 0)
        printf("    [!] %d fonction(s) potentiellement hookee(s) par EDR/AV\n", hooked);
    else
        printf("    [+] Aucun hook detecte (pas d'EDR actif)\n");
}

/* Comparer ntdll en memoire vs sur disque pour detecter les hooks */
void compare_ntdll_disk_vs_memory(HMODULE ntdll_mem) {
    printf("\n[*] Comparaison ntdll.dll : memoire vs disque\n");

    /* Lire ntdll depuis le disque (copie propre, sans hooks) */
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, MAX_PATH, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    [-] Impossible d'ouvrir ntdll.dll depuis le disque\n");
        return;
    }

    DWORD size = GetFileSize(hFile, NULL);
    BYTE* disk = (BYTE*)malloc(size);
    DWORD read;
    ReadFile(hFile, disk, size, &read, NULL);
    CloseHandle(hFile);

    /* Comparer la section .text */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll_mem;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll_mem + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sec[i].Name, 8);

        if (strcmp(name, ".text") == 0) {
            BYTE* mem_text = (BYTE*)ntdll_mem + sec[i].VirtualAddress;
            BYTE* disk_text = disk + sec[i].PointerToRawData;
            DWORD text_size = sec[i].Misc.VirtualSize;

            int diffs = 0;
            for (DWORD j = 0; j < text_size && j < sec[i].SizeOfRawData; j++) {
                if (mem_text[j] != disk_text[j])
                    diffs++;
            }

            printf("    Section .text : %lu octets\n", text_size);
            printf("    Differences   : %d octets\n", diffs);
            if (diffs > 0)
                printf("    [!] Des hooks EDR ont ete detectes!\n");
            else
                printf("    [+] Identique = pas de hooks inline\n");
            break;
        }
    }

    free(disk);
}

int main(void) {
    printf("[*] Demo : NTDLL Internals - Exploration de ntdll.dll\n");
    printf("[*] ==========================================\n\n");

    /* Etape 1 : Obtenir le handle de ntdll (deja chargee dans tout processus) */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[-] GetModuleHandle(ntdll) echoue\n");
        return 1;
    }
    printf("[+] ntdll.dll chargee a : %p\n\n", ntdll);

    /* Etape 2 : Examiner quelques stubs syscall connus */
    printf("[*] Stubs syscall de fonctions cles :\n");
    const char* key_funcs[] = {
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtProtectVirtualMemory", "NtCreateThreadEx",
        "NtOpenProcess", "NtClose"
    };
    for (int i = 0; i < 6; i++) {
        BYTE* addr = (BYTE*)GetProcAddress(ntdll, key_funcs[i]);
        if (addr)
            dump_bytes(key_funcs[i], addr, 12);
    }
    printf("\n");

    /* Etape 3 : Enumerer toutes les fonctions Nt* */
    enumerate_nt_functions(ntdll);

    /* Etape 4 : Comparer memoire vs disque */
    compare_ntdll_disk_vs_memory(ntdll);

    printf("\n[+] Exemple termine avec succes\n");
    return 0;
}

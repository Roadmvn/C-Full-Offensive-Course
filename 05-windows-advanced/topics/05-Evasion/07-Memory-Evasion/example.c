/*
 * OBJECTIF  : Comprendre l'evasion des scans memoire (fluctuation RWX, gargoyle, stomping)
 * PREREQUIS : VirtualAlloc/VirtualProtect, sections PE, timers Windows
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les EDR scannent la memoire a la recherche de shellcode dans des regions suspectes :
 * - Regions RWX (Read-Write-Execute) : tres suspect
 * - Regions RX non backees par un fichier (private/unbacked)
 * - Regions contenant des signatures connues
 *
 * Techniques d'evasion :
 * 1. Fluctuation RWX : alterner entre RW et RX
 * 2. Gargoyle : rendre le code non-executable pendant le sleep
 * 3. Module stomping : executer depuis une DLL legitime
 * 4. Phantom DLL hollowing : charger une DLL fantome
 */

#include <windows.h>
#include <stdio.h>

/* Shellcode demo : NOP sled + RET */
unsigned char demo_shellcode[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xC3
};

/* Helper : afficher les attributs d'une region memoire */
void print_memory_info(BYTE* addr) {
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(addr, &mbi, sizeof(mbi));

    const char* type_str = "UNKNOWN";
    switch (mbi.Type) {
        case MEM_IMAGE:   type_str = "MEM_IMAGE (DLL/EXE)"; break;
        case MEM_MAPPED:  type_str = "MEM_MAPPED"; break;
        case MEM_PRIVATE: type_str = "MEM_PRIVATE (VirtualAlloc)"; break;
    }

    const char* prot_str = "???";
    switch (mbi.Protect) {
        case PAGE_READONLY:          prot_str = "R--"; break;
        case PAGE_READWRITE:         prot_str = "RW-"; break;
        case PAGE_EXECUTE:           prot_str = "--X"; break;
        case PAGE_EXECUTE_READ:      prot_str = "R-X"; break;
        case PAGE_EXECUTE_READWRITE: prot_str = "RWX"; break;
        case PAGE_NOACCESS:          prot_str = "---"; break;
    }

    printf("        Base: %p  Size: 0x%llX  Protect: %s  Type: %s\n",
           mbi.BaseAddress, (unsigned long long)mbi.RegionSize, prot_str, type_str);
}

/* Demo 1 : Pourquoi RWX est suspect */
void demo_rwx_detection(void) {
    printf("[1] Pourquoi les allocations RWX sont detectees\n\n");

    /* Allocation RWX classique (tres suspect) */
    BYTE* rwx_mem = (BYTE*)VirtualAlloc(NULL, 4096,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!rwx_mem) return;
    memcpy(rwx_mem, demo_shellcode, sizeof(demo_shellcode));

    printf("    [!] Allocation RWX :\n");
    print_memory_info(rwx_mem);
    printf("    [!] Les EDR flaggent MEM_PRIVATE + RWX comme TRES suspect\n\n");

    /* Allocation correcte en 2 etapes */
    BYTE* staged_mem = (BYTE*)VirtualAlloc(NULL, 4096,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    memcpy(staged_mem, demo_shellcode, sizeof(demo_shellcode));

    DWORD old;
    VirtualProtect(staged_mem, 4096, PAGE_EXECUTE_READ, &old);

    printf("    [+] Allocation staged (RW -> RX) :\n");
    print_memory_info(staged_mem);
    printf("    [+] Mieux : pas de RWX, mais toujours MEM_PRIVATE + unbacked\n\n");

    VirtualFree(rwx_mem, 0, MEM_RELEASE);
    VirtualFree(staged_mem, 0, MEM_RELEASE);
}

/* Demo 2 : Fluctuation de protection memoire */
void demo_protection_fluctuation(void) {
    printf("[2] Fluctuation de protection memoire\n\n");

    BYTE* payload = (BYTE*)VirtualAlloc(NULL, 4096,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (!payload) return;
    memcpy(payload, demo_shellcode, sizeof(demo_shellcode));

    printf("    Cycle de fluctuation :\n\n");
    DWORD old;

    /* Phase 1 : Ecriture (RW) */
    printf("    [Phase 1] RW - Ecriture du payload\n");
    print_memory_info(payload);

    /* Phase 2 : Execution (RX) */
    VirtualProtect(payload, 4096, PAGE_EXECUTE_READ, &old);
    printf("    [Phase 2] RX - Execution\n");
    print_memory_info(payload);
    ((void(*)(void))payload)();
    printf("        -> Shellcode execute\n");

    /* Phase 3 : Sleep (RW, chiffre) */
    VirtualProtect(payload, 4096, PAGE_READWRITE, &old);
    for (int i = 0; i < (int)sizeof(demo_shellcode); i++)
        payload[i] ^= 0xAA;
    printf("    [Phase 3] RW - Sleep (memoire chiffree)\n");
    print_memory_info(payload);
    printf("        -> Bytes: ");
    for (int i = 0; i < 8; i++) printf("%02X ", payload[i]);
    printf("(chiffre)\n");

    Sleep(500);

    /* Phase 4 : Reveil (dechiffre, RX) */
    for (int i = 0; i < (int)sizeof(demo_shellcode); i++)
        payload[i] ^= 0xAA;
    VirtualProtect(payload, 4096, PAGE_EXECUTE_READ, &old);
    printf("    [Phase 4] RX - Reveil (dechiffre, re-executable)\n");
    print_memory_info(payload);
    ((void(*)(void))payload)();
    printf("        -> Shellcode re-execute\n\n");

    VirtualFree(payload, 0, MEM_RELEASE);
}

/* Demo 3 : Concept Gargoyle (execution depuis memoire non-executable) */
void demo_gargoyle_concept(void) {
    printf("[3] Concept Gargoyle : code non-executable au repos\n\n");

    printf("    Principe :\n");
    printf("    Le Gargoyle maintient le payload non-executable en permanence.\n");
    printf("    Il utilise un timer ROP chain pour se reveiller :\n\n");
    printf("    1. Etat initial : payload en memoire RW (non-executable)\n");
    printf("    2. Timer callback declenche -> ROP chain :\n");
    printf("       a. VirtualProtect(payload, RX)   -> rend executable\n");
    printf("       b. payload()                     -> execute le code\n");
    printf("       c. VirtualProtect(payload, RW)   -> re-rend non-executable\n");
    printf("       d. SetTimer(next_callback)       -> programme le prochain reveil\n");
    printf("    3. Retour a l'etat RW (invisible aux scans)\n\n");

    /* Demo simplifiee */
    printf("    [Demo simplifiee]\n");
    BYTE* payload = (BYTE*)VirtualAlloc(NULL, 4096,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (!payload) return;
    memcpy(payload, demo_shellcode, sizeof(demo_shellcode));

    printf("    [Repos]   ");
    print_memory_info(payload);

    /* Reveil : rendre executable momentanement */
    DWORD old;
    VirtualProtect(payload, 4096, PAGE_EXECUTE_READ, &old);
    printf("    [Actif]   ");
    print_memory_info(payload);
    ((void(*)(void))payload)();
    printf("        -> Execute\n");

    /* Retour au repos */
    VirtualProtect(payload, 4096, PAGE_READWRITE, &old);
    printf("    [Repos]   ");
    print_memory_info(payload);
    printf("        -> Non-executable (invisible)\n\n");

    VirtualFree(payload, 0, MEM_RELEASE);
}

/* Demo 4 : MEM_IMAGE vs MEM_PRIVATE (backed vs unbacked) */
void demo_backed_memory(void) {
    printf("[4] MEM_IMAGE vs MEM_PRIVATE (backed vs unbacked)\n\n");

    /* MEM_PRIVATE : allocation suspecte */
    BYTE* private_mem = (BYTE*)VirtualAlloc(NULL, 4096,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_READWRITE);
    printf("    VirtualAlloc (MEM_PRIVATE) :\n");
    print_memory_info(private_mem);
    printf("    [!] MEM_PRIVATE = pas de fichier associe (suspect si RX)\n\n");

    /* MEM_IMAGE : via chargement de DLL (legitime) */
    HMODULE hDll = LoadLibraryA("version.dll");
    if (hDll) {
        printf("    LoadLibrary version.dll (MEM_IMAGE) :\n");
        print_memory_info((BYTE*)hDll);
        printf("    [+] MEM_IMAGE = backe par version.dll sur disque (legitime)\n\n");

        printf("    [*] Module Stomping : ecraser .text de la DLL avec le payload\n");
        printf("    [*] Le shellcode s'execute depuis MEM_IMAGE = beaucoup plus furtif\n\n");
        FreeLibrary(hDll);
    }

    /* MEM_MAPPED : via file mapping */
    HANDLE hMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                          PAGE_EXECUTE_READWRITE,
                                          0, 4096, NULL);
    if (hMapping) {
        BYTE* mapped = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
                                             0, 0, 4096);
        if (mapped) {
            printf("    CreateFileMapping (MEM_MAPPED) :\n");
            print_memory_info(mapped);
            printf("    [*] MEM_MAPPED peut etre RX sans etre aussi suspect que PRIVATE\n\n");
            UnmapViewOfFile(mapped);
        }
        CloseHandle(hMapping);
    }

    VirtualFree(private_mem, 0, MEM_RELEASE);
}

/* Demo 5 : Scanner memoire simple (ce que fait l'EDR) */
void demo_memory_scanner(void) {
    printf("[5] Mini-scanner memoire (simule un scan EDR)\n\n");

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* max_addr = (BYTE*)si.lpMaximumApplicationAddress;

    int rwx_regions = 0;
    int rx_private = 0;

    while (addr < max_addr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) break;

        /* Detecter RWX */
        if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT) {
            rwx_regions++;
            if (rwx_regions <= 3) {
                printf("    [!] RWX : %p (0x%llX bytes, %s)\n",
                       mbi.BaseAddress, (unsigned long long)mbi.RegionSize,
                       mbi.Type == MEM_PRIVATE ? "PRIVATE" : "IMAGE/MAPPED");
            }
        }

        /* Detecter RX + PRIVATE (unbacked executable) */
        if (mbi.Protect == PAGE_EXECUTE_READ && mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT) {
            rx_private++;
            if (rx_private <= 3) {
                printf("    [?] RX+PRIVATE : %p (0x%llX bytes, unbacked)\n",
                       mbi.BaseAddress, (unsigned long long)mbi.RegionSize);
            }
        }

        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    printf("\n    [+] Resultat du scan :\n");
    printf("        RWX regions      : %d %s\n", rwx_regions,
           rwx_regions > 0 ? "(SUSPECT)" : "(clean)");
    printf("        RX+PRIVATE       : %d %s\n", rx_private,
           rx_private > 0 ? "(a verifier)" : "(clean)");
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Memory Evasion - Contourner les scans memoire\n");
    printf("[*] ==========================================\n\n");

    demo_rwx_detection();
    demo_protection_fluctuation();
    demo_gargoyle_concept();
    demo_backed_memory();
    demo_memory_scanner();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

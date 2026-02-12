/*
 * OBJECTIF  : Comprendre la gestion memoire kernel Windows
 * PREREQUIS : Driver Basics, Virtual Memory
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Le kernel a son propre espace d'adressage et ses propres
 * mecanismes d'allocation (pool). Ce module explore les concepts
 * depuis le usermode.
 */

#include <windows.h>
#include <stdio.h>

void demo_address_space(void) {
    printf("[1] Espace d'adressage Windows x64\n\n");
    printf("    0x0000000000000000 - 0x00007FFFFFFFFFFF : Usermode (128 TB)\n");
    printf("    0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF : Kernel   (128 TB)\n\n");
    printf("    Le kernel voit TOUT l'espace d'adressage :\n");
    printf("    - Sa propre memoire (code + donnees)\n");
    printf("    - La memoire de TOUS les processus\n");
    printf("    - Le hardware (MMIO)\n\n");

    /* Montrer les adresses usermode du processus courant */
    void* stack_var = &stack_var;
    void* heap_var = malloc(1);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    printf("    Adresses usermode de ce processus :\n");
    printf("    Stack   : %p\n", stack_var);
    printf("    Heap    : %p\n", heap_var);
    printf("    ntdll   : %p\n", (void*)ntdll);
    printf("    -> Toutes < 0x00007FFF'FFFFFFFF\n\n");
    free(heap_var);
}

void demo_kernel_pools(void) {
    printf("[2] Pools memoire kernel\n\n");
    printf("    NonPagedPool (NP) :\n");
    printf("    - Toujours en RAM (jamais swappee)\n");
    printf("    - Pour les donnees accedees a IRQL >= DISPATCH\n");
    printf("    - Ressource limitee et precieuse\n");
    printf("    - ExAllocatePoolWithTag(NonPagedPool, size, tag)\n\n");

    printf("    PagedPool (PP) :\n");
    printf("    - Peut etre swappee sur disque\n");
    printf("    - Pour les donnees accedees a IRQL < DISPATCH\n");
    printf("    - Plus abondante\n");
    printf("    - ExAllocatePoolWithTag(PagedPool, size, tag)\n\n");

    printf("    NonPagedPoolNx (NX) :\n");
    printf("    - Non-paginee ET non-executable\n");
    printf("    - Recommandee depuis Windows 8\n");
    printf("    - Empeche l'execution de shellcode kernel\n\n");

    printf("    ExAllocatePool2 (moderne) :\n");
    printf("    - Remplace ExAllocatePoolWithTag\n");
    printf("    - Zero-initialize par defaut\n");
    printf("    - POOL_FLAG_NON_PAGED, POOL_FLAG_PAGED\n\n");
}

void demo_pool_tags(void) {
    printf("[3] Pool Tags et forensics\n\n");
    printf("    Chaque allocation kernel a un tag (4 chars) :\n");
    printf("    ExAllocatePoolWithTag(pool, size, 'Tag1')\n\n");
    printf("    Tags connus :\n");
    printf("    'Proc' - EPROCESS structures\n");
    printf("    'Thre' - ETHREAD structures\n");
    printf("    'File' - FILE_OBJECT\n");
    printf("    'ObNm' - Object names\n");
    printf("    'MmSt' - Memory Manager\n\n");

    printf("    Outils de diagnostic :\n");
    printf("    - poolmon.exe (WDK) : moniteur de pool en temps reel\n");
    printf("    - !poolused (WinDbg) : utilisation par tag\n");
    printf("    - !pool (WinDbg) : info sur une allocation\n\n");

    /* Demonstrer la lecture de SystemPoolTagInformation */
    printf("    Les tags EDR/AV sont identifiables :\n");
    printf("    CsFa - CrowdStrike Falcon\n");
    printf("    Sent - SentinelOne\n");
    printf("    WdFl - Windows Defender\n\n");
}

void demo_mdl(void) {
    printf("[4] MDL (Memory Descriptor List)\n\n");
    printf("    Les MDL decrivent des zones de memoire physique.\n");
    printf("    Utilises pour le DMA et le mapping kernel<->user.\n\n");

    printf("    Workflow typique :\n");
    printf("    1. IoAllocateMdl(baseVA, length, ...)\n");
    printf("    2. MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess)\n");
    printf("    3. MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority)\n");
    printf("    4. ... utiliser le mapping ...\n");
    printf("    5. MmUnlockPages(mdl)\n");
    printf("    6. IoFreeMdl(mdl)\n\n");

    printf("    Usage offensif :\n");
    printf("    - Mapper la memoire kernel en usermode\n");
    printf("    - Contourner les protections de pages\n");
    printf("    - Double-mapping : meme page physique, 2 VAs\n\n");
}

void demo_system_info(void) {
    printf("[5] Informations systeme kernel\n\n");

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    printf("    Processeurs     : %lu\n", si.dwNumberOfProcessors);
    printf("    Page size       : %lu bytes\n", si.dwPageSize);
    printf("    Alloc granularity: %lu bytes\n", si.dwAllocationGranularity);
    printf("    Min address     : %p\n", si.lpMinimumApplicationAddress);
    printf("    Max address     : %p\n", si.lpMaximumApplicationAddress);

    MEMORYSTATUSEX mem = { .dwLength = sizeof(mem) };
    if (GlobalMemoryStatusEx(&mem)) {
        printf("    RAM totale      : %llu MB\n", mem.ullTotalPhys / (1024*1024));
        printf("    RAM disponible  : %llu MB\n", mem.ullAvailPhys / (1024*1024));
    }

    /* Version de l'OS */
    typedef NTSTATUS (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    RtlGetVersion_t pRtlGetVersion = (RtlGetVersion_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (pRtlGetVersion) {
        RTL_OSVERSIONINFOW ver = { .dwOSVersionInfoSize = sizeof(ver) };
        if (pRtlGetVersion(&ver) == 0) {
            printf("    OS Version      : %lu.%lu.%lu\n",
                   ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber);
        }
    }
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Kernel Memory\n");
    printf("[*] ==========================================\n\n");
    demo_address_space();
    demo_kernel_pools();
    demo_pool_tags();
    demo_mdl();
    demo_system_info();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

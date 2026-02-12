/*
 * OBJECTIF  : Acceder au PEB et TEB pour enumerer les modules charges
 * PREREQUIS : Bases du C, notions de structures Windows internes
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Le PEB (Process Environment Block) contient les metadonnees du processus :
 * modules charges, parametres, flags de debug, etc.
 * Le TEB (Thread Environment Block) contient les infos du thread courant.
 * Acceder a ces structures permet d'operer SANS appeler d'APIs detectables.
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

/*
 * Structure PEB_LDR_DATA et LDR_DATA_TABLE_ENTRY
 * sont partiellement definies dans winternl.h.
 * On les redefinit ici pour avoir les champs complets.
 */
typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY, *PMY_LDR_ENTRY;

/* Methode 1 : Acceder au PEB via NtQueryInformationProcess */
PPEB get_peb_via_api(void) {
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len);

    if (status == 0)
        return pbi.PebBaseAddress;
    return NULL;
}

/* Methode 2 : Acceder au PEB via le registre segment (TEB->PEB) */
PPEB get_peb_via_teb(void) {
#if defined(_M_X64) || defined(__x86_64__)
    /* En x64, le TEB est pointe par GS:[0x30], et PEB est a TEB+0x60 */
    return (PPEB)__readgsqword(0x60);
#else
    /* En x86, le TEB est pointe par FS:[0x18], et PEB est a TEB+0x30 */
    return (PPEB)__readfsdword(0x30);
#endif
}

/* Enumerer les modules charges via PEB->Ldr */
void enumerate_modules_from_peb(PPEB peb) {
    printf("[*] Enumeration des modules via PEB->Ldr->InLoadOrderModuleList\n\n");

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    int count = 0;
    printf("    %-4s  %-18s  %-10s  %s\n", "#", "Base", "Size", "Module");
    printf("    %-4s  %-18s  %-10s  %s\n", "----", "------------------", "----------", "------");

    while (current != head) {
        PMY_LDR_ENTRY entry = CONTAINING_RECORD(current, MY_LDR_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer) {
            printf("    [%2d]  %p  0x%08lX  %.*ls\n",
                   count,
                   entry->DllBase,
                   entry->SizeOfImage,
                   entry->BaseDllName.Length / 2,
                   entry->BaseDllName.Buffer);
        }

        count++;
        current = current->Flink;

        if (count > 100) break;
    }
    printf("\n    [+] Total : %d modules charges\n", count);
}

/* Lire les informations interessantes du PEB */
void print_peb_info(PPEB peb) {
    printf("[*] Informations du PEB\n");
    printf("    Adresse PEB        : %p\n", peb);
    printf("    ImageBaseAddress   : %p\n", peb->Reserved3[1]); /* ImageBaseAddress */
    printf("    BeingDebugged      : %d", peb->BeingDebugged);
    if (peb->BeingDebugged)
        printf(" (DEBUGGER DETECTE!)\n");
    else
        printf(" (pas de debugger)\n");
    printf("    Ldr (PEB_LDR_DATA) : %p\n", peb->Ldr);
    printf("    ProcessHeap        : %p\n", peb->Reserved4[0]); /* ProcessHeap */
    printf("    OSMajorVersion     : %lu\n", peb->OSMajorVersion);
    printf("    OSMinorVersion     : %lu\n", peb->OSMinorVersion);
    printf("    OSBuildNumber      : %u\n", peb->OSBuildNumber);
    printf("\n");
}

/* Obtenir l'adresse du TEB */
void print_teb_info(void) {
    printf("[*] Informations du TEB\n");

#if defined(_M_X64) || defined(__x86_64__)
    PVOID teb = (PVOID)__readgsqword(0x30); /* TEB self-pointer */
    PVOID peb = (PVOID)__readgsqword(0x60);
    PVOID stack_base = (PVOID)__readgsqword(0x08);
    PVOID stack_limit = (PVOID)__readgsqword(0x10);
    printf("    Acces via        : GS:[0x30]\n");
#else
    PVOID teb = (PVOID)__readfsdword(0x18);
    PVOID peb = (PVOID)__readfsdword(0x30);
    PVOID stack_base = (PVOID)__readfsdword(0x04);
    PVOID stack_limit = (PVOID)__readfsdword(0x08);
    printf("    Acces via        : FS:[0x18]\n");
#endif

    printf("    Adresse TEB      : %p\n", teb);
    printf("    PEB (depuis TEB) : %p\n", peb);
    printf("    StackBase        : %p\n", stack_base);
    printf("    StackLimit       : %p\n", stack_limit);
    printf("    Thread ID        : %lu\n", GetCurrentThreadId());
    printf("\n");
}

/* Demo anti-debug : patcher BeingDebugged dans le PEB */
void demo_anti_debug_patch(PPEB peb) {
    printf("[*] Demo anti-debug : lecture du flag BeingDebugged\n");
    printf("    Valeur actuelle : %d\n", peb->BeingDebugged);
    printf("    [!] Un malware pourrait patcher ce flag a 0 pour cacher le debugger\n");
    printf("    [!] peb->BeingDebugged = 0; // bypass IsDebuggerPresent()\n\n");
}

int main(void) {
    printf("[*] Demo : PEB et TEB - Structures internes Windows\n");
    printf("[*] ==========================================\n\n");

    /* Methode 1 : via API */
    printf("=== Methode 1 : PEB via NtQueryInformationProcess ===\n");
    PPEB peb1 = get_peb_via_api();
    if (peb1)
        printf("[+] PEB obtenu via API : %p\n\n", peb1);

    /* Methode 2 : via registre segment (plus furtif) */
    printf("=== Methode 2 : PEB via registre segment (TEB->PEB) ===\n");
    PPEB peb2 = get_peb_via_teb();
    printf("[+] PEB obtenu via TEB : %p\n", peb2);
    printf("[+] Les deux methodes pointent vers la meme adresse : %s\n\n",
           peb1 == peb2 ? "OUI" : "NON");

    /* Informations TEB */
    print_teb_info();

    /* Informations PEB */
    print_peb_info(peb2);

    /* Enumerer les modules */
    enumerate_modules_from_peb(peb2);

    /* Demo anti-debug */
    printf("\n");
    demo_anti_debug_patch(peb2);

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

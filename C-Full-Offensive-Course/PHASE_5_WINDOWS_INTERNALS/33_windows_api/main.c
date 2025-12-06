/*
 * ═══════════════════════════════════════════════════════════════════════════
 * Module 23 : APIs Windows Avancées
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT LÉGAL :
 * Ce code est à des fins ÉDUCATIVES et de RECHERCHE EN SÉCURITÉ uniquement.
 * L'utilisation à des fins malveillantes est ILLÉGALE.
 *
 * Démonstration de :
 * - kernel32.dll APIs (VirtualAlloc, Process*, etc.)
 * - ntdll.dll APIs natives
 * - Énumération de processus
 * - Manipulation mémoire
 * - PEB walking
 * - Résolution d'API manuelle
 *
 * Compilation :
 *   Windows : gcc main.c -o main.exe
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifdef _WIN32

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>

// ═══════════════════════════════════════════════════════════════════════════
// STRUCTURES NATIVES
// ═══════════════════════════════════════════════════════════════════════════

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

// Structure PEB simplifiée
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

// Prototype NtQuerySystemInformation
typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// ═══════════════════════════════════════════════════════════════════════════
// UTILITAIRES
// ═══════════════════════════════════════════════════════════════════════════

void print_hex_bytes(const char *label, BYTE *data, size_t length) {
    printf("[%s] ", label);
    for (size_t i = 0; i < length && i < 16; i++) {
        printf("%02X ", data[i]);
    }
    if (length > 16) {
        printf("...");
    }
    printf("\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION 1 : GESTION MÉMOIRE (VirtualAlloc, VirtualProtect)
// ═══════════════════════════════════════════════════════════════════════════

void demo_memory_management() {
    printf("\n═══ Gestion Mémoire (VirtualAlloc/VirtualProtect) ═══\n\n");

    // 1. Allouer de la mémoire
    SIZE_T size = 4096;
    PVOID memory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);

    if (memory == NULL) {
        printf("  [Erreur] VirtualAlloc failed\n");
        return;
    }

    printf("  [+] Mémoire allouée : 0x%p, taille : %zu bytes\n", memory, size);

    // 2. Écrire dans la mémoire
    const char *message = "Hello from allocated memory!";
    strcpy((char *)memory, message);
    printf("  [+] Écrit : '%s'\n", message);

    // 3. Changer les permissions en exécution
    DWORD old_protect;
    if (VirtualProtect(memory, size, PAGE_EXECUTE_READ, &old_protect)) {
        printf("  [+] Permissions changées : PAGE_EXECUTE_READ\n");
        printf("      (ancien : 0x%lX)\n", old_protect);
    }

    // 4. Lire le contenu
    printf("  [+] Contenu : '%s'\n", (char *)memory);

    // 5. Libérer
    VirtualFree(memory, 0, MEM_RELEASE);
    printf("  [+] Mémoire libérée\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION 2 : ÉNUMÉRATION DE PROCESSUS
// ═══════════════════════════════════════════════════════════════════════════

void demo_process_enumeration() {
    printf("\n═══ Énumération de Processus (CreateToolhelp32Snapshot) ═══\n\n");

    // Créer un snapshot de tous les processus
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("  [Erreur] CreateToolhelp32Snapshot failed\n");
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Premier processus
    if (!Process32First(snapshot, &pe32)) {
        printf("  [Erreur] Process32First failed\n");
        CloseHandle(snapshot);
        return;
    }

    printf("  %-30s %8s %8s\n", "Nom", "PID", "Threads");
    printf("  %s\n", "──────────────────────────────────────────────────");

    int count = 0;

    // Énumérer tous les processus
    do {
        printf("  %-30s %8lu %8lu\n",
               pe32.szExeFile, pe32.th32ProcessID, pe32.cntThreads);

        count++;
        if (count >= 15) {  // Limiter l'affichage
            printf("  [...%d processus supplémentaires...]\n",
                   (int)(pe32.th32ProcessID / 100));  // Estimation
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    printf("\n  [+] Énumération terminée\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION 3 : LECTURE/ÉCRITURE MÉMOIRE DISTANTE
// ═══════════════════════════════════════════════════════════════════════════

void demo_remote_memory() {
    printf("\n═══ Lecture/Écriture Mémoire Distante ═══\n\n");

    // Ouvrir notre propre processus pour la démo
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (process == NULL) {
        printf("  [Erreur] OpenProcess failed\n");
        return;
    }

    printf("  [+] Processus ouvert : PID %lu\n", GetCurrentProcessId());

    // Allouer dans le processus "distant" (nous-même)
    SIZE_T size = 1024;
    PVOID remote_memory = VirtualAllocEx(process, NULL, size,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);

    if (remote_memory == NULL) {
        printf("  [Erreur] VirtualAllocEx failed\n");
        CloseHandle(process);
        return;
    }

    printf("  [+] Mémoire distante allouée : 0x%p\n", remote_memory);

    // Écrire dans la mémoire distante
    const char *data = "Test écriture distante";
    SIZE_T written;
    if (WriteProcessMemory(process, remote_memory, data, strlen(data) + 1,
                          &written)) {
        printf("  [+] Écrit %zu bytes : '%s'\n", written, data);
    }

    // Lire depuis la mémoire distante
    char buffer[256] = {0};
    SIZE_T read;
    if (ReadProcessMemory(process, remote_memory, buffer, sizeof(buffer),
                         &read)) {
        printf("  [+] Lu %zu bytes : '%s'\n", read, buffer);
    }

    // Nettoyer
    VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
    CloseHandle(process);
    printf("  [+] Nettoyage effectué\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION 4 : RÉSOLUTION D'API DYNAMIQUE
// ═══════════════════════════════════════════════════════════════════════════

void demo_api_resolution() {
    printf("\n═══ Résolution d'API Dynamique (LoadLibrary/GetProcAddress) ═══\n\n");

    // Charger kernel32.dll (déjà chargé, mais pour la démo)
    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    if (kernel32 == NULL) {
        printf("  [Erreur] LoadLibrary failed\n");
        return;
    }

    printf("  [+] kernel32.dll chargé : 0x%p\n", kernel32);

    // Résoudre des fonctions
    const char *functions[] = {
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetTickCount",
        "GetLastError",
        NULL
    };

    for (int i = 0; functions[i] != NULL; i++) {
        PVOID func_addr = GetProcAddress(kernel32, functions[i]);
        if (func_addr) {
            printf("  [+] %-25s : 0x%p\n", functions[i], func_addr);

            // Afficher les premiers bytes
            BYTE *bytes = (BYTE *)func_addr;
            printf("      Premiers bytes : ");
            for (int j = 0; j < 8; j++) {
                printf("%02X ", bytes[j]);
            }
            printf("\n");
        } else {
            printf("  [-] %-25s : non trouvée\n", functions[i]);
        }
    }

    // Note : FreeLibrary() omis car kernel32 est toujours nécessaire
    printf("\n  [+] Résolution terminée\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION 5 : PEB WALKING
// ═══════════════════════════════════════════════════════════════════════════

#ifdef _WIN64
PPEB get_peb() {
    // Sur x64, le PEB est accessible via GS:[0x60]
    return (PPEB)__readgsqword(0x60);
}
#else
PPEB get_peb() {
    // Sur x86, le PEB est accessible via FS:[0x30]
    return (PPEB)__readfsdword(0x30);
}
#endif

void demo_peb_walking() {
    printf("\n═══ PEB Walking (Énumération de Modules) ═══\n\n");

    PPEB peb = get_peb();
    printf("  [+] PEB : 0x%p\n", peb);
    printf("  [+] BeingDebugged : %s\n", peb->BeingDebugged ? "OUI" : "NON");
    printf("  [+] SessionId : %lu\n", peb->SessionId);

    // Accéder au Loader Data
    PPEB_LDR_DATA ldr = peb->Ldr;
    if (ldr == NULL) {
        printf("  [Erreur] Ldr est NULL\n");
        return;
    }

    printf("\n  [+] Modules chargés (via PEB) :\n");
    printf("  %-40s %s\n", "Nom", "Base");
    printf("  %s\n", "────────────────────────────────────────────────────────");

    // Parcourir la liste des modules
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    int count = 0;
    while (current != head && count < 10) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        // Convertir UNICODE_STRING en char*
        wchar_t name[256] = {0};
        if (entry->BaseDllName.Length > 0) {
            wcsncpy(name, entry->BaseDllName.Buffer,
                   min(entry->BaseDllName.Length / 2, 255));
        }

        printf("  %-40ls 0x%p\n", name, entry->DllBase);

        current = current->Flink;
        count++;
    }

    printf("\n  [+] PEB walking terminé\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION 6 : NtQuerySystemInformation
// ═══════════════════════════════════════════════════════════════════════════

void demo_ntquery() {
    printf("\n═══ NtQuerySystemInformation ═══\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("  [Erreur] ntdll.dll non trouvé\n");
        return;
    }

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(ntdll,
                                                  "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        printf("  [Erreur] NtQuerySystemInformation non trouvée\n");
        return;
    }

    printf("  [+] NtQuerySystemInformation : 0x%p\n",
           NtQuerySystemInformation);

    // Exemple : SystemBasicInformation
    typedef struct _SYSTEM_BASIC_INFORMATION {
        ULONG Reserved;
        ULONG TimerResolution;
        ULONG PageSize;
        ULONG NumberOfPhysicalPages;
        ULONG LowestPhysicalPageNumber;
        ULONG HighestPhysicalPageNumber;
        ULONG AllocationGranularity;
        ULONG_PTR MinimumUserModeAddress;
        ULONG_PTR MaximumUserModeAddress;
        ULONG_PTR ActiveProcessorsAffinityMask;
        CCHAR NumberOfProcessors;
    } SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

    SYSTEM_BASIC_INFORMATION sbi = {0};
    ULONG return_length;

    NTSTATUS status = NtQuerySystemInformation(
        SystemBasicInformation, &sbi, sizeof(sbi), &return_length);

    if (NT_SUCCESS(status)) {
        printf("  [+] SystemBasicInformation :\n");
        printf("      Page Size : %lu bytes\n", sbi.PageSize);
        printf("      Processeurs : %d\n", sbi.NumberOfProcessors);
        printf("      Pages physiques : %lu\n", sbi.NumberOfPhysicalPages);
        printf("      Granularité allocation : %lu\n",
               sbi.AllocationGranularity);
    } else {
        printf("  [Erreur] NtQuerySystemInformation failed : 0x%lX\n", status);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DÉMONSTRATION 7 : EXEMPLE D'INJECTION SIMPLE
// ═══════════════════════════════════════════════════════════════════════════

void demo_injection_concept() {
    printf("\n═══ Concept d'Injection (Théorique) ═══\n\n");

    printf("  [Info] Étapes typiques d'une injection de DLL :\n\n");

    printf("  1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)\n");
    printf("     → Obtenir un handle sur le processus cible\n\n");

    printf("  2. VirtualAllocEx(process, NULL, size, MEM_COMMIT, PAGE_READWRITE)\n");
    printf("     → Allouer de la mémoire dans le processus distant\n\n");

    printf("  3. WriteProcessMemory(process, remote_mem, dll_path, ...)\n");
    printf("     → Écrire le chemin de la DLL dans la mémoire distante\n\n");

    printf("  4. GetProcAddress(kernel32, \"LoadLibraryA\")\n");
    printf("     → Obtenir l'adresse de LoadLibraryA\n\n");

    printf("  5. CreateRemoteThread(process, NULL, 0, LoadLibraryA, remote_mem, ...)\n");
    printf("     → Créer un thread qui exécute LoadLibraryA(dll_path)\n\n");

    printf("  6. WaitForSingleObject(thread, ...)\n");
    printf("     → Attendre que le thread se termine\n\n");

    printf("  7. VirtualFreeEx(...) + CloseHandle(...)\n");
    printf("     → Nettoyer les ressources\n\n");

    printf("  [Note] Implémentation réelle nécessite des privilèges élevés\n");
    printf("  [Note] Peut être détecté par EDR/AV\n");
    printf("  [Note] Usage légitime : debuggers, profilers, etc.\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Module 23 : APIs Windows Avancées\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("AVERTISSEMENT : Code éducatif uniquement !\n");
    printf("Ne pas utiliser à des fins malveillantes.\n");

    demo_memory_management();
    demo_process_enumeration();
    demo_remote_memory();
    demo_api_resolution();
    demo_peb_walking();
    demo_ntquery();
    demo_injection_concept();

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

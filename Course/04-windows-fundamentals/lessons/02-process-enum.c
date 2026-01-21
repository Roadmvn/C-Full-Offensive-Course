/*
 * LESSON 02: Process Enumeration
 *
 * OBJECTIFS:
 * - Enumerer tous les processus en cours d'execution
 * - Obtenir des informations sur les processus
 * - Ouvrir des handles vers des processus existants
 * - Recuperer les noms des processus
 *
 * CONCEPTS CLES:
 * - EnumProcesses: Liste tous les PIDs
 * - OpenProcess: Ouvre un handle vers un processus existant
 * - PSAPI (Process Status API): API pour informations processus
 * - Droits d'acces: PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")

/*
 * ENUMERATION DES PROCESSUS
 *
 * EnumProcesses retourne un tableau de PIDs de tous les processus actifs.
 */
void enumerate_processes_basic() {
    printf("=== ENUMERATION BASIQUE DES PROCESSUS ===\n\n");

    // Tableau pour stocker les PIDs
    DWORD processes[1024];
    DWORD bytesReturned;

    // Enumerer tous les processus
    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        printf("[-] EnumProcesses echoue: %lu\n", GetLastError());
        return;
    }

    // Calculer le nombre de processus
    DWORD numProcesses = bytesReturned / sizeof(DWORD);

    printf("[+] Nombre de processus: %lu\n\n", numProcesses);

    // Afficher les premiers PIDs
    printf("Premiers 20 PIDs:\n");
    for (DWORD i = 0; i < 20 && i < numProcesses; i++) {
        if (processes[i] != 0) {
            printf("  [%2lu] PID: %5lu\n", i, processes[i]);
        }
    }
    printf("\n");
}

/*
 * OBTENIR LE NOM D'UN PROCESSUS
 *
 * Pour obtenir le nom, il faut:
 * 1. Ouvrir un handle avec OpenProcess
 * 2. Utiliser GetModuleBaseName ou GetProcessImageFileName
 * 3. Fermer le handle
 */
const char* get_process_name(DWORD pid, char* buffer, size_t bufferSize) {
    // Ouvrir le processus avec droits de lecture
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (hProcess == NULL) {
        // Processus inaccessible (systeme, privileges insuffisants)
        snprintf(buffer, bufferSize, "[Access Denied]");
        return buffer;
    }

    // Obtenir le nom du module principal
    if (GetModuleBaseNameA(hProcess, NULL, buffer, (DWORD)bufferSize) == 0) {
        snprintf(buffer, bufferSize, "[Unknown]");
    }

    CloseHandle(hProcess);
    return buffer;
}

/*
 * ENUMERATION AVEC NOMS
 *
 * Combine EnumProcesses et GetModuleBaseName pour lister les processus.
 */
void enumerate_processes_with_names() {
    printf("=== ENUMERATION AVEC NOMS ===\n\n");

    DWORD processes[1024];
    DWORD bytesReturned;

    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        printf("[-] EnumProcesses echoue\n");
        return;
    }

    DWORD numProcesses = bytesReturned / sizeof(DWORD);

    printf("╔═══════╦═══════════════════════════════════════╗\n");
    printf("║  PID  ║         NOM DU PROCESSUS              ║\n");
    printf("╠═══════╬═══════════════════════════════════════╣\n");

    int displayed = 0;
    char processName[MAX_PATH];

    for (DWORD i = 0; i < numProcesses && displayed < 25; i++) {
        if (processes[i] != 0) {
            get_process_name(processes[i], processName, sizeof(processName));
            printf("║ %5lu ║ %-37s ║\n", processes[i], processName);
            displayed++;
        }
    }

    printf("╚═══════╩═══════════════════════════════════════╝\n");
    printf("[*] %d processus affiches (sur %lu total)\n\n", displayed, numProcesses);
}

/*
 * INFORMATIONS DETAILLEES SUR UN PROCESSUS
 *
 * Recuperer diverses informations sur un processus specifique.
 */
void get_process_info(DWORD pid) {
    printf("=== INFORMATIONS SUR LE PROCESSUS %lu ===\n\n", pid);

    // Ouvrir le processus
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (hProcess == NULL) {
        printf("[-] Impossible d'ouvrir le processus: %lu\n", GetLastError());
        return;
    }

    // Nom du processus
    char processName[MAX_PATH];
    if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName))) {
        printf("Nom: %s\n", processName);
    }

    // Chemin complet
    char processPath[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, processPath, sizeof(processPath))) {
        printf("Chemin: %s\n", processPath);
    }

    // Memoire utilisee
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        printf("\nUtilisation memoire:\n");
        printf("  Working Set: %lu KB\n", pmc.WorkingSetSize / 1024);
        printf("  Peak Working Set: %lu KB\n", pmc.PeakWorkingSetSize / 1024);
        printf("  Pagefile Usage: %lu KB\n", pmc.PagefileUsage / 1024);
    }

    // Temps d'execution
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        // Convertir en temps utilisable
        ULARGE_INTEGER kt, ut;
        kt.LowPart = kernelTime.dwLowDateTime;
        kt.HighPart = kernelTime.dwHighDateTime;
        ut.LowPart = userTime.dwLowDateTime;
        ut.HighPart = userTime.dwHighDateTime;

        printf("\nTemps CPU:\n");
        printf("  Kernel Time: %llu ms\n", kt.QuadPart / 10000);
        printf("  User Time: %llu ms\n", ut.QuadPart / 10000);
    }

    CloseHandle(hProcess);
    printf("\n");
}

/*
 * RECHERCHER UN PROCESSUS PAR NOM
 *
 * Trouver le PID d'un processus a partir de son nom.
 */
DWORD find_process_by_name(const char* targetName) {
    DWORD processes[1024];
    DWORD bytesReturned;

    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        return 0;
    }

    DWORD numProcesses = bytesReturned / sizeof(DWORD);
    char processName[MAX_PATH];

    for (DWORD i = 0; i < numProcesses; i++) {
        if (processes[i] == 0) continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processes[i]
        );

        if (hProcess) {
            if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName))) {
                // Comparaison insensible a la casse
                if (_stricmp(processName, targetName) == 0) {
                    CloseHandle(hProcess);
                    return processes[i];
                }
            }
            CloseHandle(hProcess);
        }
    }

    return 0;  // Non trouve
}

void demonstrate_find_process() {
    printf("=== RECHERCHE DE PROCESSUS ===\n\n");

    const char* targets[] = {
        "explorer.exe",
        "svchost.exe",
        "notepad.exe",
        "chrome.exe"
    };

    for (int i = 0; i < 4; i++) {
        printf("[*] Recherche: %s\n", targets[i]);
        DWORD pid = find_process_by_name(targets[i]);

        if (pid != 0) {
            printf("[+] Trouve! PID: %lu\n", pid);
        } else {
            printf("[-] Non trouve ou inaccessible\n");
        }
        printf("\n");
    }
}

/*
 * COMPTER LES PROCESSUS PAR NOM
 *
 * Certains processus (comme svchost.exe) ont plusieurs instances.
 */
void count_process_instances(const char* targetName) {
    printf("=== COMPTAGE DES INSTANCES: %s ===\n\n", targetName);

    DWORD processes[1024];
    DWORD bytesReturned;

    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        return;
    }

    DWORD numProcesses = bytesReturned / sizeof(DWORD);
    char processName[MAX_PATH];
    int count = 0;

    printf("Instances trouvees:\n");

    for (DWORD i = 0; i < numProcesses; i++) {
        if (processes[i] == 0) continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processes[i]
        );

        if (hProcess) {
            if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName))) {
                if (_stricmp(processName, targetName) == 0) {
                    count++;
                    printf("  [%d] PID: %lu\n", count, processes[i]);
                }
            }
            CloseHandle(hProcess);
        }
    }

    printf("\nTotal: %d instance(s)\n\n", count);
}

/*
 * DROITS D'ACCES AUX PROCESSUS
 *
 * Demonstration des differents niveaux d'acces.
 */
void demonstrate_process_access_rights() {
    printf("=== DROITS D'ACCES AUX PROCESSUS ===\n\n");

    printf("Droits courants:\n");
    printf("  PROCESS_TERMINATE (0x%08X)\n", PROCESS_TERMINATE);
    printf("  PROCESS_CREATE_THREAD (0x%08X)\n", PROCESS_CREATE_THREAD);
    printf("  PROCESS_VM_OPERATION (0x%08X)\n", PROCESS_VM_OPERATION);
    printf("  PROCESS_VM_READ (0x%08X)\n", PROCESS_VM_READ);
    printf("  PROCESS_VM_WRITE (0x%08X)\n", PROCESS_VM_WRITE);
    printf("  PROCESS_QUERY_INFORMATION (0x%08X)\n", PROCESS_QUERY_INFORMATION);
    printf("  PROCESS_ALL_ACCESS (0x%08X)\n", PROCESS_ALL_ACCESS);

    printf("\n[*] Test d'ouverture du processus actuel\n");

    DWORD currentPid = GetCurrentProcessId();

    // Tenter differents droits d'acces
    struct {
        DWORD access;
        const char* name;
    } tests[] = {
        {PROCESS_QUERY_INFORMATION, "QUERY_INFORMATION"},
        {PROCESS_VM_READ, "VM_READ"},
        {PROCESS_ALL_ACCESS, "ALL_ACCESS"}
    };

    for (int i = 0; i < 3; i++) {
        HANDLE h = OpenProcess(tests[i].access, FALSE, currentPid);
        if (h) {
            printf("[+] %s: OK\n", tests[i].name);
            CloseHandle(h);
        } else {
            printf("[-] %s: REFUSE (%lu)\n", tests[i].name, GetLastError());
        }
    }
    printf("\n");
}

/*
 * ENUMERER LES MODULES D'UN PROCESSUS
 *
 * Lister les DLLs chargees dans un processus.
 */
void enumerate_process_modules(DWORD pid) {
    printf("=== MODULES DU PROCESSUS %lu ===\n\n", pid);

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProcess) {
        printf("[-] Impossible d'ouvrir le processus\n");
        return;
    }

    HMODULE modules[1024];
    DWORD bytesNeeded;

    if (EnumProcessModules(hProcess, modules, sizeof(modules), &bytesNeeded)) {
        DWORD numModules = bytesNeeded / sizeof(HMODULE);

        printf("Nombre de modules: %lu\n\n", numModules);

        char moduleName[MAX_PATH];

        // Afficher les 10 premiers modules
        for (DWORD i = 0; i < 10 && i < numModules; i++) {
            if (GetModuleBaseNameA(hProcess, modules[i], moduleName, sizeof(moduleName))) {
                printf("  [%2lu] %s\n", i, moduleName);
            }
        }

        if (numModules > 10) {
            printf("  ... et %lu autres\n", numModules - 10);
        }
    } else {
        printf("[-] EnumProcessModules echoue: %lu\n", GetLastError());
    }

    CloseHandle(hProcess);
    printf("\n");
}

/*
 * BONNES PRATIQUES
 */
void show_best_practices() {
    printf("=== BONNES PRATIQUES ===\n\n");

    printf("1. TOUJOURS verifier le retour de OpenProcess\n");
    printf("2. Demander uniquement les droits necessaires\n");
    printf("3. TOUJOURS fermer les handles avec CloseHandle\n");
    printf("4. Gerer les erreurs d'acces (processus systeme)\n");
    printf("5. Utiliser PSAPI pour les informations detaillees\n");
    printf("6. Attention aux privileges (certains processus sont proteges)\n\n");
}

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      LESSON 02: PROCESS ENUMERATION - WINDOWS API        ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    enumerate_processes_basic();
    enumerate_processes_with_names();

    // Informations sur le processus actuel
    get_process_info(GetCurrentProcessId());

    demonstrate_find_process();
    count_process_instances("svchost.exe");
    demonstrate_process_access_rights();

    // Enumerer les modules du processus actuel
    enumerate_process_modules(GetCurrentProcessId());

    show_best_practices();

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║                    FIN DE LA LESSON                       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}

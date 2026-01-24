/*
 * SOLUTION EXERCICE 02: Process Lister
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

typedef struct {
    DWORD pid;
    char name[MAX_PATH];
    SIZE_T memoryKB;
} ProcessInfo;

int compare_by_name(const void* a, const void* b) {
    ProcessInfo* pa = (ProcessInfo*)a;
    ProcessInfo* pb = (ProcessInfo*)b;
    return _stricmp(pa->name, pb->name);
}

DWORD find_process_by_name(const char* targetName, DWORD* processes, DWORD numProcesses) {
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
                if (_stricmp(processName, targetName) == 0) {
                    CloseHandle(hProcess);
                    return processes[i];
                }
            }
            CloseHandle(hProcess);
        }
    }

    return 0;
}

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      SOLUTION 02: LISTER LES PROCESSUS ACTIFS            ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    DWORD processes[1024];
    DWORD bytesReturned;

    printf("[*] Enumeration des processus...\n");

    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        printf("[-] EnumProcesses echoue: %lu\n", GetLastError());
        return 1;
    }

    DWORD numProcesses = bytesReturned / sizeof(DWORD);
    printf("[+] %lu processus detectes\n\n", numProcesses);

    ProcessInfo* infos = (ProcessInfo*)malloc(numProcesses * sizeof(ProcessInfo));
    if (!infos) {
        printf("[-] Allocation memoire echouee\n");
        return 1;
    }

    int validCount = 0;
    int deniedCount = 0;

    for (DWORD i = 0; i < numProcesses; i++) {
        if (processes[i] == 0) continue;

        infos[validCount].pid = processes[i];
        infos[validCount].memoryKB = 0;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processes[i]
        );

        if (hProcess == NULL) {
            strcpy_s(infos[validCount].name, MAX_PATH, "[Access Denied]");
            deniedCount++;
            validCount++;
            continue;
        }

        if (!GetModuleBaseNameA(hProcess, NULL, infos[validCount].name, MAX_PATH)) {
            strcpy_s(infos[validCount].name, MAX_PATH, "[Unknown]");
        }

        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            infos[validCount].memoryKB = pmc.WorkingSetSize / 1024;
        }

        CloseHandle(hProcess);
        validCount++;
    }

    qsort(infos, validCount, sizeof(ProcessInfo), compare_by_name);

    printf("╔═══════╦═══════════════════════════╦══════════════╗\n");
    printf("║  PID  ║ NOM DU PROCESSUS          ║ MEMOIRE (KB) ║\n");
    printf("╠═══════╬═══════════════════════════╬══════════════╣\n");

    for (int i = 0; i < validCount; i++) {
        printf("║ %5lu ║ %-25s ║ %12lu ║\n",
            infos[i].pid,
            infos[i].name,
            infos[i].memoryKB
        );
    }

    printf("╚═══════╩═══════════════════════════╩══════════════╝\n\n");

    printf("Statistiques:\n");
    printf("  Total processus: %d\n", validCount);
    printf("  Acces refuse: %d\n", deniedCount);
    printf("  Accessibles: %d\n\n", validCount - deniedCount);

    printf("[*] Recherche de processus specifiques...\n");
    const char* targets[] = {"explorer.exe", "svchost.exe", "chrome.exe"};

    for (int i = 0; i < 3; i++) {
        DWORD pid = find_process_by_name(targets[i], processes, numProcesses);
        if (pid) {
            printf("  [+] %s trouve (PID: %lu)\n", targets[i], pid);
        } else {
            printf("  [-] %s non trouve\n", targets[i]);
        }
    }

    free(infos);

    printf("\n[*] Programme termine\n");
    return 0;
}

/*
 * EXPLICATIONS:
 *
 * 1. EnumProcesses:
 *    - Remplit un tableau avec tous les PIDs
 *    - bytesReturned indique combien d'octets ont ete ecrits
 *    - Diviser par sizeof(DWORD) donne le nombre de processus
 *
 * 2. OpenProcess:
 *    - PROCESS_QUERY_INFORMATION: infos basiques
 *    - PROCESS_VM_READ: lecture memoire (pour le nom)
 *    - Peut echouer si privileges insuffisants
 *
 * 3. GetModuleBaseName:
 *    - Obtient le nom du fichier executable
 *    - NULL = module principal du processus
 *
 * 4. Gestion erreurs:
 *    - Certains processus systeme sont proteges
 *    - Marquer comme "[Access Denied]"
 *
 * BONUS IMPLEMENTES:
 * - Tri par nom avec qsort
 * - Affichage memoire avec GetProcessMemoryInfo
 * - Recherche par nom avec fonction dediee
 * - Statistiques detaillees
 */

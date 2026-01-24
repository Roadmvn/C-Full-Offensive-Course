/*
 * EXERCICE 02: Process Lister
 *
 * OBJECTIF:
 * Creer un programme qui liste tous les processus en cours d'execution
 * avec leurs noms et PIDs.
 *
 * TACHES:
 * 1. Utiliser EnumProcesses pour obtenir tous les PIDs
 * 2. Pour chaque PID, ouvrir le processus avec OpenProcess
 * 3. Obtenir le nom du processus avec GetModuleBaseName
 * 4. Afficher le PID et le nom dans un tableau formate
 * 5. Compter le nombre total de processus
 * 6. Gerer les processus inaccessibles (systeme, privileges)
 *
 * BONUS:
 * - Trier les processus par nom
 * - Afficher l'utilisation memoire de chaque processus
 * - Chercher un processus specifique par nom
 * - Compter le nombre d'instances de chaque processus
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║        EXERCICE 02: LISTER LES PROCESSUS ACTIFS          ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    // TODO: Declarer un tableau pour stocker les PIDs


    // TODO: Appeler EnumProcesses pour remplir le tableau


    // TODO: Calculer le nombre de processus


    // TODO: Afficher un en-tete de tableau


    // TODO: Boucle sur chaque PID
    //   - Ouvrir le processus avec OpenProcess
    //   - Obtenir le nom avec GetModuleBaseName
    //   - Afficher PID et nom
    //   - Fermer le handle


    // TODO: Afficher le nombre total de processus


    printf("\n[*] Programme termine\n");
    return 0;
}

/*
 * CONSEILS:
 *
 * 1. Enumerer:
 *    DWORD processes[1024];
 *    DWORD bytesReturned;
 *    EnumProcesses(processes, sizeof(processes), &bytesReturned);
 *
 * 2. Compter:
 *    DWORD numProcesses = bytesReturned / sizeof(DWORD);
 *
 * 3. Ouvrir processus:
 *    HANDLE hProcess = OpenProcess(
 *        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
 *        FALSE,
 *        pid
 *    );
 *
 * 4. Nom:
 *    char processName[MAX_PATH];
 *    GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH);
 *
 * 5. Gestion erreurs:
 *    if (hProcess == NULL) {
 *        // Processus inaccessible
 *        strcpy(processName, "[Access Denied]");
 *    }
 */

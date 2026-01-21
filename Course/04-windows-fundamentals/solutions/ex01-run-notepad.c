/*
 * SOLUTION EXERCICE 01: Launch Notepad
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║           SOLUTION 01: LANCER NOTEPAD.EXE                ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};

    si.cb = sizeof(si);

    char cmdline[] = "notepad.exe";

    printf("[*] Lancement de notepad.exe...\n");

    BOOL success = CreateProcessA(
        NULL,
        cmdline,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        printf("[-] Echec de CreateProcess: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Notepad lance avec succes!\n\n");
    printf("Informations du processus:\n");
    printf("  Process ID (PID): %lu\n", pi.dwProcessId);
    printf("  Thread ID (TID): %lu\n", pi.dwThreadId);
    printf("  Handle processus: 0x%p\n", pi.hProcess);
    printf("  Handle thread: 0x%p\n\n", pi.hThread);

    printf("[*] Ferme notepad pour continuer...\n");

    DWORD startTime = GetTickCount();

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD endTime = GetTickCount();
    DWORD elapsedTime = endTime - startTime;

    printf("\n[+] Notepad ferme!\n");

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    printf("\nResultats:\n");
    printf("  Code de sortie: %lu\n", exitCode);
    printf("  Temps d'execution: %lu ms (%.2f secondes)\n",
        elapsedTime, elapsedTime / 1000.0);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("\n[*] Handles fermes proprement\n");
    printf("[*] Programme termine\n");

    return 0;
}

/*
 * EXPLICATIONS:
 *
 * 1. Structures:
 *    - STARTUPINFO: Configuration du demarrage
 *    - PROCESS_INFORMATION: Informations retournees
 *
 * 2. Initialisation:
 *    {0} initialise toute la structure a zero
 *    si.cb DOIT etre defini pour que Windows sache la taille
 *
 * 3. CreateProcess:
 *    - Retourne TRUE si succes, FALSE sinon
 *    - Remplit pi avec les infos du processus cree
 *
 * 4. WaitForSingleObject:
 *    - Bloque jusqu'a ce que le processus se termine
 *    - INFINITE = attente illimitee
 *
 * 5. CloseHandle:
 *    - CRITIQUE: libere les ressources kernel
 *    - Oublier = fuite de handles
 *
 * BONUS IMPLEMENTES:
 * - Gestion erreur avec GetLastError
 * - Mesure du temps d'execution
 * - Affichage detaille des informations
 */

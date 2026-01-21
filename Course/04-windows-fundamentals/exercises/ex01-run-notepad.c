/*
 * EXERCICE 01: Launch Notepad
 *
 * OBJECTIF:
 * Utiliser CreateProcess pour lancer notepad.exe et afficher
 * des informations sur le processus cree.
 *
 * TACHES:
 * 1. Lancer notepad.exe avec CreateProcess
 * 2. Afficher le PID du processus cree
 * 3. Afficher les handles de processus et thread
 * 4. Attendre que l'utilisateur ferme notepad
 * 5. Recuperer et afficher le code de sortie
 * 6. Fermer proprement les handles
 *
 * BONUS:
 * - Lancer notepad avec un fichier specifique en argument
 * - Gerer les erreurs si notepad ne peut pas etre lance
 * - Afficher le temps d'execution total
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║           EXERCICE 01: LANCER NOTEPAD.EXE                ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    // TODO: Declarer les structures STARTUPINFO et PROCESS_INFORMATION


    // TODO: Initialiser STARTUPINFO


    // TODO: Creer la commande pour lancer notepad.exe


    // TODO: Appeler CreateProcess pour lancer notepad


    // TODO: Afficher les informations du processus cree (PID, TID, Handles)


    // TODO: Attendre que le processus se termine (fermeture de notepad)


    // TODO: Recuperer le code de sortie du processus


    // TODO: Fermer les handles


    printf("\n[*] Programme termine\n");
    return 0;
}

/*
 * CONSEILS:
 *
 * 1. Structure STARTUPINFO:
 *    STARTUPINFOA si = {0};
 *    si.cb = sizeof(si);
 *
 * 2. CreateProcess:
 *    BOOL success = CreateProcessA(
 *        NULL,              // lpApplicationName
 *        "notepad.exe",     // lpCommandLine
 *        NULL, NULL,        // Security
 *        FALSE,             // bInheritHandles
 *        0,                 // dwCreationFlags
 *        NULL, NULL,        // Environment, Directory
 *        &si,               // lpStartupInfo
 *        &pi                // lpProcessInformation
 *    );
 *
 * 3. Attendre:
 *    WaitForSingleObject(pi.hProcess, INFINITE);
 *
 * 4. Code de sortie:
 *    DWORD exitCode;
 *    GetExitCodeProcess(pi.hProcess, &exitCode);
 *
 * 5. Fermer:
 *    CloseHandle(pi.hProcess);
 *    CloseHandle(pi.hThread);
 */

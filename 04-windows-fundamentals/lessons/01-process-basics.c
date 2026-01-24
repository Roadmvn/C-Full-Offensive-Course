/*
 * LESSON 01: Process Basics
 *
 * OBJECTIFS:
 * - Comprendre ce qu'est un processus Windows
 * - Utiliser CreateProcess pour lancer des programmes
 * - Gerer les handles de processus
 * - Executer des commandes systeme
 *
 * CONCEPTS CLES:
 * - PROCESS_INFORMATION: Structure contenant les handles du processus cree
 * - STARTUPINFO: Configuration du processus a lancer
 * - Handles: References aux objets kernel (processus, threads)
 * - CloseHandle: Liberation des ressources kernel
 */

#include <windows.h>
#include <stdio.h>

/*
 * QU'EST-CE QU'UN PROCESSUS ?
 *
 * Un processus est une instance d'un programme en execution.
 * Sous Windows, chaque processus possede:
 * - Un espace d'adressage virtuel (memoire isolee)
 * - Un identifiant unique (PID - Process ID)
 * - Au moins un thread d'execution
 * - Des handles vers des ressources (fichiers, registre, etc.)
 * - Un token de securite (privileges, droits)
 */

void demonstrate_process_concept() {
    printf("=== CONCEPT DE PROCESSUS ===\n\n");

    printf("Processus actuel:\n");
    printf("  PID: %lu\n", GetCurrentProcessId());
    printf("  Thread ID: %lu\n", GetCurrentThreadId());

    // Obtenir le nom du fichier executable
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    printf("  Executable: %s\n\n", exePath);
}

/*
 * CREER UN PROCESSUS SIMPLE
 *
 * CreateProcess est la fonction Windows pour lancer un programme.
 * Elle est plus puissante que system() du C standard.
 */
void create_simple_process() {
    printf("=== CREATION DE PROCESSUS SIMPLE ===\n\n");

    // Structures necessaires
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};

    si.cb = sizeof(si);  // Taille de la structure (OBLIGATOIRE)

    // Commande a executer
    char cmdline[] = "notepad.exe";

    printf("[*] Lancement de notepad.exe...\n");

    // CreateProcess necessite un buffer modifiable pour lpCommandLine
    BOOL success = CreateProcessA(
        NULL,           // lpApplicationName (NULL = utilise lpCommandLine)
        cmdline,        // lpCommandLine (commande a executer)
        NULL,           // lpProcessAttributes (securite par defaut)
        NULL,           // lpThreadAttributes (securite par defaut)
        FALSE,          // bInheritHandles (pas d'heritage de handles)
        0,              // dwCreationFlags (flags de creation)
        NULL,           // lpEnvironment (environnement herite)
        NULL,           // lpCurrentDirectory (repertoire courant herite)
        &si,            // lpStartupInfo (configuration de demarrage)
        &pi             // lpProcessInformation (infos retournees)
    );

    if (success) {
        printf("[+] Processus cree avec succes!\n");
        printf("    PID: %lu\n", pi.dwProcessId);
        printf("    Thread ID: %lu\n", pi.dwThreadId);
        printf("    Handle processus: 0x%p\n", pi.hProcess);
        printf("    Handle thread: 0x%p\n\n", pi.hThread);

        // IMPORTANT: Toujours fermer les handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        printf("[*] Notepad lance en arriere-plan\n\n");
    } else {
        printf("[-] Echec CreateProcess: %lu\n\n", GetLastError());
    }
}

/*
 * ATTENDRE LA FIN D'UN PROCESSUS
 *
 * WaitForSingleObject permet d'attendre qu'un processus se termine.
 */
void create_and_wait_process() {
    printf("=== CREATION ET ATTENTE DE PROCESSUS ===\n\n");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Lancer la calculatrice
    char cmdline[] = "calc.exe";

    printf("[*] Lancement de calc.exe...\n");
    printf("[*] Ferme la calculatrice pour continuer\n\n");

    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[+] Processus cree (PID: %lu)\n", pi.dwProcessId);
        printf("[*] En attente de la fin du processus...\n");

        // Attendre que le processus se termine
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Obtenir le code de retour
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        printf("[+] Processus termine avec code: %lu\n\n", exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] Echec: %lu\n\n", GetLastError());
    }
}

/*
 * EXECUTER UNE COMMANDE AVEC ARGUMENTS
 *
 * Lancer un programme avec des arguments en ligne de commande.
 */
void execute_command_with_args() {
    printf("=== EXECUTION AVEC ARGUMENTS ===\n\n");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Commande: ping avec arguments
    char cmdline[] = "cmd.exe /C ping 127.0.0.1 -n 3";

    printf("[*] Execution: %s\n\n", cmdline);

    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW,  // Pas de fenetre console
                       NULL, NULL, &si, &pi)) {

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        printf("[+] Commande terminee (code: %lu)\n\n", exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] Echec: %lu\n\n", GetLastError());
    }
}

/*
 * CREATION FLAGS - OPTIONS DE LANCEMENT
 *
 * Les flags de creation modifient le comportement du processus.
 */
void demonstrate_creation_flags() {
    printf("=== CREATION FLAGS ===\n\n");

    printf("Flags courants:\n");
    printf("  CREATE_NO_WINDOW (0x%08X)     - Pas de console\n", CREATE_NO_WINDOW);
    printf("  CREATE_NEW_CONSOLE (0x%08X)   - Nouvelle console\n", CREATE_NEW_CONSOLE);
    printf("  CREATE_SUSPENDED (0x%08X)     - Demarre suspendu\n", CREATE_SUSPENDED);
    printf("  DETACHED_PROCESS (0x%08X)     - Sans console parent\n", DETACHED_PROCESS);

    printf("\n[*] Exemple: Processus suspendu\n");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    char cmdline[] = "notepad.exe";

    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_SUSPENDED,  // Demarre suspendu
                       NULL, NULL, &si, &pi)) {

        printf("[+] Processus cree en mode SUSPENDU (PID: %lu)\n", pi.dwProcessId);
        printf("[*] Le processus ne s'execute pas encore...\n");
        printf("[*] Appuie sur Entree pour le demarrer\n");
        getchar();

        // Reprendre l'execution
        ResumeThread(pi.hThread);
        printf("[+] Processus demarre!\n\n");

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/*
 * STARTUPINFO - CONFIGURATION DU DEMARRAGE
 *
 * La structure STARTUPINFO controle l'apparence et le comportement initial.
 */
void demonstrate_startupinfo() {
    printf("=== CONFIGURATION STARTUPINFO ===\n\n");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Configurer la fenetre
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_MAXIMIZE;  // Fenetre maximisee

    char cmdline[] = "notepad.exe";

    printf("[*] Lancement de notepad en mode MAXIMISE\n");

    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[+] Notepad lance en plein ecran\n\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/*
 * GESTION DES ERREURS
 *
 * Toujours verifier les codes d'erreur avec GetLastError().
 */
void demonstrate_error_handling() {
    printf("=== GESTION DES ERREURS ===\n\n");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Tenter de lancer un programme inexistant
    char cmdline[] = "programme_inexistant.exe";

    printf("[*] Tentative de lancement d'un programme inexistant...\n");

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DWORD error = GetLastError();
        printf("[-] Echec de CreateProcess\n");
        printf("    Code erreur: %lu\n", error);

        // Afficher le message d'erreur Windows
        char* errorMsg = NULL;
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            error,
            0,
            (LPSTR)&errorMsg,
            0,
            NULL
        );

        if (errorMsg) {
            printf("    Message: %s\n", errorMsg);
            LocalFree(errorMsg);
        }
    }
}

/*
 * BONNES PRATIQUES
 */
void show_best_practices() {
    printf("\n=== BONNES PRATIQUES ===\n\n");

    printf("1. TOUJOURS initialiser STARTUPINFO avec {0}\n");
    printf("2. TOUJOURS definir si.cb = sizeof(si)\n");
    printf("3. TOUJOURS fermer les handles avec CloseHandle()\n");
    printf("4. TOUJOURS verifier le retour de CreateProcess\n");
    printf("5. Utiliser un buffer modifiable pour lpCommandLine\n");
    printf("6. Gerer les erreurs avec GetLastError()\n\n");
}

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         LESSON 01: PROCESS BASICS - WINDOWS API          ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    demonstrate_process_concept();
    create_simple_process();

    printf("[*] Appuie sur Entree pour continuer avec attente...\n");
    getchar();

    create_and_wait_process();
    execute_command_with_args();
    demonstrate_creation_flags();
    demonstrate_startupinfo();
    demonstrate_error_handling();
    show_best_practices();

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║                    FIN DE LA LESSON                       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}

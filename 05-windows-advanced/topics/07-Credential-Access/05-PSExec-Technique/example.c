/*
 * OBJECTIF  : Comprendre la technique PsExec : creation de service distant, execution
 * PREREQUIS : Services Windows, SMB, Named Pipes, SCM API
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib mpr.lib
 *
 * PsExec est un outil Sysinternals qui permet l'execution a distance.
 * Son fonctionnement interne :
 * 1. Copier un executable sur le partage ADMIN$ de la cible
 * 2. Se connecter au Service Control Manager (SCM) distant
 * 3. Creer un service pointant vers l'executable copie
 * 4. Demarrer le service (execute le code)
 * 5. Recuperer la sortie via un named pipe
 * 6. Nettoyer (arreter le service, supprimer le fichier)
 *
 * Ce module demontre chaque etape localement.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/* Demo 1 : Etapes du PsExec expliquees */
void demo_psexec_flow(void) {
    printf("[1] Architecture interne de PsExec\n\n");

    printf("    Attaquant                           Cible\n");
    printf("    ---------                           -----\n");
    printf("    1. SMB Connect (port 445)    ->     \\\\CIBLE\\ADMIN$\n");
    printf("    2. Copier PSEXESVC.exe       ->     C:\\Windows\\PSEXESVC.exe\n");
    printf("    3. OpenSCManager (RPC)       ->     Service Control Manager\n");
    printf("    4. CreateService             ->     Service 'PSEXESVC'\n");
    printf("    5. StartService              ->     PSEXESVC.exe demarre\n");
    printf("    6. Named Pipe                <->    \\\\CIBLE\\pipe\\PSEXESVC\n");
    printf("       (stdin/stdout/stderr)             (communication bidirectionnelle)\n");
    printf("    7. DeleteService + cleanup\n\n");

    printf("    Prerequis :\n");
    printf("    - Credentials admin sur la cible\n");
    printf("    - Port 445 (SMB) ouvert\n");
    printf("    - Service ADMIN$ accessible\n");
    printf("    - SCM accessible via RPC\n\n");
}

/* Demo 2 : Interagir avec le SCM local */
void demo_scm_local(void) {
    printf("[2] Service Control Manager - Operations locales\n\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        printf("    [-] OpenSCManager echoue (err %lu)\n\n", GetLastError());
        return;
    }
    printf("    [+] SCM ouvert (local)\n");

    /* Enumerer quelques services */
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusA(scm, SERVICE_WIN32, SERVICE_ACTIVE,
                         NULL, 0, &needed, &count, &resume);

    ENUM_SERVICE_STATUSA* services = (ENUM_SERVICE_STATUSA*)malloc(needed);
    if (EnumServicesStatusA(scm, SERVICE_WIN32, SERVICE_ACTIVE,
                             services, needed, &needed, &count, &resume)) {
        printf("    [+] %lu services actifs. Exemples :\n", count);
        for (DWORD i = 0; i < count && i < 5; i++) {
            printf("        - %s (%s)\n",
                   services[i].lpServiceName, services[i].lpDisplayName);
        }
        if (count > 5) printf("        ... (%lu de plus)\n", count - 5);
    }
    free(services);

    CloseServiceHandle(scm);
    printf("\n");
}

/* Demo 3 : Creer et supprimer un service (local, safe) */
void demo_service_lifecycle(void) {
    printf("[3] Cycle de vie d'un service (demo locale)\n\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("    [-] OpenSCManager echoue (err %lu)\n", GetLastError());
        printf("    [*] Necessite des droits administrateur\n\n");
        return;
    }

    /* Creer un service demo (cmd /c echo) - non persistant */
    const char* svc_name = "DemoPsExecSvc";
    const char* bin_path = "cmd.exe /c echo PsExec_Demo";

    printf("    [Etape 1] CreateService(\"%s\")\n", svc_name);
    SC_HANDLE svc = CreateServiceA(
        scm, svc_name, "Demo PsExec Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,       /* Demarrage manuel */
        SERVICE_ERROR_NORMAL,
        bin_path,
        NULL, NULL, NULL, NULL, NULL);

    if (svc) {
        printf("    [+] Service cree : %s\n", svc_name);
        printf("    [+] BinPath : %s\n", bin_path);

        /* En reel, on demarrerait le service ici */
        printf("    [Etape 2] En reel : StartService() executerait la commande\n");
        printf("    [*] On ne demarre PAS le service dans cette demo\n");

        /* Supprimer le service */
        printf("    [Etape 3] DeleteService()\n");
        if (DeleteService(svc)) {
            printf("    [+] Service supprime\n");
        }
        CloseServiceHandle(svc);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            printf("    [*] Service existe deja, suppression...\n");
            svc = OpenServiceA(scm, svc_name, DELETE);
            if (svc) {
                DeleteService(svc);
                CloseServiceHandle(svc);
            }
        } else {
            printf("    [-] CreateService echoue (err %lu)\n", err);
        }
    }

    CloseServiceHandle(scm);
    printf("\n");
}

/* Demo 4 : Communication via named pipe (simulation output retrieval) */
void demo_named_pipe_output(void) {
    printf("[4] Recuperation de sortie via Named Pipe\n\n");

    const char* pipe_name = "\\\\.\\pipe\\PsExecDemoPipe";

    /* Creer le pipe serveur */
    HANDLE hPipe = CreateNamedPipeA(pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
        1, 4096, 4096, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("    [-] CreateNamedPipe echoue\n\n");
        return;
    }
    printf("    [+] Pipe cree : %s\n", pipe_name);

    /* Simuler le client (le service distant ecrirait dans le pipe) */
    HANDLE hClient = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                                  0, NULL, OPEN_EXISTING, 0, NULL);
    if (hClient != INVALID_HANDLE_VALUE) {
        /* Le "service" envoie la sortie de sa commande */
        const char* output = "C:\\Windows>whoami\r\nnt authority\\system\r\n";
        DWORD written;
        WriteFile(hClient, output, (DWORD)strlen(output), &written, NULL);
        printf("    [+] Service -> Pipe : %lu octets\n", written);

        /* Le client PsExec lit la sortie */
        ConnectNamedPipe(hPipe, NULL);
        char buffer[4096] = {0};
        DWORD bytesRead;
        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            printf("    [+] Pipe -> Client : \"%s\"\n", buffer);
        }

        CloseHandle(hClient);
    }

    CloseHandle(hPipe);
    printf("\n");
}

/* Demo 5 : Variantes de PsExec */
void demo_variants(void) {
    printf("[5] Variantes de la technique PsExec\n\n");

    printf("    A) PsExec classique (Sysinternals) :\n");
    printf("       - Copie PSEXESVC.exe -> ADMIN$\n");
    printf("       - Tres detecte (signature connue)\n\n");

    printf("    B) sc.exe (natif Windows) :\n");
    printf("       sc \\\\CIBLE create svc binPath= \"cmd /c whoami\"\n");
    printf("       sc \\\\CIBLE start svc\n");
    printf("       - Pas de copie de fichier\n");
    printf("       - Mais pas de recuperation de sortie\n\n");

    printf("    C) smbexec (Impacket) :\n");
    printf("       - Service qui execute via cmd.exe\n");
    printf("       - Sortie redirigee vers un fichier sur le share\n");
    printf("       - Moins de traces qu'un PsExec complet\n\n");

    printf("    D) WMI :\n");
    printf("       - Win32_Process.Create(\"cmd.exe /c ...\")\n");
    printf("       - Pas de service cree\n");
    printf("       - Mais parent process = WmiPrvSE.exe (detectable)\n\n");

    printf("    E) WinRM :\n");
    printf("       - Invoke-Command -ComputerName CIBLE -ScriptBlock {...}\n");
    printf("       - Port 5985/5986 (HTTP/HTTPS)\n");
    printf("       - Necessite WinRM active sur la cible\n\n");
}

/* Demo 6 : Detection */
void demo_detection(void) {
    printf("[6] Detection de la technique PsExec\n\n");

    printf("    Indicateurs reseau :\n");
    printf("    - SMB (445) : ecriture dans ADMIN$\n");
    printf("    - RPC (135+) : connexion au SCM\n");
    printf("    - Named pipe : PSEXESVC (nom par defaut)\n\n");

    printf("    Indicateurs hote :\n");
    printf("    - Event ID 7045 : nouveau service installe\n");
    printf("    - Event ID 4697 : service installe (Security log)\n");
    printf("    - Sysmon Event ID 11 : fichier cree dans C:\\Windows\n");
    printf("    - Sysmon Event ID 13 : cle de registre service creee\n");
    printf("    - Sysmon Event ID 17/18 : pipe cree/connecte\n\n");

    printf("    Contre-mesures :\n");
    printf("    - Bloquer ADMIN$/C$ pour les non-admins\n");
    printf("    - Monitorer la creation de services\n");
    printf("    - LAPS + admin tiering\n");
    printf("    - Firewall : restreindre SMB entre postes\n\n");
}

int main(void) {
    printf("[*] Demo : PsExec Technique - Execution de service distant\n");
    printf("[*] ==========================================\n\n");

    demo_psexec_flow();
    demo_scm_local();
    demo_service_lifecycle();
    demo_named_pipe_output();
    demo_variants();
    demo_detection();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

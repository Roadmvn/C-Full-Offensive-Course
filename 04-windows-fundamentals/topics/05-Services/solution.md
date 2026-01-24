# Module W06 : Services Windows - Solutions

## Solution Exercice 1 : Énumération des services

**Objectif** : Lister tous les services Windows et leur état

```c
#include <windows.h>
#include <stdio.h>

const char* GetServiceState(DWORD state) {
    switch(state) {
        case SERVICE_STOPPED: return "STOPPED";
        case SERVICE_RUNNING: return "RUNNING";
        case SERVICE_PAUSED: return "PAUSED";
        case SERVICE_START_PENDING: return "STARTING";
        case SERVICE_STOP_PENDING: return "STOPPING";
        case SERVICE_CONTINUE_PENDING: return "CONTINUING";
        case SERVICE_PAUSE_PENDING: return "PAUSING";
        default: return "UNKNOWN";
    }
}

int main() {
    printf("[*] === Exercice 1 : Enumeration des services ===\n\n");

    // 1. Ouvrir le SCM
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        printf("[-] OpenSCManager echoue: %lu\n", GetLastError());
        printf("[-] Privileges administrateur probablement necessaires\n");
        return 1;
    }

    printf("[+] Connexion au SCM reussie\n\n");

    // 2. Obtenir la taille nécessaire
    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;

    EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
                          &servicesReturned, &resumeHandle, NULL);

    // 3. Allouer le buffer
    BYTE *buffer = (BYTE*)malloc(bytesNeeded);
    if (!buffer) {
        printf("[-] Allocation memoire echouee\n");
        CloseServiceHandle(hSCManager);
        return 1;
    }

    // 4. Énumérer les services
    if (EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                              SERVICE_STATE_ALL, buffer, bytesNeeded, &bytesNeeded,
                              &servicesReturned, &resumeHandle, NULL)) {

        ENUM_SERVICE_STATUS_PROCESSA *services = (ENUM_SERVICE_STATUS_PROCESSA*)buffer;

        printf("[+] %lu services trouves\n\n", servicesReturned);
        printf("%-35s %-15s %-8s %s\n", "Nom", "Etat", "PID", "Affichage");
        printf("--------------------------------------------------------------------------------\n");

        for (DWORD i = 0; i < servicesReturned; i++) {
            printf("%-35s %-15s %-8lu %s\n",
                   services[i].lpServiceName,
                   GetServiceState(services[i].ServiceStatusProcess.dwCurrentState),
                   services[i].ServiceStatusProcess.dwProcessId,
                   services[i].lpDisplayName);
        }
    } else {
        printf("[-] EnumServicesStatusEx echoue: %lu\n", GetLastError());
    }

    free(buffer);
    CloseServiceHandle(hSCManager);

    return 0;
}
```

**Explications** :
- `OpenSCManagerA` : connexion au Service Control Manager
- `EnumServicesStatusExA` : énumère tous les services
- Premier appel avec buffer NULL pour obtenir la taille nécessaire
- Deuxième appel avec le buffer alloué pour récupérer les données

---

## Solution Exercice 2 : Interroger un service spécifique

**Objectif** : Obtenir les détails d'un service par son nom

```c
#include <windows.h>
#include <stdio.h>

void QueryServiceDetails(const char *serviceName) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        printf("[-] OpenSCManager echoue: %lu\n", GetLastError());
        return;
    }

    // Ouvrir le service
    SC_HANDLE hService = OpenServiceA(
        hSCManager,
        serviceName,
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG
    );

    if (!hService) {
        printf("[-] Service '%s' introuvable: %lu\n", serviceName, GetLastError());
        CloseServiceHandle(hSCManager);
        return;
    }

    printf("[+] Service: %s\n\n", serviceName);

    // 1. Interroger le statut
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                             (BYTE*)&ssp, sizeof(ssp), &bytesNeeded)) {
        printf("Statut:\n");
        printf("  Etat       : %s\n", GetServiceState(ssp.dwCurrentState));
        printf("  PID        : %lu\n", ssp.dwProcessId);
        printf("  Type       : 0x%lx\n", ssp.dwServiceType);
        printf("  Controles  : 0x%lx\n", ssp.dwControlsAccepted);
    }

    // 2. Interroger la configuration
    DWORD configSize = 0;
    QueryServiceConfigA(hService, NULL, 0, &configSize);

    QUERY_SERVICE_CONFIGA *config = (QUERY_SERVICE_CONFIGA*)malloc(configSize);
    if (config) {
        if (QueryServiceConfigA(hService, config, configSize, &bytesNeeded)) {
            printf("\nConfiguration:\n");
            printf("  Type demarrage : ");
            switch(config->dwStartType) {
                case SERVICE_AUTO_START: printf("Automatique\n"); break;
                case SERVICE_DEMAND_START: printf("Manuel\n"); break;
                case SERVICE_DISABLED: printf("Desactive\n"); break;
                case SERVICE_BOOT_START: printf("Boot\n"); break;
                case SERVICE_SYSTEM_START: printf("Systeme\n"); break;
            }
            printf("  Chemin binaire : %s\n", config->lpBinaryPathName);
            if (config->lpServiceStartName) {
                printf("  Compte         : %s\n", config->lpServiceStartName);
            }
        }
        free(config);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}

int main(int argc, char *argv[]) {
    printf("[*] === Exercice 2 : Interrogation de service ===\n\n");

    const char *serviceName = (argc > 1) ? argv[1] : "Spooler";
    QueryServiceDetails(serviceName);

    return 0;
}
```

**Explications** :
- `OpenServiceA` : ouvre un handle vers un service spécifique
- `QueryServiceStatusEx` : obtient l'état actuel du service
- `QueryServiceConfigA` : obtient la configuration (chemin binaire, type de démarrage, compte)

---

## Solution Exercice 3 : Créer un service simple

**Objectif** : Installer un nouveau service Windows

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <nom_service> <chemin_executable>\n", argv[0]);
        printf("Exemple: %s TestService C:\\Tools\\service.exe\n", argv[0]);
        return 1;
    }

    const char *serviceName = argv[1];
    const char *binaryPath = argv[2];

    printf("[*] === Exercice 3 : Creation de service ===\n\n");

    // 1. Ouvrir le SCM avec droits de création
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        printf("[-] OpenSCManager echoue: %lu\n", GetLastError());
        printf("[-] Privileges administrateur necessaires\n");
        return 1;
    }

    printf("[+] SCM ouvert avec droits de creation\n");

    // 2. Créer le service
    SC_HANDLE hService = CreateServiceA(
        hSCManager,
        serviceName,              // Nom du service
        serviceName,              // Nom d'affichage
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,     // Demarrage manuel
        SERVICE_ERROR_NORMAL,
        binaryPath,               // Chemin de l'executable
        NULL,                     // Load order group
        NULL,                     // Tag ID
        NULL,                     // Dependencies
        NULL,                     // Service start name (LocalSystem)
        NULL                      // Password
    );

    if (!hService) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            printf("[-] Le service existe deja\n");
        } else {
            printf("[-] CreateService echoue: %lu\n", error);
        }
        CloseServiceHandle(hSCManager);
        return 1;
    }

    printf("[+] Service '%s' cree avec succes!\n", serviceName);
    printf("[+] Chemin binaire: %s\n", binaryPath);
    printf("[+] Type demarrage: DEMAND_START (manuel)\n");
    printf("[+] Compte: LocalSystem\n");

    // 3. Ajouter une description
    SERVICE_DESCRIPTIONA desc;
    desc.lpDescription = "Service de test cree depuis C";
    if (ChangeServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, &desc)) {
        printf("[+] Description ajoutee\n");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    printf("\n[*] Pour demarrer le service:\n");
    printf("    sc start %s\n", serviceName);
    printf("[*] Pour supprimer le service:\n");
    printf("    sc delete %s\n", serviceName);

    return 0;
}
```

**Explications** :
- `CreateServiceA` : installe un nouveau service
- `SERVICE_WIN32_OWN_PROCESS` : le service s'exécute dans son propre processus
- `SERVICE_DEMAND_START` : démarrage manuel (pas automatique au boot)
- `ChangeServiceConfig2A` : modifie des paramètres supplémentaires comme la description

---

## Solution Exercice 4 : Contrôler un service (Start/Stop)

**Objectif** : Démarrer et arrêter un service

```c
#include <windows.h>
#include <stdio.h>

BOOL StartMyService(const char *serviceName) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return FALSE;

    SC_HANDLE hService = OpenServiceA(hSCManager, serviceName, SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    BOOL result = StartServiceA(hService, 0, NULL);
    DWORD error = GetLastError();

    if (!result && error != ERROR_SERVICE_ALREADY_RUNNING) {
        printf("[-] Echec demarrage: %lu\n", error);
    } else {
        printf("[+] Service demarre ou deja en cours d'execution\n");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return result || (error == ERROR_SERVICE_ALREADY_RUNNING);
}

BOOL StopMyService(const char *serviceName) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return FALSE;

    SC_HANDLE hService = OpenServiceA(hSCManager, serviceName, SERVICE_STOP);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    SERVICE_STATUS ss;
    BOOL result = ControlService(hService, SERVICE_CONTROL_STOP, &ss);

    if (!result) {
        printf("[-] Echec arret: %lu\n", GetLastError());
    } else {
        printf("[+] Service arrete\n");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return result;
}

BOOL DeleteMyService(const char *serviceName) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return FALSE;

    SC_HANDLE hService = OpenServiceA(hSCManager, serviceName, DELETE);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    BOOL result = DeleteService(hService);

    if (!result) {
        printf("[-] Echec suppression: %lu\n", GetLastError());
    } else {
        printf("[+] Service supprime\n");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <start|stop|delete> <nom_service>\n", argv[0]);
        return 1;
    }

    const char *action = argv[1];
    const char *serviceName = argv[2];

    printf("[*] === Exercice 4 : Controle de service ===\n\n");
    printf("[*] Action: %s\n", action);
    printf("[*] Service: %s\n\n", serviceName);

    if (_stricmp(action, "start") == 0) {
        StartMyService(serviceName);
    } else if (_stricmp(action, "stop") == 0) {
        StopMyService(serviceName);
    } else if (_stricmp(action, "delete") == 0) {
        StopMyService(serviceName);  // Arreter avant de supprimer
        Sleep(1000);
        DeleteMyService(serviceName);
    } else {
        printf("[-] Action invalide. Utilisez: start, stop ou delete\n");
    }

    return 0;
}
```

**Explications** :
- `StartServiceA` : démarre un service
- `ControlService` avec `SERVICE_CONTROL_STOP` : arrête un service
- `DeleteService` : supprime le service (doit être arrêté d'abord)
- Gestion des erreurs pour détecter si le service est déjà démarré/arrêté

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Énumérer les services avec EnumServicesStatusEx
- [x] Interroger un service spécifique (statut, configuration)
- [x] Créer un service avec CreateService
- [x] Contrôler un service (démarrer, arrêter, supprimer)
- [x] Comprendre les implications offensives (persistence, élévation de privilèges)
- [x] Identifier les considérations OPSEC (détection Event ID 7045, noms légitimes)

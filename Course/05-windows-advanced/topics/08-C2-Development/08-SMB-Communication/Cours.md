# Cours : SMB Communication pour C2

## Objectifs pedagogiques

A la fin de ce module, vous serez capable de :
- [ ] Comprendre les Named Pipes Windows et leur utilisation en C2
- [ ] Implementer un client/serveur SMB pour communication laterale
- [ ] Utiliser SMB comme canal C2 pour eviter la detection reseau
- [ ] Appliquer ces techniques dans un contexte Red Team

## Prerequis

Avant de commencer ce module, assurez-vous de maitriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Les concepts de fichiers et I/O Windows
- Les bases de la communication reseau
- Module W45 (HTTP Client) pour comparaison

## Introduction

**SMB** (Server Message Block) est un protocole de partage de fichiers Windows. Les **Named Pipes** sont des mecanismes IPC (Inter-Process Communication) qui utilisent SMB.

### Pourquoi ce sujet est important ?

En Red Team, SMB Named Pipes permettent :
1. **Communication laterale** : Controle d'agents via le reseau local
2. **Evasion** : Trafic SMB legitime, difficile a detecter
3. **Pivot** : Agent parent/enfant sans HTTP externe
4. **Persistence** : Connexions locales meme si firewall bloque HTTP

**Analogie** : Imaginez une entreprise avec des bureaux connectes. Au lieu d'appeler l'exterieur (HTTP), vous utilisez le telephone interne (SMB) - plus discret !

```ascii
ARCHITECTURE SMB C2 :

INTERNET               RESEAU INTERNE

C2 Server         Named Pipe Server       Named Pipe Client
┌─────────┐       ┌──────────────┐       ┌──────────────┐
│ HTTPS   │◄─────►│ Agent Parent │◄─────►│ Agent Child  │
│ Listener│       │ (Beacon 1)   │  SMB  │ (Beacon 2)   │
└─────────┘       │              │       │              │
   ^  │           │ \\.\pipe\c2  │       │  Client de  │
   │  │           └──────────────┘       │  \\srv\pipe\ │
   │  v                                  └──────────────┘
  HTTPS                                        │
Bloque par                                     │
  firewall                              Lateral movement
                                         via SMB (port 445)

Flux :
1. Agent Parent etablit HTTPS avec C2
2. Agent Parent cree Named Pipe local
3. Agent Child (lateral move) se connecte via SMB
4. Parent relaie commandes : C2 ◄─► Parent ◄─► Child
```

## Concepts fondamentaux

### Concept 1 : Named Pipes Windows

**Named Pipe** = canal de communication bidirectionnel identifie par un nom.

**Format** : `\\.\pipe\<nom>` (local) ou `\\<serveur>\pipe\<nom>` (reseau)

**Types** :
- **Byte mode** : Flux d'octets continu (comme TCP)
- **Message mode** : Messages discrets avec limites preservees

**Directions** :
- **PIPE_ACCESS_DUPLEX** : Bidirectionnel (lecture + ecriture)
- **PIPE_ACCESS_INBOUND** : Entree uniquement
- **PIPE_ACCESS_OUTBOUND** : Sortie uniquement

```ascii
NAMED PIPE ARCHITECTURE :

Serveur (Agent Parent)              Client (Agent Child)
┌────────────────────┐              ┌────────────────────┐
│ CreateNamedPipe()  │              │ CreateFile()       │
│ \\.\pipe\myc2      │              │ \\srv\pipe\myc2    │
├────────────────────┤              ├────────────────────┤
│ ConnectNamedPipe() │◄─Connexion──►│ WaitNamedPipe()    │
├────────────────────┤              ├────────────────────┤
│ ReadFile()         │◄─────────────┤ WriteFile()        │
│ WriteFile()        ├─────────────►│ ReadFile()         │
└────────────────────┘              └────────────────────┘

Lifecycle :
1. Server : CreateNamedPipe() - Cree le pipe
2. Server : ConnectNamedPipe() - Attend connexion
3. Client : CreateFile() - Se connecte au pipe
4. Both : ReadFile()/WriteFile() - Communication
5. Both : CloseHandle() - Fermeture
```

### Concept 2 : SMB pour C2

**Avantages SMB C2** :
1. **Legitime** : SMB omniprésent dans reseaux Windows
2. **Firewall-friendly** : Port 445 rarement bloque en interne
3. **Encrypted** : SMB 3.0+ chiffre automatiquement
4. **Peer-to-peer** : Architecture parent/child, pas de serveur central

**Inconvenients** :
1. **Lateral uniquement** : Necessite acces reseau direct
2. **Logs** : Connexions SMB loggees par Windows Event Log
3. **Detection** : Anomalies SMB detectables (pipes inhabituels)

```ascii
COMPARAISON PROTOCOLES C2 :

HTTP/HTTPS C2                 SMB Named Pipes C2
┌──────────────┐              ┌──────────────┐
│ Internet     │              │ LAN uniquement│
│ Firewall OK  │              │ Pas d'Internet│
│ Detection ++ │              │ Detection +   │
│ Exfiltration │              │ Lateral move  │
└──────────────┘              └──────────────┘

Usage combine :
┌──────────────────────────────────────┐
│  Scenario Red Team Typique :         │
├──────────────────────────────────────┤
│ 1. Initial compromise : HTTPS beacon │
│ 2. Lateral movement : SMB pipes      │
│ 3. Exfiltration : HTTPS beacon       │
└──────────────────────────────────────┘
```

### Concept 3 : Securite et Authentification

Les Named Pipes supportent les ACL (Access Control Lists) pour controler qui peut se connecter.

**Security Descriptor** : Definit permissions (lecture/ecriture/full control)

```c
// Exemple : Pipe accessible uniquement par SYSTEM et Administrators
SECURITY_ATTRIBUTES sa;
SECURITY_DESCRIPTOR sd;

InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE); // NULL DACL = tous acces

sa.nLength = sizeof(sa);
sa.lpSecurityDescriptor = &sd;
sa.bInheritHandle = FALSE;

HANDLE hPipe = CreateNamedPipe(
    "\\\\.\\pipe\\myc2",
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    1,
    4096,
    4096,
    0,
    &sa  // Security attributes
);
```

**Impersonation** : Le serveur peut impersonner le client pour executer avec ses privileges.

```c
// Server impersonne le client
ImpersonateNamedPipeClient(hPipe);
// ... operations avec privileges du client ...
RevertToSelf();  // Retour aux privileges du serveur
```

## Mise en pratique

### Etape 1 : Creer un Named Pipe Server (Agent Parent)

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\myc2pipe"
#define BUFFER_SIZE 4096

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    printf("[*] Creating Named Pipe: %s\n", PIPE_NAME);

    // 1. Creer le pipe
    hPipe = CreateNamedPipe(
        PIPE_NAME,                    // Nom du pipe
        PIPE_ACCESS_DUPLEX,           // Lecture + Ecriture
        PIPE_TYPE_BYTE | PIPE_WAIT,   // Byte mode, blocking
        1,                            // Max instances
        BUFFER_SIZE,                  // Output buffer size
        BUFFER_SIZE,                  // Input buffer size
        0,                            // Default timeout
        NULL                          // Default security
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipe failed: %d\n", GetLastError());
        return 1;
    }

    printf("[+] Named Pipe created successfully\n");
    printf("[*] Waiting for client connection...\n");

    // 2. Attendre connexion client
    BOOL connected = ConnectNamedPipe(hPipe, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("[!] ConnectNamedPipe failed: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("[+] Client connected!\n");

    // 3. Communication
    while (1) {
        // Lire commande du client
        if (!ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
            printf("[!] ReadFile failed: %d\n", GetLastError());
            break;
        }

        buffer[bytesRead] = '\0';
        printf("[<] Received: %s\n", buffer);

        if (strcmp(buffer, "exit") == 0) {
            break;
        }

        // Repondre au client
        char response[BUFFER_SIZE];
        snprintf(response, BUFFER_SIZE, "Server received: %s", buffer);

        if (!WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL)) {
            printf("[!] WriteFile failed: %d\n", GetLastError());
            break;
        }

        printf("[>] Sent: %s\n", response);
    }

    // 4. Nettoyage
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    printf("[*] Pipe closed\n");

    return 0;
}
```

### Etape 2 : Creer un Named Pipe Client (Agent Child)

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\myc2pipe"  // Local
// Pour connexion reseau : "\\\\192.168.1.10\\pipe\\myc2pipe"
#define BUFFER_SIZE 4096

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    printf("[*] Connecting to Named Pipe: %s\n", PIPE_NAME);

    // 1. Attendre que le pipe soit disponible
    if (!WaitNamedPipe(PIPE_NAME, 5000)) {
        printf("[!] Pipe not available: %d\n", GetLastError());
        return 1;
    }

    // 2. Se connecter au pipe
    hPipe = CreateFile(
        PIPE_NAME,                    // Nom du pipe
        GENERIC_READ | GENERIC_WRITE, // Acces lecture+ecriture
        0,                            // Pas de partage
        NULL,                         // Default security
        OPEN_EXISTING,                // Ouvrir existant
        0,                            // Default attributes
        NULL                          // No template
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile failed: %d\n", GetLastError());
        return 1;
    }

    printf("[+] Connected to Named Pipe\n");

    // 3. Communication
    while (1) {
        printf("Enter command: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = '\0';  // Remove newline

        // Envoyer commande
        if (!WriteFile(hPipe, buffer, strlen(buffer), &bytesWritten, NULL)) {
            printf("[!] WriteFile failed: %d\n", GetLastError());
            break;
        }

        if (strcmp(buffer, "exit") == 0) {
            break;
        }

        // Lire reponse
        if (!ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
            printf("[!] ReadFile failed: %d\n", GetLastError());
            break;
        }

        buffer[bytesRead] = '\0';
        printf("[<] Server response: %s\n", buffer);
    }

    // 4. Nettoyage
    CloseHandle(hPipe);
    printf("[*] Disconnected\n");

    return 0;
}
```

### Etape 3 : SMB C2 avec Relay Parent/Child

```c
// Agent Parent : Relaie commandes entre C2 HTTP et agent child SMB
#include <windows.h>
#include <stdio.h>

void* http_receive_commands(void* arg) {
    // Simule reception commandes depuis C2 HTTP
    HANDLE hPipe = (HANDLE)arg;
    char commands[][256] = {
        "whoami",
        "ipconfig",
        "exit"
    };

    for (int i = 0; i < 3; i++) {
        Sleep(2000);  // Simule interval beacon

        printf("[HTTP C2] Received command: %s\n", commands[i]);

        // Envoyer commande au child via SMB
        DWORD written;
        WriteFile(hPipe, commands[i], strlen(commands[i]), &written, NULL);

        // Lire resultat du child
        char result[4096];
        DWORD read;
        ReadFile(hPipe, result, 4096, &read, NULL);
        result[read] = '\0';

        printf("[HTTP C2] Sending result to C2: %s\n", result);
    }

    return NULL;
}

int main() {
    HANDLE hPipe;

    // Creer Named Pipe
    hPipe = CreateNamedPipe(
        "\\\\.\\pipe\\c2relay",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL
    );

    printf("[*] Waiting for child agent via SMB...\n");
    ConnectNamedPipe(hPipe, NULL);
    printf("[+] Child agent connected\n");

    // Thread pour recevoir commandes HTTP
    HANDLE hThread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)http_receive_commands,
        hPipe, 0, NULL);

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hPipe);
    return 0;
}
```

## Application offensive

### Contexte Red Team

**Scenario** : Lateral movement apres initial compromise

1. **Initial Access** : Phishing -> Agent HTTPS sur workstation
2. **Enumeration** : Decouverte serveur fichiers sans Internet
3. **Lateral Move** : PsExec/WMI deploie agent child
4. **SMB Pivot** : Child se connecte au parent via Named Pipe
5. **Command Relay** : Parent relaie commandes C2 au child

```ascii
SCENARIO RED TEAM :

┌─────────────────────────────────────────────────────┐
│                    INTERNET                         │
│                  C2 Server (VPS)                    │
└───────────────────┬─────────────────────────────────┘
                    │ HTTPS
                    │ (port 443)
┌───────────────────┼─────────────────────────────────┐
│                   │        RESEAU INTERNE           │
│                   v                                 │
│          ┌─────────────────┐                        │
│          │  WORKSTATION-01 │                        │
│          │  Agent Parent   │                        │
│          │  (HTTP Beacon)  │                        │
│          └────────┬────────┘                        │
│                   │ SMB Named Pipe                  │
│                   │ \\WKS01\pipe\c2                 │
│                   │                                 │
│          ┌────────v────────┐                        │
│          │  FILE-SERVER    │                        │
│          │  Agent Child    │                        │
│          │  (SMB only)     │                        │
│          │  NO INTERNET    │                        │
│          └─────────────────┘                        │
│                                                     │
└─────────────────────────────────────────────────────┘

Avantages :
- File-Server n'a pas d'acces Internet (pas d'alerte egress)
- Trafic SMB legitime entre workstation et serveur fichiers
- Contournement firewall perimetrique
```

### Considerations OPSEC

**Detection Risks** :
1. **Event Logs** :
   - Event ID 5145 : Acces objet partage SMB
   - Event ID 5140 : Partage reseau accede

2. **Anomalies** :
   - Named Pipes inhabituels (noms suspects)
   - Connexions SMB entre workstations (pas normal)
   - Pipes avec noms generiques (pipe1, data, etc.)

3. **EDR/AV** :
   - Behavioral detection : Process creating pipes
   - Network monitoring : SMB traffic analysis

**Mitigations OPSEC** :
```c
// 1. Noms de pipes legitimes (mimicking)
#define PIPE_NAME "\\\\.\\pipe\\mojo.12345.67890.12345"  // Chrome IPC
#define PIPE_NAME "\\\\.\\pipe\\LOCAL\\crashpad_1234"   // Crashpad

// 2. Limiter connexions externes (localhost only)
// Utiliser pipes locaux (\\.\ ) sauf lateral necessaire

// 3. Chiffrement additionnel (meme si SMB3 chiffre)
// AES encrypt data before WriteFile()

// 4. Limiter duree de vie
CreateNamedPipe(..., PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, ...);
// Empeche creation de pipes multiples (limite empreinte)

// 5. Cleanup agressif
DisconnectNamedPipe(hPipe);
CloseHandle(hPipe);  // Toujours fermer proprement
```

**Blue Team Detection** :
```powershell
# Lister Named Pipes actifs
Get-ChildItem \\.\pipe\

# Monitorer creations de pipes (Sysmon Event ID 17/18)
# Sysmon config :
<PipeEvent onmatch="include">
  <PipeName condition="contains">suspicious</PipeName>
</PipeEvent>

# Analyser connexions SMB
Get-SmbConnection
Get-SmbSession
```

## Resume

- **Named Pipes** : Mecanisme IPC Windows pour communication locale/reseau
- **SMB C2** : Utilise Named Pipes pour communication laterale entre agents
- **Architecture Parent/Child** : Agent parent (Internet) relaie vers child (SMB)
- **Avantages** : Trafic legitime, firewall-friendly, chiffrement natif
- **OPSEC** : Noms legitimes, limitation acces, cleanup, eviter anomalies
- **Detection** : Event logs, anomalies reseau, behavioral analytics

## Ressources complementaires

- [Microsoft Named Pipes Documentation](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
- [SMB Protocol Documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [Sysmon Pipe Monitoring](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Cobalt Strike SMB Beacons](https://www.cobaltstrike.com/help-smb-beacon)
- [Red Team Tactics: Named Pipes](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)

---

**Navigation**
- [Module precedent](../W51_proxy_awareness/)
- [Module suivant](../W53_beacon_architecture/)

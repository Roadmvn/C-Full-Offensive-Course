/*
 * OBJECTIF  : Comprendre les pipes Windows (named pipes et anonymous pipes)
 * PREREQUIS : Bases du C, API Windows, notions de processus
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les pipes sont un mecanisme IPC (Inter-Process Communication) sous Windows.
 * - Anonymous pipes : communication parent-enfant (unidirectionnels)
 * - Named pipes : communication entre processus quelconques (bidirectionnels)
 * Ils sont utilises par les implants C2 pour la communication laterale.
 */

#include <windows.h>
#include <stdio.h>

/* Demo 1 : Anonymous pipe (communication parent -> enfant) */
void demo_anonymous_pipe(void) {
    printf("[1] Anonymous Pipe\n\n");

    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        printf("    [-] CreatePipe echoue (err %lu)\n", GetLastError());
        return;
    }
    printf("    [+] Pipe cree : Read=%p, Write=%p\n", hRead, hWrite);

    /* Ecrire dans le pipe */
    const char* msg = "Message via anonymous pipe!";
    DWORD written;
    WriteFile(hWrite, msg, (DWORD)strlen(msg), &written, NULL);
    printf("    [+] Ecrit %lu octets\n", written);

    /* Lire depuis le pipe */
    char buffer[256] = {0};
    DWORD read;
    ReadFile(hRead, buffer, sizeof(buffer) - 1, &read, NULL);
    printf("    [+] Lu %lu octets : \"%s\"\n", read, buffer);

    printf("    [*] Les anonymous pipes sont unidirectionnels\n");
    printf("    [*] Utilises pour rediriger stdout/stderr d'un processus enfant\n");

    CloseHandle(hRead);
    CloseHandle(hWrite);
    printf("\n");
}

/* Demo 2 : Named pipe server */
void demo_named_pipe_server(void) {
    printf("[2] Named Pipe Server\n\n");

    const char* pipe_name = "\\\\.\\pipe\\DemoPipe";

    /* Creer le named pipe */
    HANDLE hPipe = CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,               /* Bidirectionnel */
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,                                  /* Max instances */
        4096,                               /* Output buffer */
        4096,                               /* Input buffer */
        0,                                  /* Default timeout */
        NULL);                              /* Default security */

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("    [-] CreateNamedPipe echoue (err %lu)\n", GetLastError());
        return;
    }
    printf("    [+] Named pipe cree : %s\n", pipe_name);
    printf("    [+] Handle : %p\n", hPipe);

    printf("    [*] En mode reel, le serveur appellerait ConnectNamedPipe()\n");
    printf("    [*] pour attendre qu'un client se connecte\n");

    /* On ne peut pas faire connect + read dans un seul thread de demo
       sans bloquer, donc on montre juste la creation */

    CloseHandle(hPipe);
    printf("\n");
}

/* Demo 3 : Named pipe client (connexion a un pipe existant) */
void demo_named_pipe_client(void) {
    printf("[3] Named Pipe Client\n\n");

    /* D'abord creer un pipe serveur pour que le client puisse se connecter */
    const char* pipe_name = "\\\\.\\pipe\\DemoClientPipe";

    HANDLE hServer = CreateNamedPipeA(pipe_name,
        PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
        1, 4096, 4096, 0, NULL);

    if (hServer == INVALID_HANDLE_VALUE) {
        printf("    [-] CreateNamedPipe echoue\n");
        return;
    }

    /* Se connecter en tant que client */
    HANDLE hClient = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                                  0, NULL, OPEN_EXISTING, 0, NULL);

    if (hClient != INVALID_HANDLE_VALUE) {
        printf("    [+] Client connecte au pipe : %s\n", pipe_name);

        /* Envoyer un message du client vers le serveur */
        const char* msg = "Commande C2 via named pipe";
        DWORD written;
        WriteFile(hClient, msg, (DWORD)strlen(msg), &written, NULL);
        printf("    [+] Client -> Serveur : %lu octets envoyes\n", written);

        /* Le serveur lit le message */
        ConnectNamedPipe(hServer, NULL); /* Accepter la connexion */
        char buffer[256] = {0};
        DWORD read;
        BOOL ok = ReadFile(hServer, buffer, sizeof(buffer) - 1, &read, NULL);
        if (ok && read > 0) {
            printf("    [+] Serveur <- Client : \"%s\" (%lu octets)\n", buffer, read);
        }

        /* Reponse du serveur vers le client */
        const char* reply = "ACK: commande recue";
        WriteFile(hServer, reply, (DWORD)strlen(reply), &written, NULL);

        char reply_buf[256] = {0};
        ReadFile(hClient, reply_buf, sizeof(reply_buf) - 1, &read, NULL);
        if (read > 0) {
            printf("    [+] Client <- Serveur : \"%s\"\n", reply_buf);
        }

        CloseHandle(hClient);
    } else {
        printf("    [-] Connexion client echouee (err %lu)\n", GetLastError());
    }

    CloseHandle(hServer);
    printf("\n");
}

/* Demo 4 : Enumeration des named pipes */
void demo_enumerate_pipes(void) {
    printf("[4] Enumeration des named pipes existants\n\n");

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA("\\\\.\\pipe\\*", &ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("    [-] FindFirstFile echoue\n");
        return;
    }

    int count = 0;
    printf("    Named pipes actifs :\n");
    do {
        if (count < 20)
            printf("    \\\\.\\pipe\\%s\n", ffd.cFileName);
        count++;
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    if (count > 20)
        printf("    ... (%d de plus)\n", count - 20);
    printf("\n    [+] Total : %d named pipes\n", count);
    printf("\n");
}

/* Demo 5 : Concept C2 via named pipes */
void demo_c2_pipe_concept(void) {
    printf("[5] Concept : C2 via Named Pipes (SMB lateral movement)\n\n");

    printf("    Les named pipes sont accessibles via SMB (port 445) :\n");
    printf("    \\\\TARGET\\pipe\\MonC2Pipe\n\n");
    printf("    Architecture C2 SMB :\n");
    printf("    1. Beacon principal : connecte au C2 via HTTP/HTTPS\n");
    printf("    2. Beacons secondaires : communiquent via named pipes\n");
    printf("    3. Le beacon principal fait le relais vers le C2\n\n");
    printf("    Avantage : les beacons internes ne font AUCUN trafic externe\n");
    printf("    Seul le beacon principal communique avec l'attaquant\n\n");
    printf("    [!] Detection : Sysmon Event ID 17/18 (Pipe Created/Connected)\n\n");
}

int main(void) {
    printf("[*] Demo : Pipes Windows (IPC)\n");
    printf("[*] ==========================================\n\n");

    demo_anonymous_pipe();
    demo_named_pipe_server();
    demo_named_pipe_client();
    demo_enumerate_pipes();
    demo_c2_pipe_concept();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

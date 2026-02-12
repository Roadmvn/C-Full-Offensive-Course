/*
 * OBJECTIF  : Communication C2 via SMB Named Pipes
 * PREREQUIS : Named Pipes, SMB
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les named pipes permettent la communication inter-processus via SMB.
 * Ideal pour le mouvement lateral : les beacons internes communiquent
 * via pipes, seul le beacon principal sort sur Internet.
 */

#include <windows.h>
#include <stdio.h>

void demo_smb_pipe_server(void) {
    printf("[1] Serveur SMB Pipe (beacon listener)\n\n");

    const char* pipe_name = "\\\\.\\pipe\\C2DemoPipe";
    HANDLE hPipe = CreateNamedPipeA(pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
        1, 4096, 4096, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("    [-] CreateNamedPipe echoue\n\n");
        return;
    }
    printf("    [+] Pipe cree : %s\n", pipe_name);

    /* Simuler un client */
    HANDLE hClient = CreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                                  0, NULL, OPEN_EXISTING, 0, NULL);
    if (hClient != INVALID_HANDLE_VALUE) {
        const char* cmd = "{\"cmd\":\"whoami\"}";
        DWORD written;
        WriteFile(hClient, cmd, (DWORD)strlen(cmd), &written, NULL);
        printf("    [+] Client envoie : %s\n", cmd);

        ConnectNamedPipe(hPipe, NULL);
        char buf[4096] = {0};
        DWORD bytesRead;
        ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL);
        if (bytesRead > 0)
            printf("    [+] Serveur recoit : %s\n", buf);

        CloseHandle(hClient);
    }
    CloseHandle(hPipe);
    printf("\n");
}

void demo_architecture(void) {
    printf("[2] Architecture C2 SMB\n\n");
    printf("    Internet <- HTTPS -> Beacon Principal (pivot)\n");
    printf("                              |\n");
    printf("                         SMB pipe\n");
    printf("                              |\n");
    printf("                    Beacon Secondaire 1\n");
    printf("                    Beacon Secondaire 2\n\n");
    printf("    Avantage : les beacons internes ne font AUCUN trafic externe\n");
    printf("    Detection : Sysmon Event ID 17/18 (Pipe Created/Connected)\n\n");
}

int main(void) {
    printf("[*] Demo : SMB Communication C2\n");
    printf("[*] ==========================================\n\n");
    demo_smb_pipe_server();
    demo_architecture();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

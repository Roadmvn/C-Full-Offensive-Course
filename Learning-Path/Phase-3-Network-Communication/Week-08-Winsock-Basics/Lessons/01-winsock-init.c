/*
 * Lesson 01: Winsock Initialization
 *
 * Concepts covered:
 * - WSAStartup: Initialize Winsock library
 * - WSACleanup: Cleanup Winsock resources
 * - WSADATA: Structure containing Winsock implementation details
 * - Error handling with WSAGetLastError
 *
 * Winsock is Windows' implementation of Berkeley sockets API.
 * Every Winsock application MUST call WSAStartup before using any socket functions.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

int main(void) {
    WSADATA wsaData;
    int result;

    printf("[*] Initializing Winsock...\n");

    /*
     * WSAStartup parameters:
     * - MAKEWORD(2, 2): Request Winsock version 2.2
     * - &wsaData: Pointer to WSADATA structure to receive details
     *
     * Returns 0 on success, error code otherwise
     */
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[!] WSAStartup failed: %d\n", result);
        return 1;
    }

    printf("[+] Winsock initialized successfully\n");
    printf("[*] Winsock version: %d.%d\n",
           LOBYTE(wsaData.wVersion),
           HIBYTE(wsaData.wVersion));
    printf("[*] Highest version supported: %d.%d\n",
           LOBYTE(wsaData.wHighVersion),
           HIBYTE(wsaData.wHighVersion));
    printf("[*] Description: %s\n", wsaData.szDescription);
    printf("[*] System Status: %s\n", wsaData.szSystemStatus);

    /*
     * Key WSADATA fields:
     * - wVersion: Winsock version the application will use
     * - wHighVersion: Highest version available
     * - szDescription: Description string
     * - szSystemStatus: System status string
     */

    /*
     * Understanding MAKEWORD macro:
     * MAKEWORD(2, 2) creates version 2.2
     * - Low byte: minor version (2)
     * - High byte: major version (2)
     */
    WORD requestedVersion = MAKEWORD(2, 2);
    printf("[*] Requested version: 0x%04X\n", requestedVersion);

    /*
     * Version compatibility check:
     * Ensure we got the version we requested
     */
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        printf("[!] Warning: Could not find Winsock 2.2\n");
        WSACleanup();
        return 1;
    }

    printf("[*] Version check passed\n");

    /*
     * WSACleanup MUST be called before application exits
     * - Terminates use of Winsock DLL
     * - Frees resources allocated by WSAStartup
     * - Should be called once for each successful WSAStartup
     */
    printf("[*] Cleaning up Winsock...\n");
    WSACleanup();
    printf("[+] Winsock cleanup complete\n");

    /*
     * Common errors:
     * - WSASYSNOTREADY: Network subsystem not ready
     * - WSAVERNOTSUPPORTED: Requested version not supported
     * - WSAEINPROGRESS: Blocking Winsock 1.1 operation in progress
     * - WSAEPROCLIM: Too many processes using Winsock
     */

    printf("\n[*] Winsock initialization/cleanup pattern complete\n");
    printf("[*] This pattern is REQUIRED for all Winsock applications\n");

    return 0;
}

/*
 * Compilation:
 * cl /W4 01-winsock-init.c /link ws2_32.lib
 *
 * OR with build.bat:
 * build.bat 01-winsock-init.c
 *
 * Key takeaways:
 * 1. Always call WSAStartup before any socket operations
 * 2. Check return value for errors
 * 3. Verify version compatibility
 * 4. Always call WSACleanup when done
 * 5. Link against ws2_32.lib
 */

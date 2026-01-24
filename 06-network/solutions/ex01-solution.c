/*
 * Solution: Exercise 01 - Connect to Server and Send Message
 *
 * This solution demonstrates:
 * - Proper Winsock initialization
 * - TCP socket creation
 * - Connection establishment
 * - Sending data
 * - Error handling
 * - Resource cleanup
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444

int main(void) {
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    const char *message = "Hello";
    int result;

    printf("[*] Exercise 01: Connect and Send\n\n");

    /* Initialize Winsock */
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[!] WSAStartup failed: %d\n", result);
        return 1;
    }
    printf("[+] Winsock initialized\n");

    /* Create socket */
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Socket created\n");

    /* Setup server address */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);

    result = inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);
    if (result != 1) {
        printf("[!] inet_pton() failed\n");
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    /* Connect to server */
    printf("[*] Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
    result = connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[!] connect() failed: %d\n", WSAGetLastError());
        printf("[!] Make sure a listener is running: nc -lvp %d\n", SERVER_PORT);
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Connected!\n");

    /* Send message */
    printf("[*] Sending message...\n");
    result = send(clientSocket, message, (int)strlen(message), 0);
    if (result == SOCKET_ERROR) {
        printf("[!] send() failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Sent %d bytes\n", result);

    /* Cleanup */
    closesocket(clientSocket);
    WSACleanup();

    printf("[+] Exercise complete\n");
    return 0;
}

/*
 * Key Points:
 *
 * 1. Error Checking:
 *    - Every function call is checked
 *    - Helpful error messages printed
 *    - Resources cleaned up on error
 *
 * 2. Proper Cleanup Order:
 *    - Close socket first
 *    - WSACleanup last
 *
 * 3. Network Byte Order:
 *    - htons() for port (host to network short)
 *    - inet_pton() for IP address
 *
 * 4. Socket Lifecycle:
 *    - Create -> Connect -> Send -> Close
 */

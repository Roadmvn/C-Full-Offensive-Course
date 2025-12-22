/*
 * Solution: Exercise 02 - Echo Client
 *
 * This solution demonstrates:
 * - Command line argument handling
 * - Bidirectional communication (send and receive)
 * - Proper buffer management
 * - Connection close detection
 * - Comprehensive error handling
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5555
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char sendBuffer[BUFFER_SIZE];
    char recvBuffer[BUFFER_SIZE];
    int result;
    int bytesReceived;

    printf("[*] Exercise 02: Echo Client\n\n");

    /* Get message to send */
    if (argc > 1) {
        /* Use command line argument */
        strncpy_s(sendBuffer, BUFFER_SIZE, argv[1], _TRUNCATE);
    } else {
        /* Prompt user */
        printf("Enter message: ");
        if (fgets(sendBuffer, BUFFER_SIZE, stdin) == NULL) {
            printf("[!] Failed to read input\n");
            return 1;
        }
        /* Remove newline */
        sendBuffer[strcspn(sendBuffer, "\n")] = '\0';
    }

    if (strlen(sendBuffer) == 0) {
        printf("[!] Message cannot be empty\n");
        return 1;
    }

    printf("[*] Message to send: %s\n", sendBuffer);

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

    /* Setup server address */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    /* Connect to server */
    printf("[*] Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
    result = connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[!] connect() failed: %d\n", WSAGetLastError());
        printf("[!] Make sure echo server is running: nc -lvp %d\n", SERVER_PORT);
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Connected to %s:%d\n", SERVER_IP, SERVER_PORT);

    /* Send message */
    printf("[*] Sending: %s\n", sendBuffer);
    result = send(clientSocket, sendBuffer, (int)strlen(sendBuffer), 0);
    if (result == SOCKET_ERROR) {
        printf("[!] send() failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Sent %d bytes\n", result);

    /* Receive echo response */
    printf("[*] Waiting for echo...\n");
    memset(recvBuffer, 0, BUFFER_SIZE);
    bytesReceived = recv(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0);

    if (bytesReceived > 0) {
        /* Data received */
        recvBuffer[bytesReceived] = '\0';
        printf("[+] Received: %s\n", recvBuffer);
    } else if (bytesReceived == 0) {
        /* Connection closed gracefully */
        printf("[*] Connection closed by server\n");
    } else {
        /* Error occurred */
        printf("[!] recv() failed: %d\n", WSAGetLastError());
    }

    /* Cleanup */
    closesocket(clientSocket);
    WSACleanup();

    printf("[+] Connection closed gracefully\n");
    return 0;
}

/*
 * Key Points:
 *
 * 1. Input Handling:
 *    - Supports both command line and interactive input
 *    - Uses strncpy_s for safe string copy
 *    - Removes newline from fgets()
 *
 * 2. recv() Return Values:
 *    - > 0: Number of bytes received
 *    - = 0: Connection closed gracefully
 *    - < 0: Error (SOCKET_ERROR)
 *
 * 3. Buffer Safety:
 *    - Always leave room for null terminator
 *    - Clear buffer before recv()
 *    - Null-terminate after recv()
 *
 * 4. User Experience:
 *    - Clear status messages
 *    - Helpful error messages
 *    - Usage instructions
 *
 * BONUS: Loop Version
 * To send/receive multiple messages, wrap send/recv in a loop:
 *
 * while (1) {
 *     // Get message
 *     // Send message
 *     // Receive response
 *     // Check for "quit" to break
 * }
 */

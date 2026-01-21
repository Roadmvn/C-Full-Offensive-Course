/*
 * Lesson 03: TCP Server Implementation
 *
 * Concepts covered:
 * - bind(): Bind socket to address/port
 * - listen(): Listen for incoming connections
 * - accept(): Accept client connection
 * - Server socket lifecycle
 *
 * TCP server workflow:
 * 1. WSAStartup
 * 2. socket() - Create listening socket
 * 3. bind() - Bind to address/port
 * 4. listen() - Start listening
 * 5. accept() - Accept client connections
 * 6. send()/recv() - Exchange data
 * 7. closesocket() - Close connections
 * 8. WSACleanup
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define LISTEN_PORT 4444
#define BACKLOG 5
#define BUFFER_SIZE 1024

int main(void) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char recvBuffer[BUFFER_SIZE];
    char sendBuffer[] = "Hello from TCP server!";
    int result;
    int bytesReceived;

    printf("[*] TCP Server Example\n\n");

    /* Step 1: Initialize Winsock */
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[!] WSAStartup failed: %d\n", result);
        return 1;
    }
    printf("[+] Winsock initialized\n");

    /* Step 2: Create listening socket */
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Listening socket created\n");

    /*
     * Step 3: Setup server address structure and bind
     *
     * INADDR_ANY (0.0.0.0): Listen on all network interfaces
     * This allows connections from any IP address
     */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(LISTEN_PORT);

    /*
     * bind() associates socket with local address/port
     *
     * Parameters:
     * - listenSocket: Socket to bind
     * - (struct sockaddr*)&serverAddr: Address structure
     * - sizeof(serverAddr): Size of address structure
     *
     * Returns SOCKET_ERROR on failure
     */
    printf("[*] Binding to port %d...\n", LISTEN_PORT);
    result = bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[!] bind() failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Socket bound to 0.0.0.0:%d\n", LISTEN_PORT);

    /*
     * Step 4: Start listening for connections
     *
     * listen() parameters:
     * - listenSocket: Socket to listen on
     * - BACKLOG: Maximum queue length for pending connections
     *
     * BACKLOG determines how many connection requests can be queued
     * while waiting for accept()
     */
    printf("[*] Starting to listen (backlog=%d)...\n", BACKLOG);
    result = listen(listenSocket, BACKLOG);
    if (result == SOCKET_ERROR) {
        printf("[!] listen() failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Listening for connections...\n");
    printf("[*] Press Ctrl+C to stop server\n\n");

    /*
     * Step 5: Accept incoming connection
     *
     * accept() is BLOCKING - waits until client connects
     *
     * Parameters:
     * - listenSocket: Listening socket
     * - (struct sockaddr*)&clientAddr: Receives client address
     * - &clientAddrLen: Size of client address structure
     *
     * Returns new socket for communicating with client
     */
    printf("[*] Waiting for client connection...\n");
    clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
    if (clientSocket == INVALID_SOCKET) {
        printf("[!] accept() failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    /* Get client IP and port */
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    int clientPort = ntohs(clientAddr.sin_port);

    printf("[+] Client connected from %s:%d\n", clientIP, clientPort);

    /*
     * Step 6: Receive data from client
     */
    printf("[*] Receiving data...\n");
    bytesReceived = recv(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived > 0) {
        recvBuffer[bytesReceived] = '\0';
        printf("[+] Received %d bytes: %s\n", bytesReceived, recvBuffer);

        /* Step 7: Send response */
        printf("[*] Sending response...\n");
        result = send(clientSocket, sendBuffer, (int)strlen(sendBuffer), 0);
        if (result == SOCKET_ERROR) {
            printf("[!] send() failed: %d\n", WSAGetLastError());
        } else {
            printf("[+] Sent %d bytes\n", result);
        }
    } else if (bytesReceived == 0) {
        printf("[*] Connection closed by client\n");
    } else {
        printf("[!] recv() failed: %d\n", WSAGetLastError());
    }

    /*
     * Step 8: Close sockets
     *
     * Important: Close both client socket AND listening socket
     */
    printf("[*] Closing client connection...\n");
    closesocket(clientSocket);

    printf("[*] Closing listening socket...\n");
    closesocket(listenSocket);

    /* Step 9: Cleanup Winsock */
    WSACleanup();
    printf("[+] Server shutdown complete\n");

    return 0;
}

/*
 * Server vs Client Socket Lifecycle:
 *
 * CLIENT:                    SERVER:
 * socket()                   socket()
 *   |                          |
 * connect() ------------->   bind()
 *   |                          |
 * send()/recv()              listen()
 *   |                          |
 * closesocket()              accept() (creates new socket)
 *                              |
 *                            send()/recv()
 *                              |
 *                            closesocket() (client socket)
 *                            closesocket() (listening socket)
 *
 *
 * Key differences:
 *
 * 1. Server has TWO sockets:
 *    - Listening socket (for accepting connections)
 *    - Client socket (for data exchange)
 *
 * 2. Client has ONE socket:
 *    - Connected directly to server
 *
 * 3. accept() creates new socket:
 *    - Listening socket remains open
 *    - New socket handles specific client
 *
 *
 * Testing this server:
 *
 * 1. Run server:
 *    03-tcp-server.exe
 *
 * 2. Connect with netcat:
 *    nc 127.0.0.1 4444
 *
 * 3. Type a message in netcat
 *
 * OR use the TCP client from lesson 02:
 *    02-tcp-client.exe
 *
 *
 * Production server considerations:
 * - This accepts only ONE connection
 * - Real servers use loop with accept()
 * - Use threads/async I/O for multiple clients
 * - Implement proper error handling
 * - Add timeouts and connection limits
 */

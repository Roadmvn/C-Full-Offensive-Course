/*
 * Lesson 02: TCP Client Implementation
 *
 * Concepts covered:
 * - socket(): Create a socket
 * - connect(): Connect to remote server
 * - send(): Send data over socket
 * - recv(): Receive data from socket
 * - closesocket(): Close socket connection
 *
 * TCP client workflow:
 * 1. WSAStartup
 * 2. socket() - Create socket
 * 3. connect() - Connect to server
 * 4. send()/recv() - Exchange data
 * 5. closesocket() - Close connection
 * 6. WSACleanup
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444
#define BUFFER_SIZE 1024

int main(void) {
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char sendBuffer[] = "Hello from TCP client!";
    char recvBuffer[BUFFER_SIZE];
    int result;
    int bytesReceived;

    printf("[*] TCP Client Example\n\n");

    /* Step 1: Initialize Winsock */
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("[!] WSAStartup failed: %d\n", result);
        return 1;
    }
    printf("[+] Winsock initialized\n");

    /*
     * Step 2: Create socket
     *
     * socket() parameters:
     * - AF_INET: IPv4 address family
     * - SOCK_STREAM: TCP socket (stream-oriented, reliable)
     * - IPPROTO_TCP: TCP protocol
     *
     * Returns INVALID_SOCKET on failure
     */
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Socket created: %lld\n", (long long)clientSocket);

    /*
     * Step 3: Setup server address structure
     *
     * sockaddr_in structure:
     * - sin_family: Address family (AF_INET)
     * - sin_port: Port number (in network byte order - htons)
     * - sin_addr.s_addr: IP address (inet_addr or inet_pton)
     */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);

    /* Convert IP address string to binary form */
    result = inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);
    if (result != 1) {
        printf("[!] inet_pton() failed: Invalid address\n");
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    printf("[*] Target: %s:%d\n", SERVER_IP, SERVER_PORT);

    /*
     * Step 4: Connect to server
     *
     * connect() parameters:
     * - clientSocket: Socket descriptor
     * - (struct sockaddr*)&serverAddr: Server address
     * - sizeof(serverAddr): Size of address structure
     *
     * Returns SOCKET_ERROR on failure
     */
    printf("[*] Attempting connection...\n");
    result = connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        printf("[!] connect() failed: %d\n", WSAGetLastError());
        printf("[!] Make sure a server is running on %s:%d\n", SERVER_IP, SERVER_PORT);
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Connected to server!\n");

    /*
     * Step 5: Send data
     *
     * send() parameters:
     * - clientSocket: Socket descriptor
     * - sendBuffer: Data to send
     * - strlen(sendBuffer): Number of bytes to send
     * - 0: Flags (0 for default behavior)
     *
     * Returns number of bytes sent, or SOCKET_ERROR on failure
     */
    printf("[*] Sending: %s\n", sendBuffer);
    result = send(clientSocket, sendBuffer, (int)strlen(sendBuffer), 0);
    if (result == SOCKET_ERROR) {
        printf("[!] send() failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Sent %d bytes\n", result);

    /*
     * Step 6: Receive response
     *
     * recv() parameters:
     * - clientSocket: Socket descriptor
     * - recvBuffer: Buffer to store received data
     * - BUFFER_SIZE - 1: Maximum bytes to receive (leave room for null)
     * - 0: Flags (0 for default behavior)
     *
     * Returns:
     * - Number of bytes received
     * - 0 if connection closed gracefully
     * - SOCKET_ERROR on error
     */
    printf("[*] Waiting for response...\n");
    bytesReceived = recv(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived > 0) {
        recvBuffer[bytesReceived] = '\0';
        printf("[+] Received %d bytes: %s\n", bytesReceived, recvBuffer);
    } else if (bytesReceived == 0) {
        printf("[*] Connection closed by server\n");
    } else {
        printf("[!] recv() failed: %d\n", WSAGetLastError());
    }

    /*
     * Step 7: Close socket
     *
     * closesocket() gracefully closes the connection
     * Always close sockets to free resources
     */
    printf("[*] Closing connection...\n");
    closesocket(clientSocket);
    printf("[+] Socket closed\n");

    /* Step 8: Cleanup Winsock */
    WSACleanup();
    printf("[+] Winsock cleanup complete\n");

    return 0;
}

/*
 * Important network byte order functions:
 *
 * htons() - Host TO Network Short (16-bit)
 *   Converts port numbers to network byte order (big-endian)
 *
 * htonl() - Host TO Network Long (32-bit)
 *   Converts IP addresses to network byte order
 *
 * ntohs() - Network TO Host Short
 *   Converts network port to host byte order
 *
 * ntohl() - Network TO Host Long
 *   Converts network IP to host byte order
 *
 * Network byte order is always big-endian!
 *
 *
 * Testing this client:
 *
 * 1. Start a netcat listener:
 *    nc -lvp 4444
 *
 * 2. Run this client:
 *    02-tcp-client.exe
 *
 * 3. Type a response in netcat
 *
 *
 * Common errors:
 * - WSAECONNREFUSED (10061): No server listening
 * - WSAETIMEDOUT (10060): Connection timeout
 * - WSAEHOSTUNREACH (10065): Host unreachable
 * - WSAEADDRINUSE (10048): Address already in use
 */

/*
 * Exercise 01: Connect to Server and Send Message
 *
 * OBJECTIVE:
 * Create a TCP client that:
 * 1. Connects to localhost:4444
 * 2. Sends the message "Hello"
 * 3. Prints confirmation
 * 4. Closes gracefully
 *
 * TASKS:
 * - Initialize Winsock
 * - Create a TCP socket
 * - Connect to 127.0.0.1:4444
 * - Send "Hello" message
 * - Handle errors appropriately
 * - Clean up resources
 *
 * TESTING:
 * Start a listener first:
 *   nc -lvp 4444
 * Then run your program
 *
 * HINTS:
 * - Use WSAStartup with MAKEWORD(2, 2)
 * - socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
 * - Don't forget htons() for port
 * - Check every function's return value
 * - Remember to link ws2_32.lib
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444

int main(void) {
    /* TODO: Declare variables
     * - WSADATA for WSAStartup
     * - SOCKET for client socket
     * - struct sockaddr_in for server address
     * - int for return values
     */

    printf("[*] Exercise 01: Connect and Send\n\n");

    /* TODO: Initialize Winsock
     * - Call WSAStartup
     * - Check return value
     */

    /* TODO: Create socket
     * - Use socket() with AF_INET, SOCK_STREAM, IPPROTO_TCP
     * - Check for INVALID_SOCKET
     */

    /* TODO: Setup server address
     * - Zero out structure with memset
     * - Set sin_family to AF_INET
     * - Set sin_port with htons()
     * - Set sin_addr with inet_pton()
     */

    /* TODO: Connect to server
     * - Use connect()
     * - Check for SOCKET_ERROR
     * - Print helpful error if connection fails
     */

    /* TODO: Send message
     * - Send "Hello"
     * - Use send() function
     * - Print number of bytes sent
     */

    /* TODO: Cleanup
     * - closesocket()
     * - WSACleanup()
     */

    printf("[+] Exercise complete\n");
    return 0;
}

/*
 * EXPECTED OUTPUT:
 * [*] Exercise 01: Connect and Send
 * [+] Winsock initialized
 * [+] Socket created
 * [*] Connecting to 127.0.0.1:4444...
 * [+] Connected!
 * [*] Sending message...
 * [+] Sent 5 bytes
 * [+] Exercise complete
 *
 * EXPECTED IN NETCAT:
 * Hello
 *
 * COMPILE:
 * cl /W4 ex01-connect-server.c /link ws2_32.lib
 *
 * GRADING CRITERIA:
 * [ ] Winsock initialized correctly
 * [ ] Socket created successfully
 * [ ] Connection established
 * [ ] Message sent correctly
 * [ ] Proper error handling
 * [ ] Resources cleaned up
 */

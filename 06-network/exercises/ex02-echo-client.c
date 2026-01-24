/*
 * Exercise 02: Echo Client
 *
 * OBJECTIVE:
 * Create a TCP client that:
 * 1. Connects to localhost:5555
 * 2. Sends a user-provided message
 * 3. Receives and prints the echo response
 * 4. Closes gracefully
 *
 * TASKS:
 * - Get message from user (command line or stdin)
 * - Connect to echo server
 * - Send the message
 * - Receive response (up to 1024 bytes)
 * - Print the received message
 * - Handle case where server closes connection
 *
 * TESTING:
 * Setup echo server with netcat:
 *   nc -lvp 5555
 * Type response when client connects
 *
 * Or use ncat for auto-echo:
 *   ncat -lkp 5555 --sh-exec "cat"
 *
 * BONUS CHALLENGES:
 * 1. Accept message as command line argument
 * 2. Loop to send/receive multiple messages
 * 3. Add timeout for recv()
 * 4. Handle partial receives (recv in loop)
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
    /* TODO: Declare all necessary variables
     * - WSADATA
     * - SOCKET
     * - sockaddr_in
     * - Send buffer
     * - Receive buffer (BUFFER_SIZE)
     * - Result variables
     */

    printf("[*] Exercise 02: Echo Client\n\n");

    /* TODO: Get message to send
     * Option 1: From command line (argc/argv)
     * Option 2: Prompt user with fgets()
     * Store in send buffer
     */

    /* TODO: Initialize Winsock */

    /* TODO: Create socket */

    /* TODO: Setup server address structure
     * - sin_family = AF_INET
     * - sin_port = htons(SERVER_PORT)
     * - sin_addr from inet_pton()
     */

    /* TODO: Connect to server */

    /* TODO: Send message
     * - Use send() with your message
     * - Print bytes sent
     */

    /* TODO: Receive echo response
     * - Use recv() to get response
     * - Check return value:
     *   > 0: Data received
     *   = 0: Connection closed
     *   < 0: Error occurred
     * - Null-terminate received data
     * - Print the response
     */

    /* TODO: Cleanup
     * - closesocket()
     * - WSACleanup()
     */

    return 0;
}

/*
 * USAGE EXAMPLES:
 *
 * With command line argument:
 *   ex02-echo-client.exe "Test message"
 *
 * With user input:
 *   ex02-echo-client.exe
 *   Enter message: Test message
 *
 * EXPECTED OUTPUT:
 * [*] Exercise 02: Echo Client
 * [*] Message to send: Test message
 * [+] Winsock initialized
 * [+] Connected to 127.0.0.1:5555
 * [*] Sending: Test message
 * [+] Sent 12 bytes
 * [*] Waiting for echo...
 * [+] Received: Test message
 * [+] Connection closed gracefully
 *
 * HINTS:
 * - Use strlen() to get message length
 * - Remember to null-terminate received data
 * - recv() might not receive all data at once
 * - For bonus loop: check for "quit" or "exit"
 *
 * ERROR HANDLING:
 * - What if server isn't running?
 * - What if server closes connection early?
 * - What if message is too large?
 *
 * GRADING CRITERIA:
 * [ ] Message input works
 * [ ] Connection successful
 * [ ] Message sent correctly
 * [ ] Response received and displayed
 * [ ] Handles connection close
 * [ ] Proper error messages
 * [ ] Clean resource cleanup
 */

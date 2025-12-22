# Week 08: Winsock Basics

## Phase 3: Network Communication - Foundation

Welcome to Phase 3 of the C Maldev Journey! This week introduces Windows Sockets (Winsock), the foundation for all network communication in Windows. You'll learn how to create TCP clients and servers, and build your first reverse shell.

## Overview

Winsock is Windows' implementation of the Berkeley Sockets API. It provides a standardized interface for network programming, enabling applications to communicate over TCP/IP networks. Understanding Winsock is essential for malware development, C2 infrastructure, network tools, and offensive security.

## Learning Objectives

By the end of this week, you will be able to:

- Initialize and cleanup the Winsock library properly
- Create TCP client applications that connect to remote servers
- Understand TCP server basics (bind, listen, accept)
- Implement a basic reverse shell with I/O redirection
- Handle network byte order conversion (htons, inet_pton)
- Manage socket lifecycle and error handling
- Redirect process I/O to network sockets

## Topics Covered

### 1. Winsock Initialization
- `WSAStartup()` - Initialize Winsock library
- `WSACleanup()` - Cleanup Winsock resources
- `WSADATA` structure - Version information
- Error handling with `WSAGetLastError()`
- Version compatibility checking

### 2. TCP Client Implementation
- `socket()` - Create a socket
- `connect()` - Connect to remote server
- `send()` - Send data over socket
- `recv()` - Receive data from socket
- `closesocket()` - Close connection
- Network byte order (htons, inet_pton)

### 3. TCP Server Basics
- `bind()` - Bind socket to address/port
- `listen()` - Start listening for connections
- `accept()` - Accept client connections
- Understanding listening vs client sockets
- Server lifecycle and connection handling

### 4. Reverse Shell Fundamentals
- Reverse shell vs bind shell concepts
- Process creation with `CreateProcess()`
- `STARTUPINFO` and `PROCESS_INFORMATION` structures
- I/O redirection to sockets
- Handle inheritance (`bInheritHandles`)
- Interactive shell over network

## Prerequisites

- Completed Phase 1 and Phase 2 (C fundamentals and Windows API)
- Understanding of processes and handles
- Basic networking concepts (IP, port, TCP)
- Access to a Windows development environment
- Netcat or similar network tool for testing

## File Structure

```
Week-08-Winsock-Basics/
├── Lessons/
│   ├── 01-winsock-init.c          # Winsock initialization
│   ├── 02-tcp-client.c            # TCP client implementation
│   ├── 03-tcp-server.c            # TCP server basics
│   └── 04-reverse-shell.c         # Basic reverse shell
├── Exercises/
│   ├── ex01-connect-server.c      # Connect and send message
│   ├── ex02-echo-client.c         # Bidirectional communication
│   └── ex03-simple-revshell.c     # Implement reverse shell
├── Solutions/
│   ├── ex01-solution.c
│   ├── ex02-solution.c
│   └── ex03-solution.c
├── quiz.json                      # 10 quiz questions
├── build.bat                      # Compilation script
└── README.md                      # This file
```

## Compilation

All Winsock programs must link against `ws2_32.lib`.

### Using MSVC (cl.exe)
```cmd
cl /W4 file.c /link ws2_32.lib
```

### Using build.bat
```cmd
build.bat 01-winsock-init.c
```

### Using GCC (MinGW)
```cmd
gcc -Wall file.c -o file.exe -lws2_32
```

## Testing Environment Setup

### Install Netcat (if not available)
```cmd
# Nmap's ncat (recommended)
# Download from: https://nmap.org/download.html

# Or use Windows built-in Test-NetConnection
```

### Basic Testing Commands

**Start TCP listener (server):**
```cmd
nc -lvp 4444
```

**Connect to server (client):**
```cmd
nc 127.0.0.1 4444
```

**Echo server (reflects data back):**
```cmd
ncat -lkp 5555 --sh-exec "cat"
```

## Week Structure

### Day 1-2: Winsock Initialization and TCP Clients
- Study `01-winsock-init.c`
- Study `02-tcp-client.c`
- Complete `ex01-connect-server.c`
- Complete `ex02-echo-client.c`
- Practice with different servers (netcat, Python HTTP server)

### Day 3-4: TCP Server Basics
- Study `03-tcp-server.c`
- Understand socket lifecycle differences (client vs server)
- Test with multiple clients
- Experiment with bind, listen, accept

### Day 5-7: Reverse Shell
- Study `04-reverse-shell.c`
- Understand I/O redirection concepts
- Complete `ex03-simple-revshell.c`
- Test in controlled environment
- Take the quiz

## Key Concepts

### Socket Lifecycle

**TCP Client:**
```
WSAStartup()
    ↓
socket()
    ↓
connect()
    ↓
send()/recv()
    ↓
closesocket()
    ↓
WSACleanup()
```

**TCP Server:**
```
WSAStartup()
    ↓
socket()
    ↓
bind()
    ↓
listen()
    ↓
accept() → client socket
    ↓
send()/recv()
    ↓
closesocket() (client)
closesocket() (listening)
    ↓
WSACleanup()
```

### Network Byte Order

Networks use **big-endian** byte order. Always convert:

- **Port numbers:** Use `htons()` (Host TO Network Short)
- **IP addresses:** Use `inet_pton()` (Presentation TO Network)

To convert back:
- **Port numbers:** Use `ntohs()` (Network TO Host Short)
- **IP addresses:** Use `inet_ntop()` (Network TO Presentation)

### Common Errors

| Error Code | Constant | Meaning |
|------------|----------|---------|
| 10061 | WSAECONNREFUSED | Connection refused (no server) |
| 10060 | WSAETIMEDOUT | Connection timeout |
| 10048 | WSAEADDRINUSE | Address already in use |
| 10065 | WSAEHOSTUNREACH | Host unreachable |

Check errors with `WSAGetLastError()`.

## Security Considerations

### Legal Warning
The reverse shell code is for **EDUCATIONAL PURPOSES ONLY**. Unauthorized access to computer systems is **ILLEGAL** under laws such as:
- Computer Fraud and Abuse Act (CFAA) in the US
- Computer Misuse Act in the UK
- Similar laws worldwide

**Only use on systems you own or have explicit written permission to test.**

### Detection Indicators

Reverse shells are detectable by:
- Network monitoring (unusual outbound connections)
- EDR/AV (suspicious process spawning patterns)
- Firewall (cmd.exe making network connections)
- Behavioral analysis (process I/O redirection)

### Defense Techniques

How to defend against these techniques:
- Monitor outbound connections on unusual ports
- Alert on cmd.exe/powershell.exe with redirected handles
- Use application whitelisting
- Implement egress filtering
- Deploy EDR solutions
- Analyze process parent-child relationships

## Practice Challenges

1. **Port Scanner:** Create a TCP client that tests multiple ports
2. **Multi-client Server:** Modify server to handle multiple connections
3. **Encrypted Shell:** Add basic XOR encryption to reverse shell
4. **Bind Shell:** Implement opposite of reverse shell
5. **HTTP Client:** Parse basic HTTP responses

## Common Mistakes

### Mistake 1: Forgetting WSAStartup
```c
// WRONG - Will fail
SOCKET s = socket(AF_INET, SOCK_STREAM, 0);

// CORRECT
WSAStartup(MAKEWORD(2,2), &wsaData);
SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
```

### Mistake 2: Wrong Byte Order
```c
// WRONG - Port in host byte order
addr.sin_port = 4444;

// CORRECT - Port in network byte order
addr.sin_port = htons(4444);
```

### Mistake 3: Not Checking Return Values
```c
// WRONG - Ignores errors
connect(sock, ...);
send(sock, ...);

// CORRECT - Checks errors
if (connect(sock, ...) == SOCKET_ERROR) {
    printf("Error: %d\n", WSAGetLastError());
}
```

### Mistake 4: Forgetting Handle Inheritance
```c
// WRONG - Child can't use handles
CreateProcessA(..., FALSE, ...); // bInheritHandles = FALSE

// CORRECT - Child inherits handles
CreateProcessA(..., TRUE, ...);  // bInheritHandles = TRUE
```

## Additional Resources

### Documentation
- [Winsock Reference - Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/winsock/)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [TCP/IP Illustrated, Volume 1](https://www.amazon.com/TCP-Illustrated-Protocols-Addison-Wesley-Professional/dp/0321336313)

### Tools
- [Netcat](https://nmap.org/ncat/)
- [Wireshark](https://www.wireshark.org/) - Network packet analyzer
- [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview) - Monitor connections

### Related Courses
- Phase 1: C Fundamentals (prerequisite)
- Phase 2: Windows Internals (prerequisite)
- Week 09: HTTP and WinHTTP (next week)
- Week 10: Advanced Network Techniques (future)

## Next Steps

After completing this week:

1. **Take the quiz** - Verify your understanding
2. **Complete all exercises** - Practice is essential
3. **Experiment** - Try modifications and variations
4. **Week 09: HTTP Client with WinHTTP** - Build HTTP/HTTPS clients
5. **Week 10+** - Advanced C2 communication techniques

## Troubleshooting

### "WSAStartup failed: 10093"
- Winsock DLL not found or wrong version
- Reinstall/update Windows

### "connect() failed: 10061"
- No server listening on target port
- Check server is running: `netstat -an | findstr :4444`

### "Unresolved external symbol WSAStartup"
- Not linking ws2_32.lib
- Add: `/link ws2_32.lib` to compile command

### Reverse shell connects but no prompt
- Check `bInheritHandles = TRUE`
- Verify all three handles are redirected
- Ensure socket is valid before CreateProcess

### Can't compile - missing winsock2.h
- Install Windows SDK
- Use Visual Studio Developer Command Prompt

## Assessment

Complete the following to finish this week:

- [ ] Read all lesson files and understand concepts
- [ ] Complete Exercise 01: Connect to server
- [ ] Complete Exercise 02: Echo client
- [ ] Complete Exercise 03: Reverse shell
- [ ] Take and pass the quiz (70%+)
- [ ] Experiment with modifications
- [ ] Test with netcat and observe network traffic

## Notes

- Always test in isolated/controlled environments
- Document your learning in code comments
- Focus on understanding WHY, not just memorizing HOW
- Network programming is foundational - master it!

---

**Remember:** This is the foundation of network-based malware and C2 infrastructure. Understanding Winsock thoroughly will make advanced topics much easier.

**Week 08 marks the beginning of offensive network programming. Let's build!**

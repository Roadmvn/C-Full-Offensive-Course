# Week 09: HTTP/WinHTTP

## Overview

This week covers HTTP-based network communication using the WinHTTP API, the foundation of modern C2 frameworks. You'll learn how to implement GET/POST requests, handle responses, and build beacon check-in patterns.

**Why This Matters:**
- HTTP/HTTPS is the most common C2 communication channel
- Blends with normal web traffic
- Can leverage CDNs and domain fronting
- Foundation of Cobalt Strike, Metasploit, Sliver HTTP beacons

## Learning Objectives

By the end of this week, you will be able to:

1. Understand WinHTTP API architecture and workflow
2. Implement HTTP GET requests to fetch data
3. Implement HTTP POST requests to send data
4. Build a complete beacon check-in pattern
5. Handle HTTP responses and headers
6. Apply C2 communication concepts in practice

## Table of Contents

### Lessons

1. **01-winhttp-intro.c** - WinHTTP API Introduction
   - WinHTTP vs WinINet comparison
   - Complete request flow walkthrough
   - Understanding handles and lifecycle
   - Error handling basics

2. **02-http-get.c** - HTTP GET Requests
   - Complete GET implementation
   - Response reading and buffering
   - Header querying
   - Dynamic memory allocation

3. **03-http-post.c** - HTTP POST Requests
   - POST with different Content-Types
   - Form data (application/x-www-form-urlencoded)
   - JSON data (application/json)
   - Binary data (application/octet-stream)

4. **04-http-callback.c** - C2 Beacon Pattern
   - Task fetching (GET)
   - Result exfiltration (POST)
   - Beacon loop implementation
   - Sleep intervals and timing

### Exercises

1. **ex01-fetch-page.c** - Fetch and Save Web Page
   - Make GET request to httpbin.org
   - Save response to file
   - Query and display headers

2. **ex02-post-data.c** - POST System Information
   - Collect computer name, username, OS
   - Format as JSON
   - POST to server
   - Verify data received

3. **ex03-beacon-checkin.c** - Beacon Implementation
   - Fetch tasks from C2
   - Execute commands with output capture
   - Send results back
   - Implement beacon loop with jitter

## Key Concepts

### WinHTTP vs WinINet

| Feature | WinHTTP | WinINet |
|---------|---------|---------|
| **Use Case** | Services, automation | Browser-like apps |
| **IE Settings** | Independent | Uses IE settings |
| **User Interaction** | Background | Interactive |
| **Stability** | High | Medium |
| **C2 Suitability** | Excellent | Poor |

### WinHTTP Request Flow

```
┌─────────────────┐
│ WinHttpOpen     │  Initialize session
└────────┬────────┘
         │
┌────────▼────────┐
│ WinHttpConnect  │  Connect to server
└────────┬────────┘
         │
┌────────▼────────────┐
│ WinHttpOpenRequest │  Create HTTP request
└────────┬────────────┘
         │
┌────────▼────────────┐
│ WinHttpSendRequest │  Send request
└────────┬────────────┘
         │
┌────────▼──────────────────┐
│ WinHttpReceiveResponse   │  Receive response
└────────┬──────────────────┘
         │
┌────────▼──────────────────────┐
│ WinHttpQueryDataAvailable    │  Check data size
└────────┬──────────────────────┘
         │
┌────────▼─────────────┐
│ WinHttpReadData     │  Read response data
└────────┬─────────────┘
         │
┌────────▼─────────────┐
│ WinHttpCloseHandle  │  Cleanup
└─────────────────────┘
```

### Beacon Check-in Pattern

```
┌──────────────┐
│ Start Beacon │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  GET /tasks  │ ◄─────┐
└──────┬───────┘       │
       │               │
       ▼               │
┌──────────────┐       │
│ Parse Task   │       │
└──────┬───────┘       │
       │               │
       ▼               │
┌──────────────┐       │
│ Execute Cmd  │       │
└──────┬───────┘       │
       │               │
       ▼               │
┌──────────────┐       │
│ POST Results │       │
└──────┬───────┘       │
       │               │
       ▼               │
┌──────────────┐       │
│ Sleep+Jitter │───────┘
└──────────────┘
```

## Important Functions

### Session Management

```c
HINTERNET WinHttpOpen(
    LPCWSTR pwszUserAgent,      // User-Agent string
    DWORD   dwAccessType,        // Proxy access type
    LPCWSTR pwszProxyName,       // Proxy name
    LPCWSTR pwszProxyBypass,     // Proxy bypass
    DWORD   dwFlags              // Flags (0 for sync)
);

HINTERNET WinHttpConnect(
    HINTERNET     hSession,      // Session handle
    LPCWSTR       pswzServerName,// Server hostname
    INTERNET_PORT nServerPort,   // Port number
    DWORD         dwReserved     // Reserved (0)
);
```

### Request Operations

```c
HINTERNET WinHttpOpenRequest(
    HINTERNET hConnect,          // Connection handle
    LPCWSTR   pwszVerb,          // HTTP method (GET/POST)
    LPCWSTR   pwszObjectName,    // Resource path
    LPCWSTR   pwszVersion,       // HTTP version (NULL)
    LPCWSTR   pwszReferrer,      // Referrer (NULL)
    LPCWSTR   *ppwszAcceptTypes, // Accept types
    DWORD     dwFlags            // WINHTTP_FLAG_SECURE for HTTPS
);

BOOL WinHttpSendRequest(
    HINTERNET hRequest,          // Request handle
    LPCWSTR   pwszHeaders,       // Additional headers
    DWORD     dwHeadersLength,   // Headers length
    LPVOID    lpOptional,        // Request body (POST)
    DWORD     dwOptionalLength,  // Body length
    DWORD     dwTotalLength,     // Total length
    DWORD_PTR dwContext          // Context for async
);
```

### Response Handling

```c
BOOL WinHttpReceiveResponse(
    HINTERNET hRequest,          // Request handle
    LPVOID    lpReserved         // Reserved (NULL)
);

BOOL WinHttpQueryHeaders(
    HINTERNET hRequest,          // Request handle
    DWORD     dwInfoLevel,       // Header to query
    LPCWSTR   pwszName,          // Header name
    LPVOID    lpBuffer,          // Output buffer
    LPDWORD   lpdwBufferLength,  // Buffer size
    LPDWORD   lpdwIndex          // Header index
);

BOOL WinHttpQueryDataAvailable(
    HINTERNET hRequest,          // Request handle
    LPDWORD   lpdwNumberOfBytesAvailable  // Output size
);

BOOL WinHttpReadData(
    HINTERNET hRequest,          // Request handle
    LPVOID    lpBuffer,          // Buffer
    DWORD     dwNumberOfBytesToRead,  // Size to read
    LPDWORD   lpdwNumberOfBytesRead   // Bytes read
);
```

## Common Content-Types

### For POST Requests

| Content-Type | Use Case | Example |
|--------------|----------|---------|
| `application/x-www-form-urlencoded` | HTML forms | `username=admin&password=secret` |
| `application/json` | JSON data | `{"user":"admin","pass":"secret"}` |
| `application/octet-stream` | Binary data | Raw bytes (screenshots, files) |
| `multipart/form-data` | File uploads | File upload with metadata |
| `text/plain` | Plain text | Simple text data |

## HTTP Status Codes

### Common Status Codes

- **200 OK** - Success
- **201 Created** - Resource created
- **204 No Content** - Success, no response body
- **301 Moved Permanently** - Redirect (permanent)
- **302 Found** - Redirect (temporary)
- **400 Bad Request** - Invalid request
- **401 Unauthorized** - Authentication required
- **403 Forbidden** - Access denied
- **404 Not Found** - Resource not found
- **500 Internal Server Error** - Server error
- **502 Bad Gateway** - Proxy error
- **503 Service Unavailable** - Server overloaded

## C2 Communication Best Practices

### 1. User-Agent Strings

```c
// Bad - Obvious malware
L"MyC2Agent/1.0"

// Good - Blend with normal traffic
L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### 2. Sleep with Jitter

```c
// Bad - Predictable
Sleep(60000);  // Always 60 seconds

// Good - Random variation
DWORD jitter = rand() % 10000;  // ±10 seconds
Sleep(60000 + jitter - 5000);
```

### 3. Error Handling

```c
// Always check return values
if (!WinHttpSendRequest(...)) {
    // Retry logic
    // Fallback mechanism
    // Don't crash - stay persistent
}
```

### 4. Resource Cleanup

```c
// Always close handles in reverse order
if (hRequest) WinHttpCloseHandle(hRequest);
if (hConnect) WinHttpCloseHandle(hConnect);
if (hSession) WinHttpCloseHandle(hSession);
```

## Compilation

### Build Single File

```batch
cl /W4 filename.c /link winhttp.lib
```

### Build All Lessons

```batch
build.bat
```

### Required Library

- **winhttp.lib** - WinHTTP import library
- Ships with Windows SDK
- Available on all Windows systems

## Testing Endpoints

### httpbin.org - HTTP Testing Service

- **GET**: `http://httpbin.org/get` - Echoes request info
- **POST**: `http://httpbin.org/post` - Echoes POST data
- **HTML**: `http://httpbin.org/html` - Returns HTML page
- **JSON**: `http://httpbin.org/json` - Returns JSON data
- **Status**: `http://httpbin.org/status/200` - Returns specific status code

### Local Testing

For C2 development, set up a local server:

```python
# Simple Python HTTP server
python -m http.server 8080

# Flask server for C2 testing
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/tasks', methods=['GET'])
def get_tasks():
    return jsonify({"command": "whoami", "task_id": "001"})

@app.route('/results', methods=['POST'])
def post_results():
    print(request.json)
    return jsonify({"status": "received"})

app.run(port=8080)
```

## Real-World C2 Examples

### Cobalt Strike HTTP Beacon

- Uses HTTP/HTTPS for communication
- GET requests to fetch tasks
- POST requests to exfiltrate data
- Supports malleable C2 profiles (custom headers, URIs)
- Jitter and sleep intervals configurable

### Metasploit HTTP(S) Meterpreter

- HTTP polling for commands
- Chunked encoding for large data
- Supports proxies
- Session management

### Sliver HTTP(S) C2

- Modern Go-based C2
- HTTP/HTTPS communication
- Mutual TLS support
- Session multiplexing

## Security Considerations

### OPSEC Tips

1. **Traffic Blending**
   - Use common User-Agent strings
   - Mimic legitimate application traffic
   - Add realistic headers (Accept, Accept-Language, etc.)

2. **Timing**
   - Variable beacon intervals
   - Jitter to avoid patterns
   - Consider business hours for stealth

3. **Encryption**
   - Always use HTTPS in production
   - Consider additional encryption layer
   - Protect C2 protocol from analysis

4. **Error Resilience**
   - Handle network failures gracefully
   - Implement retry logic
   - Multiple C2 domains/IPs for redundancy

### Anti-Detection

```c
// Add realistic headers
wchar_t headers[] =
    L"Accept: text/html,application/xhtml+xml\r\n"
    L"Accept-Language: en-US,en;q=0.9\r\n"
    L"Accept-Encoding: gzip, deflate\r\n"
    L"Cache-Control: no-cache";

// Use common endpoints
L"/api/v1/users"      // vs L"/beacon"
L"/static/js/app.js"  // vs L"/tasks"
```

## Common Errors and Solutions

### Error: WinHttpOpen Returns NULL

```c
// Check proxy settings
hSession = WinHttpOpen(
    L"UserAgent",
    WINHTTP_ACCESS_TYPE_NO_PROXY,  // Try this
    WINHTTP_NO_PROXY_NAME,
    WINHTTP_NO_PROXY_BYPASS,
    0
);
```

### Error: Failed to Send Request

```c
// Check if server is reachable
// Verify port number
// Ensure proper flags for HTTPS
```

### Error: Status Code 0

```c
// WinHttpReceiveResponse may have failed
// Check return value before querying status
if (WinHttpReceiveResponse(hRequest, NULL)) {
    // Now query status code
}
```

## Additional Resources

### Microsoft Documentation

- [WinHTTP API Documentation](https://docs.microsoft.com/en-us/windows/win32/winhttp/winhttp-start-page)
- [HTTP Protocol Specification (RFC 2616)](https://tools.ietf.org/html/rfc2616)
- [HTTPS/TLS Overview](https://docs.microsoft.com/en-us/windows/win32/secauthn/secure-sockets-layer-protocol)

### Related Topics

- **Week 08**: Winsock Basics - Low-level socket programming
- **Week 10**: HTTPS/TLS - Secure communication
- **Week 11**: C2 Channels - Advanced C2 techniques
- **Phase 4**: Encryption - Protecting C2 traffic

### Books

- "HTTP: The Definitive Guide" by David Gourley
- "Network Security Assessment" by Chris McNab
- "The Art of Invisibility" by Kevin Mitnick

## Next Steps

After completing this week:

1. Complete all exercises
2. Take the quiz (70% to pass)
3. Build a custom HTTP beacon
4. Move to Week 10: HTTPS/TLS
5. Study Cobalt Strike Malleable C2 profiles

## Quiz

Complete `quiz.json` to test your knowledge:
- 10 questions covering WinHTTP API
- Focus on practical C2 applications
- 70% passing score required
- 15-minute time limit

---

**Week 09 Complete**: You now understand HTTP-based C2 communication! Next week covers HTTPS/TLS for encrypted communication.

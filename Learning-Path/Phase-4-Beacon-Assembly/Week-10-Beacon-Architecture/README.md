# Week 10: Beacon Architecture

## Overview

Welcome to **Phase 4: Beacon Assembly**! This week marks the beginning of building a real C2 beacon from scratch. Unlike reverse shells that maintain persistent connections, beacons are stealthy implants that periodically check in to a Command & Control server using short-lived HTTP/HTTPS requests.

This week focuses on the **core architecture** of a beacon, without diving into evasion techniques yet. You'll learn the fundamental concepts, design patterns, and communication flow that make beacons effective offensive tools.

## Learning Objectives

By the end of this week, you will:

- Understand what a beacon is and how it differs from other implant types
- Design a robust beacon configuration structure
- Implement sleep loops with randomized jitter for stealth
- Create HTTP check-in mechanisms using WinINet
- Parse simple task responses from a C2 server
- Build a functional beacon skeleton ready for command execution

## Week Structure

### Lessons

1. **01-beacon-concept.c** - Beacon Fundamentals
   - What is a beacon?
   - C2 architecture overview
   - Beacon vs reverse shell comparison
   - Communication protocols
   - Beacon lifecycle and main loop

2. **02-config-struct.c** - Configuration Management
   - BEACON_CONFIG structure design
   - Required configuration fields
   - Configuration initialization
   - Configuration validation
   - Kill date implementation

3. **03-sleep-loop.c** - Sleep and Jitter
   - Why jitter is critical for stealth
   - Sleep time calculation with randomness
   - Interruptible sleep for responsiveness
   - Sleep obfuscation techniques
   - Adaptive sleep strategies

4. **04-check-in.c** - HTTP Communication
   - HTTP check-in implementation
   - Task structure design
   - Parsing server responses
   - Sending task results
   - Error handling and retries

### Exercises

1. **ex01-config-init.c** - Initialize and validate beacon configuration
2. **ex02-jitter-sleep.c** - Implement sleep with statistical jitter
3. **ex03-beacon-skeleton.c** - Build a complete beacon skeleton (config + sleep + check-in)

### Solutions

Complete, working solutions for all exercises are provided in the `Solutions/` directory.

## Key Concepts

### Beacon vs Reverse Shell

| Feature | Reverse Shell | Beacon |
|---------|--------------|--------|
| Connection | Persistent TCP | Periodic HTTP/HTTPS |
| Timing | Real-time | Asynchronous (delayed) |
| Network Pattern | Long-lived connection | Short bursts |
| Detection Risk | High (unusual connection) | Low (looks like web traffic) |
| Resilience | Dies if connection breaks | Survives network issues |
| Operator Experience | Interactive shell | Task queuing |

### Beacon Lifecycle

```
┌─────────────────────────────────────────────────────────┐
│ 1. INITIALIZATION                                       │
│    - Load configuration                                 │
│    - Generate/retrieve beacon ID                        │
│    - Initial check-in to register                       │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ 2. MAIN LOOP (runs forever)                             │
│    ┌───────────────────────────────────────────┐        │
│    │ a) Sleep for configured interval (+ jitter)│        │
│    └───────────────────────────────────────────┘        │
│                      │                                   │
│    ┌───────────────────────────────────────────┐        │
│    │ b) HTTP check-in to C2 server             │        │
│    └───────────────────────────────────────────┘        │
│                      │                                   │
│    ┌───────────────────────────────────────────┐        │
│    │ c) Receive tasks (if any)                 │        │
│    └───────────────────────────────────────────┘        │
│                      │                                   │
│    ┌───────────────────────────────────────────┐        │
│    │ d) Execute tasks sequentially             │        │
│    └───────────────────────────────────────────┘        │
│                      │                                   │
│    ┌───────────────────────────────────────────┐        │
│    │ e) Send results back to C2                │        │
│    └───────────────────────────────────────────┘        │
│                      │                                   │
│                   (repeat)                               │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ 3. TERMINATION                                          │
│    - Receive EXIT command from C2                       │
│    - Clean up resources                                 │
│    - Self-destruct (optional)                           │
└─────────────────────────────────────────────────────────┘
```

### Jitter Calculation

```
Given:
  baseSleep = 60 seconds
  jitterPercent = 20% (meaning ±20%)

Calculate:
  jitterRange = baseSleep × (jitterPercent / 100)
              = 60 × (20 / 100)
              = 12 seconds

  minSleep = baseSleep - jitterRange = 60 - 12 = 48 seconds
  maxSleep = baseSleep + jitterRange = 60 + 12 = 72 seconds

  actualSleep = random value between 48 and 72 seconds
```

**Result:** Check-ins occur at irregular intervals (48s, 67s, 51s, 72s, 59s, ...) making detection much harder.

### Configuration Structure

```c
typedef struct {
    // C2 Server
    char szHost[256];           // Hostname or IP
    DWORD dwPort;               // Port (80, 443, custom)
    BOOL bUseSSL;               // HTTP vs HTTPS

    // Timing
    DWORD dwSleepTime;          // Base sleep in seconds
    DWORD dwJitter;             // Jitter percentage (0-100)

    // Identity
    char szBeaconID[65];        // Unique identifier
    char szUserAgent[512];      // Browser User-Agent string

    // Communication
    char szCheckInPath[256];    // URI for check-ins
    char szResultPath[256];     // URI for results

    // Operational
    DWORD dwMaxRetries;         // Connection retry count
    DWORD dwRetryDelay;         // Delay between retries
    BOOL bKillDate;             // Auto-terminate after date?
    SYSTEMTIME stKillDate;      // Termination date
} BEACON_CONFIG;
```

## Compilation

All code compiles with Visual Studio's `cl.exe`:

```batch
# Lessons (some require wininet.lib)
cl.exe Lessons\01-beacon-concept.c /link wininet.lib
cl.exe Lessons\02-config-struct.c
cl.exe Lessons\03-sleep-loop.c
cl.exe Lessons\04-check-in.c /link wininet.lib

# Exercises
cl.exe Exercises\ex01-config-init.c
cl.exe Exercises\ex02-jitter-sleep.c
cl.exe Exercises\ex03-beacon-skeleton.c /link wininet.lib

# Solutions
cl.exe Solutions\sol01-config-init.c
cl.exe Solutions\sol02-jitter-sleep.c
cl.exe Solutions\sol03-beacon-skeleton.c /link wininet.lib
```

Or use the provided `build.bat` script:

```batch
build.bat
```

## Testing Your Beacon

To test the beacon skeleton with actual HTTP communication, create a simple Python C2 server:

```python
# server.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class C2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/beacon':
            beacon_id = self.headers.get('X-Beacon-ID', 'UNKNOWN')
            print(f"[*] Check-in from beacon: {beacon_id}")

            # Respond with task or no task
            self.send_response(200)
            self.end_headers()

            # Choose one:
            self.wfile.write(b"NOTASK")        # No task
            # self.wfile.write(b"SLEEP:120")   # Change sleep to 120s
            # self.wfile.write(b"EXIT")        # Terminate beacon

    def log_message(self, format, *args):
        # Customize logging
        print(f"[HTTP] {format % args}")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), C2Handler)
    print("[*] C2 Server listening on port 8080")
    print("[*] Waiting for beacon check-ins...")
    server.serve_forever()
```

Run the server:
```bash
python server.py
```

Then run your beacon:
```batch
ex03-beacon-skeleton.exe
```

You should see check-ins from the beacon to the server!

## Important Notes

### This Week's Scope

This week focuses on **architecture**, not **evasion**. We intentionally:
- Use plaintext HTTP communication (no encryption)
- Use simple string-based task format (no binary protocol)
- Don't implement API obfuscation
- Don't implement string encryption
- Don't implement anti-analysis techniques

**Why?** Because you need to understand how beacons work before making them stealthy. Evasion will be covered in later weeks.

### Operational Security Considerations

In real operations:

1. **Sleep Time**: 60-300 seconds (1-5 minutes) for stealthy ops, 5-30 seconds for active ops
2. **Jitter**: 20-50% to make timing unpredictable
3. **User-Agent**: Copy from real browsers, update regularly
4. **Paths**: Use realistic URIs (`/api/status`, `/updates`, etc.)
5. **SSL/TLS**: Always use HTTPS in production
6. **Kill Date**: Set to operation end date for auto-cleanup

## Next Week Preview

**Week 11: Command Execution**

In Week 11, we'll add actual functionality to the beacon:
- Shell command execution with output capture
- File download/upload
- Process enumeration
- System information gathering
- Building the C2 server infrastructure

The beacon skeleton you build this week will become the foundation for a fully-featured C2 implant!

## Quiz

Test your knowledge with the `quiz.json` (10 questions covering beacon concepts, jitter, configuration, and HTTP communication).

## Resources

### Recommended Reading
- "The C2 Matrix" - Comparison of real-world C2 frameworks
- Cobalt Strike documentation - Industry-standard beacon implementation
- Metasploit Meterpreter architecture
- Sliver C2 source code (open source)

### Related Windows APIs
- **WinINet**: `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`
- **Time**: `Sleep`, `GetTickCount`, `GetSystemTime`
- **Random**: `rand`, `srand`

## Troubleshooting

**Problem:** Beacon can't connect to C2 server
- **Solution:** Make sure the Python server is running and listening on the correct port (8080)
- **Solution:** Check firewall settings (Windows Firewall may block connections)

**Problem:** Jitter produces the same value every time
- **Solution:** Make sure you call `srand(time(NULL))` before using `rand()`

**Problem:** WinINet functions fail with error 12029
- **Solution:** This is `ERROR_INTERNET_CANNOT_CONNECT` - the server isn't running or hostname/port is wrong

## Summary

This week you learned:
- Beacons are periodic check-in implants using HTTP/HTTPS
- Jitter makes timing unpredictable and harder to detect
- Configuration centralizes all beacon settings
- HTTP communication uses WinINet APIs
- Task parsing enables command execution from C2 server

You now have a working beacon skeleton ready for command execution in Week 11!

---

**Next:** [Week 11: Command Execution](../Week-11-Command-Execution/README.md)

**Previous:** [Phase 3: Summary](../../Phase-3-Evasion-Techniques/README.md)

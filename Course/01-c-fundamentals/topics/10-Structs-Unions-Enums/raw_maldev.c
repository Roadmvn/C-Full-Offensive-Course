/*
 * Structs/Unions/Enums - Data structures from real malware
 * PE format, C2 protocols, Windows internals
 */

#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef unsigned long long QWORD;
typedef void* PVOID;
typedef int BOOL;
typedef WORD WCHAR;
#endif

// ============================================================================
// PE FORMAT STRUCTURES
// ============================================================================

#pragma pack(push,1)

// DOS Header (64 bytes)
typedef struct {
    WORD  e_magic;      // 0x00: "MZ" (0x5A4D)
    WORD  e_cblp;       // 0x02
    WORD  e_cp;         // 0x04
    WORD  e_crlc;       // 0x06
    WORD  e_cparhdr;    // 0x08
    WORD  e_minalloc;   // 0x0A
    WORD  e_maxalloc;   // 0x0C
    WORD  e_ss;         // 0x0E
    WORD  e_sp;         // 0x10
    WORD  e_csum;       // 0x12
    WORD  e_ip;         // 0x14
    WORD  e_cs;         // 0x16
    WORD  e_lfarlc;     // 0x18
    WORD  e_ovno;       // 0x1A
    WORD  e_res[4];     // 0x1C
    WORD  e_oemid;      // 0x24
    WORD  e_oeminfo;    // 0x26
    WORD  e_res2[10];   // 0x28
    DWORD e_lfanew;     // 0x3C: Offset to PE header
} _DOS_HDR;

// File Header (20 bytes)
typedef struct {
    WORD  Machine;              // 0x00: 0x8664 (x64), 0x014c (x86)
    WORD  NumberOfSections;     // 0x02
    DWORD TimeDateStamp;        // 0x04
    DWORD PointerToSymbolTable; // 0x08
    DWORD NumberOfSymbols;      // 0x0C
    WORD  SizeOfOptionalHeader; // 0x10
    WORD  Characteristics;      // 0x12
} _FILE_HDR;

// Data Directory
typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} _DATA_DIR;

// Optional Header (x64)
typedef struct {
    WORD  Magic;                    // 0x00: 0x20B (PE32+)
    BYTE  MajorLinkerVersion;       // 0x02
    BYTE  MinorLinkerVersion;       // 0x03
    DWORD SizeOfCode;               // 0x04
    DWORD SizeOfInitializedData;    // 0x08
    DWORD SizeOfUninitializedData;  // 0x0C
    DWORD AddressOfEntryPoint;      // 0x10
    DWORD BaseOfCode;               // 0x14
    QWORD ImageBase;                // 0x18
    DWORD SectionAlignment;         // 0x20
    DWORD FileAlignment;            // 0x24
    WORD  MajorOSVersion;           // 0x28
    WORD  MinorOSVersion;           // 0x2A
    WORD  MajorImageVersion;        // 0x2C
    WORD  MinorImageVersion;        // 0x2E
    WORD  MajorSubsystemVersion;    // 0x30
    WORD  MinorSubsystemVersion;    // 0x32
    DWORD Win32VersionValue;        // 0x34
    DWORD SizeOfImage;              // 0x38
    DWORD SizeOfHeaders;            // 0x3C
    DWORD CheckSum;                 // 0x40
    WORD  Subsystem;                // 0x44
    WORD  DllCharacteristics;       // 0x46
    QWORD SizeOfStackReserve;       // 0x48
    QWORD SizeOfStackCommit;        // 0x50
    QWORD SizeOfHeapReserve;        // 0x58
    QWORD SizeOfHeapCommit;         // 0x60
    DWORD LoaderFlags;              // 0x68
    DWORD NumberOfRvaAndSizes;      // 0x6C
    _DATA_DIR DataDirectory[16];    // 0x70
} _OPT_HDR64;

// Section Header (40 bytes)
typedef struct {
    char  Name[8];              // 0x00
    DWORD VirtualSize;          // 0x08
    DWORD VirtualAddress;       // 0x0C
    DWORD SizeOfRawData;        // 0x10
    DWORD PointerToRawData;     // 0x14
    DWORD PointerToRelocations; // 0x18
    DWORD PointerToLinenumbers; // 0x1C
    WORD  NumberOfRelocations;  // 0x20
    WORD  NumberOfLinenumbers;  // 0x22
    DWORD Characteristics;      // 0x24
} _SEC_HDR;

// Export Directory
typedef struct {
    DWORD Characteristics;      // 0x00
    DWORD TimeDateStamp;        // 0x04
    WORD  MajorVersion;         // 0x08
    WORD  MinorVersion;         // 0x0A
    DWORD Name;                 // 0x0C
    DWORD Base;                 // 0x10
    DWORD NumberOfFunctions;    // 0x14
    DWORD NumberOfNames;        // 0x18
    DWORD AddressOfFunctions;   // 0x1C
    DWORD AddressOfNames;       // 0x20
    DWORD AddressOfNameOrdinals;// 0x24
} _EXP_DIR;

// Import Descriptor
typedef struct {
    DWORD OriginalFirstThunk;   // 0x00: RVA to INT
    DWORD TimeDateStamp;        // 0x04
    DWORD ForwarderChain;       // 0x08
    DWORD Name;                 // 0x0C: RVA to DLL name
    DWORD FirstThunk;           // 0x10: RVA to IAT
} _IMP_DESC;

#pragma pack(pop)

// ============================================================================
// WINDOWS INTERNALS - PEB/TEB
// ============================================================================

// UNICODE_STRING
typedef struct {
    WORD  Length;
    WORD  MaximumLength;
    WCHAR* Buffer;
} _UNICODE_STRING;

// LDR_DATA_TABLE_ENTRY (simplified)
typedef struct _LDR_ENTRY {
    struct {
        struct _LDR_ENTRY* Flink;
        struct _LDR_ENTRY* Blink;
    } InLoadOrderLinks;
    struct {
        struct _LDR_ENTRY* Flink;
        struct _LDR_ENTRY* Blink;
    } InMemoryOrderLinks;
    struct {
        struct _LDR_ENTRY* Flink;
        struct _LDR_ENTRY* Blink;
    } InInitOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    DWORD SizeOfImage;
    _UNICODE_STRING FullDllName;
    _UNICODE_STRING BaseDllName;
} _LDR_ENTRY;

// PEB_LDR_DATA
typedef struct {
    DWORD Length;
    BYTE  Initialized;
    PVOID SsHandle;
    struct { _LDR_ENTRY* Flink; _LDR_ENTRY* Blink; } InLoadOrderModuleList;
    struct { _LDR_ENTRY* Flink; _LDR_ENTRY* Blink; } InMemoryOrderModuleList;
    struct { _LDR_ENTRY* Flink; _LDR_ENTRY* Blink; } InInitOrderModuleList;
} _PEB_LDR;

// PEB (Process Environment Block)
typedef struct {
    BYTE  InheritedAddressSpace;    // 0x00
    BYTE  ReadImageFileExecOptions; // 0x01
    BYTE  BeingDebugged;            // 0x02  <- anti-debug check
    BYTE  BitField;                 // 0x03
    PVOID Mutant;                   // 0x08
    PVOID ImageBaseAddress;         // 0x10
    _PEB_LDR* Ldr;                  // 0x18  <- module list
    // ... more fields
} _PEB;

// TEB (Thread Environment Block)
typedef struct {
    PVOID Reserved1[12];
    _PEB* ProcessEnvironmentBlock;  // 0x60 (x64)
    // ... more fields
} _TEB;

// ============================================================================
// C2 PROTOCOL STRUCTURES
// ============================================================================

#pragma pack(push,1)

// Cobalt Strike beacon config
typedef struct {
    WORD  version;          // 0x00
    WORD  payload_type;     // 0x02
    DWORD port;             // 0x04
    DWORD sleeptime;        // 0x08
    DWORD maxget;           // 0x0C
    DWORD jitter;           // 0x10
    DWORD maxdns;           // 0x14
    BYTE  publickey[256];   // 0x18
    BYTE  c2_server[256];   // 0x118
    BYTE  user_agent[128];  // 0x218
    BYTE  http_get_uri[64]; // 0x298
    // ... more config
} CS_BEACON_CFG;

// Check-in packet
typedef struct {
    DWORD magic;            // 0xDEADBEEF
    DWORD beacon_id;
    DWORD timestamp;
    BYTE  iv[16];
    DWORD enc_len;
    // BYTE encrypted_data[];
} CHECKIN_PKT;

// Task header
typedef struct {
    DWORD task_id;
    WORD  task_type;
    WORD  flags;
    DWORD data_len;
    // BYTE data[];
} TASK_HDR;

// Response header
typedef struct {
    DWORD task_id;
    DWORD status;
    DWORD data_len;
    // BYTE data[];
} RESP_HDR;

#pragma pack(pop)

// Task types enum
enum {
    CMD_SHELL       = 0x01,
    CMD_UPLOAD      = 0x02,
    CMD_DOWNLOAD    = 0x03,
    CMD_EXECUTE     = 0x04,
    CMD_INJECT      = 0x05,
    CMD_KEYLOG_START= 0x10,
    CMD_KEYLOG_STOP = 0x11,
    CMD_SCREENSHOT  = 0x20,
    CMD_EXIT        = 0xFF
};

// ============================================================================
// NETWORK STRUCTURES
// ============================================================================

#pragma pack(push,1)

typedef struct {
    BYTE  dst_mac[6];
    BYTE  src_mac[6];
    WORD  ethertype;
} ETH_HDR;

typedef struct {
    BYTE  ver_ihl;      // version:4, ihl:4
    BYTE  tos;
    WORD  total_len;
    WORD  id;
    WORD  flags_frag;   // flags:3, frag_offset:13
    BYTE  ttl;
    BYTE  protocol;
    WORD  checksum;
    DWORD src_ip;
    DWORD dst_ip;
} IP_HDR;

typedef struct {
    WORD  src_port;
    WORD  dst_port;
    DWORD seq_num;
    DWORD ack_num;
    BYTE  data_offset;  // offset:4, reserved:4
    BYTE  flags;
    WORD  window;
    WORD  checksum;
    WORD  urgent_ptr;
} TCP_HDR;

typedef struct {
    WORD  src_port;
    WORD  dst_port;
    WORD  length;
    WORD  checksum;
} UDP_HDR;

typedef struct {
    WORD  id;
    WORD  flags;
    WORD  qdcount;
    WORD  ancount;
    WORD  nscount;
    WORD  arcount;
} DNS_HDR;

#pragma pack(pop)

// ============================================================================
// UNION FOR TYPE PUNNING
// ============================================================================

typedef union {
    DWORD dw;
    WORD  w[2];
    BYTE  b[4];
} VIEW32;

typedef union {
    QWORD qw;
    DWORD dw[2];
    WORD  w[4];
    BYTE  b[8];
} VIEW64;

typedef union {
    DWORD ip;
    BYTE  oct[4];
} IP_ADDR;

// ============================================================================
// CRYPTO CONFIG STRUCTURES
// ============================================================================

#pragma pack(push,1)

// RC4 encrypted blob header
typedef struct {
    BYTE  key[16];
    DWORD data_len;
    // BYTE encrypted[];
} RC4_BLOB;

// AES encrypted blob
typedef struct {
    BYTE  iv[16];
    BYTE  key[32];
    DWORD data_len;
    // BYTE encrypted[];
} AES_BLOB;

// XOR config
typedef struct {
    BYTE  key;
    DWORD len;
    DWORD offset;
} XOR_CFG;

#pragma pack(pop)

// ============================================================================
// GHIDRA DECOMPILER OUTPUT STYLE
// ============================================================================

// What you see before recovery
typedef struct _UNK_STRUCT_0x28 {
    DWORD dw0;
    DWORD dw4;
    PVOID p8;
    DWORD dwC;
    DWORD dw10;
    QWORD q18;
    DWORD dw20;
    DWORD dw24;
} UNK_0x28;

// After analysis - recovered structure
typedef struct {
    DWORD beacon_id;
    DWORD timestamp;
    PVOID config_ptr;
    DWORD sleep_time;
    DWORD jitter;
    QWORD session_key;
    DWORD flags;
    DWORD status;
} BEACON_STATE;

// ============================================================================
// HELPER MACROS
// ============================================================================

// Container of - get struct from member pointer
#define CONTAINING_RECORD(addr, type, field) \
    ((type*)((BYTE*)(addr) - offsetof(type, field)))

// List entry walking
#define LIST_ENTRY_NEXT(entry) ((entry)->Flink)
#define LIST_ENTRY_PREV(entry) ((entry)->Blink)

// ============================================================================
// EOF
// ============================================================================

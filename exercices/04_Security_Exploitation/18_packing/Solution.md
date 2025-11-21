SOLUTIONS - Module 40 : Packing & Unpacking

AVERTISSEMENT : Solutions educatives uniquement. Ne jamais utiliser pour evasion malware.

Solution 1 : Entropy Analyzer

Analyse entropie par section PE avec detection anomalies.

```c

```c
void analyze_pe_sections(const char* filename) {
```
    size_t filesize;
    unsigned char* data = read_file(filename, &filesize);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)
        ((char*)nt + sizeof(IMAGE_NT_HEADERS));

    printf("Section         Size      Entropy   Status\n");
    printf("------------------------------------------------\n");

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        unsigned char* section_data = data + section[i].PointerToRawData;
        double entropy = calculate_entropy(section_data, section[i].SizeOfRawData);

        printf("%-15.8s %-9u %.2f     ", section[i].Name,
               section[i].SizeOfRawData, entropy);

        if (entropy > 7.5) printf("SUSPICIOUS (packed/encrypted)\n");
        else if (entropy > 6.5) printf("Compressed?\n");
        else printf("Normal\n");
    }

    free(data);
}
```

Solution 2 : Multi-Layer XOR Packer

Packing multi-couches avec XOR + ADD + ROL operations.

```c

```c
void multilayer_pack(unsigned char* data, size_t len, uint8_t* keys, int layers) {
```
    for (int layer = 0; layer < layers; layer++) {
        uint8_t key = keys[layer];

        switch (layer % 3) {
            case 0:  // XOR
                for (size_t i = 0; i < len; i++) data[i] ^= key;
                break;
            case 1:  // ADD
                for (size_t i = 0; i < len; i++) data[i] += key;
                break;
            case 2:  // ROL
                for (size_t i = 0; i < len; i++) {
                    data[i] = (data[i] << (key % 8)) | (data[i] >> (8 - (key % 8)));
                }
                break;
        }
    }
    printf("[+] Applied %d encryption layers\n", layers);
}


```c
void multilayer_unpack(unsigned char* data, size_t len, uint8_t* keys, int layers) {
    // Inversion ordre (LIFO)
```
    for (int layer = layers - 1; layer >= 0; layer--) {
        uint8_t key = keys[layer];

        switch (layer % 3) {
            case 0:  // XOR (symetrique)
                for (size_t i = 0; i < len; i++) data[i] ^= key;
                break;
            case 1:  // SUB (inverse ADD)
                for (size_t i = 0; i < len; i++) data[i] -= key;
                break;
            case 2:  // ROR (inverse ROL)
                for (size_t i = 0; i < len; i++) {
                    data[i] = (data[i] >> (key % 8)) | (data[i] << (8 - (key % 8)));
                }
                break;
        }
    }
}
```

Solution 3 : Compression Packer (zlib)

Integration compression zlib dans packer.

```c

```c
#include <zlib.h>
```

int compress_data(unsigned char* input, size_t input_len,
                  unsigned char* output, size_t* output_len) {
    z_stream stream = {0};
    stream.next_in = input;
    stream.avail_in = input_len;
    stream.next_out = output;
    stream.avail_out = *output_len;

    if (deflateInit(&stream, Z_BEST_COMPRESSION) != Z_OK) {
        return -1;
    }

    int ret = deflate(&stream, Z_FINISH);
    deflateEnd(&stream);

    if (ret != Z_STREAM_END) {
        return -1;
    }

    *output_len = stream.total_out;
    printf("[+] Compression ratio: %.2f%%\n",
           100.0 * (1.0 - (double)*output_len / input_len));
    return 0;
}

int decompress_data(unsigned char* input, size_t input_len,
                    unsigned char* output, size_t output_len) {
    z_stream stream = {0};
    stream.next_in = input;
    stream.avail_in = input_len;
    stream.next_out = output;
    stream.avail_out = output_len;

    if (inflateInit(&stream) != Z_OK) {
        return -1;
    }

    int ret = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);

    return (ret == Z_STREAM_END) ? 0 : -1;
}
```

Solution 4 : Stub Unpacker Executable

Stub prepended au payload avec unpacking runtime.

```c

```c
// Stub unpacker (prepend au payload packe)
void __attribute__((section(".stub"))) unpacker_stub(void) {
    // Header situe apres stub
```
    PackHeader* header = (PackHeader*)((char*)unpacker_stub + 4096);
    unsigned char* packed_data = (unsigned char*)(header + 1);


```c
    // Allouer memoire pour payload original
    void* mem = VirtualAlloc(NULL, header->original_size,
```
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


```c
    // Copier et decrypter
```
    memcpy(mem, packed_data, header->packed_size);
    xor_crypt(mem, header->packed_size, header->key, header->key_length);


```c
    // Jump vers OEP du payload
    void (*entry_point)(void) = mem;
```
    entry_point();
}


```c
// Construction fichier packe avec stub
int create_packed_executable(const char* input, const char* output) {
    // 1. Compiler stub unpacker
    // 2. Lire payload original
    // 3. Packer payload
    // 4. Concatener: [stub][header][packed_payload]
    // 5. Modifier PE entry point vers stub
}
```
```

Solution 5 : Import Table Reconstruction

Resolution dynamique imports dans stub unpacker.

```c

```c
typedef struct {
    char dll_name[64];
    char func_name[64];
```
    uint32_t rva_iat;
} ImportEntry;


```c
void reconstruct_imports(void* image_base, ImportEntry* imports, int count) {
```
    for (int i = 0; i < count; i++) {
        HMODULE dll = LoadLibraryA(imports[i].dll_name);
        if (!dll) continue;

        void* func_addr = GetProcAddress(dll, imports[i].func_name);
        if (!func_addr) continue;


```c
        // Ecrire adresse dans IAT
        void** iat_entry = (void**)((char*)image_base + imports[i].rva_iat);
```
        *iat_entry = func_addr;

        printf("[+] Resolved %s!%s -> 0x%p\n",
               imports[i].dll_name, imports[i].func_name, func_addr);
    }
}
```

Solution 6 : Anti-Unpacking Techniques

Detection debugging/VM dans stub unpacker.

```c
int detect_debugger(void) {

```bash
    #ifdef _WIN32
```
    if (IsDebuggerPresent()) return 1;

    BOOL remote_debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
    if (remote_debugger) return 1;

```bash
    #endif
```

    return 0;
}

int detect_vm(void) {

```c
    // CPUID check
```
    unsigned int cpuid_result[4];
    __cpuid(cpuid_result, 1);


```c
    // VMware detection
```
    if ((cpuid_result[2] >> 31) & 1) return 1;


```c
    // Timing check (VM plus lent)
```
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(10);
    QueryPerformanceCounter(&end);

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    if (elapsed > 0.05) return 1;  // VM overhead detecte

    return 0;
}


```c
void stub_with_anti_analysis(void) {
```
    if (detect_debugger() || detect_vm()) {

```c
        // Comportement benin ou self-destruct
```
        ExitProcess(0);
    }


```c
    // Continue unpacking...
}
```
```

Solution 7 : Dynamic Unpacking & Dump

Script x64dbg/gdb pour unpacking automatise.

```javascript

```c
// x64dbg script
```
var base = Process.GetMainModule().base;
var size = Process.GetMainModule().size;


```c
// Breakpoint sur VirtualAlloc/VirtualProtect
```
bp("VirtualAlloc", function() {
    log("VirtualAlloc called");
    var ret_addr = Memory.ReadPtr(Register("rsp"));
    bp(ret_addr, function() {
        var allocated = Register("rax");
        log("Allocated memory: " + allocated.toString(16));


```c
        // Breakpoint sur premiere ecriture
```
        Memory.Protect(allocated, 0x1000, PAGE_READONLY);
    }, true);
});


```c
// Detecter changement entropy (unpacking complete)
```
setInterval(function() {
    var entropy = calculateEntropy(base, 0x1000);
    if (entropy < 6.0) {  // Unpacked!
        log("[+] Low entropy detected - OEP reached");
        Process.Suspend();
        Memory.Dump(base, size, "unpacked.bin");
        Process.Exit();
    }
}, 100);
```

Solution 8 : Polymorphic Packer

Generation stub unpacker variable a chaque execution.

```c

```c
typedef struct {
```
    uint8_t opcode;
    uint8_t reg_src;
    uint8_t reg_dst;
    uint8_t operand;
} Instruction;


```c
void generate_polymorphic_stub(unsigned char* output, size_t* len) {
    // Randomiser registres utilises
    int regs[] = {REG_EAX, REG_EBX, REG_ECX, REG_EDX};
```
    shuffle(regs, 4);

    int pc = 0;


```c
    // MOV reg, [key_addr]
```
    output[pc++] = 0x8B;
    output[pc++] = 0x05 | (regs[0] << 3);


```c
    // XOR loop avec junk instructions
```
    for (int i = 0; i < rand() % 5; i++) {

```c
        // NOP variations
```
        output[pc++] = 0x90 + (rand() % 8);
    }


```c
    // XOR [data], reg
```
    output[pc++] = 0x31;
    output[pc++] = 0x05 | (regs[0] << 3);

    *len = pc;
    printf("[+] Generated %zu-byte polymorphic stub\n", *len);
}
```

POINTS CLES

- Packing efficace combine compression + encryption
- Entropy analysis detecte packing avec >95% precision
- Unpacking dynamique plus fiable que statique
- Anti-analysis complique mais pas impossible a bypass
- Blue team utilise memory scanning pour contrer

DETECTION PAR BLUE TEAM

1. Entropy scanning (Yara rules, PE scanners)
2. Behavioral analysis (VirtualAlloc, WriteProcessMemory)
3. Memory dumps periodiques durant execution
4. API hooking pour monitorer unpacking
5. Sandboxing avec snapshots memoire

CONTRE-MESURES

- EDR avec memory scanning
- Application whitelisting
- Deep packet inspection (C2 traffic)
- YARA rules packers connus
- Automated unpacking pipelines


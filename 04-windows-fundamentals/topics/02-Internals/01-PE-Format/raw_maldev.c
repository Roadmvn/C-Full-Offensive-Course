/*
 * PE Format - Parsing primitives for loaders, packers, injectors
 * What you see in reflective loaders, Cobalt Strike beacon, Donut
 */

#include <windows.h>

// ============================================================================
// PE NAVIGATION MACROS
// ============================================================================

#define RVA(b,r)     ((BYTE*)(b)+(r))
#define DEREF(p)     (*(DWORD_PTR*)(p))
#define DEREF32(p)   (*(DWORD*)(p))
#define DEREF16(p)   (*(WORD*)(p))

// Header access
#define DOS(m)       ((PIMAGE_DOS_HEADER)(m))
#define NT(m)        ((PIMAGE_NT_HEADERS)RVA(m,DOS(m)->e_lfanew))
#define FILE_H(m)    (&NT(m)->FileHeader)
#define OPT(m)       (&NT(m)->OptionalHeader)
#define SEC(m)       ((PIMAGE_SECTION_HEADER)RVA(m,DOS(m)->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+FILE_H(m)->SizeOfOptionalHeader))

// Data directories
#define DIR(m,i)     (&OPT(m)->DataDirectory[i])
#define EXP(m)       ((PIMAGE_EXPORT_DIRECTORY)RVA(m,DIR(m,0)->VirtualAddress))
#define IMP(m)       ((PIMAGE_IMPORT_DESCRIPTOR)RVA(m,DIR(m,1)->VirtualAddress))
#define RES(m)       ((PIMAGE_RESOURCE_DIRECTORY)RVA(m,DIR(m,2)->VirtualAddress))
#define RELOC(m)     ((PIMAGE_BASE_RELOCATION)RVA(m,DIR(m,5)->VirtualAddress))
#define TLS(m)       ((PIMAGE_TLS_DIRECTORY)RVA(m,DIR(m,9)->VirtualAddress))

// ============================================================================
// VALIDATION
// ============================================================================

#define IS_PE(m)     (DEREF16(m)==0x5A4D && DEREF32(RVA(m,DEREF32(RVA(m,0x3C))))==0x4550)
#define IS_64(m)     (OPT(m)->Magic==0x20B)
#define IS_DLL(m)    (FILE_H(m)->Characteristics&0x2000)

// ============================================================================
// HASH FUNCTIONS
// ============================================================================

// ROR13 - Metasploit block_api compatible
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

__forceinline DWORD hash_ror13(char* s)
{
    DWORD h = 0;
    while(*s) { h = ROR(h, 13); h += *s++; }
    return h;
}

// DJB2 - widely used
__forceinline DWORD hash_djb2(char* s)
{
    DWORD h = 5381;
    while(*s) h = ((h << 5) + h) + *s++;
    return h;
}

// Case insensitive hash for DLL names
__forceinline DWORD hash_dll(WCHAR* s)
{
    DWORD h = 0;
    while(*s) {
        WCHAR c = *s++;
        if(c >= 'A' && c <= 'Z') c += 0x20;
        h = ROR(h, 13);
        h += c;
    }
    return h;
}

// ============================================================================
// EXPORT RESOLUTION
// ============================================================================

PVOID get_proc_by_name(PVOID base, char* name)
{
    PIMAGE_EXPORT_DIRECTORY exp = EXP(base);
    DWORD* names = (DWORD*)RVA(base, exp->AddressOfNames);
    WORD*  ords  = (WORD*)RVA(base, exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)RVA(base, exp->AddressOfFunctions);

    for(DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fn = (char*)RVA(base, names[i]);
        char* a = fn; char* b = name;
        while(*a && *a == *b) { a++; b++; }
        if(*a == *b)
            return RVA(base, funcs[ords[i]]);
    }
    return 0;
}

PVOID get_proc_by_hash(PVOID base, DWORD hash)
{
    PIMAGE_EXPORT_DIRECTORY exp = EXP(base);
    DWORD* names = (DWORD*)RVA(base, exp->AddressOfNames);
    WORD*  ords  = (WORD*)RVA(base, exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)RVA(base, exp->AddressOfFunctions);

    for(DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fn = (char*)RVA(base, names[i]);
        if(hash_ror13(fn) == hash)
            return RVA(base, funcs[ords[i]]);
    }
    return 0;
}

PVOID get_proc_by_ordinal(PVOID base, WORD ord)
{
    PIMAGE_EXPORT_DIRECTORY exp = EXP(base);
    DWORD* funcs = (DWORD*)RVA(base, exp->AddressOfFunctions);
    ord -= (WORD)exp->Base;
    if(ord >= exp->NumberOfFunctions) return 0;
    return RVA(base, funcs[ord]);
}

// Check for forwarded export
BOOL is_forwarded(PVOID base, PVOID func)
{
    PIMAGE_DATA_DIRECTORY dir = DIR(base, 0);
    DWORD rva = (DWORD)((BYTE*)func - (BYTE*)base);
    return (rva >= dir->VirtualAddress && rva < dir->VirtualAddress + dir->Size);
}

// ============================================================================
// SECTION OPERATIONS
// ============================================================================

PIMAGE_SECTION_HEADER get_section(PVOID base, char* name)
{
    WORD count = FILE_H(base)->NumberOfSections;
    PIMAGE_SECTION_HEADER sec = SEC(base);

    for(WORD i = 0; i < count; i++) {
        int j;
        for(j = 0; j < 8 && sec[i].Name[j] == name[j]; j++);
        if(j == 8 || (!sec[i].Name[j] && !name[j]))
            return &sec[i];
    }
    return 0;
}

PIMAGE_SECTION_HEADER rva_to_section(PVOID base, DWORD rva)
{
    WORD count = FILE_H(base)->NumberOfSections;
    PIMAGE_SECTION_HEADER sec = SEC(base);

    for(WORD i = 0; i < count; i++) {
        if(rva >= sec[i].VirtualAddress &&
           rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            return &sec[i];
    }
    return 0;
}

DWORD rva_to_raw(PVOID base, DWORD rva)
{
    PIMAGE_SECTION_HEADER sec = rva_to_section(base, rva);
    if(!sec) return 0;
    return rva - sec->VirtualAddress + sec->PointerToRawData;
}

// ============================================================================
// RELOCATION PROCESSING
// ============================================================================

void process_relocs(PVOID base, DWORD_PTR delta)
{
    PIMAGE_DATA_DIRECTORY dir = DIR(base, 5);
    if(!dir->Size) return;

    PIMAGE_BASE_RELOCATION reloc = RELOC(base);

    while(reloc->VirtualAddress) {
        DWORD count = (reloc->SizeOfBlock - 8) / 2;
        WORD* entry = (WORD*)(reloc + 1);

        for(DWORD i = 0; i < count; i++) {
            BYTE type = entry[i] >> 12;
            WORD off  = entry[i] & 0xFFF;
            PVOID addr = RVA(base, reloc->VirtualAddress + off);

            if(type == IMAGE_REL_BASED_HIGHLOW)
                *(DWORD*)addr += (DWORD)delta;
            else if(type == IMAGE_REL_BASED_DIR64)
                *(QWORD*)addr += delta;
        }

        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}

// ============================================================================
// IMPORT RESOLUTION
// ============================================================================

typedef HMODULE (WINAPI *t_LLA)(LPCSTR);
typedef FARPROC (WINAPI *t_GPA)(HMODULE, LPCSTR);

void process_imports(PVOID base, t_LLA pLLA, t_GPA pGPA)
{
    PIMAGE_IMPORT_DESCRIPTOR imp = IMP(base);

    while(imp->Name) {
        char* dll = (char*)RVA(base, imp->Name);
        HMODULE hMod = pLLA(dll);

        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)RVA(base,
            imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk);
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)RVA(base, imp->FirstThunk);

        while(orig->u1.AddressOfData) {
            if(orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                iat->u1.Function = (ULONGLONG)pGPA(hMod, (LPCSTR)(orig->u1.Ordinal & 0xFFFF));
            else {
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)RVA(base, orig->u1.AddressOfData);
                iat->u1.Function = (ULONGLONG)pGPA(hMod, ibn->Name);
            }
            orig++; iat++;
        }
        imp++;
    }
}

// ============================================================================
// TLS CALLBACKS
// ============================================================================

void run_tls_callbacks(PVOID base, DWORD reason)
{
    PIMAGE_DATA_DIRECTORY dir = DIR(base, 9);
    if(!dir->Size) return;

    PIMAGE_TLS_DIRECTORY tls = TLS(base);
    PIMAGE_TLS_CALLBACK* cbs = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

    if(!cbs) return;

    while(*cbs) {
        (*cbs)(base, reason, 0);
        cbs++;
    }
}

// ============================================================================
// REFLECTIVE LOADER PATTERN
// ============================================================================

PVOID load_pe(PVOID raw, DWORD raw_sz)
{
    if(!IS_PE(raw)) return 0;

    DWORD img_sz = OPT(raw)->SizeOfImage;
    PVOID base = VirtualAlloc((PVOID)OPT(raw)->ImageBase, img_sz, 0x3000, 0x40);
    if(!base)
        base = VirtualAlloc(0, img_sz, 0x3000, 0x40);
    if(!base) return 0;

    // Copy headers
    __movsb(base, raw, OPT(raw)->SizeOfHeaders);

    // Copy sections
    WORD nsec = FILE_H(raw)->NumberOfSections;
    PIMAGE_SECTION_HEADER sec = SEC(raw);
    for(WORD i = 0; i < nsec; i++) {
        if(sec[i].SizeOfRawData)
            __movsb(RVA(base, sec[i].VirtualAddress),
                    RVA(raw, sec[i].PointerToRawData),
                    sec[i].SizeOfRawData);
    }

    // Process relocations
    DWORD_PTR delta = (DWORD_PTR)base - OPT(raw)->ImageBase;
    if(delta)
        process_relocs(base, delta);

    // Process imports
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    t_LLA pLLA = (t_LLA)get_proc_by_name(k32, "LoadLibraryA");
    t_GPA pGPA = (t_GPA)get_proc_by_name(k32, "GetProcAddress");
    process_imports(base, pLLA, pGPA);

    // Run TLS callbacks
    run_tls_callbacks(base, DLL_PROCESS_ATTACH);

    // Set section protections
    for(WORD i = 0; i < nsec; i++) {
        DWORD prot = 0;
        DWORD chr = sec[i].Characteristics;

        if(chr & IMAGE_SCN_MEM_EXECUTE)
            prot = (chr & IMAGE_SCN_MEM_WRITE) ? 0x40 : 0x20;
        else
            prot = (chr & IMAGE_SCN_MEM_WRITE) ? 0x04 : 0x02;

        DWORD old;
        VirtualProtect(RVA(base, sec[i].VirtualAddress),
                       sec[i].Misc.VirtualSize, prot, &old);
    }

    return base;
}

// ============================================================================
// CODE CAVE FINDER
// ============================================================================

DWORD find_cave(PVOID base, DWORD min_sz)
{
    WORD nsec = FILE_H(base)->NumberOfSections;
    PIMAGE_SECTION_HEADER sec = SEC(base);

    for(WORD i = 0; i < nsec; i++) {
        // Only in executable sections
        if(!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE* start = RVA(base, sec[i].VirtualAddress);
        BYTE* end = start + sec[i].Misc.VirtualSize;

        DWORD cave_sz = 0;
        BYTE* cave_start = 0;

        for(BYTE* p = start; p < end; p++) {
            if(*p == 0x00 || *p == 0xCC) {
                if(!cave_start) cave_start = p;
                cave_sz++;
            } else {
                if(cave_sz >= min_sz)
                    return (DWORD)(cave_start - (BYTE*)base);
                cave_sz = 0;
                cave_start = 0;
            }
        }

        if(cave_sz >= min_sz)
            return (DWORD)(cave_start - (BYTE*)base);
    }
    return 0;
}

// ============================================================================
// PRECOMPUTED API HASHES (ROR13)
// ============================================================================

#define H_KERNEL32           0x6A4ABC5B
#define H_NTDLL              0x3CFA685D
#define H_LOADLIBRARYA       0xEC0E4E8E
#define H_GETPROCADDRESS     0x7C0DFCAA
#define H_VIRTUALALLOC       0x91AFCA54
#define H_VIRTUALPROTECT     0x7946C61B
#define H_VIRTUALFREE        0x30633AC
#define H_CREATETHREAD       0xCA2BD06B
#define H_GETMODULEHANDLEA   0xD3324904
#define H_EXITPROCESS        0x73E2D87E

// ============================================================================
// EOF
// ============================================================================

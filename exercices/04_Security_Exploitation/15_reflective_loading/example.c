/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 37 : Reflective PE Loading (Windows only)
 */

#ifdef _WIN32
#include <windows.h>
#include <stdio.h>

// Simplified PE loader demo
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

// 1. Parse PE headers
int parse_pe_headers(BYTE* pe_buffer, IMAGE_DOS_HEADER** dos, IMAGE_NT_HEADERS** nt) {
    *dos = (IMAGE_DOS_HEADER*)pe_buffer;

    if ((*dos)->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return 0;
    }

    *nt = (IMAGE_NT_HEADERS*)(pe_buffer + (*dos)->e_lfanew);

    if ((*nt)->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid PE signature\n");
        return 0;
    }

    printf("[+] PE headers parsed successfully\n");
    printf("[*] Number of sections: %d\n", (*nt)->FileHeader.NumberOfSections);
    printf("[*] Entry point RVA: 0x%X\n", (*nt)->OptionalHeader.AddressOfEntryPoint);

    return 1;
}

// 2. Copy PE sections to memory
LPVOID copy_pe_to_memory(BYTE* pe_buffer, IMAGE_NT_HEADERS* nt_headers) {
    LPVOID base = VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!base) {
        printf("[-] VirtualAlloc failed\n");
        return NULL;
    }

    printf("[+] Allocated memory at: %p\n", base);

    // Copy headers
    memcpy(base, pe_buffer, nt_headers->OptionalHeader.SizeOfHeaders);

    // Copy sections
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPBYTE)base + section[i].VirtualAddress;
        LPVOID src = pe_buffer + section[i].PointerToRawData;

        memcpy(dest, src, section[i].SizeOfRawData);
        printf("[*] Copied section: %.8s to %p\n", section[i].Name, dest);
    }

    return base;
}

// 3. Resolve imports (simplified)
void resolve_imports(LPVOID base_address, IMAGE_NT_HEADERS* nt_headers) {
    IMAGE_DATA_DIRECTORY* import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_dir->Size == 0) {
        printf("[*] No imports to resolve\n");
        return;
    }

    IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)((LPBYTE)base_address + import_dir->VirtualAddress);

    printf("[+] Resolving imports...\n");

    while (import_desc->Name) {
        char* dll_name = (char*)((LPBYTE)base_address + import_desc->Name);
        printf("[*] Loading: %s\n", dll_name);

        HMODULE dll = LoadLibraryA(dll_name);
        if (!dll) {
            printf("[-] Failed to load %s\n", dll_name);
            import_desc++;
            continue;
        }

        // Resolve functions (simplified - just count them)
        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((LPBYTE)base_address + import_desc->FirstThunk);
        int func_count = 0;
        while (thunk->u1.AddressOfData) {
            func_count++;
            thunk++;
        }
        printf("    [*] %d functions\n", func_count);

        import_desc++;
    }
}

// 4. Apply relocations (simplified demo)
void apply_relocations(LPVOID base_address, IMAGE_NT_HEADERS* nt_headers) {
    DWORD_PTR delta = (DWORD_PTR)base_address - nt_headers->OptionalHeader.ImageBase;

    if (delta == 0) {
        printf("[*] No relocation needed (loaded at preferred base)\n");
        return;
    }

    printf("[+] Applying relocations (delta: 0x%llX)\n", delta);

    IMAGE_DATA_DIRECTORY* reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir->Size == 0) {
        printf("[*] No relocations present\n");
        return;
    }

    printf("[*] Relocation table at RVA: 0x%X\n", reloc_dir->VirtualAddress);
}

// 5. Execute entry point (DllMain)
void execute_entry_point(LPVOID base_address, IMAGE_NT_HEADERS* nt_headers) {
    printf("\n[!] NOTE: Actual execution skipped in demo (would crash)\n");
    printf("[*] Entry point would be at: %p\n",
           (LPBYTE)base_address + nt_headers->OptionalHeader.AddressOfEntryPoint);

    // In real reflective loader:
    // DllMain_t entry = (DllMain_t)((LPBYTE)base_address + nt_headers->OptionalHeader.AddressOfEntryPoint);
    // entry((HINSTANCE)base_address, DLL_PROCESS_ATTACH, NULL);
}

int main(int argc, char* argv[]) {
    printf("\n⚠️  AVERTISSEMENT : Reflective PE loading demo\n");
    printf("   Usage éducatif uniquement. Tests VM isolées.\n\n");

    if (argc < 2) {
        printf("Usage: %s <pe_file.dll>\n", argv[0]);
        return 1;
    }

    // Load PE file to buffer
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s\n", argv[1]);
        return 1;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE* pe_buffer = (BYTE*)malloc(file_size);

    DWORD bytes_read;
    ReadFile(hFile, pe_buffer, file_size, &bytes_read, NULL);
    CloseHandle(hFile);

    printf("[+] Loaded PE file: %s (%lu bytes)\n\n", argv[1], file_size);

    // Parse PE headers
    IMAGE_DOS_HEADER* dos_header;
    IMAGE_NT_HEADERS* nt_headers;

    if (!parse_pe_headers(pe_buffer, &dos_header, &nt_headers)) {
        free(pe_buffer);
        return 1;
    }

    // Copy to memory
    LPVOID base = copy_pe_to_memory(pe_buffer, nt_headers);
    if (!base) {
        free(pe_buffer);
        return 1;
    }

    // Resolve imports
    resolve_imports(base, nt_headers);

    // Apply relocations
    apply_relocations(base, nt_headers);

    // Execute (skipped in demo)
    execute_entry_point(base, nt_headers);

    printf("\n[+] Demo completed successfully\n");
    printf("[!] In real malware: DLL now loaded and running from memory\n");
    printf("[!] Detection: Memory scan, Yara, EDR behavioral analysis\n");

    // Cleanup
    VirtualFree(base, 0, MEM_RELEASE);
    free(pe_buffer);

    return 0;
}

#else
#include <stdio.h>
int main() {
    printf("This demo is Windows-only (PE format)\n");
    printf("Linux equivalent: ELF in-memory loading with dlopen/dlsym\n");
    return 1;
}
#endif

/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 * Tests sur VM isolées. Usage malveillant = PRISON.
 *
 * Module 23 : Windows APIs Arsenal
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

// Énumérer processus avec CreateToolhelp32Snapshot
void enumerate_processes() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    printf("[*] Process Enumeration:\n");
    if (Process32First(hSnapshot, &pe32)) {
        do {
            printf("  [%lu] %s\n", pe32.th32ProcessID, pe32.szExeFile);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

// Allouer mémoire RWX dans processus distant
LPVOID allocate_remote_memory(HANDLE hProcess, SIZE_T size) {
    return VirtualAllocEx(hProcess, NULL, size,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
}

// Résolution dynamique API (éviter IAT)
FARPROC resolve_api(const char* module, const char* function) {
    HMODULE hMod = LoadLibraryA(module);
    if (!hMod) return NULL;
    return GetProcAddress(hMod, function);
}

// Lire PEB pour obtenir image base
PVOID get_image_base_from_peb() {
    #ifdef _WIN64
    PVOID peb;
    __asm__ ("mov %%gs:0x60, %0" : "=r"(peb));
    return *(PVOID*)((BYTE*)peb + 0x10);
    #else
    PVOID peb;
    __asm__ ("mov %%fs:0x30, %0" : "=r"(peb));
    return *(PVOID*)((BYTE*)peb + 0x08);
    #endif
}

int main() {
    printf("=== Windows APIs Demo ===\n\n");
    enumerate_processes();

    // Demo VirtualAlloc local
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    printf("\n[+] VirtualAlloc: %p\n", mem);
    VirtualFree(mem, 0, MEM_RELEASE);

    // Demo résolution API
    FARPROC func = resolve_api("kernel32.dll", "Sleep");
    printf("[+] GetProcAddress(Sleep): %p\n", func);

    return 0;
}

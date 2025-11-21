# Process Injection - Techniques d'Injection Avancées

CreateRemoteThread, QueueUserAPC, Process Hollowing, Thread Hijacking - techniques pour exécuter du code dans un processus distant. Fondamentales pour migration, élévation de privilèges et persistence stealthée.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Classic CreateRemoteThread injection
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID mem = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, mem, shellcode, size, NULL);
HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
```

## Compilation

gcc example.c -o inject.exe

## Concepts clés

- **CreateRemoteThread** : Injection classique via thread distant (très détectée)
- **QueueUserAPC** : Injection via APC queue (plus furtive, nécessite alertable state)
- **Process Hollowing (RunPE)** : Vider processus légitime et injecter PE complet
- **Thread Hijacking** : Suspendre thread, modifier contexte (RIP/EIP), reprendre
- **AtomBombing** : Utiliser atom tables pour injection cross-session
- **Early Bird** : Injection dans processus CREATE_SUSPENDED avant démarrage
- **Module Stomping** : Overwrite module légitime déjà chargé

## Techniques utilisées par

- **Cobalt Strike** : Process hollowing pour spawn+inject, Early Bird pour stealth
- **APT28 (Fancy Bear)** : Thread hijacking pour migration furtive
- **Lazarus Group** : Process hollowing dans explorer.exe, svchost.exe
- **Emotet** : QueueUserAPC pour injection sans CreateRemoteThread detection
- **TrickBot** : AtomBombing pour bypass session isolation

## Détection et Mitigation

**Indicateurs** :
- CreateRemoteThread usage (Sysmon Event ID 8)
- Memory allocations RWX dans processus distants
- Processus suspendus anormaux (CREATE_SUSPENDED)
- Context modifications via SetThreadContext

**Mitigations EDR** :
- Hook CreateRemoteThread, QueueUserAPC
- Memory scanning pour PE headers anormaux
- Thread context monitoring
- Process Mitigation Policies (ACG, CIG)

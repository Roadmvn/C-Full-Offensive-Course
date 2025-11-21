# Reflective Loading - In-Memory PE/DLL Execution

Reflective DLL injection, manual PE loading, import resolution - charger et exécuter PE/DLL directement depuis mémoire sans écrire sur disque. Technique fileless avancée, évite détection antivirus basée sur fichiers.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Basic concept: Load PE from memory
LPVOID base = VirtualAlloc(NULL, pe_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(base, pe_buffer, pe_headers_size);

// Copy sections
for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
    memcpy(section_dest, section_src, section_size);
}

// Resolve imports, relocations, then execute
DllMain entry = (DllMain)((LPBYTE)base + nt_headers->OptionalHeader.AddressOfEntryPoint);
entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
```

## Compilation

### Windows
```bash
gcc example.c -o reflective_loader.exe
```

### Linux (ELF loading)
```bash
gcc example.c -o elf_loader -ldl
```

## Concepts clés

- **Reflective DLL Injection** : Load DLL from memory (no disk)
- **PE Structure** : DOS header, NT headers, sections (.text, .data)
- **Import Resolution** : Fix IAT (Import Address Table)
- **Base Relocation** : Adjust addresses if loaded at different base
- **Entry Point** : DllMain or exe entry point
- **PIC (Position Independent Code)** : Code works at any address
- **Fileless** : Jamais écrit sur disque (antivirus bypass)

## Techniques utilisées par

- **Metasploit** : Reflective DLL injection (exploit/multi/handler)
- **Cobalt Strike** : Beacon DLL loaded reflectively
- **Mimikatz** : In-memory credential dumping
- **PowerSploit** : Invoke-ReflectivePEInjection.ps1
- **sRDI (Shellcode Reflective DLL Injection)** : Convert DLL to PIC shellcode

## Détection et Mitigation

**Indicateurs** :
- VirtualAlloc + WriteProcessMemory + CreateRemoteThread pattern
- PE headers in non-file-backed memory
- Suspicious memory regions (RWX, no MZ/PE on disk)
- LoadLibrary not called (manual loading)
- Yara rules for PE-in-memory signatures

**Mitigations** :
- Memory scanning (Yara, pe-sieve)
- EDR behavioral analysis
- Hook VirtualAlloc/WriteProcessMemory
- Process hollowing detection
- AMSI integration (PowerShell)

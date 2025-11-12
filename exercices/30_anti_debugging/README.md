# Anti-Debugging - Détection et Évasion Debuggers

IsDebuggerPresent, PEB checks, RDTSC timing, hardware breakpoints - techniques pour détecter GDB/WinDbg/x64dbg et crasher/exit si débogué. Complique analyse dynamique par reverse engineers.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// PEB BeingDebugged check (Windows)
BOOL is_debugged() {
    PPEB peb = (PPEB)__readgsqword(0x60);  // x64
    return peb->BeingDebugged;
}

// RDTSC timing check
BOOL timing_check() {
    uint64_t start = __rdtsc();
    // Operation simple
    uint64_t end = __rdtsc();
    return (end - start) > 1000;  // Debugger ralentit beaucoup
}
```

## Compilation

### Windows
```bash
gcc example.c -o antidebug.exe
```

### Linux
```bash
gcc example.c -o antidebug
```

## Concepts clés

- **IsDebuggerPresent** : API Windows détection basique (facilement bypassé)
- **PEB BeingDebugged** : Flag dans Process Environment Block
- **NtQueryInformationProcess** : ProcessDebugPort, ProcessDebugObjectHandle
- **RDTSC Timing** : Mesurer cycles CPU (debugger ralentit)
- **Hardware Breakpoints** : DR0-DR7 registers check
- **INT 2D** : Kernel debug interrupt detection
- **SEH Exceptions** : Debugger intercepte exceptions différemment

## Techniques utilisées par

- **Themida/VMProtect** : Multi-layer anti-debug (PEB, timing, DR, INT3)
- **Malware APT** : Timing checks + PEB + exit si détecté
- **Packers** : Anti-debug dans unpack stub
- **TeslaCrypt** : RDTSC timing checks multiples
- **Dridex** : NtQueryInformationProcess + hardware BP detection

## Détection et Mitigation

**Indicateurs** :
- IsDebuggerPresent/NtQueryInformationProcess calls
- Accès PEB (gs:[0x60] en x64)
- RDTSC instructions répétées
- Accès DR0-DR7 debug registers
- Anti-debug strings ("debugger detected")

**Bypass Techniques** :
- Hook IsDebuggerPresent (return 0)
- Patch PEB BeingDebugged flag
- NOP timing checks (patch RDTSC)
- ScyllaHide plugin (IDA/x64dbg)
- Kernel debugging (bypass userland checks)

# Module 41 - ETW Patching

AVERTISSEMENT : Ce module est strictement educatif. Le patching ETW est une technique d'evasion EDR utilisee par ransomwares et APT groups. Ne jamais utiliser sur systemes non autorises.

## Concepts

ETW (Event Tracing for Windows) est le systeme de logging Windows utilise par EDR/AV pour monitorer activites systeme. Le patching ETW desactive cette telemetrie.

### Architecture ETW

```
Application
    |
    v
EtwEventWrite() [ntdll.dll]
    |
    v
Kernel ETW Subsystem
    |
    v
ETW Consumers (EDR, Sysmon, etc.)
```

### Fonctions Cibles

**EtwEventWrite**: Fonction principale emission events ETW
**EtwEventWriteFull**: Variante extended
**EtwEventWriteEx**: Version ex avec options

### Techniques Patching

**Return Patching**: Remplacer debut fonction par RET (0xC3)
**NOP Sledding**: Remplacer par NOPs (0x90)
**Jump Hooking**: Rediriger vers stub vide
**Memory Protection**: Modifier protection page puis patch

### Process Patching

1. Localiser adresse EtwEventWrite dans ntdll.dll
2. Modifier protection memoire (VirtualProtect -> RWX)
3. Sauvegarder bytes originaux (pour restauration)
4. Ecrire patch (RET ou NOPs)
5. Restaurer protection originale (optionnel)

### Real-World Usage

**Ransomware Groups**: Conti, LockBit, BlackCat utilisent ETW patching
**APT29 (Cozy Bear)**: ETW bypass dans campaigns recentes
**Cobalt Strike**: Beacon inclut commande ETW patching
**Metasploit**: Module post-exploitation ETW disable

### Variations Techniques

**Inline Patching**: Directement dans process courant
**Remote Patching**: Via WriteProcessMemory dans process distant
**Hardware Breakpoints**: Hook via debug registers (DR0-DR7)
**Syscall Hooking**: Bypass ntdll completement (direct syscalls)

## Detection & Mitigation

**Kernel ETW Protection**: Windows 10+ protected process (PPL)
**Memory Scanning**: EDR detecte modifications ntdll.dll
**Integrity Checks**: Verification hash sections critiques
**Canary Values**: Detection corruption memory patterns

## Compilation

```bash
# Windows
cl etw_patcher.c /Fe:etw_patcher.exe

# Test detection
sysmon  # Verifier events apres patch
```

## ETW Providers Critiques

```
Microsoft-Windows-Threat-Intelligence
Microsoft-Windows-PowerShell
Microsoft-Windows-DotNETRuntime
Microsoft-Windows-Kernel-Process
```

## Limitations

- Detecte par EDR modernes (memory scanning)
- Inefficace contre kernel-mode monitoring
- Ne bypasse pas tous mecanismes telemetrie
- Windows 11 durcit protections ETW

## References

- Microsoft Docs: ETW Architecture
- Research: MDSec ETW Bypass Techniques
- Tools: SilentETW, ETWExplorer
- Malware: Conti Ransomware ETW Patching Analysis

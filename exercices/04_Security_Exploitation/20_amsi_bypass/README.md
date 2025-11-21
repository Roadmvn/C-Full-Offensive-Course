# Module 42 - AMSI Bypass

AVERTISSEMENT : Ce module est strictement educatif. AMSI bypass est technique d'evasion AV utilisee par malwares pour executer scripts malveillants. Ne jamais utiliser sur systemes non autorises.

## Concepts

AMSI (Antimalware Scan Interface) est API Windows permettant aux applications (PowerShell, VBScript, JScript) de soumettre contenu a l'antivirus pour scanning avant execution.

### Architecture AMSI

```
PowerShell Script
    |
    v
AmsiScanBuffer() [amsi.dll]
    |
    v
Windows Defender / AV
    |
    v
Return: CLEAN / MALICIOUS
```

### Fonctions Cibles

**AmsiScanBuffer**: Scan buffer memoire pour contenu malveillant
**AmsiScanString**: Scan string pour signatures
**AmsiOpenSession**: Ouvre session AMSI
**AmsiInitialize**: Initialise contexte AMSI

### Techniques Bypass

**Memory Patching**: Modifier AmsiScanBuffer pour retourner toujours CLEAN
**Reflection Bypass**: Modifier attributs .NET pour desactiver AMSI
**DLL Unloading**: Unload amsi.dll du process
**Context Corruption**: Corrompre contexte AMSI pour invalider scans

### Patterns Patch Classiques

**Return 0 Patch**: Remplacer debut fonction par `MOV EAX, 0; RET`
**Force Success**: Forcer AMSI_RESULT_CLEAN (0x00)
**NOP Sledding**: NOPs sur checks critiques

### Real-World Usage

**Cobalt Strike**: Beacon inclut AMSI bypass automatique
**Empire Framework**: Multiple techniques AMSI bypass integrees
**Metasploit**: Module post-exploitation AMSI disable
**Ransomware**: Groups modernes bypassent AMSI pour execution payloads

### PowerShell AMSI Context

PowerShell v5+ integre AMSI pour scanner scripts avant execution. Bypass AMSI permet execution payloads malveillants sans detection.

### Variations Techniques

**Obfuscation**: Fragmenter strings pour eviter signatures AMSI
**In-Memory Bypass**: Patch process memory sans toucher disque
**CLR Hooking**: Hook .NET CLR pour disable AMSI
**COM Hijacking**: Detourner COM objects AMSI

## Detection & Mitigation

**Behavioral Analysis**: Monitoring appels suspect VirtualProtect sur amsi.dll
**Memory Integrity**: Verification hash amsi.dll runtime
**Event Logging**: Logger tentatives modification AMSI context
**Protected Process**: PPL pour processes utilisant AMSI

## Compilation

```bash
# Windows
cl amsi_bypass.c /Fe:amsi_bypass.exe

# Test avec PowerShell
powershell -Command "Invoke-Expression 'AMSI Test Sample'"
# Detecte par AMSI normalement
```

## PowerShell AMSI Bypass Examples

```powershell
# Classic bypass (patched depuis)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Memory patch
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext",[Reflection.BindingFlags]"NonPublic,Static").SetValue($null,$mem)
```

## Limitations

- Detecte par EDR modernes (memory scanning)
- Windows 11 durcit protections AMSI
- Inefficace contre kernel-mode AV
- Signatures bypass connues bloquees

## References

- Microsoft Docs: AMSI API Reference
- Research: Bypass AMSI (Rastamouse, MDSec)
- Tools: AMSITrigger (identifier signatures)
- Malware: Analysis AMSI bypass in-the-wild

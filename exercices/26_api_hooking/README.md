# API Hooking - IAT, EAT & Inline Hooking

Hooking de fonctions Windows pour interception d'appels API. IAT hooking (Import Address Table), inline hooking (hot patching), et trampoline functions pour redirection d'exécution.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Inline hook avec trampoline
BYTE original_bytes[5];
memcpy(original_bytes, target_func, 5);

// Patch JMP vers hook
BYTE jmp_patch[5] = { 0xE9, 0, 0, 0, 0 };
*(DWORD*)(jmp_patch + 1) = (BYTE*)hook_func - (BYTE*)target_func - 5;

VirtualProtect(target_func, 5, PAGE_EXECUTE_READWRITE, &old);
memcpy(target_func, jmp_patch, 5);
VirtualProtect(target_func, 5, old, &old);
```

## Compilation

gcc example.c -o hook.exe

## Concepts clés

- **IAT Hooking** : Modifier Import Address Table pour rediriger imports
- **Inline Hooking** : Patch premiers bytes fonction (JMP/CALL) vers hook
- **Trampoline** : Sauvegarder opcodes originaux pour appeler fonction légitime
- **EAT Hooking** : Modifier Export Address Table
- **VTable Hooking** : Hooking de virtual tables C++
- **SSDT Hooking** : System Service Descriptor Table (kernel-mode)
- **API Unhooking** : Restaurer opcodes originaux pour bypass EDR

## Techniques utilisées par

- **EDRs/AVs** : Inline hooks sur APIs critiques (VirtualAlloc, CreateProcess, etc.)
- **Rootkits** : SSDT hooking en kernel pour cacher processus
- **Game cheats** : VTable hooking pour Direct3D
- **Banking trojans** : IAT hooking de send/recv pour MitM
- **Malware** : API unhooking pour désactiver EDR hooks

## Détection et Mitigation

**Indicateurs** :
- Opcodes anormaux au début de fonctions (0xE9, 0xEB)
- IAT entries pointant hors modules légitimes
- VirtualProtect sur .text sections
- Discrepancies entre disk et memory

**Mitigations** :
- Kernel Patch Protection (PatchGuard)
- Code Integrity Guard
- Memory integrity checking
- ETW pour monitor VirtualProtect

⚠️ AVERTISSEMENT STRICT - Usage éducatif uniquement


### EXERCICES - MODULE 26 : API HOOKING

[ ] 1. INLINE HOOK AVEC TRAMPOLINE
Hook MessageBoxA avec trampoline complète :
- Sauvegarder 5+ bytes originaux
- Créer stub trampoline (original bytes + JMP back)
- Patch JMP vers hook
- Hook peut appeler trampoline pour fonction originale

[ ] 2. IAT HOOKING COMPLET
Hook toutes les imports d'un module :
- Parser IAT
- Hook send/recv pour network MitM
- Hook CreateFileA pour file monitoring

[ ] 3. API UNHOOKING (EDR BYPASS)
Détecter et restaurer hooks EDR :
- Comparer .text avec ntdll.dll sur disk
- Identifier hooks (JMP opcodes)
- Restaurer bytes originaux
- Technique Perun's Fart

[ ] 4. VTABLE HOOKING
Hook DirectX functions :
- Trouver VTable de IDirect3DDevice9
- Hook Present() function
- Render overlay

[ ] 5. EXCEPTION HANDLER HOOKING
Hook via Vectored Exception Handler :
- AddVectoredExceptionHandler
- Modifier EIP/RIP dans context
- Alternative à inline hooking

[ ] 6. HARDWARE BREAKPOINT HOOKING
Hook via debug registers :
- SetThreadContext avec Dr0-Dr3
- Trigger exception on access
- Stealthier que inline hooks

[ ] 7. PAGE GUARD HOOKING
Hook via page permissions :
- VirtualProtect PAGE_GUARD
- Handle exception in VEH
- Restore and re-guard

[ ] 8. ETW PATCHING
Désactiver Event Tracing :
- Hook EtwEventWrite
- Patch avec 'ret'
- Bypass logging

Référence : MITRE ATT&CK T1574, Hooking techniques


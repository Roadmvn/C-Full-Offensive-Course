⚠️ AVERTISSEMENT STRICT - Usage éducatif uniquement


### EXERCICES - MODULE 25 : DLL INJECTION

[ ] 1. LOADLIBRARY INJECTION COMPLET
Injection classique avec cleanup :
- OpenProcess + VirtualAllocEx
- WriteProcessMemory du chemin DLL
- CreateRemoteThread vers LoadLibraryA
- WaitForSingleObject puis VirtualFreeEx

[ ] 2. MANUAL MAPPING COMPLET
PE loader manuel :
- Mapper DLL dans processus distant
- Fix relocations (IMAGE_BASE_RELOCATION)
- Fix imports (IAT reconstruction)
- Call TLS callbacks
- Call DllMain

Référence : github.com/strobejb/ReflectiveDLLInjection

[ ] 3. REFLECTIVE DLL
Créer DLL auto-chargeable :
- Stub loader en DLL
- GetProcAddress dynamique
- Self-relocation
- No LoadLibrary needed

[ ] 4. DLL HIJACKING
Exploiter DLL search order :
- Identifier DLL vulnérable (ProcMon)
- Créer proxy DLL avec export forwarding
- Hook fonctions ciblées

[ ] 5. DLL UNLOADING
Éjecter DLL injectée :
- Trouver base address du module
- CreateRemoteThread vers FreeLibrary
- VirtualFreeEx memory

[ ] 6. THREAD LOCAL STORAGE INJECTION
Utiliser TLS callbacks :
- Modifier PE pour ajouter TLS callback
- Inject avant entry point

[ ] 7. APPINIT_DLLS PERSISTENCE
Registry persistence :
- HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows
- Clé AppInit_DLLs

[ ] 8. MODULE ENUMERATION
Détecter DLLs injectées :
- EnumProcessModules
- Comparer avec PEB.Ldr
- Identifier discrepancies

Référence : MITRE ATT&CK T1055.001


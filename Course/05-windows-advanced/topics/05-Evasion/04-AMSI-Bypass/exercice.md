
### EXERCICES - Module 42 : AMSI Bypass

AVERTISSEMENT : Exercices strictement educatifs. Technique evasion AV - jamais usage malveillant.

Difficulte : ★★★★★ (Avance - AV Evasion)

Exercice 1 : AMSI Function Enumerator
[ ] Enumerer toutes fonctions AMSI exportees par amsi.dll
[ ] Identifier AmsiScanBuffer, AmsiScanString, AmsiInitialize, etc.
[ ] Afficher adresses et prototypes de chaque fonction
[ ] Analyser premiers bytes (detecter si deja patchees)
[ ] Creer rapport complet API surface AMSI

Exercice 2 : Multiple Patch Techniques
[ ] Implementer 5 techniques patch differentes (MOV/XOR/NOP/JMP/etc.)
[ ] Tester efficacite chaque technique contre Defender
[ ] Mesurer stealth (detectabilite par memory scanning)
[ ] Comparer tailles patches (plus court = mieux)
[ ] Creer tableau comparatif techniques

Exercice 3 : Context Corruption Bypass
[ ] Corrompre AMSI context au lieu patcher fonction
[ ] Localiser structure HAMSICONTEXT en memoire
[ ] Modifier champs critiques (flags, pointers)
[ ] Invalider context pour desactiver scans
[ ] Tester si plus stealth que patching direct

Exercice 4 : PowerShell Integration
[ ] Creer script PowerShell appelant DLL bypass C
[ ] Implementer reflection-based bypass en C#
[ ] Tester execution payload malveillant apres bypass
[ ] Comparer detection vs bypass PowerShell pur
[ ] Automatiser injection bypass dans sessions PS

Exercice 5 : AMSI Trigger Analyzer
[ ] Creer outil identification strings declenchant AMSI
[ ] Tester dictionnaire mots-cles malveillants
[ ] Identifier signatures exactes (hash, patterns)
[ ] Implementer obfuscation strings detectees
[ ] Generer rapport triggers AMSI complet

Exercice 6 : Remote Process AMSI Bypass
[ ] Identifier process PowerShell distant (PID)
[ ] Ouvrir handle avec permissions VM_WRITE
[ ] Localiser amsi.dll dans process distant
[ ] Patcher AmsiScanBuffer via WriteProcessMemory
[ ] Verifier bypass effectif dans process cible

Exercice 7 : Persistent AMSI Bypass
[ ] Implementer monitoring continu integrite patch
[ ] Detecter si AV restaure bytes originaux
[ ] Re-patcher automatiquement si necessaire
[ ] Logger tentatives restauration detectees
[ ] Creer thread watchdog pour persistence

Exercice 8 : Hardware Breakpoint AMSI Hook
[ ] Configurer debug registers (DR0-DR7) sur AmsiScanBuffer
[ ] Implementer exception handler interception appels
[ ] Forcer retour AMSI_RESULT_CLEAN dans handler
[ ] Aucune modification memoire amsi.dll (stealth maximal)
[ ] Tester avec Defender + Sysmon actifs

BONUS CHALLENGES

Challenge 9 : CLR Hooking (.NET)
[ ] Hook CLR AMSI integration au niveau .NET
[ ] Modifier System.Management.Automation.AmsiUtils
[ ] Desactiver amsiInitFailed ou amsiContext
[ ] Implementer en C avec COM interop
[ ] Bypass PowerShell sans toucher amsi.dll

Challenge 10 : Kernel AMSI Bypass
[ ] Rechercher driver kernel pour patch kernel-space AMSI
[ ] Identifier KernelBase AMSI callbacks
[ ] Utiliser BYOVD (Bring Your Own Vulnerable Driver)
[ ] Patcher AMSI au niveau kernel
[ ] Documenter risques BSOD et mitigations

Challenge 11 : AMSI Evasion via COM
[ ] Hijacker COM objects AMSI (IAmsiStream, etc.)
[ ] Creer proxy COM retournant toujours CLEAN
[ ] Enregistrer proxy dans registry
[ ] Tester redirection appels AMSI vers proxy
[ ] Restaurer COM objects originaux

OUTILS RECOMMANDES
- AMSITrigger : Identifier strings declenchant AMSI
- Process Hacker : Inspection memoire amsi.dll
- x64dbg : Debugger pour analyse runtime AMSI
- PowerShell ISE : Tester scripts avec AMSI
- Sysmon : Monitorer tentatives bypass

CRITERES VALIDATION
- Bypass empeche detection payloads malveillants
- Aucun crash PowerShell ou process hote
- Restauration retablit detection AMSI
- Techniques stealth (pas detection triviale EDR)
- Fonctionnel contre Windows Defender actif

INDICATEURS DETECTION EDR
1. Modifications memoire amsi.dll
2. Appels VirtualProtect sur pages amsi.dll
3. Strings suspectes ("amsi", "AmsiScanBuffer", etc.)
4. Reflection PowerShell sur AmsiUtils
5. WriteProcessMemory cross-process vers amsi.dll
6. Hardware breakpoints sur fonctions AMSI
7. Drop soudain events AMSI (behavioral)

SIGNATURES AMSI COMMUNES
- "AMSI Test Sample" (test string officielle)
- Obfuscation keywords: Invoke-Expression, DownloadString
- Base64 decode patterns suspects
- Known malware families signatures
- PowerShell Empire/Cobalt Strike indicators

CONTRE-MESURES BLUE TEAM
- Memory scanning periodique amsi.dll
- Integrity checks hash sections critiques
- Protected Process Light (PPL) pour PowerShell
- Event correlation (bypass attempt + suspicious activity)
- Multiple AV layers (pas seulement AMSI)
- Behavioral analysis post-bypass

AVERTISSEMENT LEGAL
AMSI bypass pour execution malware est clairement illegal dans contexte reel.
Technique enseignee pour comprehension blue team defense et detection uniquement.
Ne jamais tester sur systemes sans autorisation explicite ecrite.


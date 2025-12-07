
### EXERCICES - Module 41 : ETW Patching

AVERTISSEMENT : Exercices strictement educatifs. Technique evasion EDR - jamais usage malveillant.

Difficulte : ★★★★★ (Avance - EDR Evasion)

Exercice 1 : ETW Function Locator
[ ] Enumerer toutes fonctions ETW dans ntdll.dll
[ ] Identifier EtwEventWrite, EtwEventWriteFull, EtwEventWriteEx
[ ] Afficher adresses et premiers bytes de chaque fonction
[ ] Detecter si deja patchees (RET, NOPs)
[ ] Creer rapport detaille fonctions ETW

Exercice 2 : Multi-Function Patcher
[ ] Patcher simultanement toutes fonctions ETW trouvees
[ ] Sauvegarder backups pour chaque fonction
[ ] Verifier succes patch pour chaque fonction
[ ] Implementer restauration selective (fonction par fonction)
[ ] Logger toutes operations dans fichier

Exercice 3 : Stealth Patching
[ ] Implanter patch via hardware breakpoints (DR0-DR7)
[ ] Utiliser exception handler pour intercepter appels
[ ] Dans handler, retourner immediatement sans execution
[ ] Aucune modification memoire ntdll (stealth)
[ ] Tester avec Sysmon active

Exercice 4 : Remote Process Patching
[ ] Identifier process cible (PID)
[ ] Ouvrir handle avec PROCESS_VM_WRITE | PROCESS_VM_OPERATION
[ ] Localiser ntdll.dll dans process distant
[ ] Patcher EtwEventWrite via WriteProcessMemory
[ ] Verifier patch via ReadProcessMemory

Exercice 5 : ETW Provider Enumerator
[ ] Utiliser TdhEnumerateProviders pour lister providers ETW actifs
[ ] Identifier providers critiques pour EDR (Threat Intelligence, etc.)
[ ] Afficher GUID, nom, et nombre consumers par provider
[ ] Tester emission events vers providers avant/apres patch
[ ] Documenter quels providers toujours fonctionnels apres patch

Exercice 6 : Detection Resistance
[ ] Implementer re-patching periodique (toutes les 100ms)
[ ] Detecter si EDR restaure bytes originaux ntdll
[ ] Logger tentatives restauration detectees
[ ] Implementer multiple techniques fallback (RET, NOPs, hooks)
[ ] Monitorer integrite patch en temps reel

Exercice 7 : Syscall Direct Implementation
[ ] Bypass ntdll completement avec syscalls directs
[ ] Extraire syscall numbers pour NtAllocateVirtualMemory, etc.
[ ] Implementer wrapper syscall direct (inline assembly)
[ ] Eviter EtwEventWrite completement (pas appele)
[ ] Tester operations critiques sans passer par ntdll

Exercice 8 : ETW Patcher avec Obfuscation
[ ] Chiffrer shellcode patcher en memoire
[ ] Dechiffrer uniquement durant execution patch
[ ] Utiliser timers pour delayer patch (eviter detection comportementale)
[ ] Nettoyer traces memoire apres patch
[ ] Implementer anti-debugging checks avant patch

BONUS CHALLENGES

Challenge 9 : Kernel ETW Patching
[ ] Rechercher driver kernel pour patch kernel-mode ETW
[ ] Identifier KernelBase!EtwEventWrite (kernel space)
[ ] Utiliser vulnerable driver pour write kernel memory (BYOVD)
[ ] Patcher fonction kernel ETW
[ ] Documenter risque BSOD et mitigations

Challenge 10 : PPL/PPL-Light Bypass
[ ] Comprendre Protected Process Light (Windows 10+)
[ ] Rechercher vulnerabilites PPL bypass connues
[ ] Tenter patch ETW dans process protege
[ ] Documenter echecs et pourquoi (protections OS)
[ ] Proposer alternatives (kernel patching, etc.)

Challenge 11 : ETW Forensics Evasion
[ ] Analyser logs ETW generes avant patch
[ ] Identifier artifacts patch (EventID suspects)
[ ] Implementer nettoyage logs ETW post-patch
[ ] Supprimer traces dans Event Log Windows
[ ] Creer timeline complete anti-forensics

OUTILS RECOMMANDES
- WinDbg : Debugger kernel/user pour analyse ntdll
- Process Hacker : Inspection memoire process
- Sysmon : Tester si events toujours emis apres patch
- ProcMon : Monitorer operations systeme
- ETWExplorer : Analyse providers ETW actifs

CRITERES VALIDATION
- Patch bloque emission events ETW (verifie Sysmon)
- Aucun crash process apres patch
- Restauration retablit fonctionnalite ETW 100%
- Techniques stealthy (pas detection triviale)
- Resistant a restauration EDR basique

INDICATEURS DETECTION EDR
1. Modifications memoire ntdll.dll
2. Appels VirtualProtect sur pages ntdll
3. WriteProcessMemory cross-process vers ntdll
4. Hardware breakpoints sur fonctions critiques
5. Anomalies syscalls (direct vs ntdll)
6. Drop soudain events ETW (behavioral)
7. Threads suspects avec stack traces anormales

CONTRE-MESURES BLUE TEAM
- Memory scanning periodique ntdll.dll
- Integrity checks hash sections critiques
- PPL protection pour processes sensibles
- Kernel-mode monitoring (pas user-mode ETW)
- Behavioral analysis (drop events = alerte)
- Canary values dans fonctions ETW

AVERTISSEMENT LEGAL
ETW patching pour evasion EDR est clairement malveillant dans contexte reel.
Technique enseignee pour comprehension defense et detection uniquement.


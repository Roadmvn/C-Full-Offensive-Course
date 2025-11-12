# Progression - Learning C pour Red Teaming

## Vue d'ensemble

**Durée totale** : 3-6 mois (120-200 heures)
**Niveau départ** : Débutant absolu
**Niveau final** : Malware developer / Red teamer

---

## Phase 1 : Bases C (Modules 01-09)
**Durée** : 1-2 semaines | **Style** : Bro Code ultra-concis

Apprentissage des fondamentaux du langage C avec exemples neutres et pédagogiques.

### Modules
- **01 - Hello World** (30-45 min) : Premier programme, compilation gcc
- **02 - Variables et Types** (45-60 min) : int, char, float, double, sizeof()
- **03 - Printf et Scanf** (1h) : Format specifiers, saisie utilisateur
- **04 - Opérateurs** (1h) : Arithmétiques, logiques, bit à bit
- **05 - If/Else/Switch** (1-1.5h) : Conditions, opérateur ternaire
- **06 - Loops** (1.5-2h) : for, while, do-while, break, continue
- **07 - Arrays** (1.5-2h) : Tableaux 1D et 2D, parcours
- **08 - Strings** (2h) : Chaînes, string.h, manipulation de texte
- **09 - Functions** (2h) : Déclaration, paramètres, return, scope

### Compétences acquises
✓ Syntaxe C de base
✓ Structures de contrôle
✓ Manipulation de données
✓ Organisation du code en fonctions

---

## Phase 2 : Transition (Modules 10-14)
**Durée** : 1 semaine | **Style** : Bases avancées + notes red team

Concepts avancés du C avec une **section "Application Red Team"** dans chaque README expliquant l'usage en sécurité offensive.

### Modules
- **10 - Pointeurs Intro** (2-3h) : &, *, NULL, manipulation mémoire
  - *Red team : WriteProcessMemory, injection de code*

- **11 - Pointeurs Avancés** (2-3h) : Arithmétique, **, relation arrays/pointeurs
  - *Red team : Parsing PE, IAT hooking*

- **12 - Malloc et Free** (2-3h) : Stack vs Heap, allocation dynamique
  - *Red team : VirtualAlloc, heap spray*

- **13 - Structures** (2h) : struct, typedef, . vs ->
  - *Red team : PROCESS_INFORMATION, PE headers*

- **14 - Fichiers** (2h) : fopen, fread, fwrite, binaire
  - *Red team : Droppers, PE parsing, payloads*

### Compétences acquises
✓ Gestion mémoire avancée
✓ Structures de données
✓ Manipulation de fichiers
✓ Compréhension des usages en sécurité

---

## Phase 3 : Exploitation (Modules 15-20)
**Durée** : 1-2 semaines | **Style** : Code vulnérable, exploitation

Code **intentionnellement vulnérable** avec avertissements légaux stricts.

### Modules
- **15 - Buffer Concept** (2-3h) : Buffers, overflow simple, strcpy dangereux
- **16 - Stack Overflow** (3-4h) : Stack frame, écraser return address
- **17 - Shellcode** (3-4h) : Shellcode x86/x64, execve, NOP sled
- **18 - Format String** (3-4h) : printf() vulnérable, %n pour écrire
- **19 - Heap Exploitation** (4h) : Use-after-free, double-free, heap spray
- **20 - Reverse Shell** (4h) : Socket TCP, dup2(), shell over network

### Compétences acquises
✓ Comprendre les vulnérabilités binaires
✓ Exploiter des buffer overflows
✓ Créer et injecter du shellcode
✓ Développer des reverse shells

---

## Phase 4 : Malware Development (Modules 21-45)
**Durée** : 3-4 semaines | **Style** : Techniques réelles APT/malware

Techniques **professionnelles** utilisées par Cobalt Strike, Metasploit et APT groups.

### Architecture Offensive (21-27)
- **21 - Process & Threads** (3-5h) : fork, CreateProcess, pthread, IPC
- **22 - Syscalls Directs** (4h) : Hell's Gate, Halo's Gate, bypass EDR hooks
- **23 - Windows APIs** (3-4h) : VirtualAlloc, OpenProcess, GetProcAddress
- **24 - Process Injection** (4-5h) : CreateRemoteThread, QueueUserAPC, Process Hollowing
- **25 - DLL Injection** (4h) : LoadLibrary, Manual Mapping, Reflective DLL
- **26 - API Hooking** (4h) : IAT, Inline hooking, Trampolines, Unhooking
- **27 - Networking & C2** (4h) : Sockets, HTTP/DNS C2, beaconing

### Evasion (28-33)
- **28 - Cryptographie** (3-4h) : XOR, AES, string obfuscation, crypters
- **29 - Obfuscation** (3-4h) : Control flow, opaque predicates, junk code
- **30 - Anti-Debugging** (3-4h) : IsDebuggerPresent, PEB, RDTSC timing
- **31 - Anti-VM/Sandbox** (3-4h) : CPUID, sleep acceleration, VM artifacts
- **32 - Persistence Windows** (4h) : Registry, scheduled tasks, services
- **33 - Persistence Linux** (3h) : Cron, systemd, LD_PRELOAD, bashrc

### Techniques Avancées (34-40)
- **34 - Token Manipulation** (4-5h) : OpenProcessToken, SeDebugPrivilege, impersonation
- **35 - Registry Manipulation** (3h) : RegOpenKey, RegSetValue, data hiding
- **36 - Memory Mapping** (3-4h) : mmap, MapViewOfFile, shared memory
- **37 - Reflective Loading** (5-6h) : Reflective DLL, manual PE loading
- **38 - ROP Chains** (5-6h) : Gadgets, bypass DEP/NX, ret2libc
- **39 - Code Caves** (4h) : PE injection, backdooring binaries
- **40 - Packing/Unpacking** (4h) : UPX, custom packers, entropy

### EDR Bypass & Post-Exploitation (41-45)
- **41 - ETW Patching** (4-5h) : Patching EtwEventWrite, bypass EDR logging
- **42 - AMSI Bypass** (4h) : Patching AmsiScanBuffer, PowerShell bypass
- **43 - Credential Dumping** (5-6h) : LSASS, Mimikatz, SAM database
- **44 - Lateral Movement** (5h) : PsExec, WMI, Pass-the-Hash, RDP
- **45 - C2 Development** (6-8h) : Architecture C2, multi-protocol, tasking

### Compétences acquises
✓ Injection de code avancée
✓ Bypass EDR/AV
✓ Techniques de persistence
✓ Privilege escalation
✓ Développement C2 complet
✓ Toutes les compétences pour **OSWA**

---

## Progression recommandée

### Tempo optimal
- **1-2h par jour** en semaine
- **4-6h** le weekend
- **6-8 semaines** au total pour finir les 45 modules

### Checkpoints importants
- [ ] **Module 09 complété** : Tu maîtrises les bases du C
- [ ] **Module 14 complété** : Tu comprends la gestion mémoire avancée
- [ ] **Module 20 complété** : Tu sais exploiter des vulnérabilités
- [ ] **Module 33 complété** : Tu maîtrises injection et persistence
- [ ] **Module 45 complété** : Tu es prêt pour OSWA et Red Team jobs

### Conseils
✅ Fais les modules dans l'ordre strict
✅ Compile et teste TOUS les exemples
✅ Fais au minimum 6/8 exercices par module
✅ Relis les modules précédents si bloqué
✅ Prends des notes dans un carnet
✅ Pratique sur des VMs isolées (modules 15+)

❌ Ne saute AUCUN module
❌ Ne copie pas sans comprendre
❌ Ne teste PAS les techniques sur des systèmes réels sans autorisation

---

## Après avoir terminé

Tu seras capable de :
- Développer des exploits en C
- Créer des implants malware custom
- Bypasser EDR/AV modernes
- Passer la certification **OSWA**
- Postuler pour des postes **Red Team** (FAANG, sécurité)

### Prochaines étapes
1. **CTF** : Practice sur HackTheBox, TryHackMe
2. **Certifications** : OSWA → OSCP → OSCE
3. **Assembleur** : Apprendre x86-64 pour reverse engineering
4. **Outils** : Maîtriser IDA/Ghidra/Binary Ninja
5. **Projects** : Développer ton propre C2 framework

---

**Bonne chance dans ton apprentissage ! 🔥**

*"Chaque expert a été un débutant. La clé est la persistance."*

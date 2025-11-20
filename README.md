# Learning C - Red Team Development

[![Stars](https://img.shields.io/github/stars/yourusername/Learning-C?style=social)](https://github.com/yourusername/Learning-C/stargazers)
[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![French](https://img.shields.io/badge/Lang-Fran%C3%A7ais-blue.svg)](README.md)
[![Level](https://img.shields.io/badge/Level-Beginner%20to%20Advanced-green.svg)](PROGRESSION.md)
[![Modules](https://img.shields.io/badge/Modules-45-brightgreen.svg)](exercices/)
[![OSWA](https://img.shields.io/badge/Prep-OSWA%20Ready-red.svg)](https://www.offsec.com/courses/web-300/)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](LICENSE)

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║          Formation Complète C → Red Team Development                      ║
║          De Débutant Absolu à Malware Developer Professionnel             ║
║                                                                           ║
║          45 Modules | 120-200h | OSWA/OSCP Ready                          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

### La formation C la plus complète en français pour le Red Teaming

Apprenez le C avec une **progression naturelle et optimisée** vers le red teaming et la sécurité offensive. **45 modules progressifs** couvrant les fondamentaux jusqu'aux techniques APT avancées utilisées par **Cobalt Strike, Metasploit** et les groupes de menaces persistantes (APT29, Emotet, TrickBot).

### Points Forts

| Avantage | Description |
|----------|-------------|
| **100% Gratuit** | Formation complète open-source, aucun coût caché |
| **Progression Optimale** | Du Hello World au développement de C2 frameworks |
| **Certifications** | Préparation directe OSWA, OSCP, OSCE |
| **Carrière** | Compétences pour Red Team FAANG et entreprises sécurité |
| **Pratique** | 360+ exercices avec solutions complètes |
| **Techniques Réelles** | Code utilisé par APT groups et frameworks professionnels |

### Pour qui ?

- **Débutants absolus** voulant apprendre le C pour la cybersécurité
- **Étudiants en sécurité** préparant OSWA/OSCP/OSCE
- **Pentesters** cherchant à maîtriser l'exploitation binaire
- **Bug bounty hunters** ciblant des vulnérabilités bas niveau
- **Aspirants Red Teamers** visant des postes en sécurité offensive
- **CTF players** spécialisés en pwn et binary exploitation

---

## Table des Matières

- [Objectif](#objectif)
- [Pourquoi ce cours ?](#pourquoi-ce-cours-)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Structure](#structure)
- [Progression Complète](#progression-complète)
  - [Phase 1 : Fondamentaux C (01-09)](#phase-1--fondamentaux-c-01-09--1-2-semaines)
  - [Phase 2 : Transition (10-14)](#phase-2--transition-10-14--1-semaine)
  - [Phase 3 : Exploitation (15-20)](#phase-3--exploitation-15-20--1-2-semaines)
  - [Phase 4 : Malware Development (21-45)](#phase-4--malware-development-21-45--3-4-semaines)
- [Comment utiliser](#comment-utiliser)
- [Temps estimé](#temps-estimé)
- [Compétences Acquises](#compétences-acquises)
- [Prochaines Étapes](#prochaines-étapes)
- [Ressources Complémentaires](#ressources-complémentaires)
- [Soutenir le Projet](#soutenir-le-projet)
- [Avertissement Légal](#️-avertissement-légal-strict)
- [Démarrage Rapide](#démarrage-rapide)

---

## Objectif

Maîtriser le C avec une **progression pédagogique optimale** vers le red teaming professionnel :

- **Modules 01-09** : Fondamentaux du C (style Bro Code ultra-concis)
- **Modules 10-14** : Concepts avancés avec applications red team
- **Modules 15-20** : Exploitation binaire (buffer overflow, shellcode, ROP)
- **Modules 21-45** : Malware development complet (préparation OSWA/OSCP)

## Pourquoi ce cours ?

- Formation **100% gratuite** et open-source
- Progression **zéro à expert** en 3-6 mois
- Techniques **réelles** utilisées en production par les red teams
- Préparation directe aux certifications **OSWA**, **OSCP**, **OSCE**
- Code prêt pour **CTF**, **Bug Bounty**, **Pentest professionnel**
- Référence complète pour **entretiens FAANG Red Team**

## Prérequis

**AUCUN** - Ce cours part de zéro absolu.

Connaissances minimales requises :
- Utiliser un terminal (bash/cmd)
- Naviguer dans les dossiers (cd, ls)

## Installation

```bash
chmod +x setup.sh
./setup.sh
```

Ou manuellement :
```bash
# macOS
brew install gcc

# Linux
sudo apt install build-essential gcc

# Windows
# Utilise WSL ou MinGW
```

## Structure

Chaque module contient **4 fichiers** :
```
XX_nom_module/
├── README.md       # Cours concis + exemples
├── example.c       # Code d'exemple commenté
├── exercice.txt    # 8 défis pratiques avec [ ] auto-évaluation
└── solution.txt    # Solutions complètes
```

**Plus de Makefile** - Compilation simple : `gcc example.c -o program`

## Progression Complète

### 🟢 Phase 1 : Fondamentaux C (01-09) — 1-2 semaines
Style **Bro Code** : ultra-concis, exemples pédagogiques neutres

| Module | Sujet | Durée |
|--------|-------|-------|
| 01 | Hello World | 30-45 min |
| 02 | Variables et types | 45-60 min |
| 03 | Printf et scanf | 1h |
| 04 | Opérateurs | 1h |
| 05 | If/else/switch | 1-1.5h |
| 06 | Loops (for, while, do-while) | 1.5-2h |
| 07 | Arrays | 1.5-2h |
| 08 | Strings | 2h |
| 09 | Functions | 2h |

### 🟡 Phase 2 : Transition (10-14) — 1 semaine
Concepts avancés + **section Application Red Team**

| Module | Sujet | Application Red Team |
|--------|-------|---------------------|
| 10 | Pointeurs intro | WriteProcessMemory, injection |
| 11 | Pointeurs avancés | Parsing PE, IAT hooking |
| 12 | Malloc et free | VirtualAlloc, heap spray |
| 13 | Structures | PE headers, PROCESS_INFORMATION |
| 14 | Fichiers | Droppers, PE parsing, payloads |

### 🟠 Phase 3 : Exploitation (15-20) — 1-2 semaines
Code **vulnérable intentionnel** avec avertissements stricts

| Module | Sujet | Technique |
|--------|-------|-----------|
| 15 | Buffer concept | Overflow simple, strcpy dangereux |
| 16 | Stack overflow | Écraser return address |
| 17 | Shellcode | Shellcode x86/x64, NOP sled |
| 18 | Format string | printf() vulnérable, %n |
| 19 | Heap exploitation | Use-after-free, double-free |
| 20 | Reverse shell | Socket TCP, dup2(), shell over network |

### 🔴 Phase 4 : Malware Development (21-45) — 3-4 semaines
Techniques **professionnelles** APT/Red Team

#### Architecture Offensive (21-27)
- **21** : Process & Threads — fork, CreateProcess, pthread, IPC
- **22** : Syscalls Directs — Hell's Gate, Halo's Gate, EDR bypass
- **23** : Windows APIs — VirtualAlloc, OpenProcess, GetProcAddress
- **24** : Process Injection — CreateRemoteThread, QueueUserAPC, Process Hollowing
- **25** : DLL Injection — LoadLibrary, Manual Mapping, Reflective DLL
- **26** : API Hooking — IAT, Inline hooking, Trampolines, Unhooking
- **27** : Networking & C2 — Sockets, HTTP/DNS C2, beaconing

#### Evasion (28-33)
- **28** : Cryptographie — XOR, AES, string obfuscation, crypters
- **29** : Obfuscation — Control flow, opaque predicates, junk code
- **30** : Anti-Debugging — IsDebuggerPresent, PEB, RDTSC timing
- **31** : Anti-VM/Sandbox — CPUID, sleep acceleration, VM artifacts
- **32** : Persistence Windows — Registry, scheduled tasks, services
- **33** : Persistence Linux — Cron, systemd, LD_PRELOAD, bashrc

#### Techniques Avancées (34-40)
- **34** : Token Manipulation — OpenProcessToken, SeDebugPrivilege
- **35** : Registry Manipulation — RegOpenKey, RegSetValue, data hiding
- **36** : Memory Mapping — mmap, MapViewOfFile, shared memory
- **37** : Reflective Loading — Reflective DLL, manual PE loading
- **38** : ROP Chains — Gadgets, bypass DEP/NX, ret2libc
- **39** : Code Caves — PE injection, backdooring binaries
- **40** : Packing/Unpacking — UPX, custom packers, entropy

#### EDR Bypass & Post-Exploitation (41-45)
- **41** : ETW Patching — Patching EtwEventWrite, bypass EDR logging
- **42** : AMSI Bypass — Patching AmsiScanBuffer, PowerShell bypass
- **43** : Credential Dumping — LSASS, Mimikatz, SAM database
- **44** : Lateral Movement — PsExec, WMI, Pass-the-Hash, RDP
- **45** : C2 Development — Architecture C2, multi-protocol, tasking

## Comment utiliser

### Pour chaque module :

```bash
cd exercices/01_hello_world/

# 1. Lire le cours
cat README.md

# 2. Étudier le code
cat example.c

# 3. Compiler et tester
gcc example.c -o program
./program

# 4. Faire les exercices
cat exercice.txt

# 5. Vérifier les solutions
cat solution.txt
```

### Règles d'apprentissage :

**À faire :**
- Faire les modules dans l'ordre (01 → 02 → 03 → ...)
- Lire TOUS les commentaires dans le code
- Faire les exercices avant de regarder les solutions
- Réécrire le code sans regarder pour mémoriser

**À éviter :**
- Ne pas sauter de modules
- Ne pas copier-coller sans comprendre
- Ne pas ignorer les warnings du compilateur

## Temps estimé

| Modules | Durée par module |
|---------|------------------|
| 01-09 | 30-60 min |
| 10-14 | 1-2h |
| 15-20 | 2-4h |
| 21-33 | 3-5h |
| 34-45 | 4-6h |

**Total** : 120-200 heures (~3-6 mois à temps partiel)

## Compétences Acquises

Après avoir complété ce cours, tu maîtriseras :

### Compétences Techniques
- **C Programming** : Maîtrise professionnelle du langage C
- **Architecture Système** : Compréhension approfondie de la mémoire et du système
- **Binary Exploitation** : Buffer overflow, ROP, shellcode crafting
- **Malware Development** : Techniques réelles utilisées par les APT groups
- **EDR/AV Bypass** : Contournement de sécurités modernes (ETW, AMSI)
- **Post-Exploitation** : Credential dumping, lateral movement, persistence

### Certifications & Carrière
- **OSWA** : Préparation complète Offensive Security Web Assessor
- **OSCP** : Base solide pour Offensive Security Certified Professional
- **OSCE** : Fondations pour Offensive Security Certified Expert
- **Red Team Jobs** : Compétences pour postes FAANG et entreprises de sécurité
- **Bug Bounty** : Exploitation de vulnérabilités binaires en production
- **CTF** : Domination des challenges binaires et pwn

## Prochaines Étapes

### Plateformes d'Entraînement
| Plateforme | Focus | Niveau |
|------------|-------|--------|
| [HackTheBox](https://hackthebox.com) | Binary exploitation, malware analysis | Intermédiaire-Avancé |
| [TryHackMe](https://tryhackme.com) | Red team, offensive security | Débutant-Intermédiaire |
| [PicoCTF](https://picoctf.org) | Pwn challenges, reverse engineering | Débutant |
| [pwnable.kr](http://pwnable.kr) | Binary exploitation pure | Avancé |

### Certifications Recommandées
1. **OSWA** (Web Assessor) ← Ce cours te prépare directement
2. **OSCP** (Certified Professional) ← Base solide acquise
3. **OSCE** (Certified Expert) ← Niveau avancé accessible

### Compétences Complémentaires
- **Assembleur x86/x64** : Pour reverse engineering avancé
- **Outils** : IDA Pro, Ghidra, Binary Ninja, x64dbg
- **Techniques avancées** : Heap feng shui, kernel exploitation
- **Frameworks** : Développer ton propre C2 (Cobalt Strike-like)

## Ressources Complémentaires

### Documentation Officielle
- [GCC Documentation](https://gcc.gnu.org/onlinedocs/) — Compilateur C complet
- [GDB Tutorial](https://www.gdbtutorial.com/) — Debugging avancé
- [C Reference](https://en.cppreference.com/w/c) — Référence complète du langage

### Inspirations Pédagogiques
- [Bro Code - C Tutorial](https://www.youtube.com/watch?v=87SH2Cn0s9A) — Style d'enseignement concis
- [LiveOverflow](https://www.youtube.com/c/LiveOverflow) — Binary exploitation
- [IppSec](https://www.youtube.com/c/ippsec) — HackTheBox walkthroughs

### Livres Recommandés
- **The C Programming Language** (Kernighan & Ritchie) — Bible du C
- **Hacking: The Art of Exploitation** (Jon Erickson) — Exploitation fondamentale
- **Practical Malware Analysis** (Sikorski & Honig) — Analyse de malware
- **The Shellcoder's Handbook** — Exploitation avancée

## Soutenir le Projet

Si ce cours t'aide dans ton apprentissage du C et du red teaming :

1. **⭐ Star ce repository** pour le rendre plus visible
2. **Fork** pour créer ta propre version
3. **Partage** avec d'autres apprenants en cybersécurité
4. **Contribue** en reportant des bugs ou proposant des améliorations
5. **Feedback** : Ouvre une issue pour suggestions ou questions

**Objectif : Devenir la meilleure ressource C pour Red Team en français**

### Comment Contribuer

```bash
# Fork le projet
git clone https://github.com/yourusername/Learning-C.git
cd Learning-C

# Crée une branche pour tes modifications
git checkout -b feature/amelioration-module-X

# Fais tes modifications et commite
git add .
git commit -m "feat: amélioration module X avec technique Y"

# Push et crée une Pull Request
git push origin feature/amelioration-module-X
```

### Contributions Recherchées
- Corrections de bugs ou typos
- Amélioration des exercices
- Ajout d'exemples supplémentaires
- Traduction en anglais
- Nouvelles techniques de bypass EDR/AV
- Optimisation du code

## ⚠️ AVERTISSEMENT LÉGAL STRICT

**Les techniques enseignées sont à des fins ÉDUCATIVES et de RECHERCHE EN SÉCURITÉ UNIQUEMENT.**

### Usage Autorisé

- **Tes propres systèmes** personnels
- **VM de test isolées** (VirtualBox, VMware, etc.)
- **CTF et challenges** légaux (HackTheBox, TryHackMe, etc.)
- **Bug bounty** avec autorisation explicite du programme
- **Red team contractuel** avec accord écrit de l'entreprise cliente
- **Recherche en sécurité** dans un environnement contrôlé

### Strictement INTERDIT

- **Systèmes sans autorisation** écrite explicite
- **Usage malveillant** ou criminel de toute nature
- **Attaques réelles** sur infrastructures publiques ou privées
- **Distribution de malware** fonctionnel à des tiers
- **Cybercriminalité** sous toutes ses formes

### Responsabilité Légale

**L'usage illégal de ces techniques peut entraîner** :
- Poursuites judiciaires civiles et pénales
- Peines de prison (jusqu'à 10 ans selon juridiction)
- Amendes importantes (jusqu'à plusieurs millions d'euros)
- Interdiction d'exercer dans le domaine informatique
- Casier judiciaire permanent

**Les auteurs de ce cours déclinent toute responsabilité** pour l'usage malveillant ou illégal des techniques enseignées. La responsabilité légale incombe entièrement à l'utilisateur.

## Démarrage Rapide

```bash
# Clone le repository
git clone https://github.com/yourusername/Learning-C.git
cd Learning-C

# Vérifie l'installation de GCC
gcc --version

# Commence avec le premier module
cd exercices/01_hello_world/
cat README.md
gcc example.c -o program
./program
```

## Statistiques du Projet

- **45 modules progressifs** du débutant à l'expert
- **180+ fichiers** de cours, exemples et exercices
- **360+ exercices pratiques** avec solutions complètes
- **120-200 heures** de contenu pédagogique
- **3-6 mois** pour maîtrise complète

---

## Contact & Support

- **Issues GitHub** : Pour bugs, questions techniques et suggestions
- **Discussions** : Pour partager tes projets et progressions
- **Pull Requests** : Contributions bienvenues !

---

**Bonne chance dans ton apprentissage du C et du Red Teaming !**

*"Le C est la clé pour comprendre comment les systèmes fonctionnent réellement. Maîtrise-le, et tu maîtriseras la sécurité offensive."*

---

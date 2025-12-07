# C Full Offensive Course

> **Formation complète en C pour Red Teamers et Malware Developers**
> De "Hello World" au développement de C2 frameworks

## Objectif

Ce cours t'apprend le C depuis zéro avec un objectif clair : devenir Red Teamer / Malware Developer.
Progression : bases → exploitation → évasion → post-exploitation.

## Prérequis

- **Aucune connaissance en C requise**
- Motivation pour l'offensive security
- Machine virtuelle recommandée pour les phases d'exploitation
- OS supportés : Linux, macOS, Windows

## Installation rapide

```bash
git clone https://github.com/roadmvn/C-Full-Offensive-Course.git
cd C-Full-Offensive-Course
chmod +x setup.sh
./setup.sh
```

## Structure du cours (206 modules)

### 01_CORE - Fondamentaux C et Exploitation (31 modules)

#### PHASE_01 : Fondamentaux C
| Module | Sujet |
|--------|-------|
| 01-09 | Variables, types, opérateurs, conditions, boucles |
| 10-14 | Fonctions, pointeurs, structures, préprocesseur, I/O |

#### PHASE_02 : Mémoire Avancée
| Module | Sujet |
|--------|-------|
| 15-17 | Stack/Heap, Integer overflow, Compilation |
| 18-21 | Buffer overflow, Format strings, Data structures |

#### PHASE_03 : Exploitation Basics
| Module | Sujet |
|--------|-------|
| 22-23 | ARM64 architecture, Shellcode ARM64 |
| 24-26 | Calling conventions, Shellcode basics, Reverse shell |
| 27-31 | Stack overflow, ROP basics/ARM64, Heap exploitation |

### 02_WINDOWS - Windows Offensive (82 modules)

| Phase | Modules | Sujets |
|-------|---------|--------|
| W01 | W01-W10 | Windows API, Processes, Memory, Services, WMI, Winsock |
| W02 | W11-W22 | PE Format, PEB/TEB, NTDLL, Syscalls, ETW, Defender |
| W03 | W23-W32 | DLL Injection, Process Hollowing, Shellcode, Hooking |
| W04 | W33-W44 | String obfuscation, AMSI/ETW bypass, Anti-debug, Packers |
| W05 | W45-W64 | Agent dev, HTTP/DNS C2, Beacon, Keylogger, Persistence |
| W06 | W65-W70 | Token manipulation, Credentials, Pass-the-Hash, WMI lateral |
| W07 | W71-W82 | Kernel drivers, DKOM, SSDT, Minifilters, BYOVD, PatchGuard |

### 03_LINUX - Linux Offensive (46 modules)

| Phase | Modules | Sujets |
|-------|---------|--------|
| L01 | L01-L08 | ELF, Syscalls, /proc, Shared libs, Permissions, Memory |
| L02 | L09-L16 | Process injection, Syscall hooking, Anti-debug, PAM, Shellcode |
| L03 | L17-L22 | Stack overflow, Format strings, UAF, Kernel exploits, Dirty Pipe |
| L04 | L23-L32 | HTTP/DNS client, Beacon, Evasion, Keylogger, Lateral movement |
| L05 | L33-L40 | LKM, Syscall hooks, Process/File hiding, Rootkits, eBPF |
| L06 | L41-L46 | Containers, Docker/K8s exploitation, Namespace/Cgroup escape |

### 04_MACOS - macOS Offensive (25 modules)

| Phase | Modules | Sujets |
|-------|---------|--------|
| M01 | M01-M06 | Mach-O, Syscalls, Dylib, Mach ports, Codesigning, XPC |
| M02 | M07-M12 | TCC, SIP, Gatekeeper, Endpoint Security, Kext, AMFI |
| M03 | M13-M19 | HTTP client, Beacon, Dylib injection, Keychain, Screenshot |
| M04 | M21-M25 | Sandbox detection, Anti-debug, Process injection, Lateral |

### 05_ADVANCED - Techniques Avancées (22 modules)

| Phase | Modules | Sujets |
|-------|---------|--------|
| A01 | A01-A05 | Virtualization, VM detection/escape, Hyperjacking, Cloud |
| A02 | A06-A10 | UEFI, Secure Boot, SPI Flash, Bootkits, SMM |
| A03 | A11-A14 | Side-channel, Spectre/Meltdown, Rowhammer, Hardware implants |
| A04 | A15-A18 | Dependency confusion, Typosquatting, Build compromise |
| A05 | A19-A22 | LLM attacks, Prompt injection, Model extraction, AI Red Team |

## Comment utiliser ce cours

Chaque module contient :
- `Cours.md` - Théorie complète avec diagrammes ASCII
- `example.c` - Code commenté fonctionnel
- `exercice.md` - Exercices pratiques progressifs
- `solution.md` - Solutions détaillées

**Progression recommandée :**
1. Lis le `Cours.md`
2. Analyse `example.c`
3. Fais les exercices
4. Compare avec les solutions

## Statistiques

| Type | Fichiers |
|------|----------|
| Cours | 206 |
| Exercices | 206 |
| Solutions | 129 |
| **Total lignes** | ~91,000 |

## Disclaimer

**Ce cours est à but éducatif uniquement.**
L'utilisation de ces techniques sur des systèmes sans autorisation explicite est **illégale**.
Utilise ces connaissances de manière éthique et responsable.

## Licence

MIT License - Voir [LICENCE](LICENCE)

---

**Happy Hacking!**

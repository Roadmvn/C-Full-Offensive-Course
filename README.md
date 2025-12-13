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

## Structure du cours

```
C-Full-Offensive-Course/
├── 00-Fondations/          # Fondamentaux C + Mémoire + ASM
├── 01-Windows/             # Windows Offensive (API, Internals, Injection, Evasion, C2)
├── 02-Linux/               # Linux Offensive (Syscalls, Rootkits, C2)
├── 03-macOS/               # macOS Offensive (Mach-O, Injection, Evasion)
├── 04-Advanced/            # Hyperviseur, Firmware, Hardware, Supply Chain, AI
├── Labs/                   # Environnements de pratique
└── Resources/              # Cheatsheets et templates
```

---

### 00-Fondations - Fondamentaux C et Exploitation

| Phase | Dossier | Modules | Contenu |
|-------|---------|---------|---------|
| **C Programming** | `01-C-Programmation/` | 12 | Variables, types, pointeurs, structures, fonctions |
| **Mémoire Bas-Niveau** | `02-Memoire-Bas-Niveau/` | 12 | Stack/Heap, Buffer overflow, Format strings, Heap exploitation |
| **Assembleur x64** | `03-ASM-x64/` | 5 | Registres, Calling conventions, Inline ASM, MASM/NASM |

---

### 01-Windows - Windows Offensive

| Phase | Dossier | Modules | Contenu |
|-------|---------|---------|---------|
| **Fondamentaux** | `01-Fondamentaux/` | 10 | Windows API, Processes, Memory, Services, WMI, Winsock, Tokens |
| **Internals** | `02-Internals/` | 12 | PE Format, PEB/TEB, NTDLL, Syscalls, ETW, Defender Internals |
| **Shellcoding** | `03-Shellcoding/` | 7 | Shellcode basics, PIC, Null-free, API hashing, Encoders, Crypters |
| **Process Injection** | `04-Process-Injection/` | 10 | DLL Injection, Process Hollowing, Module Stomping, Hooking, Reflective DLL |
| **Evasion** | `05-Evasion/` | 12 | String obfuscation, AMSI/ETW bypass, Direct Syscalls, Sleep obfuscation, Anti-debug |
| **Credential Access** | `07-Credential-Access/` | 6 | Token manipulation, Pass-the-Hash, WMI lateral, DCOM |
| **C2 Development** | `08-C2-Development/` | 21 | HTTP/DNS C2, Beacon, Keylogger, Screenshot, Persistence |
| **Kernel** | `09-Kernel/` | 12 | Drivers, DKOM, SSDT, Minifilters, BYOVD |

---

### 02-Linux - Linux Offensive

| Phase | Dossier | Modules | Contenu |
|-------|---------|---------|---------|
| **Fondamentaux** | `01-Fondamentaux/` | 8 | Syscalls, ELF, Ptrace, /proc, Shared libs (LD_PRELOAD), Permissions |
| **Internals** | `02-Internals/` | 8 | Process internals, Memory layout, Sandbox, Namespaces |
| **Shellcoding** | `03-Shellcoding/` | 6 | Linux shellcode, Race conditions, Exploitation |
| **Privilege Escalation** | `07-Privilege-Escalation/` | 5 | ROP, Kernel exploits, Docker exploitation |
| **Rootkits** | `08-Rootkits/` | 8 | LKM, Syscall hooks, Process/File hiding, eBPF |
| **C2 Development** | `09-C2-Development/` | 10 | Linux C2 agents, Evasion, Lateral movement |

---

### 03-macOS - macOS Offensive

| Phase | Dossier | Modules | Contenu |
|-------|---------|---------|---------|
| **Fondamentaux** | `01-Fondamentaux/` | 6 | Mach-O, Syscalls, Dylib, Mach ports, Codesigning, XPC |
| **Internals** | `02-Internals/` | 6 | TCC, SIP, Gatekeeper, Endpoint Security, AMFI |
| **Injection** | `03-Injection/` | 9 | Dylib injection, Process injection |
| **Evasion** | `04-Evasion/` | 5 | Sandbox detection, Anti-debug |
| **Privilege Escalation** | `06-Privilege-Escalation/` | 1 | macOS privesc techniques |

---

### 04-Advanced - Techniques Avancées

| Phase | Dossier | Modules | Contenu |
|-------|---------|---------|---------|
| **Hypervisor** | `01-Hypervisor/` | 5 | VM detection/escape, Hyperjacking |
| **Firmware** | `02-Firmware/` | 5 | UEFI, Secure Boot, Bootkits |
| **Hardware** | `03-Hardware/` | 4 | Side-channel, Spectre/Meltdown, Rowhammer |
| **Supply Chain** | `04-Supply-Chain/` | 4 | Dependency confusion, Build compromise |
| **AI Security** | `05-AI-Security/` | 4 | LLM attacks, Prompt injection |

---

## Comment utiliser ce cours

Chaque module contient :
- `Cours.md` - Théorie complète avec diagrammes ASCII
- `example.c` - Code commenté fonctionnel
- `exercice.md` - Exercices pratiques progressifs
- `solution.md` ou `solution.c` - Solutions détaillées

**Progression recommandée :**
1. Lis le `Cours.md`
2. Analyse `example.c`
3. Fais les exercices
4. Compare avec les solutions

## Techniques clés couvertes

### Windows Evasion
- **Syscall Evasion** : Hell's Gate, Halo's Gate, SysWhispers
- **Sleep Obfuscation** : Ekko, Foliage, Memory encryption
- **Unhooking** : Fresh NTDLL, Perun's Fart
- **Callback Evasion** : Starving, Process Doppelganging

### Linux Offensive
- **LD_PRELOAD Hooking** : Function interception, Credential stealing
- **Container Escapes** : Docker socket, Capabilities abuse, Cgroups
- **eBPF Rootkits** : Syscall monitoring, Process hiding

---

## Disclaimer

**Ce cours est à but éducatif uniquement.**
L'utilisation de ces techniques sur des systèmes sans autorisation explicite est **illégale**.
Utilise ces connaissances de manière éthique et responsable.

## Licence

MIT License - Voir [LICENCE](LICENCE)

---

**Happy Hacking!**

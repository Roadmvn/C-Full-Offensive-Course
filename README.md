# C Maldev Journey

> Du printf() au beacon C2 fonctionnel en 12 semaines.

```
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   ░█▀▀░░░░█▄█░█▀█░█░░░█▀▄░█▀▀░█░█░░░░░▀▀█░█▀█░█░█░█▀▄░█▀█░█▀▀░█░█       ║
    ║   ░█░░░░░░█░█░█▀█░█░░░█░█░█▀▀░▀▄▀░░░░░░░█░█░█░█░█░█▀▄░█░█░█▀▀░░█░       ║
    ║   ░▀▀▀░░░░▀░▀░▀░▀░▀▀▀░▀▀░░▀▀▀░░▀░░░░░░▀▀░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀▀▀░░▀░       ║
    ║                                                                           ║
    ║               Apprends le C offensif de zero a beacon                     ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
```

## Roadmap

```
SEMAINE     1    2    3    4    5    6    7    8    9   10   11   12
            │    │    │    │    │    │    │    │    │    │    │    │
            ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
         ┌─────────────────┐ ┌──────────────┐ ┌─────────┐ ┌────────────┐
         │  PHASE 1        │ │  PHASE 2     │ │ PHASE 3 │ │  PHASE 4   │
         │  C Foundations  │ │  Windows     │ │ Network │ │  Beacon    │
         │                 │ │  Internals   │ │         │ │            │
         │  - Variables    │ │  - Process   │ │ - TCP   │ │ - Arch     │
         │  - Pointeurs    │ │  - Memory    │ │ - HTTP  │ │ - Commands │
         │  - Structures   │ │  - DLLs      │ │         │ │ - Final    │
         │  - WinAPI       │ │              │ │         │ │            │
         └─────────────────┘ └──────────────┘ └─────────┘ └────────────┘
                │                   │              │            │
                ▼                   ▼              ▼            ▼
         ┌──────────┐        ┌──────────┐   ┌──────────┐  ┌──────────┐
         │ Compile  │        │ Shellcode│   │ Callback │  │  BEACON  │
         │ ton 1er  │        │ runner   │   │ HTTP     │  │  COMPLET │
         │ programme│        │ local    │   │ simple   │  │          │
         └──────────┘        └──────────┘   └──────────┘  └──────────┘
```

## Quick Start

### 1. Clone le repo
```bash
git clone https://github.com/ton-user/C-Maldev-Journey.git
cd C-Maldev-Journey
```

### 2. Installe Visual Studio Build Tools
- Telecharge [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)
- Installe "Desktop development with C++"

### 3. Commence la Semaine 1
```bash
cd Learning-Path/Phase-1-Foundations/Week-01-C-Absolute-Basics
```

### 4. Compile et pratique
```batch
REM Ouvre "Developer Command Prompt for VS"
build.bat
REM Ou manuellement:
cl Lessons\01-hello-world.c
01-hello-world.exe
```

## Structure du repo

```
C-Maldev-Journey/
│
├── Learning-Path/              <-- PARCOURS PRINCIPAL (commence ici)
│   ├── Phase-1-Foundations/       Semaines 1-4: Bases C + WinAPI
│   ├── Phase-2-Windows-Fundamentals/  Semaines 5-7: Process, Memory, DLLs
│   ├── Phase-3-Network-Communication/ Semaines 8-9: TCP, HTTP
│   └── Phase-4-Beacon-Assembly/   Semaines 10-12: Construction beacon
│
├── Reference-Code/             <-- Code avance (consulter apres)
│   ├── 00-Fondations/             Fondamentaux C et memoire
│   ├── 01-Windows/                Techniques Windows avancees
│   ├── 02-Linux/                  Techniques Linux
│   ├── 03-macOS/                  Techniques macOS
│   └── 04-Advanced/               Hyperviseur, Firmware, etc.
│
├── Resources/
│   └── Cheatsheets/            <-- Aide-memoire
│
└── README.md                   <-- Tu es ici
```

## Planning semaine par semaine

| Sem | Phase | Focus | Livrable |
|-----|-------|-------|----------|
| 1 | Foundations | C Basics: variables, if, loops, functions | Calculatrice |
| 2 | Foundations | Pointeurs, memoire, malloc/free | XOR buffer |
| 3 | Foundations | Structures, fichiers binaires | Parser binaire |
| 4 | Foundations | Premier WinAPI: MessageBox, handles | Hello WinAPI |
| 5 | Windows | Processus, threads, enumeration | Process lister |
| 6 | Windows | VirtualAlloc, VirtualProtect, RWX | Shellcode runner |
| 7 | Windows | LoadLibrary, GetProcAddress, PEB | API resolver |
| 8 | Network | Winsock, TCP client/server | Reverse shell TCP |
| 9 | Network | WinHTTP, GET/POST, parsing | HTTP callback |
| 10 | Beacon | Architecture, sleep, check-in | Beacon skeleton |
| 11 | Beacon | Commands: whoami, ls, cat, cd | Beacon + 5 cmds |
| 12 | Beacon | Obfuscation, compilation, test | **BEACON FINAL** |

## Chaque semaine contient

```
Week-XX/
├── Lessons/          4-5 fichiers .c commentes
├── Exercises/        3 exercices pratiques
├── Solutions/        Solutions des exercices
├── README.md         Objectifs et concepts
├── quiz.json         Quiz de validation
└── build.bat         Script de compilation
```

## Comment valider une semaine

1. **Lis les lessons** dans l'ordre (01, 02, 03...)
2. **Compile chaque fichier** pour verifier que tu comprends
3. **Fais les exercices** (sans regarder les solutions !)
4. **Compare avec les solutions**
5. **Passe au suivant**

## Philosophie du cours

### Ce qu'on fait
- Explications niveau debutant (analogies simples)
- Code commente ligne par ligne
- Progression tres graduelle
- Exercices pratiques a chaque etape

### Ce qu'on ne fait PAS
- Copier-coller sans comprendre
- Sauter des etapes
- Utiliser le code en production (cours educatif uniquement)

## Reference-Code : Contenu avance

Le dossier `Reference-Code/` contient le code avance original, a consulter **apres** avoir termine le Learning Path :

| Dossier | Contenu |
|---------|---------|
| `00-Fondations/` | C avance, memoire, ASM |
| `01-Windows/` | PE, Injection, Evasion, C2, Kernel |
| `02-Linux/` | Syscalls, ELF, Rootkits |
| `03-macOS/` | Mach-O, Injection |
| `04-Advanced/` | Hyperviseur, Firmware |

## Disclaimer

Ce cours est a but **educatif uniquement**.

Le code produit est destine a comprendre les techniques utilisees par les malwares, pas a les deployer. Utilise ces connaissances de maniere ethique et legale:
- Tests d'intrusion autorises
- CTF et challenges
- Recherche en securite
- Red team avec autorisation ecrite

## Ressources complementaires

- [MalDev Academy](https://maldevacademy.com/)
- [Sektor7 RED TEAM Operator](https://institute.sektor7.net/)
- [MSDN Windows API](https://learn.microsoft.com/en-us/windows/win32/api/)
- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

## Licence

MIT License - Voir [LICENCE](LICENCE)

---

**Pret a commencer ?**

```
cd Learning-Path/Phase-1-Foundations/Week-01-C-Absolute-Basics
```

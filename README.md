# C Maldev Journey

> Du printf() au beacon C2 fonctionnel en 12 semaines.

```
    ╔═════════════════════════════════════════════════════════════════════════╗
    ║                                                                         ║
    ║   ░█▀▀░░░░█▄█░█▀█░█░░░█▀▄░█▀▀░█░█░░░░░▀▀█░█▀█░█░█░█▀▄░█▀█░█▀▀░█░█       ║
    ║   ░█░░░░░░█░█░█▀█░█░░░█░█░█▀▀░▀▄▀░░░░░░░█░█░█░█░█░█▀▄░█░█░█▀▀░░█░       ║
    ║   ░▀▀▀░░░░▀░▀░▀░▀░▀▀▀░▀▀░░▀▀▀░░▀░░░░░░▀▀░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀▀▀░░▀░       ║
    ║                                                                         ║
    ║               Apprends le C offensif de zero a beacon                   ║
    ║                                                                         ║
    ╚═════════════════════════════════════════════════════════════════════════╝
```

## Philosophie Pedagogique

Ce cours est concu pour emmener quelqu'un qui n'a **aucune connaissance prealable** jusqu'a la capacite d'ecrire des outils offensifs de niveau professionnel.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PYRAMIDE D'APPRENTISSAGE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                              ┌───────────┐                                  │
│                              │  PROJETS  │  ← Outils offensifs complets     │
│                              │ INTEGRES  │    (Phase 4: Beacon)             │
│                            ┌─┴───────────┴─┐                                │
│                            │   RESEAU &    │  ← TCP, HTTP, Callbacks        │
│                            │ COMMUNICATION │    (Phase 3)                   │
│                          ┌─┴───────────────┴─┐                              │
│                          │    WINDOWS        │  ← Process, Memory, DLLs     │
│                          │   INTERNALS       │    (Phase 2)                 │
│                        ┌─┴───────────────────┴─┐                            │
│                        │   FONDAMENTAUX C &     │  ← Pointeurs, Structs,    │
│                        │      WINAPI            │    WinAPI (Phase 1)       │
│                      ┌─┴───────────────────────┴─┐                          │
│                      │  PREREQUIS INFORMATIQUES   │  ← Binaire, CPU, Memoire│
│                      │  (Bits, Memoire, CPU, OS)  │    (Phase 0)            │
│                      └────────────────────────────┘                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **Voir [LEARNING_METHODOLOGY.md](LEARNING_METHODOLOGY.md) pour la methodologie complete.**

## Roadmap

```
          PHASE 0       PHASE 1         PHASE 2          PHASE 3       PHASE 4
         Prerequis     Foundations      Windows          Network       Beacon
            │              │              │                │             │
            ▼              ▼              ▼                ▼             ▼
        ┌────────┐  ┌─────────────┐ ┌──────────────┐ ┌─────────┐ ┌────────────┐
        │Binaire │  │ Variables   │ │  Process     │ │  TCP    │ │ Arch       │
        │CPU     │  │ Pointeurs   │ │  Memory      │ │  HTTP   │ │ Commands   │
        │Memoire │  │ Structures  │ │  DLLs        │ │         │ │ Final      │
        │OS      │  │ WinAPI      │ │              │ │         │ │            │
        └────────┘  └─────────────┘ └──────────────┘ └─────────┘ └────────────┘
            │              │              │                │             │
            ▼              ▼              ▼                ▼             ▼
       Comprendre     Compiler       Shellcode        Callback      BEACON
       la machine     ton 1er        runner           HTTP          COMPLET
                      programme      local            simple
```

## Quick Start

### 1. Clone le repo
```bash
git clone https://github.com/Roadmvn/C-Full-Offensive-Course.git
cd C-Full-Offensive-Course
```

### 2. Installe Visual Studio Build Tools
- Telecharge [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)
- Installe "Desktop development with C++"

### 3. Commence par les Prerequis (recommande) ou les bases C
```bash
# Pour les debutants absolus :
cd Course/00-prerequisites

# Si tu connais deja les bases informatiques :
cd Course/01-c-fundamentals
```

### 4. Compile et pratique
```batch
REM Ouvre "Developer Command Prompt for VS"
cl lessons\01-hello-world.c
01-hello-world.exe
```

## Structure du repo

```
C-Full-Offensive-Course/
│
├── Course/                           <-- PARCOURS UNIFIE
│   ├── 00-prerequisites/                Binaire, CPU, Memoire, OS
│   ├── 01-c-fundamentals/               Bases C: variables, pointeurs, fonctions
│   ├── 02-memory-pointers/              Memoire avancee, malloc, heap
│   ├── 03-asm-x64/                      Assembly x64, registres, calling conventions
│   ├── 04-windows-fundamentals/         WinAPI, Process, Threads, Memory
│   ├── 05-windows-advanced/             Shellcode, Injection, Evasion, C2, Kernel
│   ├── 06-network/                      TCP, HTTP, Winsock
│   ├── 07-beacon-dev/                   Architecture beacon, commands, final
│   ├── 08-linux/                        Syscalls, ELF, Rootkits, eBPF
│   ├── 09-macos/                        Mach-O, TCC, Dylib, ARM64
│   └── 10-advanced/                     Hyperviseur, Firmware, Hardware, AI
│
├── Resources/
│   └── Cheatsheets/                  <-- Aide-memoire
│
├── LEARNING_METHODOLOGY.md           <-- Methodologie complete
└── README.md                         <-- Tu es ici
```

### Structure de chaque module

```
XX-module-name/
├── README.md           # Objectifs et concepts
├── CHECKPOINT.md       # Questions de validation (si applicable)
├── lessons/            # Fichiers .c commentes + cours
├── exercises/          # Exercices pratiques
├── solutions/          # Solutions
└── topics/             # Sous-modules avances (Reference-Code integre)
```

## Cycle d'Apprentissage

Pour chaque module, suis ce cycle :

```
┌─────────────────────────────────────────────────────────────────┐
│                    CYCLE D'APPRENTISSAGE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│     ┌──────────────┐                                            │
│     │   1. LIRE    │  Etudier les cours dans l'ordre            │
│     │   le cours   │  Prendre des notes                         │
│     └──────┬───────┘                                            │
│            │                                                    │
│            ▼                                                    │
│     ┌──────────────┐                                            │
│     │  2. ETUDIER  │  Lire et comprendre chaque ligne           │
│     │   le code    │  Modifier et experimenter                  │
│     └──────┬───────┘                                            │
│            │                                                    │
│            ▼                                                    │
│     ┌──────────────┐                                            │
│     │  3. FAIRE    │  Sans regarder les solutions               │
│     │ les exercices│  Echouer est normal et utile               │
│     └──────┬───────┘                                            │
│            │                                                    │
│            ▼                                                    │
│     ┌──────────────┐                                            │
│     │ 4. COMPARER  │  Comprendre les differences                │
│     │ aux solutions│  Noter les ameliorations                   │
│     └──────┬───────┘                                            │
│            │                                                    │
│            ▼                                                    │
│     ┌──────────────┐                                            │
│     │  5. PASSER   │  Seulement quand tout est clair            │
│     │   au suivant │  Pas de precipitation                      │
│     └──────────────┘                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Regles d'Or

1. **Ne sautez pas de modules** - Meme si vous pensez connaitre, revisez
2. **Tapez le code vous-meme** - Ne copiez-collez pas, meme pour les exemples
3. **Echouez d'abord** - Essayez les exercices avant de voir les solutions
4. **Experimentez** - Modifiez le code pour voir ce qui se passe
5. **Prenez votre temps** - La maitrise vaut mieux que la vitesse

## Planning semaine par semaine

| Phase | Sem | Focus | Livrable |
|-------|-----|-------|----------|
| 0 | - | Binaire, CPU, Memoire, OS | Comprehension machine |
| 1 | 1 | C Basics: variables, if, loops, functions | Calculatrice |
| 1 | 2 | Pointeurs, memoire, malloc/free | XOR buffer |
| 1 | 3 | Structures, fichiers binaires | Parser binaire |
| 1 | 4 | Premier WinAPI: MessageBox, handles | Hello WinAPI |
| 2 | 5 | Processus, threads, enumeration | Process lister |
| 2 | 6 | VirtualAlloc, VirtualProtect, RWX | Shellcode runner |
| 2 | 7 | LoadLibrary, GetProcAddress, PEB | API resolver |
| 3 | 8 | Winsock, TCP client/server | Reverse shell TCP |
| 3 | 9 | WinHTTP, GET/POST, parsing | HTTP callback |
| 4 | 10 | Architecture, sleep, check-in | Beacon skeleton |
| 4 | 11 | Commands: whoami, ls, cat, cd | Beacon + 5 cmds |
| 4 | 12 | Obfuscation, compilation, test | **BEACON FINAL** |

## Validation des Competences

### Apres Phase 0 (Prerequis)
- [ ] Convertir entre binaire, decimal et hexadecimal
- [ ] Expliquer les bases de l'architecture CPU
- [ ] Decrire l'organisation de la memoire (stack, heap)

### Apres Phase 1 (Foundations)
- [ ] Lire et ecrire des programmes C basiques
- [ ] Manipuler pointeurs et allocation dynamique
- [ ] Utiliser les bases de l'API Windows

### Apres Phase 2 (Windows)
- [ ] Manipuler la memoire avec VirtualAlloc/VirtualProtect
- [ ] Creer et enumerer des processus
- [ ] Executer du shellcode en memoire locale

### Apres Phase 3 (Network)
- [ ] Programmer des communications TCP
- [ ] Implementer des requetes HTTP
- [ ] Creer un reverse shell fonctionnel

### Apres Phase 4 (Beacon)
- [ ] Concevoir l'architecture d'un implant
- [ ] Implementer des commandes basiques
- [ ] Appliquer des techniques d'obfuscation

## Contenu par section

| Section | Modules | Contenu |
|---------|---------|---------|
| `00-prerequisites` | 5 | Binaire, CPU, Memoire, OS |
| `01-c-fundamentals` | 11+ | Variables, types, pointeurs, fonctions |
| `02-memory-pointers` | 12+ | Stack, heap, buffer overflow, format strings |
| `03-asm-x64` | 5 | Registres, calling conventions, inline ASM |
| `04-windows-fundamentals` | 21+ | WinAPI, Process, Threads, Memory, Internals |
| `05-windows-advanced` | 65+ | Shellcode, Injection, Evasion, C2, Kernel |
| `06-network` | 8+ | TCP, HTTP, Winsock, WinHTTP |
| `07-beacon-dev` | 12+ | Architecture, commands, obfuscation |
| `08-linux` | 47 | Syscalls, ELF, Rootkits, eBPF, Containers |
| `09-macos` | 28 | Mach-O, TCC, SIP, Dylib, ARM64 |
| `10-advanced` | 18 | Hyperviseur, Firmware, Hardware, AI Security |

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

```bash
# Debutant absolu ? Commence par les fondamentaux :
cd Course/00-prerequisites

# Tu connais deja les bases ? Va directement au C :
cd Course/01-c-fundamentals
```

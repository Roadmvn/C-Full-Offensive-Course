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

### 3. Commence par les Prerequis (recommande) ou Phase 1
```bash
# Pour les debutants absolus :
cd Learning-Path/Phase-0-Prerequisites

# Si tu connais deja les bases informatiques :
cd Learning-Path/Phase-1-Foundations/Week-01-C-Absolute-Basics
```

### 4. Compile et pratique
```batch
REM Ouvre "Developer Command Prompt for VS"
cl Lessons\01-hello-world.c
01-hello-world.exe
```

## Structure du repo

```
C-Full-Offensive-Course/
│
├── Learning-Path/                    <-- PARCOURS PRINCIPAL (commence ici)
│   ├── Phase-0-Prerequisites/           Fondamentaux: Binaire, CPU, Memoire
│   ├── Phase-1-Foundations/             Semaines 1-4: Bases C + WinAPI
│   ├── Phase-2-Windows-Fundamentals/    Semaines 5-7: Process, Memory, DLLs
│   ├── Phase-3-Network-Communication/   Semaines 8-9: TCP, HTTP
│   └── Phase-4-Beacon-Assembly/         Semaines 10-12: Construction beacon
│
├── Reference-Code/                   <-- Code avance (consulter apres)
│   ├── 00-Fondations/                   Fondamentaux C et memoire
│   ├── 01-Windows/                      Techniques Windows avancees
│   ├── 02-Linux/                        Techniques Linux
│   ├── 03-macOS/                        Techniques macOS
│   └── 04-Advanced/                     Hyperviseur, Firmware, etc.
│
├── Resources/
│   └── Cheatsheets/                  <-- Aide-memoire
│
├── LEARNING_METHODOLOGY.md           <-- Methodologie complete
└── README.md                         <-- Tu es ici
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

## Chaque semaine contient

```
Week-XX/
├── Lessons/          4-5 fichiers .c commentes
├── Exercises/        3 exercices pratiques
├── Solutions/        Solutions des exercices
└── README.md         Objectifs et concepts
```

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

```bash
# Debutant absolu ? Commence par les fondamentaux :
cd Learning-Path/Phase-0-Prerequisites

# Tu connais deja les bases ? Va directement au C :
cd Learning-Path/Phase-1-Foundations/Week-01-C-Absolute-Basics
```

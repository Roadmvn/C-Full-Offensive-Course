# Phase 4 : Beacon Assembly

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         PHASE 4                                     │   │
│   │                     BEACON ASSEMBLY                                 │   │
│   │                                                                     │   │
│   │    Semaines 10-12 : Construction du Beacon Final                   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   "Le moment ou tout s'assemble."                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Vue d'Ensemble

Cette phase finale assemble toutes les competences acquises pour construire un **beacon C2 fonctionnel**. C'est le projet culminant du cours.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE BEACON                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                      BEACON                              │   │
│   │  ┌─────────────────────────────────────────────────────┐ │   │
│   │  │                    MAIN LOOP                        │ │   │
│   │  │                                                     │ │   │
│   │  │   while(running) {                                  │ │   │
│   │  │       sleep(jitter);           // Anti-detection    │ │   │
│   │  │       task = check_in();       // HTTP GET          │ │   │
│   │  │       if (task) {                                   │ │   │
│   │  │           result = execute(task);  // Run command  │ │   │
│   │  │           send_result(result);     // HTTP POST    │ │   │
│   │  │       }                                             │ │   │
│   │  │   }                                                 │ │   │
│   │  │                                                     │ │   │
│   │  └─────────────────────────────────────────────────────┘ │   │
│   │                                                         │   │
│   │  MODULES:                                               │   │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │   │
│   │  │  Config  │ │  Crypto  │ │ Commands │ │  Comms   │   │   │
│   │  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Objectifs d'Apprentissage

A la fin de cette phase, vous serez capable de :

- [ ] Concevoir l'architecture d'un implant
- [ ] Implementer une boucle de check-in
- [ ] Creer des commandes (whoami, ls, cd, cat, pwd)
- [ ] Gerer le jitter et le sleep
- [ ] Appliquer des techniques d'obfuscation basiques
- [ ] Compiler un beacon fonctionnel

## Prerequis

- **Phases 0-3 completees**
- Maitrise de C, Windows API et reseau
- Serveur de test pour le C2

## Contenu Detaille

### Semaine 10 : Beacon Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    CYCLE DE VIE BEACON                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   START                                                         │
│     │                                                           │
│     ▼                                                           │
│   ┌─────────────────┐                                           │
│   │  Initialisation │  Config, crypto setup                     │
│   └────────┬────────┘                                           │
│            │                                                    │
│            ▼                                                    │
│   ┌─────────────────┐                                           │
│   │   Check-in      │←─────────────────────────┐                │
│   │   (HTTP GET)    │                          │                │
│   └────────┬────────┘                          │                │
│            │                                   │                │
│            ▼                                   │                │
│   ┌─────────────────┐     No task              │                │
│   │  Task recu ?    │──────────────────────────┤                │
│   └────────┬────────┘                          │                │
│            │ Yes                               │                │
│            ▼                                   │                │
│   ┌─────────────────┐                          │                │
│   │  Execute Task   │  whoami, ls, etc.        │                │
│   └────────┬────────┘                          │                │
│            │                                   │                │
│            ▼                                   │                │
│   ┌─────────────────┐                          │                │
│   │  Send Result    │  (HTTP POST)             │                │
│   │  (HTTP POST)    │                          │                │
│   └────────┬────────┘                          │                │
│            │                                   │                │
│            ▼                                   │                │
│   ┌─────────────────┐                          │                │
│   │     Sleep       │  + jitter                │                │
│   └────────┬────────┘                          │                │
│            │                                   │                │
│            └───────────────────────────────────┘                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | Design architecture | Module layout |
| 3-4 | Config & init | Configuration struct |
| 5-6 | Main loop | Sleep/check-in cycle |
| 7 | Integration | **Beacon Skeleton** |

### Semaine 11 : Command Execution
```
┌─────────────────────────────────────────────────────────────────┐
│                    COMMANDES BEACON                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   COMMANDE        IMPLEMENTATION            API                 │
│   ────────        ──────────────            ───                 │
│                                                                 │
│   whoami    →     GetUserName()      →     advapi32.dll        │
│                   + GetComputerName()                           │
│                                                                 │
│   pwd       →     GetCurrentDirectory() →  kernel32.dll        │
│                                                                 │
│   cd        →     SetCurrentDirectory() →  kernel32.dll        │
│                                                                 │
│   ls        →     FindFirstFile()    →     kernel32.dll        │
│                   + FindNextFile()                              │
│                                                                 │
│   cat       →     CreateFile()       →     kernel32.dll        │
│                   + ReadFile()                                  │
│                                                                 │
│   shell     →     CreateProcess()    →     kernel32.dll        │
│                   + pipe redirection                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | whoami, pwd, cd | Basic recon |
| 3-4 | ls (directory listing) | File enum |
| 5-6 | cat (file read) | File access |
| 7 | shell (command exec) | **Beacon + 5 cmds** |

### Semaine 12 : Obfuscation & Final
```
┌─────────────────────────────────────────────────────────────────┐
│                    TECHNIQUES OBFUSCATION                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   STRING ENCRYPTION                                             │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  Avant:  "kernel32.dll"                                 │   │
│   │  Apres:  XOR_decrypt(encrypted_string, key)            │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   API HASHING                                                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  Avant:  GetProcAddress(hMod, "VirtualAlloc")          │   │
│   │  Apres:  GetProcByHash(hMod, 0x91AFCA54)              │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   DYNAMIC RESOLUTION                                            │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  Avant:  #include <windows.h> + direct calls           │   │
│   │  Apres:  LoadLibrary + GetProcAddress a runtime        │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | String encryption | XOR encoding |
| 3-4 | API hashing | Hash-based resolution |
| 5-6 | Compilation flags | Size optimization |
| 7 | Test complet | **BEACON FINAL** |

## Structure Finale du Beacon

```
beacon/
├── main.c              # Entry point, main loop
├── config.h            # Configuration (C2 URL, sleep, etc.)
├── crypto.c/h          # XOR, encryption
├── commands.c/h        # Command implementations
├── comms.c/h           # HTTP communication
├── utils.c/h           # Helper functions
└── Makefile            # Compilation
```

## Checklist Beacon Final

Le beacon final doit pouvoir :

- [ ] Se connecter au C2 en HTTP
- [ ] Supporter un sleep configurable avec jitter
- [ ] Executer la commande `whoami`
- [ ] Executer la commande `pwd`
- [ ] Changer de repertoire avec `cd`
- [ ] Lister les fichiers avec `ls`
- [ ] Lire un fichier avec `cat`
- [ ] Executer des commandes shell
- [ ] Avoir des strings XOR encodees
- [ ] Compiler sans warnings

## Validation de Phase

Vous avez complete le cours si votre beacon :

- [ ] Compile sans erreurs
- [ ] Se connecte au serveur C2 de test
- [ ] Execute toutes les commandes
- [ ] Utilise l'obfuscation de strings
- [ ] Fonctionne dans une VM Windows

## Navigation

| Precedent | Suivant |
|-----------|---------|
| [Phase 3 : Network](../Phase-3-Network-Communication/) | Reference-Code (techniques avancees) |

---

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                    FELICITATIONS !                              │
│                                                                 │
│   Si vous etes arrive jusqu'ici et que votre beacon             │
│   fonctionne, vous avez acquis les competences de base          │
│   du developpement offensif en C.                               │
│                                                                 │
│   Prochaines etapes suggeres:                                  │
│   - Process injection                                           │
│   - Syscalls directs                                            │
│   - EDR evasion                                                 │
│   - Position independent code                                   │
│                                                                 │
│   Voir: Reference-Code/ pour le contenu avance                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Pret a commencer ?**

```bash
cd Week-10-Beacon-Architecture
```

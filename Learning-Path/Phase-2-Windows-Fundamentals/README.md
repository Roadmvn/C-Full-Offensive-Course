# Phase 2 : Windows Internals

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         PHASE 2                                     │   │
│   │                    WINDOWS INTERNALS                                │   │
│   │                                                                     │   │
│   │    Semaines 5-7 : Processus, Memoire et DLLs                       │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   "La maitrise de Windows est la cle du maldev professionnel."             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Vue d'Ensemble

Cette phase vous plonge dans les **mecanismes internes de Windows**. C'est ici que commence vraiment le developpement offensif : manipulation de processus, operations memoire et chargement dynamique de code.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE WINDOWS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    USER MODE                             │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │   │
│   │  │  Processus  │  │  Processus  │  │  Votre Malware  │  │   │
│   │  │   System    │  │    User     │  │                 │  │   │
│   │  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │   │
│   │         │                │                  │            │   │
│   ├─────────┴────────────────┴──────────────────┴────────────┤   │
│   │                     WINDOWS API                          │   │
│   │    CreateProcess | VirtualAlloc | LoadLibrary           │   │
│   ├──────────────────────────────────────────────────────────┤   │
│   │                    KERNEL MODE                           │   │
│   │  ┌─────────────────────────────────────────────────────┐ │   │
│   │  │              NTOSKRNL.EXE (Noyau)                   │ │   │
│   │  │    Process Manager | Memory Manager | I/O Manager   │ │   │
│   │  └─────────────────────────────────────────────────────┘ │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Objectifs d'Apprentissage

A la fin de cette phase, vous serez capable de :

- [ ] Creer et enumerer des processus Windows
- [ ] Manipuler la memoire avec VirtualAlloc/VirtualProtect
- [ ] Lire et ecrire dans la memoire d'un processus
- [ ] Executer du shellcode en memoire locale
- [ ] Charger des DLLs dynamiquement
- [ ] Resoudre des adresses de fonctions avec GetProcAddress
- [ ] Comprendre le PEB (Process Environment Block)

## Prerequis

- **Phase 1 completee** (C + WinAPI basics)
- Comprehension des pointeurs et de l'allocation memoire
- Windows 10/11 avec Visual Studio

## Contenu Detaille

### Semaine 5 : Processes & Threads
```
┌─────────────────────────────────────────────────────────────────┐
│                 PROCESSUS vs THREAD                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   PROCESSUS                          THREADS                    │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                                                         │   │
│   │  ┌───────┐  ┌───────┐  ┌───────┐                       │   │
│   │  │Thread1│  │Thread2│  │Thread3│  ← Partage memoire    │   │
│   │  └───┬───┘  └───┬───┘  └───┬───┘                       │   │
│   │      │          │          │                            │   │
│   │  ┌───┴──────────┴──────────┴───┐                       │   │
│   │  │         HEAP (partagee)     │                       │   │
│   │  └─────────────────────────────┘                       │   │
│   │                                                         │   │
│   │  Code | Data | Stack1 | Stack2 | Stack3                │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   Chaque thread a sa PROPRE stack                              │
│   Tous les threads partagent le MEME heap                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | API Cle |
|------|-------|---------|
| 1-2 | Creation de processus | CreateProcess |
| 3-4 | Enumeration | EnumProcesses, OpenProcess |
| 5-6 | Threads | CreateThread, WaitForSingleObject |
| 7 | Informations processus | **Process Lister** |

### Semaine 6 : Memory Operations
```
┌─────────────────────────────────────────────────────────────────┐
│                 PROTECTIONS MEMOIRE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   PAGE_READONLY        → Lecture seule                          │
│   PAGE_READWRITE       → Lecture + Ecriture                     │
│   PAGE_EXECUTE         → Execution seule                        │
│   PAGE_EXECUTE_READ    → Execution + Lecture                    │
│   PAGE_EXECUTE_READWRITE → TOUT (RWX) ← DANGEREUX/DETECTE      │
│                                                                 │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │                   TECHNIQUE STANDARD                      │  │
│   │                                                           │  │
│   │   1. VirtualAlloc (RW)      → Allouer memoire            │  │
│   │   2. memcpy (shellcode)     → Copier le code             │  │
│   │   3. VirtualProtect (RX)    → Rendre executable          │  │
│   │   4. CreateThread           → Executer                    │  │
│   │                                                           │  │
│   └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | API Cle |
|------|-------|---------|
| 1-2 | Allocation | VirtualAlloc |
| 3-4 | Protections | VirtualProtect |
| 5-6 | Read/Write | ReadProcessMemory, WriteProcessMemory |
| 7 | Shellcode local | **Shellcode Runner** |

### Semaine 7 : DLLs & Modules
```
┌─────────────────────────────────────────────────────────────────┐
│                 RESOLUTION DYNAMIQUE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   // Resolution statique (import table visible)                 │
│   MessageBoxA(NULL, "Hello", "Title", 0);                      │
│                                                                 │
│   // Resolution dynamique (pas dans import table)               │
│   HMODULE hUser32 = LoadLibrary("user32.dll");                 │
│   typedef int (*pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);     │
│   pMessageBoxA fn = (pMessageBoxA)GetProcAddress(hUser32,      │
│                                                  "MessageBoxA");│
│   fn(NULL, "Hello", "Title", 0);                               │
│                                                                 │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │   AVANTAGE : Fonction invisible dans les imports PE      │  │
│   │   USAGE : Evasion, API hiding                            │  │
│   └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | API Cle |
|------|-------|---------|
| 1-2 | Chargement DLL | LoadLibrary |
| 3-4 | Resolution fonctions | GetProcAddress |
| 5-6 | API dynamique | No-import technique |
| 7 | PEB walking | **API Resolver** |

## Applications Offensives

Cette phase vous prepare pour :

| Technique | APIs Utilisees |
|-----------|----------------|
| Process Injection | OpenProcess, VirtualAllocEx, WriteProcessMemory |
| DLL Injection | LoadLibrary, CreateRemoteThread |
| Shellcode Execution | VirtualAlloc, VirtualProtect |
| API Hiding | GetProcAddress, PEB walking |
| Process Hollowing | CreateProcess (SUSPENDED), manipulation memoire |

## Validation de Phase

Avant de passer a la Phase 3, verifiez que vous pouvez :

- [ ] Enumerer tous les processus du systeme
- [ ] Allouer de la memoire executable
- [ ] Executer du shellcode localement
- [ ] Charger une DLL et resoudre une fonction
- [ ] Comprendre les protections memoire (RWX)
- [ ] Expliquer ce qu'est le PEB

## Navigation

| Precedent | Suivant |
|-----------|---------|
| [Phase 1 : Foundations](../Phase-1-Foundations/) | [Phase 3 : Network](../Phase-3-Network-Communication/) |

---

**Pret a commencer ?**

```bash
cd Week-05-Processes-Threads
```

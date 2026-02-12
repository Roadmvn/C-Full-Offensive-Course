# Module 04 : Windows Fundamentals

```
+-------------------------------------------------------------------+
|                                                                     |
|   "Windows est ton terrain de jeu principal.                       |
|    Connais ses API, ses structures internes, ses mecanismes."      |
|                                                                     |
|   Ce module couvre tout ce qu'il faut savoir sur Windows           |
|   avant de passer aux techniques offensives avancees.              |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Utiliser les API Windows (CreateProcess, VirtualAlloc, LoadLibrary, GetProcAddress)
- Manipuler les processus, threads et la memoire via l'API Win32
- Comprendre les structures internes (PE, PEB, TEB, NTAPI)
- Travailler avec les fichiers, la registry, les services et les pipes
- Manipuler les tokens et privileges Windows

## Prerequis

- Module 01 (C Fundamentals) valide
- Module 02 (Memory & Pointers) valide
- Module 03 (Assembly x64) recommande
- Avoir une VM Windows pour tester

## Contenu du module

### Lessons (dans `lessons/`)

Les lessons couvrent 3 axes en parallele : Processus, DLL/API, et Memoire.

| Fichier | Sujet |
|---------|-------|
| `01-process-basics.c` | Creer et manipuler des processus |
| `01-loadlibrary.c` | Charger des DLL dynamiquement |
| `01-virtualalloc.c` | Allocation memoire avec VirtualAlloc |
| `02-process-enum.c` | Enumerer les processus en cours |
| `02-getprocaddress.c` | Resoudre des fonctions dynamiquement |
| `02-virtualprotect.c` | Changer les permissions memoire |
| `03-threads-basics.c` | Creer et gerer des threads |
| `03-dynamic-api.c` | Resolution d'API dynamique complete |
| `03-memory-rw.c` | Lire/ecrire dans la memoire d'un processus |
| `04-process-info.c` | Informations detaillees sur les processus |
| `04-peb-intro.c` | Introduction au PEB (Process Environment Block) |
| `04-shellcode-local.c` | Executer du shellcode localement |

### Topics (dans `topics/`)

| # | Dossier | Sujet | Sous-topics |
|---|---------|-------|-------------|
| 01 | `01-Windows-API-Intro/` | Introduction aux API Windows | Handles, types, conventions |
| 02 | `02-Processus-Threads/` | Gestion des processus et threads | Creation, enumeration, synchronisation |
| 02 | `02-Internals/` | Windows Internals | PE Format, PE Parsing, PE Loading, PEB/TEB, Syscalls/NTAPI, NTDLL, Object Manager, Security Model, ETW, Debugging API, Exception Handling, Windows Defender |
| 03 | `03-Gestion-Memoire/` | Gestion memoire Windows | VirtualAlloc, VirtualProtect, sections |
| 04 | `04-Fichiers-Registry/` | Fichiers et registre | CreateFile, ReadFile, RegOpenKey |
| 04b | `04b-Registry/` | Registry avancee | Persistence, enumeration |
| 05 | `05-Services/` | Services Windows | SCManager, creation, manipulation |
| 06 | `06-WMI-Basics/` | WMI (Windows Management) | Requetes WMI, execution distante |
| 07 | `07-Reseau-Winsock/` | Reseau et Winsock | Sockets, TCP, communication |
| 08 | `08-Pipes/` | Named/Anonymous Pipes | IPC, communication inter-processus |
| 09 | `09-Tokens-Privileges/` | Tokens et privileges | SeDebugPrivilege, impersonation |

### Exercices (dans `exercises/`)

| Fichier | Description |
|---------|-------------|
| `ex01-run-notepad.c` | Lancer un processus notepad |
| `ex01-load-dll.c` | Charger une DLL et appeler une fonction |
| `ex01-alloc-buffer.c` | Allouer un buffer avec VirtualAlloc |
| `ex02-process-list.c` | Lister tous les processus |
| `ex02-api-resolver.c` | Resoudre des API dynamiquement |
| `ex02-rwx-transition.c` | Transition RW -> RX sur un buffer |
| `ex03-thread-counter.c` | Compteur multi-thread |
| `ex03-no-imports.c` | Programme sans imports visibles |
| `ex03-run-shellcode.c` | Executer du shellcode en memoire |

### Solutions (dans `solutions/`)

Ne regarde qu'apres avoir essaye ! Les solutions de chaque exercice sont disponibles.

## Comment travailler

```
1. Commence par les lessons - lis dans l'ordre (01, 02, 03, 04)
2. En parallele, explore les topics pour la theorie approfondie
3. Fais les exercices apres chaque groupe de lessons
4. Verifie tes solutions uniquement si tu es bloque
```

## Compilation

```batch
REM Compiler un fichier
cl fichier.c

REM Certains fichiers necessitent des libs supplementaires
cl fichier.c /link user32.lib kernel32.lib advapi32.lib
```

## Lien avec le maldev

| Concept | Usage offensif |
|---------|---------------|
| CreateProcess | Lancer un processus pour injection |
| VirtualAlloc/Protect | Allouer memoire executable pour shellcode |
| LoadLibrary/GetProcAddress | Resolution dynamique d'API (evasion) |
| PEB/TEB | Trouver des modules sans imports |
| Tokens/Privileges | Escalade de privileges |
| Services | Persistence, execution SYSTEM |
| Pipes | Communication C2 via named pipes |

## Checklist

- [ ] J'ai compile et execute les 12 lessons
- [ ] Je sais creer un processus et un thread
- [ ] Je comprends VirtualAlloc et VirtualProtect
- [ ] Je sais charger une DLL et resoudre une API
- [ ] J'ai fait les 9 exercices
- [ ] Je comprends le PEB et son utilite
- [ ] Je sais manipuler les tokens

---

Temps estime : **15-20 heures**

Prochain module : [05 - Windows Advanced](../05-windows-advanced/)

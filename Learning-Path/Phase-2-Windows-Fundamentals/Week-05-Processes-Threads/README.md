# Week 05 - Processes & Threads

## Vue d'ensemble

Bienvenue dans la **Phase 2 - Windows Fundamentals** du C Maldev Journey ! Cette semaine marque le **début de votre transition du C pur vers la manipulation de Windows**.

Jusqu'à maintenant, vous avez appris les fondamentaux du langage C. Maintenant, nous allons utiliser ces compétences pour **interagir avec le système d'exploitation Windows** via ses API natives.

## Transition : Du C pur au Windows Maldev

### Ce que vous avez appris (Phase 1)
- Variables, pointeurs, structures
- Allocation mémoire (malloc, free)
- Manipulation de fichiers (fopen, fread)
- Concepts bas niveau (stack, heap, bits)

### Ce que vous allez apprendre maintenant (Phase 2)
- **Windows API** : L'interface pour manipuler Windows
- **Processus** : Créer, surveiller et analyser des programmes
- **Threads** : Exécution parallèle au sein d'un processus
- **Gestion de la mémoire Windows** (semaine prochaine)
- **DLLs et modules** (semaine suivante)

### Pourquoi c'est crucial pour le Maldev ?

En tant que développeur offensif, vous devez comprendre :
- Comment les programmes s'exécutent sous Windows
- Comment énumérer et analyser les processus (reconnaissance)
- Comment créer des threads (injection de code)
- Comment manipuler la mémoire des processus (process injection)

**Cette semaine pose les bases de TOUT le maldev Windows.**

## Objectifs de la semaine

À la fin de cette semaine, vous serez capable de :
- ✅ Créer et gérer des processus avec `CreateProcess`
- ✅ Énumérer tous les processus actifs sur le système
- ✅ Obtenir des informations détaillées sur n'importe quel processus
- ✅ Créer et synchroniser des threads
- ✅ Comprendre les race conditions et la concurrence
- ✅ Utiliser la PSAPI pour l'introspection de processus

## Structure du module

```
Week-05-Processes-Threads/
├── Lessons/
│   ├── 01-process-basics.c       ⭐ START HERE
│   ├── 02-process-enum.c
│   ├── 03-threads-basics.c
│   └── 04-process-info.c
├── Exercises/
│   ├── ex01-run-notepad.c
│   ├── ex02-process-list.c
│   └── ex03-thread-counter.c
├── Solutions/
│   ├── ex01-run-notepad.c
│   ├── ex02-process-list.c
│   └── ex03-thread-counter.c
├── quiz.json
├── build.bat
└── README.md (ce fichier)
```

## Plan d'apprentissage (7 jours)

### Jour 1-2 : Process Basics
**Lesson 01** : `01-process-basics.c`
- Concept de processus Windows
- `CreateProcess` : Lancer des programmes
- `WaitForSingleObject` : Attendre la fin d'un processus
- Gestion des handles et cleanup
- STARTUPINFO et PROCESS_INFORMATION

**Exercice** : `ex01-run-notepad.c`
- Lancer notepad.exe
- Afficher les infos du processus (PID, handles)
- Mesurer le temps d'exécution

### Jour 3-4 : Process Enumeration
**Lesson 02** : `02-process-enum.c`
- `EnumProcesses` : Lister tous les processus
- `OpenProcess` : Ouvrir un processus existant
- `GetModuleBaseName` : Obtenir le nom d'un processus
- Droits d'accès aux processus
- PSAPI (Process Status API)

**Exercice** : `ex02-process-list.c`
- Créer un lister de processus
- Afficher PID + nom de tous les processus
- Gérer les processus inaccessibles

### Jour 5-6 : Threads
**Lesson 03** : `03-threads-basics.c`
- Concept de thread
- `CreateThread` : Créer des threads
- Passage de paramètres aux threads
- `WaitForMultipleObjects` : Synchronisation
- Race conditions (problèmes de concurrence)

**Exercice** : `ex03-thread-counter.c`
- Créer 3 threads
- Incrémenter un compteur partagé
- Observer les race conditions

### Jour 7 : Process Information & Quiz
**Lesson 04** : `04-process-info.c`
- Informations détaillées sur les processus
- `GetCurrentProcessId`, `GetModuleFileName`
- Variables d'environnement
- Utilisation mémoire et temps CPU
- Modules chargés (DLLs)

**Quiz** : Valider vos connaissances (10 questions)

## Compilation et exécution

### Prérequis
- **Windows 10/11**
- **Visual Studio** (Community Edition gratuite)
- **MSVC Compiler** (cl.exe)

### Méthode 1 : Script de build automatique
```batch
REM Ouvrir "Developer Command Prompt for VS"
cd Week-05-Processes-Threads
build.bat
```

Cela compile automatiquement :
- Toutes les lessons → `bin/01-process-basics.exe`, etc.
- Tous les exercices → `bin/ex01-run-notepad.exe`, etc.
- Toutes les solutions → `bin/sol-ex01-run-notepad.exe`, etc.

### Méthode 2 : Compilation manuelle
```batch
REM Lesson 01
cl.exe /nologo /W4 /O2 Lessons\01-process-basics.c /link psapi.lib

REM Exercice 02 (nécessite PSAPI)
cl.exe /nologo /W4 /O2 Exercises\ex02-process-list.c /link psapi.lib
```

### Exécution
```batch
REM Exécuter une lesson
bin\01-process-basics.exe

REM Exécuter un exercice
bin\ex01-run-notepad.exe

REM Voir la solution
bin\sol-ex01-run-notepad.exe
```

## Concepts clés Windows

### 1. Processus vs Programme
- **Programme** : Fichier .exe sur le disque
- **Processus** : Instance d'un programme en mémoire
- Chaque processus a un **PID** (Process ID) unique
- Espace mémoire **isolé** (sécurité)

### 2. Handles Windows
Un **handle** est une référence à un objet kernel :
- Processus, threads, fichiers, registre, etc.
- **TOUJOURS fermer** avec `CloseHandle()` (sinon fuite mémoire kernel)
- Les handles ne sont valides que dans le processus qui les a obtenus

### 3. Thread
- **Unité d'exécution** au sein d'un processus
- Un processus a **au moins 1 thread** (thread principal)
- Les threads d'un processus **partagent la mémoire**
- Chaque thread a sa propre **pile (stack)**
- Peut s'exécuter en **parallèle** (multi-core)

### 4. Structures Windows importantes

```c
// Configuration de démarrage d'un processus
STARTUPINFO si = {0};
si.cb = sizeof(si);  // OBLIGATOIRE!

// Informations retournées après création
PROCESS_INFORMATION pi;
// Contient: hProcess, hThread, dwProcessId, dwThreadId
```

### 5. PSAPI (Process Status API)
Librairie pour obtenir des infos détaillées :
- `EnumProcesses()` : Lister tous les processus
- `GetModuleBaseName()` : Nom d'un processus
- `GetProcessMemoryInfo()` : Utilisation mémoire
- `EnumProcessModules()` : DLLs chargées

**Lien** : `psapi.lib` requis lors de la compilation

## APIs Windows essentielles

### Processus

| Fonction | Description |
|----------|-------------|
| `CreateProcess()` | Créer un nouveau processus |
| `OpenProcess()` | Ouvrir un processus existant |
| `GetCurrentProcess()` | Handle du processus actuel (pseudo-handle) |
| `GetCurrentProcessId()` | PID du processus actuel |
| `GetExitCodeProcess()` | Code de retour d'un processus |
| `TerminateProcess()` | Terminer un processus (brutal) |
| `EnumProcesses()` | Lister tous les PIDs |
| `GetModuleBaseName()` | Nom d'un processus |
| `GetModuleFileName()` | Chemin complet de l'exe |

### Threads

| Fonction | Description |
|----------|-------------|
| `CreateThread()` | Créer un thread |
| `GetCurrentThread()` | Handle du thread actuel |
| `GetCurrentThreadId()` | TID du thread actuel |
| `GetExitCodeThread()` | Code de retour d'un thread |
| `ResumeThread()` | Reprendre un thread suspendu |
| `SuspendThread()` | Suspendre un thread |

### Synchronisation

| Fonction | Description |
|----------|-------------|
| `WaitForSingleObject()` | Attendre 1 objet (processus, thread, etc.) |
| `WaitForMultipleObjects()` | Attendre plusieurs objets |
| `Sleep()` | Pause (millisecondes) |

### Cleanup

| Fonction | Description |
|----------|-------------|
| `CloseHandle()` | Fermer un handle (CRITIQUE!) |

## Erreurs courantes à éviter

### ❌ Oublier de fermer les handles
```c
CreateProcess(..., &pi);
// ERREUR: Pas de CloseHandle!
```
**Fix** :
```c
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
```

### ❌ Oublier si.cb
```c
STARTUPINFO si = {0};
// ERREUR: si.cb non défini
CreateProcess(..., &si, &pi);
```
**Fix** :
```c
STARTUPINFO si = {0};
si.cb = sizeof(si);  // OBLIGATOIRE!
```

### ❌ Ne pas vérifier les retours
```c
CreateProcess(...);  // Pas de vérification
```
**Fix** :
```c
if (!CreateProcess(...)) {
    printf("Erreur: %lu\n", GetLastError());
    return 1;
}
```

### ❌ Passer une chaîne littérale à CreateProcess
```c
// ERREUR: lpCommandLine doit être modifiable
CreateProcess(NULL, "notepad.exe", ...);
```
**Fix** :
```c
char cmdline[] = "notepad.exe";  // Buffer modifiable
CreateProcess(NULL, cmdline, ...);
```

### ❌ Race conditions non gérées
```c
int counter = 0;
// Plusieurs threads font: counter++
// DANGER: Résultat non déterministe
```
**Fix** :
```c
// Utiliser InterlockedIncrement()
InterlockedIncrement(&counter);
```

## Checklist de progression

Avant de passer à la semaine suivante, assurez-vous de :

- [ ] Avoir compilé et exécuté toutes les lessons
- [ ] Comprendre la différence entre processus et thread
- [ ] Savoir créer un processus avec `CreateProcess`
- [ ] Savoir énumérer les processus avec `EnumProcesses`
- [ ] Savoir créer des threads avec `CreateThread`
- [ ] Comprendre ce qu'est un handle et pourquoi le fermer
- [ ] Avoir fait les 3 exercices
- [ ] Avoir réussi le quiz (≥70%)
- [ ] Comprendre les race conditions

## Ressources

### Documentation officielle
- [CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
- [Process and Thread Functions](https://learn.microsoft.com/en-us/windows/win32/procthread/process-and-thread-functions)
- [PSAPI Functions](https://learn.microsoft.com/en-us/windows/win32/psapi/psapi-functions)

### Lectures recommandées
- Windows Internals (Russinovich & Solomon) - Chapitres 3-5
- Windows System Programming (Hart) - Chapitre 6

## Connexion avec le Maldev

Cette semaine vous prépare pour :

### Week 06 : Memory Operations
- Lire/écrire dans la mémoire d'un processus
- `VirtualAllocEx`, `WriteProcessMemory`
- Fondation pour l'injection de code

### Week 07 : DLLs & Modules
- Charger des DLLs
- `LoadLibrary`, `GetProcAddress`
- Prépare l'injection de DLL

### Modules offensifs futurs
- **Process Injection** : Injecter du code dans un processus
- **Process Hollowing** : Remplacer le code d'un processus légitime
- **Thread Hijacking** : Détourner l'exécution d'un thread
- **PPID Spoofing** : Usurper le parent d'un processus

**Tout commence ici !** Les processus et threads sont la base du maldev Windows.

## Notes de sécurité

### Pourquoi certains processus sont inaccessibles ?
- **Processus système** (PID 0, 4) : Noyau Windows
- **Processus protégés** : Anti-malware, services critiques
- **Privilèges insuffisants** : Certaines opérations nécessitent l'admin

### Élévation de privilèges
Pour accéder à tous les processus :
- Lancer en **administrateur** (clic droit → "Run as administrator")
- Ou utiliser des techniques d'élévation (UACBypass - module avancé)

## Exercices bonus

Si vous avez fini tous les exercices officiels :

1. **Process Monitor** : Surveiller la création/terminaison de processus
2. **Thread Pool** : Créer un pool de worker threads
3. **Process Tree** : Afficher l'arborescence parent/enfant des processus
4. **Resource Monitor** : Afficher CPU/mémoire en temps réel par processus

## Prochaine étape

Une fois cette semaine maîtrisée, vous passerez à :
**Week 06 - Memory Operations** : Manipulation de la mémoire Windows

Vous apprendrez à :
- Allouer de la mémoire dans un processus distant
- Lire et écrire la mémoire d'autres processus
- Comprendre les protections mémoire (PAGE_EXECUTE_READWRITE, etc.)

---

**Bon courage !** Cette semaine est fondamentale. Prenez le temps de bien comprendre chaque concept.

Si vous avez des questions, relisez les explications dans les fichiers sources (elles sont très détaillées).

**Remember** : La maîtrise des processus et threads Windows est la base de 80% des techniques offensives. Investissez le temps nécessaire ici, ça paiera plus tard.

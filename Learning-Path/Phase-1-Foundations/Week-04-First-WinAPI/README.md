# Week 04 - First WinAPI

## Vue d'ensemble

Bienvenue dans le monde des **Windows API** ! Cette semaine marque une transition cruciale de la programmation C standard vers la programmation Windows spécifique. Vous allez découvrir les fondamentaux qui serviront de base à tout votre parcours en maldev.

## Objectifs de la semaine

À la fin de cette semaine, vous serez capable de :

- Comprendre et utiliser les types Windows (DWORD, HANDLE, LPVOID, BOOL...)
- Effectuer vos premiers appels WinAPI (MessageBoxA, CreateFileA...)
- Gérer correctement les erreurs avec GetLastError() et FormatMessage()
- Manipuler les handles : création, utilisation, fermeture
- Comprendre la philosophie "everything is an object" de Windows

## Pourquoi c'est important en maldev ?

Les WinAPI sont la **fondation absolue** du maldev Windows :

1. **Injection de processus** : OpenProcess, VirtualAllocEx, WriteProcessMemory
2. **Manipulation de threads** : CreateRemoteThread, SuspendThread, ResumeThread
3. **Évasion** : Tout passe par les API Windows (ou syscalls directs)
4. **Persistance** : Registry (RegCreateKeyEx), Services (CreateService), Scheduled Tasks
5. **C2 Communication** : WinHTTP, WinInet, Sockets

Sans maîtriser les bases des WinAPI, impossible de progresser en maldev !

## Structure de la semaine

```
Week-04-First-WinAPI/
├── Lessons/
│   ├── 01-windows-types.c         # Types Windows et Hungarian Notation
│   ├── 02-messagebox.c            # Premier appel WinAPI avec MessageBoxA
│   ├── 03-error-handling.c        # GetLastError et FormatMessage
│   └── 04-handles.c               # Concept fondamental de HANDLE
├── Exercises/
│   ├── ex01-hello-winapi.c        # Exercice MessageBox personnalisée
│   ├── ex02-error-check.c         # Exercice gestion d'erreurs
│   └── ex03-file-handle.c         # Exercice manipulation de fichiers
├── Solutions/
│   ├── ex01-hello-winapi.c        # Solution complète ex01
│   ├── ex02-error-check.c         # Solution complète ex02
│   └── ex03-file-handle.c         # Solution complète ex03
├── quiz.json                       # 10 questions sur les concepts
├── build.bat                       # Script de compilation
└── README.md                       # Ce fichier
```

## Progression recommandée

### Jour 1-2 : Types Windows et premier appel

1. Étudier `01-windows-types.c`
   - Comprendre DWORD, HANDLE, LPVOID, BOOL
   - Apprendre la Hungarian Notation
   - Connaître les équivalences C standard ↔ Windows

2. Étudier `02-messagebox.c`
   - Premier appel WinAPI (MessageBoxA)
   - Comprendre les flags et leur combinaison
   - Différence A/W (ANSI/Unicode)

3. Faire `ex01-hello-winapi.c`

### Jour 3-4 : Gestion d'erreurs

1. Étudier `03-error-handling.c`
   - GetLastError() et son utilisation
   - FormatMessage() pour traduire les codes
   - Patterns de gestion d'erreur robuste

2. Faire `ex02-error-check.c`

### Jour 5-6 : Handles et fichiers

1. Étudier `04-handles.c`
   - Comprendre ce qu'est un HANDLE
   - Pseudo-handles vs Real handles
   - Cycle de vie : Create → Use → Close

2. Faire `ex03-file-handle.c`

### Jour 7 : Révision et quiz

1. Relire toutes les leçons
2. Refaire les exercices sans regarder les solutions
3. Compléter le quiz (7/10 minimum pour passer)

## Compilation

### Avec MSVC (recommandé)

```batch
# Compiler une leçon
cl /W4 Lessons\01-windows-types.c /link kernel32.lib user32.lib

# Compiler un exercice
cl /W4 Exercises\ex01-hello-winapi.c /link user32.lib

# Utiliser le script de compilation
build.bat Lessons\01-windows-types.c
```

### Avec MinGW

```bash
gcc -Wall -Wextra Lessons/01-windows-types.c -o 01-windows-types.exe -luser32 -lkernel32
```

## Concepts clés à maîtriser

### 1. Types Windows

| Type C Standard | Type Windows | Description |
|----------------|--------------|-------------|
| `unsigned int` | `DWORD` | Double Word (32 bits) |
| `void*` | `LPVOID` | Long Pointer to VOID |
| `void*` | `HANDLE` | Identifiant opaque ressource |
| `int` | `BOOL` | Booléen Windows (TRUE/FALSE) |
| `size_t` | `SIZE_T` | Taille adaptative (32/64 bits) |
| `char*` | `LPCSTR` | Long Pointer to Constant STRing |
| `wchar_t*` | `LPWSTR` | Long Pointer to Wide STRing |

### 2. Hungarian Notation

Préfixes courants :

- `dw` : DWORD → `dwProcessId`, `dwError`
- `h` : HANDLE → `hFile`, `hProcess`, `hThread`
- `p` : Pointer → `pBuffer`, `pData`
- `lp` : Long Pointer → `lpFileName`, `lpAddress`
- `b` : BOOL → `bSuccess`, `bFound`
- `sz` : String Zero-terminated → `szFileName`

### 3. Gestion d'erreurs

Pattern standard :

```c
HANDLE hFile = CreateFileA(...);
if (hFile == INVALID_HANDLE_VALUE) {
    DWORD dwError = GetLastError();  // IMMÉDIATEMENT après l'échec
    PrintError("CreateFileA", dwError);
    goto cleanup;
}

// Utilisation du handle
// ...

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
```

### 4. Handles

**Concept central Windows** : Tout est un objet identifié par un handle.

- **Process handle** : `OpenProcess()`, `GetCurrentProcess()`
- **Thread handle** : `OpenThread()`, `GetCurrentThread()`
- **File handle** : `CreateFileA()`, `CreateFileW()`
- **Registry handle** : `RegOpenKeyEx()`
- **Token handle** : `OpenProcessToken()`

**IMPORTANT** :
- TOUJOURS fermer avec `CloseHandle()`
- SAUF les pseudo-handles (`GetCurrentProcess()`, `GetCurrentThread()`)
- Un handle n'est valide QUE dans le processus qui l'a créé

## Codes d'erreur courants

| Code | Constante | Signification |
|------|-----------|---------------|
| 0 | `ERROR_SUCCESS` | Succès |
| 2 | `ERROR_FILE_NOT_FOUND` | Fichier introuvable |
| 3 | `ERROR_PATH_NOT_FOUND` | Chemin introuvable |
| 5 | `ERROR_ACCESS_DENIED` | Accès refusé |
| 6 | `ERROR_INVALID_HANDLE` | Handle invalide |
| 8 | `ERROR_NOT_ENOUGH_MEMORY` | Mémoire insuffisante |
| 87 | `ERROR_INVALID_PARAMETER` | Paramètre invalide |

## Pièges courants à éviter

### 1. Confusion NULL vs INVALID_HANDLE_VALUE

```c
// FAUX
HANDLE hFile = CreateFileA(...);
if (hFile == NULL) { ... }  // ❌ CreateFile retourne INVALID_HANDLE_VALUE

// CORRECT
HANDLE hFile = CreateFileA(...);
if (hFile == INVALID_HANDLE_VALUE) { ... }  // ✅

// ATTENTION : OpenProcess retourne NULL en cas d'échec !
HANDLE hProcess = OpenProcess(...);
if (hProcess == NULL) { ... }  // ✅ Pour OpenProcess
```

### 2. Oublier CloseHandle

```c
// FAUX - Handle leak
void BadFunction(void) {
    HANDLE hFile = CreateFileA(...);
    // ... utilisation ...
    // ❌ Pas de CloseHandle → fuite de handle
}

// CORRECT
void GoodFunction(void) {
    HANDLE hFile = CreateFileA(...);
    // ... utilisation ...
    CloseHandle(hFile);  // ✅
}
```

### 3. Fermer un pseudo-handle

```c
// FAUX
HANDLE hProcess = GetCurrentProcess();
CloseHandle(hProcess);  // ❌ NE JAMAIS faire ça !

// CORRECT
HANDLE hProcess = GetCurrentProcess();
// Utilisation directe, pas de CloseHandle
```

### 4. Ne pas vérifier les erreurs

```c
// FAUX
HANDLE hFile = CreateFileA(...);
WriteFile(hFile, ...);  // ❌ Pas de vérification

// CORRECT
HANDLE hFile = CreateFileA(...);
if (hFile == INVALID_HANDLE_VALUE) {
    PrintError("CreateFileA");
    return;
}

if (!WriteFile(hFile, ...)) {  // ✅
    PrintError("WriteFile");
    CloseHandle(hFile);
    return;
}
```

## Ressources complémentaires

### Documentation officielle Microsoft

- [Windows Data Types](https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types)
- [MessageBox function](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox)
- [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)
- [FormatMessage](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessage)
- [File Management](https://learn.microsoft.com/en-us/windows/win32/fileio/file-management-functions)

### Outils utiles

- **API Monitor** : Surveiller les appels WinAPI d'un programme
- **Process Hacker** : Voir les handles d'un processus
- **WinDbg** : Déboguer et analyser les appels système

## Prochaines étapes

Une fois cette semaine maîtrisée, vous passerez à :

**Week 05 - Process & Memory** :
- OpenProcess, GetCurrentProcess
- VirtualAlloc, VirtualFree
- ReadProcessMemory, WriteProcessMemory
- Base de l'injection de processus

**Week 06 - Advanced WinAPI** :
- Registry (RegCreateKeyEx, RegSetValueEx)
- Services (CreateService, StartService)
- Threads (CreateThread, CreateRemoteThread)

## Quiz et validation

Le quiz contient **10 questions** sur :
- Types Windows (DWORD, HANDLE, LPVOID...)
- Gestion d'erreurs (GetLastError, FormatMessage)
- Handles (création, utilisation, fermeture)
- MessageBox et flags

**Score minimum** : 7/10 pour passer à la semaine suivante.

## Support

Si vous bloquez :
1. Relisez la leçon correspondante
2. Regardez les exemples dans les fichiers Lessons/
3. Consultez la documentation Microsoft
4. Comparez votre code avec les Solutions/

**Bon courage et bienvenue dans le monde WinAPI !** 🚀

---

*"Everything is an object with a handle" - Philosophy Windows*

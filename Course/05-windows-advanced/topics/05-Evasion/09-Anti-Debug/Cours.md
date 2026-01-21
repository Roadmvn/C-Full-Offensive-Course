# Module W41 : Anti-Debug Techniques

## Table des Matières
1. [Objectifs Pédagogiques](#objectifs)
2. [Introduction : Pourquoi l'Anti-Debug ?](#introduction)
3. [Comprendre les Débogueurs](#comprendre-debuggers)
4. [Techniques de Détection](#techniques-detection)
5. [Implémentation Complète](#implementation)
6. [Anti-Anti-Debug : Contourner les Détections](#anti-anti-debug)
7. [Détection et OPSEC](#detection-opsec)
8. [Checklist de Développement](#checklist)
9. [Exercices Pratiques](#exercices)
10. [Ressources](#ressources)

---

## Objectifs Pédagogiques {#objectifs}

À la fin de ce module, vous serez capable de :

- ✅ Comprendre pourquoi les malwares utilisent l'anti-debug
- ✅ Implémenter 8+ techniques anti-debug différentes
- ✅ Détecter IsDebuggerPresent, CheckRemoteDebuggerPresent
- ✅ Inspecter le PEB (Process Environment Block)
- ✅ Utiliser NtQueryInformationProcess pour détecter les debuggers
- ✅ Implémenter des timing checks (RDTSC, QueryPerformanceCounter)
- ✅ Détecter les hardware breakpoints
- ✅ Scanner les INT 3 (software breakpoints)
- ✅ Comprendre les techniques d'évasion anti-anti-debug
- ✅ Évaluer les risques OPSEC de chaque technique

**Niveau** : Intermédiaire
**Prérequis** : W01 (Win32 API), W02 (Process Injection), notions de Reverse Engineering
**Durée estimée** : 4-6 heures

---

## Introduction : Pourquoi l'Anti-Debug ? {#introduction}

### Contexte Red Team

Imaginez que vous développez un implant pour une opération Red Team. Votre payload est exécuté sur le système cible, mais le Blue Team a lancé un débogueur (x64dbg, WinDbg) pour analyser votre code en temps réel.

**Sans anti-debug** :
```
[Blue Team] Ouvre x64dbg → Attache au process → Analyse le shellcode → DÉTECTÉ
```

**Avec anti-debug** :
```
[Implant] Détecte le débogueur → Exécute un code légitime → Cache le payload → ÉVADE
```

### Analogie : La Souris Piégée

Pensez à une souris qui sent la présence d'un chat :

```ascii
Sans détection (souris naïve) :
┌──────────┐
│  Souris  │ → Cherche nourriture → [CHAT] → CAPTURÉE
└──────────┘

Avec détection (souris intelligente) :
┌──────────┐
│  Souris  │ → Détecte chat → Fuit → SURVIVE
└──────────┘
```

L'anti-debug, c'est donner des "sens" à votre programme pour détecter s'il est observé.

### Cas d'Usage Légitimes

L'anti-debug n'est pas uniquement pour les malwares :

| Contexte | Raison |
|----------|--------|
| **Jeux vidéo** | Empêcher le cheating (modification mémoire) |
| **Logiciels commerciaux** | Protéger contre le reverse engineering |
| **DRM** | Empêcher le piratage de contenu |
| **Red Team** | Éviter la détection pendant les opérations |
| **Malware Analysis** | Comprendre les techniques adverses |

---

## Comprendre les Débogueurs {#comprendre-debuggers}

### Qu'est-ce qu'un Débogueur ?

Un débogueur est un outil qui permet de :
- Pauser l'exécution d'un programme (breakpoints)
- Inspecter la mémoire et les registres
- Exécuter le code instruction par instruction (step-by-step)
- Modifier le comportement du programme en temps réel

### Types de Débogueurs

```ascii
┌─────────────────────────────────────────────┐
│         DÉBOGUEURS WINDOWS                  │
├─────────────────────────────────────────────┤
│                                             │
│  User-Mode Debuggers                        │
│  ├── x64dbg / x32dbg (le plus populaire)    │
│  ├── OllyDbg (legacy)                       │
│  ├── WinDbg (Microsoft officiel)            │
│  └── Visual Studio Debugger                 │
│                                             │
│  Kernel Debuggers                           │
│  ├── WinDbg (mode kernel)                   │
│  └── SoftICE (obsolète)                     │
│                                             │
│  Hypervisor-based                           │
│  ├── GDB + QEMU                             │
│  └── VirtualBox debugger                    │
│                                             │
└─────────────────────────────────────────────┘
```

### Traces Laissées par un Débogueur

Quand un débogueur est attaché à un processus, Windows modifie plusieurs structures :

```ascii
PROCESSUS NORMAL               PROCESSUS DEBUGGÉ
┌──────────────┐              ┌──────────────┐
│     PEB      │              │     PEB      │
│ BeingDebugged│              │ BeingDebugged│
│    = 0       │              │    = 1       │ ← FLAG MODIFIÉ
└──────────────┘              └──────────────┘

┌──────────────┐              ┌──────────────┐
│DebugPort     │              │DebugPort     │
│   = NULL     │              │  = 0xFFFFFFFF│ ← PORT DE DEBUG
└──────────────┘              └──────────────┘

┌──────────────┐              ┌──────────────┐
│   Heap       │              │   Heap       │
│ Flags=0x2    │              │ Flags=0x50000│ ← HEAP FLAGS
└──────────────┘              └──────────────┘
```

Notre but : détecter ces modifications !

---

## Techniques de Détection {#techniques-detection}

### Vue d'Ensemble

```ascii
┌────────────────────────────────────────────────────────┐
│          TECHNIQUES ANTI-DEBUG                         │
├────────────────────────────────────────────────────────┤
│                                                        │
│  [1] API Windows                                       │
│      ├── IsDebuggerPresent()          (Facile)        │
│      └── CheckRemoteDebuggerPresent() (Facile)        │
│                                                        │
│  [2] Inspection Directe (PEB)                          │
│      ├── PEB->BeingDebugged           (Moyen)         │
│      ├── PEB->NtGlobalFlag            (Moyen)         │
│      └── Heap Flags                   (Avancé)        │
│                                                        │
│  [3] NT API                                            │
│      ├── NtQueryInformationProcess    (Moyen)         │
│      └── NtSetInformationThread       (Avancé)        │
│                                                        │
│  [4] Timing Checks                                     │
│      ├── RDTSC (CPU cycles)           (Moyen)         │
│      └── QueryPerformanceCounter      (Facile)        │
│                                                        │
│  [5] Hardware Breakpoints                              │
│      └── Debug Registers DR0-DR7      (Avancé)        │
│                                                        │
│  [6] Software Breakpoints                              │
│      └── Scan INT 3 (0xCC)            (Moyen)         │
│                                                        │
│  [7] Exceptions                                        │
│      └── SEH/VEH tricks                (Avancé)       │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

### Technique 1 : IsDebuggerPresent()

**Niveau** : Débutant
**Détection** : Très facile
**Efficacité** : Faible (patchable)

#### Principe

`IsDebuggerPresent()` est une API Windows qui lit simplement `PEB->BeingDebugged`.

```c
BOOL IsDebuggerPresent(void);
// Retourne TRUE si un debugger user-mode est attaché
```

#### Implémentation

```c
#include <windows.h>
#include <stdio.h>

BOOL check_debugger_present() {
    if (IsDebuggerPresent()) {
        printf("[!] Debugger detecte via IsDebuggerPresent()\n");
        return TRUE;
    }
    return FALSE;
}

int main() {
    if (check_debugger_present()) {
        printf("[!] Execution terminee : debugger detecte !\n");
        exit(1);
    }

    printf("[+] Aucun debugger detecte\n");
    printf("[+] Execution du payload...\n");

    // Payload ici

    return 0;
}
```

#### Fonctionnement Interne

```ascii
IsDebuggerPresent() INTERNALS:

1. Récupère PEB (Process Environment Block)
   ┌─────────────────────────┐
   │ mov rax, gs:[0x60]      │  ← Offset PEB en x64
   └─────────────────────────┘

2. Lit BeingDebugged (offset +0x02)
   ┌─────────────────────────┐
   │ movzx eax, byte [rax+2] │  ← PEB->BeingDebugged
   └─────────────────────────┘

3. Retourne 1 si debuggé, 0 sinon
```

#### Contournement (Anti-Anti-Debug)

Un analyste peut facilement bypass cette technique :

```python
# Dans x64dbg, script pour patcher le retour
bp IsDebuggerPresent
run
eax = 0  # Force le retour à FALSE
```

**Verdict** : Technique basique, utile en combinaison avec d'autres.

---

### Technique 2 : CheckRemoteDebuggerPresent()

**Niveau** : Débutant
**Détection** : Facile
**Efficacité** : Faible

#### Principe

Détecte si un débogueur distant (ou local) est attaché via `NtQueryInformationProcess`.

```c
BOOL CheckRemoteDebuggerPresent(
    HANDLE hProcess,        // Handle du processus
    PBOOL  pbDebuggerPresent // Résultat
);
```

#### Implémentation

```c
#include <windows.h>
#include <stdio.h>

BOOL check_remote_debugger() {
    BOOL debuggerPresent = FALSE;

    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent)) {
        if (debuggerPresent) {
            printf("[!] Debugger distant detecte !\n");
            return TRUE;
        }
    }

    return FALSE;
}

int main() {
    if (check_remote_debugger()) {
        printf("[!] Analyse detectee, arret du programme\n");
        ExitProcess(1);
    }

    printf("[+] Aucun debugger distant\n");
    return 0;
}
```

#### Différence avec IsDebuggerPresent

```ascii
IsDebuggerPresent():
├── Lit PEB->BeingDebugged directement
├── Détecte uniquement debugger LOCAL
└── Très rapide (1 lecture mémoire)

CheckRemoteDebuggerPresent():
├── Appelle NtQueryInformationProcess
├── Détecte debugger LOCAL et DISTANT
└── Plus lent (syscall NT)
```

---

### Technique 3 : Inspection Manuelle du PEB

**Niveau** : Intermédiaire
**Détection** : Moyenne
**Efficacité** : Moyenne-Haute

#### Qu'est-ce que le PEB ?

Le **Process Environment Block** contient des métadonnées sur le processus.

```ascii
PEB (Process Environment Block) - Offset x64:

gs:[0x60] → Pointeur vers PEB

┌─────────────────────────────────────────┐
│  Offset  │  Champ              │ Taille │
├──────────┼─────────────────────┼────────┤
│  +0x000  │ InheritedAddressSpace│  1    │
│  +0x001  │ ReadImageFileExecOpt│  1    │
│  +0x002  │ BeingDebugged       │  1    │ ← CIBLE #1
│  +0x003  │ BitField            │  1    │
│  ...                                    │
│  +0x0BC  │ NtGlobalFlag        │  4    │ ← CIBLE #2
│  ...                                    │
│  +0x030  │ ProcessHeap         │  8    │
└─────────────────────────────────────────┘
```

#### 3.1 : PEB->BeingDebugged

```c
#include <windows.h>
#include <stdio.h>

// Structure PEB partielle (x64)
typedef struct _PEB {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;              // +0x002
    BYTE BitField;
    // ... autres champs
} PEB, *PPEB;

BOOL check_peb_being_debugged() {
    PPEB peb;

#ifdef _WIN64
    // En x64 : PEB est à gs:[0x60]
    peb = (PPEB)__readgsqword(0x60);
#else
    // En x86 : PEB est à fs:[0x30]
    peb = (PPEB)__readfsdword(0x30);
#endif

    if (peb->BeingDebugged) {
        printf("[!] PEB->BeingDebugged = 1 (debugger detecte)\n");
        return TRUE;
    }

    return FALSE;
}
```

#### 3.2 : PEB->NtGlobalFlag

Quand un processus est débugué, Windows active des flags de debug dans le heap :

```c
BOOL check_nt_global_flag() {
    PPEB peb;
    DWORD ntGlobalFlag;

#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
    // NtGlobalFlag est à offset +0xBC (x64)
    ntGlobalFlag = *(PDWORD)((PBYTE)peb + 0xBC);
#else
    peb = (PPEB)__readfsdword(0x30);
    // NtGlobalFlag est à offset +0x68 (x86)
    ntGlobalFlag = *(PDWORD)((PBYTE)peb + 0x68);
#endif

    // Flags de debug : FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
    //                  FLG_HEAP_ENABLE_FREE_CHECK (0x20)
    //                  FLG_HEAP_VALIDATE_PARAMETERS (0x40)
    if (ntGlobalFlag & 0x70) {
        printf("[!] NtGlobalFlag = 0x%X (heap debugging actif)\n", ntGlobalFlag);
        return TRUE;
    }

    return FALSE;
}
```

#### Explication des Flags

```ascii
NtGlobalFlag NORMAL vs DEBUGGÉ:

NORMAL (0x00000000):
┌────────────────────────────────┐
│ Heap normal                    │
│ - Pas de tail check            │
│ - Pas de free check            │
│ - Allocation rapide            │
└────────────────────────────────┘

DEBUGGÉ (0x00000070):
┌────────────────────────────────┐
│ Heap en mode debug             │
│ - Tail check actif (0x10)      │  ← Détecte corruption
│ - Free check actif (0x20)      │  ← Détecte double-free
│ - Validate params (0x40)       │  ← Vérifie paramètres
└────────────────────────────────┘
```

---

### Technique 4 : NtQueryInformationProcess

**Niveau** : Intermédiaire
**Détection** : Moyenne
**Efficacité** : Haute

#### Principe

`NtQueryInformationProcess` est une fonction NT native qui retourne des informations sur un processus, incluant le **DebugPort**.

```c
NTSTATUS NtQueryInformationProcess(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);
```

#### Classes Intéressantes

```ascii
ProcessInformationClass VALUES:

┌───────────────────────────────────────────────────┐
│  Value │ Nom                      │ Usage          │
├────────┼──────────────────────────┼────────────────┤
│   0x07 │ ProcessDebugPort         │ Port de debug  │
│   0x0E │ ProcessDebugObjectHandle │ Handle debug   │
│   0x1F │ ProcessDebugFlags        │ Flags debug    │
└───────────────────────────────────────────────────┘
```

#### 4.1 : ProcessDebugPort

```c
#include <windows.h>
#include <stdio.h>

// Définition de NtQueryInformationProcess
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
);

#define ProcessDebugPort 0x07

BOOL check_debug_port() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQIP) return FALSE;

    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQIP(
        GetCurrentProcess(),
        ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        NULL
    );

    if (status == 0 && debugPort != 0) {
        printf("[!] DebugPort = 0x%p (debugger actif)\n", (PVOID)debugPort);
        return TRUE;
    }

    return FALSE;
}
```

#### 4.2 : ProcessDebugObjectHandle

```c
#define ProcessDebugObjectHandle 0x1E

BOOL check_debug_object_handle() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");

    HANDLE debugObject = NULL;
    NTSTATUS status = NtQIP(
        GetCurrentProcess(),
        ProcessDebugObjectHandle,
        &debugObject,
        sizeof(debugObject),
        NULL
    );

    if (status == 0 && debugObject != NULL) {
        printf("[!] DebugObjectHandle present (debugger actif)\n");
        CloseHandle(debugObject);
        return TRUE;
    }

    return FALSE;
}
```

#### Diagramme de Fonctionnement

```ascii
NtQueryInformationProcess(ProcessDebugPort):

1. Application appelle NtQueryInformationProcess
   ┌──────────────┐
   │  User Mode   │
   │  App.exe     │ → Syscall
   └──────────────┘
          ↓
2. Transition vers Kernel Mode
   ┌──────────────┐
   │ Kernel Mode  │
   │ ntoskrnl.exe │ → Lit EPROCESS->DebugPort
   └──────────────┘
          ↓
3. Retour à User Mode
   ┌──────────────┐
   │  debugPort   │ → Si != 0 → DEBUGGER
   └──────────────┘
```

---

### Technique 5 : Timing Checks

**Niveau** : Intermédiaire
**Détection** : Difficile
**Efficacité** : Haute

#### Principe

Quand on exécute du code dans un débogueur (step-by-step, breakpoints), l'exécution est **beaucoup plus lente** qu'en temps normal.

```ascii
EXÉCUTION NORMALE:
┌────┬────┬────┬────┐
│ 1ms│ 1ms│ 1ms│ 1ms│  Total: 4ms
└────┴────┴────┴────┘

EXÉCUTION DEBUGGÉE:
┌──────────┬──────────┬──────────┬──────────┐
│   150ms  │   200ms  │   180ms  │   170ms  │  Total: 700ms
└──────────┴──────────┴──────────┴──────────┘
           ↑ Breakpoint hit, analyste examine
```

#### 5.1 : RDTSC (Read Time-Stamp Counter)

`RDTSC` est une instruction CPU qui lit le nombre de cycles depuis le boot.

```c
#include <windows.h>
#include <stdio.h>
#include <intrin.h>  // Pour __rdtsc()

BOOL check_rdtsc() {
    unsigned __int64 start, end;
    unsigned __int64 diff;

    // Mesure avant
    start = __rdtsc();

    // Code à protéger (ici, une simple boucle)
    for (volatile int i = 0; i < 10; i++) {
        // Opération simple
    }

    // Mesure après
    end = __rdtsc();
    diff = end - start;

    // Threshold : si > 1000 cycles, suspect
    // (À ajuster selon le CPU et le code)
    if (diff > 1000) {
        printf("[!] RDTSC: %llu cycles (threshold dépassé)\n", diff);
        return TRUE;
    }

    printf("[+] RDTSC: %llu cycles (normal)\n", diff);
    return FALSE;
}
```

#### 5.2 : QueryPerformanceCounter

API Windows haute précision pour mesurer le temps.

```c
BOOL check_query_performance() {
    LARGE_INTEGER freq, start, end;
    double elapsed;

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Code à protéger
    Sleep(10);  // Normalement ~10ms

    QueryPerformanceCounter(&end);

    // Calcul du temps écoulé en ms
    elapsed = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

    // Si > 100ms pour un Sleep(10), suspect
    if (elapsed > 100.0) {
        printf("[!] QueryPerformanceCounter: %.2fms (trop lent)\n", elapsed);
        return TRUE;
    }

    printf("[+] QueryPerformanceCounter: %.2fms (normal)\n", elapsed);
    return FALSE;
}
```

#### Technique Avancée : RDTSC Multiple

Pour éviter les faux positifs (CPU busy), on fait plusieurs mesures :

```c
BOOL check_rdtsc_advanced() {
    const int SAMPLES = 10;
    unsigned __int64 deltas[SAMPLES];
    unsigned __int64 avg = 0;

    for (int i = 0; i < SAMPLES; i++) {
        unsigned __int64 start = __rdtsc();

        // Opération standard
        volatile int x = 0;
        for (int j = 0; j < 100; j++) x++;

        unsigned __int64 end = __rdtsc();
        deltas[i] = end - start;
        avg += deltas[i];
    }

    avg /= SAMPLES;

    // Calcul de l'écart-type
    unsigned __int64 variance = 0;
    for (int i = 0; i < SAMPLES; i++) {
        __int64 diff = deltas[i] - avg;
        variance += diff * diff;
    }
    variance /= SAMPLES;

    // Si variance élevée → timing anormal (debugger)
    if (variance > 100000) {
        printf("[!] RDTSC variance elevee: %llu (debugger suspecte)\n", variance);
        return TRUE;
    }

    return FALSE;
}
```

---

### Technique 6 : Hardware Breakpoints Detection

**Niveau** : Avancé
**Détection** : Difficile
**Efficacité** : Très haute

#### Principe

Les débogueurs utilisent les **Debug Registers** (DR0-DR7) pour placer des breakpoints matériels.

```ascii
DEBUG REGISTERS (x86/x64):

┌─────────────────────────────────────────────────┐
│ DR0-DR3 : Adresses des breakpoints (4 max)     │
│ DR4-DR5 : Réservés (alias de DR6-DR7)          │
│ DR6     : Debug Status (breakpoint hit ?)      │
│ DR7     : Debug Control (activation des BP)    │
└─────────────────────────────────────────────────┘

Exemple DR7:
┌───────────────────────────────────────────────┐
│  Bit  │ Signification                         │
├───────┼───────────────────────────────────────┤
│  0    │ L0 : Local BP 0 actif                 │
│  1    │ G0 : Global BP 0 actif                │
│  2-3  │ L1/G1 pour DR1                        │
│  4-5  │ L2/G2 pour DR2                        │
│  6-7  │ L3/G3 pour DR3                        │
└───────────────────────────────────────────────┘
```

#### Implémentation

```c
#include <windows.h>
#include <stdio.h>

BOOL check_hardware_breakpoints() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();

    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] Erreur GetThreadContext\n");
        return FALSE;
    }

    // Vérifie si DR0-DR3 sont utilisés
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        printf("[!] Hardware breakpoint detecte:\n");
        printf("    DR0 = 0x%p\n", (PVOID)ctx.Dr0);
        printf("    DR1 = 0x%p\n", (PVOID)ctx.Dr1);
        printf("    DR2 = 0x%p\n", (PVOID)ctx.Dr2);
        printf("    DR3 = 0x%p\n", (PVOID)ctx.Dr3);
        return TRUE;
    }

    // Vérifie DR7 (control register)
    if (ctx.Dr7 & 0xFF) {  // Bits 0-7 : enable flags
        printf("[!] DR7 active: 0x%p\n", (PVOID)ctx.Dr7);
        return TRUE;
    }

    printf("[+] Aucun hardware breakpoint detecte\n");
    return FALSE;
}
```

#### Détails de DR7

```c
void analyze_dr7(DWORD64 dr7) {
    printf("[*] Analyse de DR7: 0x%llX\n", dr7);

    // Vérifie chaque breakpoint
    for (int i = 0; i < 4; i++) {
        int local_bit = i * 2;
        int global_bit = local_bit + 1;

        BOOL local_enabled = (dr7 >> local_bit) & 1;
        BOOL global_enabled = (dr7 >> global_bit) & 1;

        if (local_enabled || global_enabled) {
            printf("    DR%d: %s %s\n", i,
                   local_enabled ? "[LOCAL]" : "",
                   global_enabled ? "[GLOBAL]" : "");

            // Type de breakpoint (bits 16-31)
            int rw_bits = (dr7 >> (16 + i * 4)) & 0x3;
            int len_bits = (dr7 >> (18 + i * 4)) & 0x3;

            const char *types[] = {"Execute", "Write", "I/O", "Read/Write"};
            const char *sizes[] = {"1 byte", "2 bytes", "8 bytes", "4 bytes"};

            printf("        Type: %s, Taille: %s\n", types[rw_bits], sizes[len_bits]);
        }
    }
}
```

---

### Technique 7 : Software Breakpoints (INT 3)

**Niveau** : Intermédiaire
**Détection** : Moyenne
**Efficacité** : Moyenne

#### Principe

Un **software breakpoint** est implémenté en remplaçant une instruction par `INT 3` (opcode `0xCC`).

```ascii
CODE NORMAL:
┌──────────────────────────────────┐
│ 0x00401000: 55        push rbp   │
│ 0x00401001: 48 89 E5  mov rbp,rsp│
│ 0x00401004: 48 83 EC  sub rsp,20 │
└──────────────────────────────────┘

CODE AVEC BREAKPOINT:
┌──────────────────────────────────┐
│ 0x00401000: CC        int 3      │ ← BREAKPOINT !
│ 0x00401001: 48 89 E5  mov rbp,rsp│
│ 0x00401004: 48 83 EC  sub rsp,20 │
└──────────────────────────────────┘
```

#### Détection par Scan Mémoire

```c
#include <windows.h>
#include <stdio.h>

BOOL scan_int3_in_function(PVOID funcPtr, SIZE_T size) {
    BYTE *code = (BYTE *)funcPtr;
    int int3_count = 0;

    for (SIZE_T i = 0; i < size; i++) {
        if (code[i] == 0xCC) {  // INT 3
            printf("[!] INT 3 trouve a offset +0x%zX\n", i);
            int3_count++;
        }
    }

    if (int3_count > 0) {
        printf("[!] %d breakpoint(s) software detecte(s)\n", int3_count);
        return TRUE;
    }

    return FALSE;
}

// Fonction à protéger
void sensitive_function() {
    printf("Code sensible en execution...\n");
    // Payload ici
}

int main() {
    // Scan de la fonction avant exécution
    if (scan_int3_in_function((PVOID)sensitive_function, 256)) {
        printf("[!] Fonction compromise, arret\n");
        return 1;
    }

    sensitive_function();
    return 0;
}
```

#### Calcul de Checksum

Méthode plus robuste : calculer un hash de la fonction.

```c
#include <windows.h>
#include <stdio.h>

// CRC32 simple
DWORD calculate_crc32(BYTE *data, SIZE_T size) {
    DWORD crc = 0xFFFFFFFF;

    for (SIZE_T i = 0; i < size; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    return ~crc;
}

BOOL verify_function_integrity(PVOID funcPtr, SIZE_T size, DWORD expectedCrc) {
    DWORD actualCrc = calculate_crc32((BYTE *)funcPtr, size);

    if (actualCrc != expectedCrc) {
        printf("[!] Checksum mismatch: 0x%08X vs 0x%08X\n", actualCrc, expectedCrc);
        printf("[!] Code modifie (breakpoint probable)\n");
        return FALSE;
    }

    printf("[+] Checksum OK: 0x%08X\n", actualCrc);
    return TRUE;
}
```

**Important** : Calculer le CRC avant compilation et le hardcoder :

```c
// CRC pré-calculé de sensitive_function (généré au build)
#define EXPECTED_CRC 0x12345678

int main() {
    if (!verify_function_integrity((PVOID)sensitive_function, 256, EXPECTED_CRC)) {
        exit(1);
    }

    sensitive_function();
    return 0;
}
```

---

## Implémentation Complète {#implementation}

### Framework Anti-Debug Complet

Voici un framework qui combine toutes les techniques :

```c
#include <windows.h>
#include <stdio.h>
#include <intrin.h>

// ============================================================================
// STRUCTURES
// ============================================================================

typedef struct _ANTI_DEBUG_RESULTS {
    BOOL isDebuggerPresent;
    BOOL remoteDebugger;
    BOOL pebBeingDebugged;
    BOOL ntGlobalFlag;
    BOOL debugPort;
    BOOL debugObject;
    BOOL timingCheck;
    BOOL hardwareBreakpoints;
} ANTI_DEBUG_RESULTS;

// ============================================================================
// PROTOTYPES
// ============================================================================

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE, DWORD, PVOID, DWORD, PDWORD);

// ============================================================================
// FONCTIONS DE DÉTECTION
// ============================================================================

BOOL AD_IsDebuggerPresent() {
    return IsDebuggerPresent();
}

BOOL AD_CheckRemoteDebugger() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent;
}

BOOL AD_PEBBeingDebugged() {
#ifdef _WIN64
    BYTE *peb = (BYTE *)__readgsqword(0x60);
#else
    BYTE *peb = (BYTE *)__readfsdword(0x30);
#endif
    return *(peb + 2);  // Offset +0x02
}

BOOL AD_NtGlobalFlag() {
#ifdef _WIN64
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    DWORD ntGlobalFlag = *(DWORD *)(peb + 0xBC);
#else
    BYTE *peb = (BYTE *)__readfsdword(0x30);
    DWORD ntGlobalFlag = *(DWORD *)(peb + 0x68);
#endif
    return (ntGlobalFlag & 0x70) != 0;
}

BOOL AD_DebugPort() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQIP) return FALSE;

    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), 0x07, &debugPort, sizeof(debugPort), NULL);

    return (status == 0 && debugPort != 0);
}

BOOL AD_DebugObject() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQIP) return FALSE;

    HANDLE debugObject = NULL;
    NTSTATUS status = NtQIP(GetCurrentProcess(), 0x1E, &debugObject, sizeof(debugObject), NULL);

    if (status == 0 && debugObject != NULL) {
        CloseHandle(debugObject);
        return TRUE;
    }
    return FALSE;
}

BOOL AD_TimingCheck() {
    unsigned __int64 start = __rdtsc();
    Sleep(10);
    unsigned __int64 end = __rdtsc();

    // Threshold : ~10ms = ~10M cycles @ 1GHz
    return (end - start) > 100000000;
}

BOOL AD_HardwareBreakpoints() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return FALSE;

    return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3 | (ctx.Dr7 & 0xFF)) != 0;
}

// ============================================================================
// FONCTION PRINCIPALE
// ============================================================================

void run_all_checks(ANTI_DEBUG_RESULTS *results) {
    printf("[*] Demarrage des checks anti-debug...\n\n");

    results->isDebuggerPresent = AD_IsDebuggerPresent();
    printf("[%c] IsDebuggerPresent:       %s\n",
           results->isDebuggerPresent ? '!' : '+',
           results->isDebuggerPresent ? "DETECTE" : "OK");

    results->remoteDebugger = AD_CheckRemoteDebugger();
    printf("[%c] CheckRemoteDebugger:     %s\n",
           results->remoteDebugger ? '!' : '+',
           results->remoteDebugger ? "DETECTE" : "OK");

    results->pebBeingDebugged = AD_PEBBeingDebugged();
    printf("[%c] PEB->BeingDebugged:      %s\n",
           results->pebBeingDebugged ? '!' : '+',
           results->pebBeingDebugged ? "DETECTE" : "OK");

    results->ntGlobalFlag = AD_NtGlobalFlag();
    printf("[%c] PEB->NtGlobalFlag:       %s\n",
           results->ntGlobalFlag ? '!' : '+',
           results->ntGlobalFlag ? "DETECTE" : "OK");

    results->debugPort = AD_DebugPort();
    printf("[%c] NtQIP(DebugPort):        %s\n",
           results->debugPort ? '!' : '+',
           results->debugPort ? "DETECTE" : "OK");

    results->debugObject = AD_DebugObject();
    printf("[%c] NtQIP(DebugObject):      %s\n",
           results->debugObject ? '!' : '+',
           results->debugObject ? "DETECTE" : "OK");

    results->timingCheck = AD_TimingCheck();
    printf("[%c] Timing Check (RDTSC):    %s\n",
           results->timingCheck ? '!' : '+',
           results->timingCheck ? "DETECTE" : "OK");

    results->hardwareBreakpoints = AD_HardwareBreakpoints();
    printf("[%c] Hardware Breakpoints:    %s\n",
           results->hardwareBreakpoints ? '!' : '+',
           results->hardwareBreakpoints ? "DETECTE" : "OK");
}

BOOL is_debugged(ANTI_DEBUG_RESULTS *results) {
    return results->isDebuggerPresent ||
           results->remoteDebugger ||
           results->pebBeingDebugged ||
           results->ntGlobalFlag ||
           results->debugPort ||
           results->debugObject ||
           results->timingCheck ||
           results->hardwareBreakpoints;
}

int main() {
    ANTI_DEBUG_RESULTS results = {0};

    run_all_checks(&results);

    printf("\n");
    if (is_debugged(&results)) {
        printf("[!] DEBUGGER DETECTE - Arret du programme\n");
        return 1;
    }

    printf("[+] Aucun debugger detecte\n");
    printf("[+] Execution du payload...\n");

    // Payload ici

    return 0;
}
```

### Compilation

```bash
# x64
x86_64-w64-mingw32-gcc anti_debug.c -o anti_debug.exe -lntdll

# x86
i686-w64-mingw32-gcc anti_debug.c -o anti_debug_x86.exe -lntdll
```

---

## Anti-Anti-Debug : Contourner les Détections {#anti-anti-debug}

### Perspective Défensive

En tant que Red Teamer, vous devez aussi comprendre comment un Blue Team peut contourner vos protections.

### Méthode 1 : Patching Binaire

```ascii
PATCHING IsDebuggerPresent:

Code original:
┌──────────────────────────────────┐
│ call IsDebuggerPresent           │
│ test eax, eax                    │
│ jnz  exit_program                │ ← Saute si debugger
└──────────────────────────────────┘

Code patché:
┌──────────────────────────────────┐
│ call IsDebuggerPresent           │
│ xor  eax, eax                    │ ← Force EAX = 0
│ jnz  exit_program                │ ← Ne saute jamais
└──────────────────────────────────┘
```

### Méthode 2 : Plugins x64dbg

Plugins populaires pour bypass anti-debug :

- **ScyllaHide** : Cache le debugger au niveau kernel
- **TitanHide** : Driver kernel pour masquer le debugging
- **PhantOm** : Anti-anti-debug pour x64dbg

```ascii
ScyllaHide CONFIGURATION:

┌─────────────────────────────────────┐
│ ☑ PEB->BeingDebugged               │ ← Force à 0
│ ☑ PEB->NtGlobalFlag                │ ← Force à 0
│ ☑ NtQueryInformationProcess        │ ← Hook et retourne faux
│ ☑ NtSetInformationThread           │ ← Bloque HideFromDebugger
│ ☑ GetTickCount                     │ ← Normalise le timing
│ ☑ RDTSC                            │ ← Émule des valeurs normales
└─────────────────────────────────────┘
```

### Méthode 3 : Hooking API

Un analyste peut hooker les API anti-debug :

```c
// Hook IsDebuggerPresent pour toujours retourner FALSE
BOOL WINAPI Hooked_IsDebuggerPresent() {
    return FALSE;  // Toujours "pas de debugger"
}

// Installation du hook (avec Detours, MinHook, etc.)
void install_hooks() {
    hook_function("kernel32.dll", "IsDebuggerPresent", Hooked_IsDebuggerPresent);
}
```

### Contre-mesure : Vérification Multi-Couches

Pour rendre le bypass plus difficile :

```c
int main() {
    // Check 1 : API
    if (AD_IsDebuggerPresent()) goto detected;

    // Check 2 : PEB direct (bypass le hook API)
    if (AD_PEBBeingDebugged()) goto detected;

    // Check 3 : NT API
    if (AD_DebugPort()) goto detected;

    // Check 4 : Timing (difficile à émuler)
    if (AD_TimingCheck()) goto detected;

    // Check 5 : Hardware BP
    if (AD_HardwareBreakpoints()) goto detected;

    // Checks répartis dans le code
    execute_payload();

    if (AD_TimingCheck()) goto detected;  // Re-check

    return 0;

detected:
    // Comportement trompeur (pas d'exit brutal)
    execute_benign_code();
    return 0;
}
```

---

## Détection et OPSEC {#detection-opsec}

### Risques de Détection

Les techniques anti-debug peuvent elles-mêmes être détectées par les EDR/AV.

```ascii
MATRICE DE RISQUE OPSEC:

┌────────────────────────────────────────────────────┐
│ Technique              │ Risque │ Signatures AV    │
├────────────────────────┼────────┼──────────────────┤
│ IsDebuggerPresent      │  BAS   │ Très commun      │
│ PEB->BeingDebugged     │  BAS   │ Commun           │
│ NtQueryInformationProc │  MOYEN │ Suspect si NT API│
│ RDTSC                  │  MOYEN │ Utilisé par malw.│
│ Hardware BP check      │  HAUT  │ Rare, très suspic│
│ INT 3 scanning         │  HAUT  │ Comportement malv│
└────────────────────────────────────────────────────┘
```

### Recommandations OPSEC

#### 1. Utiliser avec Modération

```c
// MAL : Tous les checks en boucle infinie
while (1) {
    if (AD_IsDebuggerPresent()) exit(1);
    if (AD_PEBBeingDebugged()) exit(1);
    if (AD_TimingCheck()) exit(1);
    Sleep(100);
}

// BIEN : Checks discrets à des moments clés
void execute_payload() {
    // Check initial
    if (AD_IsDebuggerPresent()) return;

    // ... code ...

    // Check avant opération sensible
    decrypt_payload();
    if (AD_TimingCheck()) return;

    run_payload();
}
```

#### 2. Obscurcir les Checks

```c
// Au lieu de :
if (IsDebuggerPresent()) exit(1);

// Utiliser :
int x = IsDebuggerPresent();
int y = compute_checksum();
int z = (x ^ y) & 0xFF;
if (z != expected_value) {
    // Comportement normal, mais payload ne s'exécute pas
    do_benign_stuff();
    return;
}
```

#### 3. Éviter les Patterns Connus

```c
// Pattern détecté par YARA:
rule detect_anti_debug {
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "NtQueryInformationProcess"
    condition:
        2 of them
}

// Contre-mesure : Résolution dynamique
FARPROC get_func(const char *dll, const char *func) {
    // Chiffrer les noms ou utiliser des hashes
    HMODULE h = LoadLibraryA(xor_decrypt(dll));
    return GetProcAddress(h, xor_decrypt(func));
}
```

#### 4. Timing Naturel

```c
// Au lieu de timing checks évidents, utiliser des événements naturels
BOOL check_natural_timing() {
    DWORD start = GetTickCount();

    // Attendre une activité réseau (légitime)
    ping_c2_server();

    DWORD elapsed = GetTickCount() - start;

    // Si trop lent, peut indiquer un debugger
    return (elapsed > 5000);  // 5 secondes pour un ping : suspect
}
```

---

## Checklist de Développement {#checklist}

### Avant d'Implémenter

- [ ] Définir les objectifs : Qui voulez-vous bloquer ? (analystes, AV, sandbox)
- [ ] Évaluer le risque OPSEC de chaque technique
- [ ] Tester en environnement contrôlé (VM + debugger)
- [ ] Prévoir des fallbacks (que faire si détecté ?)

### Pendant l'Implémentation

- [ ] Utiliser 3-5 techniques complémentaires (pas toutes)
- [ ] Répartir les checks dans le code (pas tous au début)
- [ ] Obscurcir les appels API (résolution dynamique)
- [ ] Ajouter du jitter/timing aléatoire
- [ ] Tester contre ScyllaHide, TitanHide

### Après l'Implémentation

- [ ] Tester avec x64dbg + ScyllaHide
- [ ] Vérifier les signatures AV (VirusTotal)
- [ ] Analyser le binaire avec YARA
- [ ] Documenter le comportement en cas de détection
- [ ] Prévoir des mises à jour (nouvelles techniques)

---

## Exercices Pratiques {#exercices}

### Exercice 1 : Détection Simple

Créez un programme qui :
1. Vérifie `IsDebuggerPresent()`
2. Si détecté, affiche "Mode analyse" et s'arrête
3. Sinon, affiche "Mode normal" et continue

**Solution dans** : `solution_ex1.c`

### Exercice 2 : PEB Inspection

Implémentez une fonction qui :
1. Lit `PEB->BeingDebugged`
2. Lit `PEB->NtGlobalFlag`
3. Retourne TRUE si l'un des deux indique un debugger

### Exercice 3 : Timing Attack

Créez un timing check qui :
1. Mesure le temps d'exécution d'une fonction simple
2. Compare avec un baseline pré-calculé
3. Détecte si l'exécution est > 10x plus lente

### Exercice 4 : Hardware Breakpoints

Implémentez :
1. Une fonction qui vérifie DR0-DR7
2. Affiche les adresses des breakpoints actifs
3. Analyse le type de breakpoint (read/write/execute)

### Exercice 5 : Framework Complet

Créez un framework qui :
1. Implémente 5+ techniques différentes
2. Retourne un score de confiance (0-100%)
3. Décide de l'action selon le score :
   - 0-30% : Exécution normale
   - 31-70% : Mode suspicion (logs)
   - 71-100% : Arrêt immédiat

### Exercice 6 : Bypass ScyllaHide

1. Installez ScyllaHide dans x64dbg
2. Testez votre programme anti-debug
3. Identifiez quelles techniques sont bypassées
4. Implémentez des contre-mesures

---

## Ressources {#ressources}

### Documentation Officielle

- [MSDN - IsDebuggerPresent](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)
- [MSDN - NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
- [Intel Manual - RDTSC](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=rdtsc)

### Outils

- **x64dbg** : https://x64dbg.com/
- **ScyllaHide** : https://github.com/x64dbg/ScyllaHide
- **TitanHide** : https://github.com/mrexodia/TitanHide
- **API Monitor** : http://www.rohitab.com/apimonitor

### Articles et Recherches

- [Anti-Debugging Techniques - Checkpoint](https://anti-debug.checkpoint.com/)
- [The Ultimate Anti-Debugging Reference - Peter Ferrie](http://pferrie.epizy.com/papers/antidebug.pdf)
- [Windows Anti-Debug Reference - Al-Khaser](https://github.com/LordNoteworthy/al-khaser)

### Projets Open Source

- **al-khaser** : Suite de tests anti-debug/VM/sandbox
  ```bash
  git clone https://github.com/LordNoteworthy/al-khaser
  ```

- **Pafish** : Paranoid Fish (détection VM + debug)
  ```bash
  git clone https://github.com/a0rtega/pafish
  ```

### Livres Recommandés

- *Practical Malware Analysis* - Michael Sikorski
- *The Rootkit Arsenal* - Bill Blunden
- *Windows Internals Part 1* - Pavel Yosifovich

---

## Conclusion

L'anti-debug est une technique essentielle pour :
- Protéger les implants Red Team de l'analyse
- Comprendre les mécanismes de détection adverses
- Développer des payloads résilients

**Points clés à retenir** :

1. **Diversité** : Combinez plusieurs techniques (API, PEB, timing, hardware)
2. **OPSEC** : Chaque technique a un coût en détectabilité
3. **Résilience** : Prévoyez que certaines techniques seront bypassées
4. **Évolution** : Les outils anti-anti-debug évoluent constamment

**Prochaines étapes** :
- Module W42 : Anti-VM (détection de machines virtuelles)
- Module W43 : Anti-Sandbox (détection d'environnements d'analyse)
- Module W44 : Code Obfuscation (obscurcissement avancé)

---

**Auteur** : Module W41 - C Full Offensive Course
**Dernière mise à jour** : 2025-12-07
**Licence** : Éducatif uniquement - Usage responsable requis

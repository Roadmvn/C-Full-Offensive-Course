# Module 30 : Anti-Debugging

## Vue d'ensemble

Les techniques anti-debugging permettent à un programme de détecter s'il est exécuté sous un débogueur et de réagir en conséquence. Ce module explore les principales méthodes de détection de débogage sur Windows et Linux.

## Concepts abordés

### 1. IsDebuggerPresent (Windows)
API Windows native qui vérifie si le processus est en cours de débogage.

```c
#include <windows.h>

if (IsDebuggerPresent()) {
    printf("Débogueur détecté!\n");
    exit(1);
}
```

### 2. PEB->BeingDebugged Check (Windows)
Vérification directe du flag BeingDebugged dans le Process Environment Block.

**Structure PEB** :
```
PEB (Process Environment Block)
├── BeingDebugged (offset 0x02)
├── NtGlobalFlag (offset 0x68)
└── Autres champs...
```

### 3. NtQueryInformationProcess (Windows)
API non documentée permettant d'obtenir des informations sur le processus.

**Classes d'information utiles** :
- ProcessDebugPort (0x07)
- ProcessDebugObjectHandle (0x1E)
- ProcessDebugFlags (0x1F)

### 4. Timing Checks (RDTSC)
Détection basée sur la mesure du temps d'exécution avec l'instruction RDTSC.

**Principe** :
```
Temps normal : ~1000 cycles
Sous débogueur : >10000 cycles (à cause des breakpoints)
```

### 5. Hardware Breakpoint Detection
Vérification des registres de débogage matériel (DR0-DR7).

**Registres de débogage** :
```
DR0-DR3 : Adresses des breakpoints matériels
DR6     : Status register
DR7     : Control register
```

## Techniques d'implémentation

### Windows : IsDebuggerPresent

```c
#include <windows.h>

BOOL check_debugger_present(void) {
    return IsDebuggerPresent();
}
```

### Windows : PEB Walking

```c
BOOL check_peb_being_debugged(void) {
    BOOL found = FALSE;

    #ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    #else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    #endif

    if (pPeb->BeingDebugged) {
        found = TRUE;
    }

    return found;
}
```

### Linux : ptrace Self-Attach

```c
#include <sys/ptrace.h>

int check_ptrace_self(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        // Déjà tracé par un débogueur
        return 1;
    }
    return 0;
}
```

### RDTSC Timing

```c
uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int check_timing(void) {
    uint64_t start = rdtsc();
    // Code à protéger
    uint64_t end = rdtsc();

    if ((end - start) > 10000) {
        return 1;  // Débogueur détecté
    }
    return 0;
}
```

### Hardware Breakpoints Detection

```c
#include <windows.h>

BOOL check_hardware_breakpoints(void) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return TRUE;  // Breakpoint matériel détecté
        }
    }
    return FALSE;
}
```

## Techniques avancées

### Exception-Based Detection

```c
BOOL check_debugger_via_exception(void) {
    __try {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Sous débogueur, on n'arrive pas ici
        return FALSE;
    }
    return TRUE;  // Débogueur détecté
}
```

### Parent Process Check

```c
// Vérifier si le parent est un débogueur connu
BOOL check_parent_process(void) {
    // Vérifier si le parent est "devenv.exe", "ollydbg.exe", etc.
    // Implémentation spécifique selon les besoins
    return FALSE;
}
```

### Code Checksum Verification

```c
// Vérifier l'intégrité du code (détection de breakpoints software)
BOOL check_code_integrity(void) {
    // Calculer un checksum du code et le comparer
    return FALSE;
}
```

## Avertissements et considérations

### AVERTISSEMENT LÉGAL

**IMPORTANT** : Les techniques anti-debugging peuvent être utilisées à des fins malveillantes. Ce module est fourni UNIQUEMENT à des fins éducatives.

**Utilisations légitimes** :
- Protection contre le reverse engineering commercial
- Protection de la propriété intellectuelle
- Sécurité des logiciels sensibles
- Recherche en sécurité informatique

**Utilisations ILLÉGALES** :
- Dissimulation de malware
- Fraude logicielle
- Contournement de licences
- Activités criminelles

**L'utilisateur est SEUL RESPONSABLE** de l'usage qu'il fait de ces techniques.

### Limitations techniques

**Contournement** :
- Les techniques anti-debugging peuvent toutes être contournées
- Un analyste expérimenté peut les détecter et les patcher
- Ne jamais compter uniquement sur l'anti-debugging

**Faux positifs** :
- Certains logiciels légitimes utilisent des techniques similaires aux débogueurs
- Les outils de monitoring peuvent déclencher les détections
- Impact sur l'expérience utilisateur légitime

**Performance** :
- Les vérifications fréquentes impactent les performances
- Équilibrer sécurité et performance
- Utiliser avec parcimonie

## Contre-mesures (pour analystes)

### Contournement d'IsDebuggerPresent

```
1. Patcher l'API pour retourner toujours FALSE
2. Utiliser un débogueur qui cache sa présence
3. Modifier le PEB en mémoire
```

### Contournement des timing checks

```
1. Patcher les vérifications de temps
2. Utiliser l'émulation
3. Modifier les seuils de détection
```

### Contournement de ptrace

```
1. Utiliser LD_PRELOAD pour hooker ptrace
2. Modifier le noyau (modules kernel)
3. Utiliser des débogueurs alternatifs
```

## Détection des techniques anti-debugging

### Signatures communes

```
- Appels à IsDebuggerPresent
- Accès au PEB
- Instructions RDTSC
- Appels à ptrace
- Accès aux registres DR0-DR7
```

### Outils de détection

- **IDA Pro** : Détecte les patterns anti-debug
- **x64dbg plugins** : ScyllaHide, etc.
- **Binary Ninja** : Analyse des anti-debug techniques
- **PEID** : Détection de packers et anti-debug

## Compilation et test

### Windows

```bash
# MinGW
gcc -o anti_debug main.c

# MSVC
cl /Zi main.c

# Test sous débogueur
x64dbg anti_debug.exe
```

### Linux

```bash
# Compilation
gcc -o anti_debug main.c

# Test normal
./anti_debug

# Test sous débogueur
gdb ./anti_debug
```

## Bonnes pratiques

1. **Combiner plusieurs techniques** : Diversifier les détections
2. **Obfusquer les checks** : Ne pas rendre les vérifications évidentes
3. **Réactions variées** : Ne pas toujours quitter brutalement
4. **Timing aléatoire** : Exécuter les checks à des moments imprévisibles
5. **Utilisation éthique** : Toujours dans un cadre légal

## Réactions possibles à la détection

### Réactions discrètes

```c
if (debugger_detected()) {
    // Altérer subtilement le comportement
    modify_algorithm();
    introduce_bugs();
}
```

### Réactions évidentes

```c
if (debugger_detected()) {
    printf("Débogueur détecté!\n");
    exit(1);
}
```

### Réactions retardées

```c
if (debugger_detected()) {
    // Planter dans 5 minutes
    schedule_delayed_exit();
}
```

## Ressources complémentaires

- "The Ultimate Anti-Debugging Reference" - Peter Ferrie
- "Anti-Debugging Protection Techniques with Examples" - Apriorit
- "Practical Malware Analysis" - Michael Sikorski
- OpenRCE Anti-Debugging Database

## Exercices pratiques

Consultez le fichier `exercice.txt` pour des défis d'implémentation et `solution.txt` pour les solutions détaillées.

## Avertissement final

Ce module présente des techniques puissantes qui doivent être utilisées de manière responsable et éthique. La connaissance de l'anti-debugging est importante pour :
- Comprendre comment protéger ses applications
- Analyser des logiciels suspects en sécurité
- Développer des contre-mesures appropriées

Mais elle ne doit JAMAIS servir à des activités malveillantes ou illégales.

L'analyse en sécurité informatique doit toujours se faire dans un cadre légal avec les autorisations appropriées.

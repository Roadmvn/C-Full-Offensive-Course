# Jitter et Sleep - Anti-Pattern Analysis

## Objectifs

- [ ] Comprendre la détection par pattern analysis
- [ ] Implémenter du jitter (randomisation timing)
- [ ] Utiliser des sleep variables et non prédictibles
- [ ] Éviter les signatures temporelles

## Introduction

Un beacon qui contacte le C2 exactement toutes les 60 secondes est facilement détectable. Le **jitter** ajoute de l'aléatoire au timing pour casser les patterns et ressembler à du trafic humain.

**Analogie** : Un garde qui fait sa ronde exactement toutes les 10 minutes est prévisible. S'il varie entre 8-12 minutes, il est imprévisible.

## Concepts

### 1. Pattern Analysis

```
Beacon SANS jitter (détectable):
[Request] ---60s---> [Request] ---60s---> [Request] ---60s---> [Request]
Pattern parfait = signature

Beacon AVEC jitter (furtif):
[Request] ---52s---> [Request] ---67s---> [Request] ---58s---> [Request]
Pattern varié = ressemble au trafic humain
```

### 2. Formule Jitter

```c
interval_base = 60000;  // 60 secondes
jitter_percent = 20;    // ±20%

jitter_range = interval_base * jitter_percent / 100;  // 12000 ms
jitter_value = rand() % (2 * jitter_range) - jitter_range;  // -12000 à +12000

final_interval = interval_base + jitter_value;  // 48000-72000 ms (48-72s)
```

### 3. Types de Jitter

| Type | Description | Usage |
|------|-------------|-------|
| **Uniforme** | ±X% fixe | Beacon standard |
| **Exponentiel** | Augmente après échec | Backoff retry |
| **Aléatoire pur** | Totalement aléatoire | Exfiltration opportuniste |

## Code - Jitter Simple

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BEACON_INTERVAL 60000   // 60 secondes
#define JITTER_PERCENT 20       // ±20%

DWORD GetJitteredInterval(DWORD baseInterval, int jitterPercent) {
    int maxJitter = (baseInterval * jitterPercent) / 100;

    // Génerer jitter: -maxJitter à +maxJitter
    int jitter = (rand() % (2 * maxJitter)) - maxJitter;

    DWORD finalInterval = baseInterval + jitter;

    // Éviter valeurs négatives ou trop petites
    if (finalInterval < 1000) finalInterval = 1000;

    return finalInterval;
}

int main() {
    srand(time(NULL));  // Initialiser RNG

    printf("Beacon intervals avec jitter ±20%%:\n");

    for (int i = 0; i < 10; i++) {
        DWORD interval = GetJitteredInterval(BEACON_INTERVAL, JITTER_PERCENT);
        printf("  Beacon #%d: %d ms (%.1f s)\n", i+1, interval, interval/1000.0);
    }

    return 0;
}
```

**Sortie** :
```
Beacon intervals avec jitter ±20%:
  Beacon #1: 52340 ms (52.3 s)
  Beacon #2: 67120 ms (67.1 s)
  Beacon #3: 55890 ms (55.9 s)
  Beacon #4: 71200 ms (71.2 s)
  Beacon #5: 48560 ms (48.6 s)
...
```

## Beacon avec Jitter

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define C2_SERVER "c2.example.com"
#define BASE_INTERVAL 60000  // 60s
#define JITTER 30            // ±30%

DWORD ApplyJitter(DWORD base, int percent) {
    int maxJitter = (base * percent) / 100;
    int jitter = (rand() % (2 * maxJitter)) - maxJitter;
    DWORD result = base + jitter;
    return (result < 5000) ? 5000 : result;  // Min 5 secondes
}

void BeaconLoop() {
    srand(time(NULL));

    while (1) {
        printf("[*] Sending beacon to %s\n", C2_SERVER);

        // Envoyer beacon (HTTP/DNS/etc.)
        // SendBeacon();

        DWORD sleepTime = ApplyJitter(BASE_INTERVAL, JITTER);
        printf("[*] Next beacon in %d seconds\n\n", sleepTime / 1000);

        Sleep(sleepTime);
    }
}

int main() {
    BeaconLoop();
    return 0;
}
```

## Jitter Exponentiel (Backoff)

```c
DWORD currentInterval = BASE_INTERVAL;
int failureCount = 0;

while (1) {
    if (!SendBeacon()) {
        failureCount++;
        // Doubler l'intervalle à chaque échec (max 10 min)
        currentInterval *= 2;
        if (currentInterval > 600000) currentInterval = 600000;
    } else {
        failureCount = 0;
        currentInterval = BASE_INTERVAL;  // Reset
    }

    DWORD sleepTime = ApplyJitter(currentInterval, JITTER);
    Sleep(sleepTime);
}
```

## Timing Avancé

### Sleep Obfusqué

```c
// Au lieu de Sleep() simple (signature API)
void ObfuscatedSleep(DWORD milliseconds) {
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)milliseconds * 10000;  // 100ns units

    NtDelayExecution(FALSE, &interval);  // API Native
}
```

### Waiting Time Variation

```c
// Varier selon l'heure de la journée
DWORD GetDynamicInterval() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Heures de bureau (9h-17h) : interval court
    if (st.wHour >= 9 && st.wHour < 17) {
        return ApplyJitter(60000, 20);  // 60s ±20%
    }
    // Nuit : interval long
    else {
        return ApplyJitter(300000, 30);  // 5min ±30%
    }
}
```

## OPSEC

```
[Best Practices]
✓ Toujours utiliser jitter ≥20%
✓ Varier selon contexte (heure, activité user)
✓ Éviter patterns mathématiques (fib, primes)
✓ Min interval ≥5s (éviter flooding)

[Détection]
✗ Interval fixe = signature évidente
✗ Pattern mathématique (60, 120, 240...)
✗ Trop de requêtes = anomalie volume
```

**Exemple détection** :
```python
# Blue Team - Détection pattern
intervals = [60.1, 60.0, 60.2, 59.9, 60.1]  # Beacon sans jitter
std_dev = stddev(intervals)  # ~0.1
if std_dev < 1:  # Pattern suspect!
    alert("Possible C2 beacon detected")
```

## Résumé

- **Jitter** : Randomisation timing pour casser patterns
- **Formule** : `base ± (base * percent / 100)`
- **Implémentation** : `rand()` avec seed `time(NULL)`
- **Types** : Uniforme (±X%), exponentiel (backoff), dynamique
- **OPSEC** : CRITIQUE - jitter ≥20% obligatoire
- **Détection** : Pattern fixe, faible écart-type, volume élevé

## Ressources

- [Cobalt Strike Jitter](https://www.cobaltstrike.com/help-sleep)
- [Detecting C2 via Pattern Analysis](https://www.elastic.co/security-labs/detecting-cobalt-strike-with-memory-signatures)

---

**Navigation**
- [Précédent](../10-Session-Management/)
- [Suivant](../12-Staged-vs-Stageless/)

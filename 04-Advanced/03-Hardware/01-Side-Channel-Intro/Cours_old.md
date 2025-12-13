# Module A11 : Side Channel Introduction - Attaques par canaux auxiliaires

## Objectifs pédagogiques

À la fin de ce module, tu seras capable de :
- Comprendre les attaques side-channel (timing, cache, power)
- Implémenter une attaque cache timing en C
- Mesurer et exploiter les fuites d'information timing
- Se défendre contre les side-channels

## Prérequis

- Architecture CPU (cache, pipeline, spéculation)
- C et assembleur pour timing précis
- Statistiques de base

## Introduction

Les **attaques side-channel** exploitent les **fuites d'information indirectes** (timing, consommation, émissions électromagnétiques) plutôt que les bugs logiciels.

```
┌────────────────────────────────────────────┐
│       Types de Side-Channel                │
└────────────────────────────────────────────┘

1. Timing Attack
   └─> Mesurer le temps d'exécution

2. Cache Attack (Flush+Reload, Prime+Probe)
   └─> Analyser l'état du cache CPU

3. Power Analysis (SPA, DPA)
   └─> Mesurer la consommation électrique

4. EM Attack
   └─> Capter les émissions électromagnétiques
```

## Cache Timing Attack - Exemple

**Principe :** Si une donnée est dans le cache, l'accès est rapide (~4 cycles). Si non, c'est lent (~200 cycles).

**PoC en C :**
```c
#include <stdint.h>
#include <x86intrin.h>

#define CACHE_LINE 64

uint64_t time_access(void* addr) {
    uint64_t start = __rdtsc();
    *(volatile char*)addr;
    uint64_t end = __rdtsc();
    return end - start;
}

void flush(void* addr) {
    _mm_clflush(addr);
    _mm_mfence();
}

int main() {
    char data[256 * CACHE_LINE];
    
    // Flush tout
    for (int i = 0; i < 256; i++) {
        flush(&data[i * CACHE_LINE]);
    }
    
    // Victime accède à data[secret]
    int secret = 42;
    *(volatile char*)&data[secret * CACHE_LINE];
    
    // Attaquant mesure les temps
    for (int i = 0; i < 256; i++) {
        uint64_t t = time_access(&data[i * CACHE_LINE]);
        if (t < 100) {
            printf("Secret trouvé: %d (temps: %lu)\n", i, t);
        }
    }
    
    return 0;
}
```

## Résumé

- Side-channel = fuites indirectes (timing, cache, power)
- Cache timing = mesurer si donnée est en cache
- Flush+Reload = technique pour espionner accès mémoire
- Défense : constant-time code, cache partitioning

## Ressources

- **Flush+Reload** : https://eprint.iacr.org/2013/448.pdf
- **Mastik toolkit** : https://github.com/0xADE1A1DE/Mastik

---

**Module suivant** : [A12 - Spectre & Meltdown](../A12_spectre_meltdown/)

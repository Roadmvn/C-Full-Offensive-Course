# Solutions - Model Extraction

## Exercice 1 : Découverte (Très facile)

**Solution** :

```bash
# Compilation du programme
gcc example.c -o example

# Exécution
./example
```

**Résultat attendu** :
```
[*] Module : Model Extraction
[*] ==========================================

[+] Exemple terminé avec succès
```

**Explication** :
Ce module explore les techniques d'extraction de modèles LLM, permettant à un attaquant de voler ou copier un modèle propriétaire via des requêtes API.

---

## Exercice 2 : Query-based Model Extraction Simulator (Facile)

**Objectif** : Créer un simulateur qui démontre comment des requêtes répétées peuvent extraire les connaissances d'un modèle.

**Solution** :

```c
/*
 * =============================================================================
 * Query-Based Model Extraction Simulator
 * =============================================================================
 *
 * Description : Simule l'extraction d'un modèle via requêtes répétées
 *
 * Compilation :
 *   gcc query_extraction.c -o query_extraction
 *
 * Usage :
 *   ./query_extraction <num_queries>
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_QUERIES 1000
#define MAX_RESPONSE_LENGTH 256

// Structure représentant une paire requête-réponse
typedef struct {
    char query[128];
    char response[MAX_RESPONSE_LENGTH];
    float confidence;  // Score de confiance du modèle
} QueryResponsePair;

// Simulateur de modèle "victime"
typedef struct {
    char model_name[64];
    int total_parameters;  // En millions
    int queries_received;
    float extraction_progress;  // Pourcentage extrait (0-100)
} TargetModel;

/*
 * Initialise le modèle cible
 */
TargetModel init_target_model() {
    TargetModel model;
    strcpy(model.model_name, "ProprietaryLLM-v3");
    model.total_parameters = 7000;  // 7B paramètres
    model.queries_received = 0;
    model.extraction_progress = 0.0;

    printf("[*] Modèle cible initialisé\n");
    printf("[*] Nom : %s\n", model.model_name);
    printf("[*] Paramètres : %dM\n", model.total_parameters);
    printf("[*] Valeur estimée : $500,000\n\n");

    return model;
}

/*
 * Simule une requête au modèle victime
 *
 * model : Pointeur vers le modèle cible
 * query : La requête à envoyer
 * response : Buffer pour la réponse
 *
 * Retourne le score de confiance
 */
float query_model(TargetModel *model, const char *query, char *response) {
    model->queries_received++;

    // Simuler une réponse basée sur la requête
    if (strstr(query, "capital") != NULL) {
        strcpy(response, "The capital of France is Paris");
    } else if (strstr(query, "python") != NULL) {
        strcpy(response, "def hello(): print('Hello World')");
    } else if (strstr(query, "math") != NULL) {
        strcpy(response, "The result is 42");
    } else {
        strcpy(response, "I understand your question. Here is the answer.");
    }

    // Score de confiance aléatoire
    float confidence = 0.7 + ((float)rand() / RAND_MAX) * 0.3;

    return confidence;
}

/*
 * Calcule le progrès d'extraction basé sur le nombre de requêtes
 *
 * num_queries : Nombre de requêtes effectuées
 * model_size : Taille du modèle en paramètres (millions)
 *
 * Retourne le pourcentage extrait
 */
float calculate_extraction_progress(int num_queries, int model_size) {
    // Formule empirique : log scale
    // Un modèle de 7B nécessite ~100k requêtes pour extraction significative
    float queries_needed = model_size * 15.0;  // 15 queries par million de params

    float progress = (num_queries / queries_needed) * 100.0;

    if (progress > 100.0) {
        progress = 100.0;
    }

    return progress;
}

/*
 * Génère des requêtes d'extraction automatiques
 */
void generate_extraction_queries(TargetModel *model, int num_queries) {
    printf("[*] === EXTRACTION EN COURS ===\n\n");
    printf("[*] Nombre de requêtes à envoyer : %d\n", num_queries);

    // Templates de requêtes pour extraction
    const char *query_templates[] = {
        "What is the capital of France?",
        "Write Python code for hello world",
        "Solve this math problem: 2+2",
        "Translate 'hello' to Spanish",
        "Explain quantum physics",
        "What is machine learning?",
        NULL
    };

    QueryResponsePair *pairs = malloc(num_queries * sizeof(QueryResponsePair));
    if (pairs == NULL) {
        printf("[!] ERREUR : Allocation mémoire échouée\n");
        return;
    }

    printf("[*] Envoi des requêtes...\n\n");

    // Simuler l'envoi de requêtes
    for (int i = 0; i < num_queries; i++) {
        // Choisir un template aléatoire
        int template_idx = rand() % 6;
        strcpy(pairs[i].query, query_templates[template_idx]);

        // Envoyer la requête
        char response[MAX_RESPONSE_LENGTH];
        float confidence = query_model(model, pairs[i].query, response);

        strcpy(pairs[i].response, response);
        pairs[i].confidence = confidence;

        // Affichage périodique
        if ((i + 1) % 100 == 0 || i == 0) {
            printf("[*] Requête %d/%d\n", i + 1, num_queries);
            printf("    Query: %s\n", pairs[i].query);
            printf("    Response: %.50s...\n", pairs[i].response);
            printf("    Confidence: %.2f\n\n", confidence);
        }
    }

    // Calculer le progrès d'extraction
    model->extraction_progress = calculate_extraction_progress(
        model->queries_received,
        model->total_parameters
    );

    printf("[*] Collecte terminée : %d paires query-response\n", num_queries);
    printf("[*] Progrès d'extraction : %.2f%%\n\n", model->extraction_progress);

    // Sauvegarder les paires (simulation)
    printf("[*] Sauvegarde des données d'extraction...\n");
    printf("[*] Fichier : stolen_model_data.json (simulé)\n");

    free(pairs);
}

/*
 * Affiche un rapport d'extraction
 */
void display_extraction_report(const TargetModel *model) {
    printf("\n[*] ===== RAPPORT D'EXTRACTION =====\n");
    printf("[*] Modèle cible : %s\n", model->model_name);
    printf("[*] Requêtes envoyées : %d\n", model->queries_received);
    printf("[*] Progrès d'extraction : %.2f%%\n", model->extraction_progress);

    if (model->extraction_progress >= 80.0) {
        printf("\n[!] *** EXTRACTION RÉUSSIE ***\n");
        printf("[!] Le modèle peut être reproduit avec haute fidélité\n");
        printf("[!] Coût pour l'attaquant : ~$%.2f en API calls\n",
               model->queries_received * 0.002);
        printf("[!] Valeur du modèle volé : $500,000+\n");
    } else if (model->extraction_progress >= 40.0) {
        printf("\n[!] EXTRACTION PARTIELLE\n");
        printf("[!] Le modèle peut être approximé pour certaines tâches\n");
        printf("[!] Requêtes supplémentaires nécessaires : ~%d\n",
               (int)((80.0 - model->extraction_progress) * model->total_parameters * 15.0 / 100.0));
    } else {
        printf("\n[*] Extraction insuffisante\n");
        printf("[*] Plus de requêtes nécessaires pour extraction viable\n");
    }

    printf("[*] ===================================\n");
}

/*
 * Affiche les défenses contre l'extraction
 */
void display_defenses() {
    printf("\n[*] === DÉFENSES CONTRE MODEL EXTRACTION ===\n");
    printf("[*] 1. Rate Limiting:\n");
    printf("       - Limiter le nombre de requêtes par utilisateur/IP\n");
    printf("       - Détecter les patterns de requêtes automatisées\n");
    printf("[*] 2. Query Monitoring:\n");
    printf("       - Analyser les patterns de requêtes suspects\n");
    printf("       - Bloquer les utilisateurs effectuant trop de requêtes similaires\n");
    printf("[*] 3. Output Perturbation:\n");
    printf("       - Ajouter du bruit aux réponses (minimal impact user, max impact extraction)\n");
    printf("       - Varier légèrement les outputs pour mêmes inputs\n");
    printf("[*] 4. Authentication & Tracking:\n");
    printf("       - Authentification forte requise\n");
    printf("       - Tracer toutes les requêtes pour audit\n");
    printf("[*] 5. Watermarking:\n");
    printf("       - Injecter des watermarks dans les outputs\n");
    printf("       - Permettre la détection de modèles volés\n");
}

int main(int argc, char *argv[]) {
    // Initialiser le générateur aléatoire
    srand(time(NULL));

    printf("[*] Module : Query-Based Model Extraction\n");
    printf("[*] ==========================================\n\n");

    // Vérification des arguments
    if (argc != 2) {
        printf("[!] Usage : %s <num_queries>\n", argv[0]);
        printf("[!] Exemple : %s 500\n", argv[0]);
        printf("\n[*] Recommandations :\n");
        printf("    - 100 requêtes  : Extraction minimale (~1%%)\n");
        printf("    - 500 requêtes  : Extraction faible (~5%%)\n");
        printf("    - 5000 requêtes : Extraction significative (~50%%)\n");
        printf("    - 10000+ requêtes : Extraction quasi-complète\n");
        return 1;
    }

    int num_queries = atoi(argv[1]);

    // Validation
    if (num_queries <= 0 || num_queries > MAX_QUERIES) {
        printf("[!] ERREUR : Nombre de requêtes invalide (1-%d)\n", MAX_QUERIES);
        return 1;
    }

    // Initialiser le modèle cible
    TargetModel model = init_target_model();

    // Exécuter l'extraction
    generate_extraction_queries(&model, num_queries);

    // Afficher le rapport
    display_extraction_report(&model);

    // Afficher les défenses
    display_defenses();

    printf("\n[+] Simulation terminée\n");
    return 0;
}
```

**Tests** :

```bash
# Compilation
gcc query_extraction.c -o query_extraction

# Test avec peu de requêtes (extraction minimale)
./query_extraction 100

# Test avec nombre moyen (extraction partielle)
./query_extraction 500

# Test avec beaucoup de requêtes (extraction significative)
./query_extraction 1000
```

**Points clés** :
- Simulation d'extraction par requêtes
- Calcul du progrès d'extraction
- Analyse coût/bénéfice pour l'attaquant
- Défenses recommandées

---

## Exercice 3 : Model Distillation Simulator (Moyen)

**Objectif** : Implémenter un simulateur de "knowledge distillation" où un petit modèle apprend d'un grand modèle via ses outputs.

**Solution** :

```c
/*
 * =============================================================================
 * Model Distillation Simulator
 * =============================================================================
 *
 * Description : Simule la distillation d'un grand modèle vers un petit modèle
 *
 * Compilation :
 *   gcc distillation_sim.c -o distillation_sim -lm
 *
 * Usage :
 *   ./distillation_sim <num_training_samples>
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define MAX_SAMPLES 10000

// Modèle "Teacher" (grand modèle propriétaire)
typedef struct {
    char name[64];
    int parameters_millions;
    float accuracy;  // Précision du modèle (0-1)
} TeacherModel;

// Modèle "Student" (petit modèle de l'attaquant)
typedef struct {
    char name[64];
    int parameters_millions;
    float initial_accuracy;
    float current_accuracy;
    int training_samples;
} StudentModel;

// Dataset d'entraînement (queries + teacher responses)
typedef struct {
    char *queries[MAX_SAMPLES];
    char *responses[MAX_SAMPLES];
    float *confidence_scores[MAX_SAMPLES];
    int size;
} DistillationDataset;

/*
 * Initialise le modèle Teacher (victime)
 */
TeacherModel init_teacher_model() {
    TeacherModel teacher;
    strcpy(teacher.name, "GPT-Enterprise-Pro");
    teacher.parameters_millions = 70000;  // 70B params
    teacher.accuracy = 0.95;

    printf("[*] Modèle Teacher initialisé\n");
    printf("[*] Nom : %s\n", teacher.name);
    printf("[*] Paramètres : %dM\n", teacher.parameters_millions);
    printf("[*] Précision : %.1f%%\n\n", teacher.accuracy * 100);

    return teacher;
}

/*
 * Initialise le modèle Student (attaquant)
 */
StudentModel init_student_model() {
    StudentModel student;
    strcpy(student.name, "MiniLLM-Stolen");
    student.parameters_millions = 7000;  // 7B params (10x plus petit)
    student.initial_accuracy = 0.45;  // Précision initiale faible
    student.current_accuracy = 0.45;
    student.training_samples = 0;

    printf("[*] Modèle Student initialisé\n");
    printf("[*] Nom : %s\n", student.name);
    printf("[*] Paramètres : %dM (10x plus petit que Teacher)\n", student.parameters_millions);
    printf("[*] Précision initiale : %.1f%%\n\n", student.initial_accuracy * 100);

    return student;
}

/*
 * Collecte des données du Teacher pour entraîner le Student
 *
 * teacher : Le modèle Teacher
 * num_samples : Nombre d'échantillons à collecter
 *
 * Retourne le dataset
 */
int collect_training_data(const TeacherModel *teacher, int num_samples) {
    printf("[*] === COLLECTE DES DONNÉES ===\n\n");
    printf("[*] Interrogation du modèle Teacher...\n");
    printf("[*] Nombre d'échantillons : %d\n\n", num_samples);

    // Simuler la collecte (affichage périodique)
    for (int i = 0; i < num_samples; i++) {
        if ((i + 1) % 1000 == 0 || i == 0) {
            printf("[*] Collecté : %d/%d échantillons\n", i + 1, num_samples);
        }
    }

    float cost = num_samples * 0.002;  // $0.002 par requête
    printf("\n[*] Collecte terminée\n");
    printf("[*] Coût total : $%.2f\n", cost);
    printf("[*] Dataset sauvegardé pour distillation\n\n");

    return num_samples;
}

/*
 * Entraîne le Student model sur les outputs du Teacher
 *
 * student : Pointeur vers le modèle Student
 * num_samples : Nombre d'échantillons d'entraînement
 *
 * Retourne la précision finale
 */
float train_student_model(StudentModel *student, int num_samples) {
    printf("[*] === ENTRAÎNEMENT PAR DISTILLATION ===\n\n");
    printf("[*] Début de l'entraînement du Student model...\n");

    student->training_samples = num_samples;

    // Simulation d'entraînement par epochs
    int epochs = 10;
    float accuracy_gain_per_epoch = 0.0;

    printf("\n");

    for (int epoch = 1; epoch <= epochs; epoch++) {
        // Calculer le gain d'accuracy pour cette epoch
        // Plus on a de samples, plus le gain est important
        // Mais avec diminishing returns
        accuracy_gain_per_epoch = (0.05 * sqrt(num_samples / 1000.0)) / epochs;

        student->current_accuracy += accuracy_gain_per_epoch;

        // Limiter à l'accuracy du Teacher (on ne peut pas dépasser)
        if (student->current_accuracy > 0.90) {
            student->current_accuracy = 0.90;  // Max 90% du Teacher (95%)
        }

        printf("[*] Epoch %d/%d - Accuracy: %.2f%%\n",
               epoch, epochs, student->current_accuracy * 100);
    }

    printf("\n[*] Entraînement terminé\n");
    printf("[*] Précision finale : %.2f%%\n\n", student->current_accuracy * 100);

    return student->current_accuracy;
}

/*
 * Compare les performances Teacher vs Student
 */
void compare_models(const TeacherModel *teacher, const StudentModel *student) {
    printf("[*] === COMPARAISON DES MODÈLES ===\n\n");

    printf("[*] %-20s | Teacher | Student\n", "Métrique");
    printf("[*] %s\n", "----------------------------------------------------");
    printf("[*] %-20s | %6dM | %6dM\n", "Paramètres", teacher->parameters_millions, student->parameters_millions);
    printf("[*] %-20s | %6.1f%% | %6.1f%%\n", "Précision", teacher->accuracy * 100, student->current_accuracy * 100);

    float accuracy_ratio = (student->current_accuracy / teacher->accuracy) * 100;
    printf("[*] %-20s | %6s | %6.1f%%\n", "Ratio de performance", "100%", accuracy_ratio);

    float size_ratio = ((float)student->parameters_millions / teacher->parameters_millions) * 100;
    printf("[*] %-20s | %6s | %6.1f%%\n", "Ratio de taille", "100%", size_ratio);

    printf("\n");

    if (accuracy_ratio >= 85.0) {
        printf("[!] *** DISTILLATION TRÈS RÉUSSIE ***\n");
        printf("[!] Le Student model a %.1f%% de la performance du Teacher\n", accuracy_ratio);
        printf("[!] Avec seulement %.1f%% de la taille !\n", size_ratio);
        printf("[!] Le modèle propriétaire a été effectivement volé\n");
    } else if (accuracy_ratio >= 70.0) {
        printf("[!] DISTILLATION RÉUSSIE\n");
        printf("[!] Performance acceptable pour un modèle volé\n");
    } else {
        printf("[*] Distillation partielle\n");
        printf("[*] Plus de données d'entraînement nécessaires\n");
    }
}

/*
 * Calcule le ROI de l'attaque
 */
void calculate_roi(const StudentModel *student) {
    printf("\n[*] === ANALYSE ÉCONOMIQUE (ROI) ===\n\n");

    float cost_data_collection = student->training_samples * 0.002;
    float cost_training = 500.0;  // Coût GPU pour entraînement
    float total_cost = cost_data_collection + cost_training;

    printf("[*] Coûts pour l'attaquant :\n");
    printf("    - Collecte de données : $%.2f\n", cost_data_collection);
    printf("    - Entraînement GPU : $%.2f\n", cost_training);
    printf("    - TOTAL : $%.2f\n\n", total_cost);

    float market_value = 500000.0;  // Valeur du modèle original
    float roi = ((market_value - total_cost) / total_cost) * 100;

    printf("[*] Valeur du modèle original : $%.2f\n", market_value);
    printf("[*] ROI de l'attaque : %.0f%%\n", roi);

    if (roi > 1000) {
        printf("\n[!] L'attaque est EXTRÊMEMENT PROFITABLE\n");
        printf("[!] L'attaquant a volé un modèle de $500k pour $%.2f\n", total_cost);
    }
}

/*
 * Affiche les défenses contre la distillation
 */
void display_defenses() {
    printf("\n[*] === DÉFENSES CONTRE MODEL DISTILLATION ===\n");
    printf("[*] 1. Output Watermarking:\n");
    printf("       - Injecter des patterns uniques dans les outputs\n");
    printf("       - Détecter si un modèle concurrent a été distillé\n");
    printf("[*] 2. Query Complexity Analysis:\n");
    printf("       - Détecter les patterns de queries de distillation\n");
    printf("       - Bloquer les utilisateurs collectant trop de données\n");
    printf("[*] 3. Output Randomization:\n");
    printf("       - Ajouter du bruit calibré aux réponses\n");
    printf("       - Dégrader la qualité de la distillation sans impacter l'UX\n");
    printf("[*] 4. Legal Protection:\n");
    printf("       - Terms of Service interdisant la distillation\n");
    printf("       - Poursuite légale en cas de violation\n");
    printf("[*] 5. Model Fingerprinting:\n");
    printf("       - Créer une signature unique du modèle\n");
    printf("       - Prouver qu'un modèle concurrent est un clone\n");
}

int main(int argc, char *argv[]) {
    // Initialiser le générateur aléatoire
    srand(time(NULL));

    printf("[*] Module : Model Distillation Simulator\n");
    printf("[*] ==========================================\n\n");

    // Vérification des arguments
    if (argc != 2) {
        printf("[!] Usage : %s <num_training_samples>\n", argv[0]);
        printf("[!] Exemple : %s 5000\n", argv[0]);
        printf("\n[*] Recommandations :\n");
        printf("    - 1000 samples  : Distillation minimale (~60%% accuracy)\n");
        printf("    - 5000 samples  : Distillation moyenne (~75%% accuracy)\n");
        printf("    - 10000 samples : Distillation excellente (~85%% accuracy)\n");
        return 1;
    }

    int num_samples = atoi(argv[1]);

    // Validation
    if (num_samples <= 0 || num_samples > MAX_SAMPLES) {
        printf("[!] ERREUR : Nombre d'échantillons invalide (1-%d)\n", MAX_SAMPLES);
        return 1;
    }

    // Initialiser les modèles
    TeacherModel teacher = init_teacher_model();
    StudentModel student = init_student_model();

    // Collecte des données
    collect_training_data(&teacher, num_samples);

    // Entraînement par distillation
    train_student_model(&student, num_samples);

    // Comparaison
    compare_models(&teacher, &student);

    // Analyse économique
    calculate_roi(&student);

    // Défenses
    display_defenses();

    printf("\n[+] Simulation terminée\n");
    return 0;
}
```

**Tests** :

```bash
# Compilation (note le -lm pour math.h)
gcc distillation_sim.c -o distillation_sim -lm

# Test avec peu de samples
./distillation_sim 1000

# Test avec nombre moyen
./distillation_sim 5000

# Test avec beaucoup de samples
./distillation_sim 10000
```

**Critères de réussite** :
- [x] Simulation Teacher-Student
- [x] Calcul de l'amélioration d'accuracy
- [x] Analyse économique (ROI)
- [x] Comparaison des performances

---

## Exercice 4 : Membership Inference Attack (Difficile)

**Objectif** : Implémenter une attaque qui détermine si une donnée spécifique était dans le training set du modèle.

**Solution** :

```c
/*
 * =============================================================================
 * Membership Inference Attack Simulator
 * =============================================================================
 *
 * Description : Détermine si des données étaient dans le training set
 *
 * Compilation :
 *   gcc membership_inference.c -o membership_inference -lm
 *
 * Usage :
 *   ./membership_inference "<text_to_test>"
 *
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define MAX_TEXT_LENGTH 512
#define THRESHOLD_LOSS 1.5  // Loss threshold pour membership

/*
 * Calcule la "perplexity" simulée d'un texte
 * (dans un vrai scénario, ceci viendrait du modèle)
 *
 * text : Le texte à analyser
 * is_training_data : 1 si le texte était dans le training, 0 sinon
 *
 * Retourne la perplexity (plus bas = plus mémorisé)
 */
float calculate_perplexity(const char *text, int is_training_data) {
    float base_perplexity = 0.0;

    // Calculer une perplexity basique basée sur la longueur
    int length = strlen(text);
    base_perplexity = 10.0 + (length / 10.0);

    // Si c'était dans le training set, perplexity beaucoup plus basse
    if (is_training_data) {
        base_perplexity *= 0.3;  // 70% de réduction
    }

    // Ajouter du bruit aléatoire
    float noise = ((float)rand() / RAND_MAX - 0.5) * 2.0;
    base_perplexity += noise;

    return base_perplexity;
}

/*
 * Calcule le loss (négatif log-likelihood) sur le texte
 *
 * text : Le texte à analyser
 * perplexity : La perplexity calculée
 *
 * Retourne le loss
 */
float calculate_loss(const char *text, float perplexity) {
    // Loss = log(perplexity)
    return log(perplexity);
}

/*
 * Effectue le membership inference test
 *
 * text : Le texte à tester
 * is_actually_in_training : La vraie réponse (pour validation)
 *
 * Retourne 1 si détecté comme membre, 0 sinon
 */
int membership_inference_attack(const char *text, int is_actually_in_training) {
    printf("\n[*] === MEMBERSHIP INFERENCE ATTACK ===\n\n");
    printf("[*] Texte à tester :\n");
    printf("    \"%s\"\n\n", text);

    // Étape 1 : Calculer la perplexity
    float perplexity = calculate_perplexity(text, is_actually_in_training);
    printf("[*] Perplexity mesurée : %.2f\n", perplexity);

    // Étape 2 : Calculer le loss
    float loss = calculate_loss(text, perplexity);
    printf("[*] Loss (negative log-likelihood) : %.2f\n", loss);

    // Étape 3 : Comparer au threshold
    printf("[*] Threshold de décision : %.2f\n\n", THRESHOLD_LOSS);

    int predicted_membership = (loss < THRESHOLD_LOSS) ? 1 : 0;

    // Affichage du résultat
    printf("[*] === RÉSULTAT DE L'ATTAQUE ===\n");
    printf("[*] Loss < Threshold ? %s\n", (loss < THRESHOLD_LOSS) ? "OUI" : "NON");
    printf("[*] Prédiction : Le texte %s dans le training set\n",
           predicted_membership ? "ÉTAIT" : "N'ÉTAIT PAS");

    if (is_actually_in_training != -1) {
        printf("[*] Réalité : Le texte %s dans le training set\n",
               is_actually_in_training ? "ÉTAIT" : "N'ÉTAIT PAS");
        printf("[*] Attaque réussie : %s\n",
               (predicted_membership == is_actually_in_training) ? "OUI" : "NON");
    }

    return predicted_membership;
}

/*
 * Test batch de plusieurs textes
 */
void batch_membership_test() {
    printf("\n========================================\n");
    printf("  TEST BATCH : MEMBERSHIP INFERENCE\n");
    printf("========================================\n");

    // Textes de test avec labels
    struct {
        const char *text;
        int in_training;
        const char *description;
    } test_cases[] = {
        {
            "The quick brown fox jumps over the lazy dog",
            1,
            "Phrase très commune (probablement dans training)"
        },
        {
            "import os\nimport sys\nAPI_KEY = 'sk-12345'",
            1,
            "Pattern de code commun avec API key"
        },
        {
            "xKzQ9mPwL3nY8rFvT2hJ4sC7bN6gD1eA5iO0uW",
            0,
            "Chaîne aléatoire unique (pas dans training)"
        },
        {
            "My email is john.doe@example.com and my password is hunter2",
            0,
            "Données personnelles uniques"
        },
        {
            "Paris is the capital of France",
            1,
            "Fait très commun (probablement dans training)"
        }
    };

    int num_tests = 5;
    int correct_predictions = 0;

    for (int i = 0; i < num_tests; i++) {
        printf("\n=== TEST %d/%d ===\n", i + 1, num_tests);
        printf("[*] Description : %s\n", test_cases[i].description);

        int prediction = membership_inference_attack(
            test_cases[i].text,
            test_cases[i].in_training
        );

        if (prediction == test_cases[i].in_training) {
            correct_predictions++;
        }

        printf("\n");
    }

    // Statistiques finales
    printf("\n[*] === STATISTIQUES GLOBALES ===\n");
    printf("[*] Tests réussis : %d/%d\n", correct_predictions, num_tests);
    printf("[*] Précision : %.1f%%\n", (float)correct_predictions / num_tests * 100);

    if (correct_predictions >= 4) {
        printf("\n[!] Attaque très efficace !\n");
        printf("[!] Le modèle leak des informations sur son training set\n");
    }
}

/*
 * Affiche les implications de sécurité
 */
void display_security_implications() {
    printf("\n[*] === IMPLICATIONS DE SÉCURITÉ ===\n");
    printf("[*] Si l'attaque réussit, l'attaquant peut :\n");
    printf("    1. Détecter si des données privées étaient dans le training\n");
    printf("    2. Confirmer des fuites de données confidentielles\n");
    printf("    3. Prouver l'utilisation non-autorisée de données\n");
    printf("    4. Extraire progressivement des informations sensibles\n");
    printf("\n[*] Exemples concrets :\n");
    printf("    - Vérifier si un email spécifique était dans le dataset\n");
    printf("    - Détecter si du code propriétaire a été utilisé\n");
    printf("    - Confirmer l'usage de données médicales sans consent\n");
}

/*
 * Affiche les défenses
 */
void display_defenses() {
    printf("\n[*] === DÉFENSES CONTRE MEMBERSHIP INFERENCE ===\n");
    printf("[*] 1. Differential Privacy:\n");
    printf("       - Ajouter du bruit pendant l'entraînement (DP-SGD)\n");
    printf("       - Garantir que le modèle ne mémorise pas d'exemples individuels\n");
    printf("[*] 2. Regularization:\n");
    printf("       - Dropout, weight decay pour éviter l'overfitting\n");
    printf("       - Limite la mémorisation exacte des données\n");
    printf("[*] 3. Data Sanitization:\n");
    printf("       - Retirer les données sensibles du training set\n");
    printf("       - Anonymiser les données avant entraînement\n");
    printf("[*] 4. Confidence Calibration:\n");
    printf("       - Ne pas retourner les scores de confiance bruts\n");
    printf("       - Limiter l'information exposée via l'API\n");
}

int main(int argc, char *argv[]) {
    // Initialiser le générateur aléatoire
    srand(time(NULL));

    printf("[*] Module : Membership Inference Attack\n");
    printf("[*] ==========================================\n");

    // Mode batch ou mode single test
    if (argc == 1) {
        // Mode batch : tester plusieurs exemples
        batch_membership_test();
    } else if (argc == 2) {
        // Mode single : tester un texte spécifique
        const char *text = argv[1];

        if (strlen(text) > MAX_TEXT_LENGTH) {
            printf("[!] ERREUR : Texte trop long (max %d caractères)\n", MAX_TEXT_LENGTH);
            return 1;
        }

        // On ne connaît pas la vraie réponse, donc -1
        membership_inference_attack(text, -1);
    } else {
        printf("\n[!] Usage :\n");
        printf("    %s                    # Mode batch (tests prédéfinis)\n", argv[0]);
        printf("    %s \"texte\"            # Test d'un texte spécifique\n", argv[0]);
        return 1;
    }

    // Affichage des implications et défenses
    display_security_implications();
    display_defenses();

    printf("\n[+] Simulation terminée\n");
    return 0;
}
```

**Tests** :

```bash
# Compilation
gcc membership_inference.c -o membership_inference -lm

# Mode batch (tests prédéfinis)
./membership_inference

# Test d'un texte spécifique
./membership_inference "The capital of France is Paris"

# Test d'un texte unique (probablement pas dans training)
./membership_inference "MySecretPassword123XYZ"
```

**Concepts avancés** :
- Perplexity et loss calculation
- Threshold-based classification
- Batch testing avec statistiques
- Analyse de sécurité et privacy

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :

- [x] Expliquer les différentes techniques d'extraction de modèles
- [x] Comprendre la distillation (Teacher-Student learning)
- [x] Implémenter des attaques membership inference
- [x] Calculer le ROI d'une attaque d'extraction
- [x] Identifier les défenses contre l'extraction de modèles
- [x] Analyser les implications économiques du vol de modèles

**Module suivant** : [A22 - AI Red Team Prep](../A22_ai_red_team_prep/)

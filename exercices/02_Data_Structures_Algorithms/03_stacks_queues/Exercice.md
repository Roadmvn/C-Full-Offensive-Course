# EXERCICE : STACKS & QUEUES


### OBJECTIF :
Implémenter des piles et files pour résoudre des problèmes réels.

═══════════════════════════════════════════════════════════════

### PARTIE 1 : VÉRIFICATEUR DE SYNTAXE (STACK)
═══════════════════════════════════════════════════════════════

Créer un programme qui vérifie si les parenthèses, crochets et accolades
sont bien équilibrés dans une expression.

FONCTIONS À IMPLÉMENTER :

1. is_balanced(char *expr)
   - Vérifie si les délimiteurs sont équilibrés
   - Retourne 1 (vrai) ou 0 (faux)
   - Doit gérer : ( ) [ ] { }


### EXEMPLES :
"(a + b)" → VALIDE
"[(a + b) * c]" → VALIDE
"{[()]}" → VALIDE
"((a + b)" → INVALIDE (pas de fermeture)
"(a + b]" → INVALIDE (mauvais type)
"((a + b)))" → INVALIDE (trop de fermetures)

2. check_html_tags(char *html)
   - Vérifie si les balises HTML sont bien fermées
   - Exemple : "<div><p>Text</p></div>" → VALIDE
   - Exemple : "<div><p>Text</div></p>" → INVALIDE

═══════════════════════════════════════════════════════════════

### PARTIE 2 : SYSTÈME D'IMPRESSION (QUEUE)
═══════════════════════════════════════════════════════════════

Simuler une file d'attente d'impression avec priorités.


### STRUCTURE :

typedef struct PrintJob {
    char document[100];
    char owner[50];
    int pages;
    int priority;  // 1=faible, 2=normal, 3=urgent
} PrintJob;

FONCTIONS À IMPLÉMENTER :

1. add_print_job(queue, job)
   - Ajoute un travail d'impression à la file

2. process_next_job(queue)
   - Traite le prochain travail
   - Affiche "Impression de [doc] pour [owner] - [pages] pages"

3. cancel_job(queue, document_name)
   - Annule un travail spécifique

4. print_queue_status(queue)
   - Affiche tous les travaux en attente

5. add_priority_job(queue, job)
   - Ajoute un travail urgent au début de la file

═══════════════════════════════════════════════════════════════

### PARTIE 3 : ÉVALUATEUR D'EXPRESSIONS (STACK)
═══════════════════════════════════════════════════════════════

Évaluer des expressions mathématiques en notation postfixée (RPN).

RAPPEL : Notation Postfixée (Reverse Polish Notation)
- Infix : 3 + 4
- Postfix : 3 4 +

- Infix : (3 + 4) * 2
- Postfix : 3 4 + 2 *

FONCTION À IMPLÉMENTER :

1. eval_postfix(char *expr)
   - Évalue une expression postfixée
   - Retourne le résultat
   - Supporte : + - * / %


### EXEMPLES :
"3 4 +" → 7
"5 2 * 3 +" → 13
"15 7 1 1 + - / 3 * 2 1 1 + + -" → 5


### ALGORITHME :
- Pour chaque token :
  - Si c'est un nombre : empiler
  - Si c'est un opérateur :
    - Dépiler deux nombres
    - Calculer le résultat
    - Empiler le résultat

═══════════════════════════════════════════════════════════════

### PARTIE 4 : HISTORIQUE DE NAVIGATION (DOUBLE STACK)
═══════════════════════════════════════════════════════════════

Simuler l'historique d'un navigateur web avec les boutons
"Précédent" et "Suivant".

FONCTIONS À IMPLÉMENTER :

1. visit_page(history, url)
   - Visite une nouvelle page
   - Efface l'historique "suivant"

2. go_back(history)
   - Retourne à la page précédente
   - Retourne l'URL

3. go_forward(history)
   - Avance à la page suivante (si existe)
   - Retourne l'URL

4. print_history(history)
   - Affiche l'historique complet


### STRUCTURE :
- Stack "back" : Pages précédentes
- Stack "forward" : Pages suivantes
- current_page : Page actuelle

═══════════════════════════════════════════════════════════════

### PARTIE 5 : BUFFER CIRCULAIRE (QUEUE)
═══════════════════════════════════════════════════════════════

Implémenter un buffer circulaire pour un système de logs.

FONCTIONS À IMPLÉMENTER :

1. init_log_buffer(size)
   - Crée un buffer de taille fixe

2. add_log(buffer, message)
   - Ajoute un log
   - Si plein, écrase le plus ancien (circular overwrite)

3. get_all_logs(buffer)
   - Retourne tous les logs du plus ancien au plus récent

4. clear_logs(buffer)
   - Vide le buffer

═══════════════════════════════════════════════════════════════

### EXERCICES BONUS
═══════════════════════════════════════════════════════════════

1. infix_to_postfix(char *infix)
   - Convertit une expression infixée en postfixée
   - "3 + 4" → "3 4 +"

2. reverse_string_with_stack(char *str)
   - Inverse une chaîne avec une pile

3. check_palindrome_with_queue(char *str)
   - Vérifie si c'est un palindrome avec une file

4. josephus_problem(n, k)
   - Résout le problème de Josèphe avec une file circulaire

5. implement_undo_redo(text_editor)
   - Implémente Undo/Redo pour un éditeur de texte


### CONTRAINTES :
- Gérer les cas limites (vides, pleins, etc.)
- Pas de memory leaks
- Valider toutes les entrées
- Afficher des messages d'erreur clairs


### TESTS :
- Tester avec des cas valides et invalides
- Tester les limites (buffer plein, etc.)
- Vérifier la mémoire avec valgrind

FICHIERS À CRÉER :
- main.c : Implémentation complète
- Compilation : gcc main.c -o stacks_queues -Wall -Wextra



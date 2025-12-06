# Module 45 : Structures de Données Avancées

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Implémenter des listes chaînées (linked lists)
- Créer des arbres binaires et arbres de recherche
- Développer des tables de hachage (hash tables)
- Utiliser des piles (stacks) et files (queues)
- Applications en Red Team (rootkits, caches d'exploits)

## 📚 Théorie

### C'est quoi une structure de données ?

Une **structure de données** est une façon d'organiser et de stocker des données pour permettre un accès et des modifications efficaces. Contrairement aux tableaux simples, ces structures offrent des propriétés spécifiques.

### Types de structures de données

1. **Listes chaînées** : Éléments liés par des pointeurs
2. **Arbres binaires** : Structure hiérarchique
3. **Tables de hachage** : Accès rapide par clé
4. **Piles** : LIFO (Last In First Out)
5. **Files** : FIFO (First In First Out)

### Pourquoi en Red Team ?

1. **Rootkits** : Cacher des processus/fichiers dans des structures
2. **Cache d'exploits** : Stocker des payloads efficacement
3. **Évasion** : Structures obfusquées difficiles à analyser
4. **Performance** : Accès rapide aux données critiques

## 🔍 Visualisation

### Liste chaînée simple

```
┌─────────────────────────────────────────────────────┐
│            LINKED LIST (Liste Chaînée)              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  HEAD                                               │
│   │                                                 │
│   ▼                                                 │
│  ┌────┬────┐    ┌────┬────┐    ┌────┬────┐         │
│  │ 10 │  ──┼───►│ 20 │  ──┼───►│ 30 │NULL│         │
│  └────┴────┘    └────┴────┘    └────┴────┘         │
│   Node 1         Node 2         Node 3              │
│                                                     │
│  Insertion en tête:                                 │
│                                                     │
│  ┌────┬────┐                                        │
│  │  5 │  ──┼───► (ancien HEAD)                     │
│  └────┴────┘                                        │
│   Nouveau HEAD                                      │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Arbre binaire de recherche

```
┌─────────────────────────────────────────────────────┐
│        BINARY SEARCH TREE (Arbre Binaire)          │
├─────────────────────────────────────────────────────┤
│                                                     │
│                      50                             │
│                    /    \                           │
│                   /      \                          │
│                 30        70                        │
│                /  \      /  \                       │
│               20  40    60  80                      │
│              /                 \                    │
│             10                  90                  │
│                                                     │
│  Propriété: Gauche < Parent < Droite               │
│                                                     │
│  Recherche de 60:                                   │
│    50 → 70 (droite) → 60 (gauche) → TROUVÉ!        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Table de hachage

```
┌─────────────────────────────────────────────────────┐
│          HASH TABLE (Table de Hachage)             │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Hash Function: h(key) = key % 10                   │
│                                                     │
│  Index  │  Bucket                                   │
│  ──────┼────────────────────────                   │
│    0   │  → NULL                                    │
│    1   │  → [21:Alice] → NULL                       │
│    2   │  → [32:Bob] → [52:Eve] → NULL              │
│    3   │  → [43:Charlie] → NULL                     │
│    4   │  → NULL                                    │
│    5   │  → [15:David] → NULL                       │
│    6   │  → NULL                                    │
│    7   │  → NULL                                    │
│    8   │  → [18:Frank] → NULL                       │
│    9   │  → NULL                                    │
│                                                     │
│  Collision: Chainages (chaining)                    │
│  32 % 10 = 2                                        │
│  52 % 10 = 2  ← Même bucket!                        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Pile vs File

```
┌─────────────────────────────────────────────────────┐
│              STACK (Pile) - LIFO                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Push(3)  Push(7)  Push(2)    Pop()                │
│                                                     │
│    │        │        │         │                    │
│    ▼        ▼        ▼         ▼                    │
│           ┌───┐    ┌───┐                            │
│           │ 7 │    │ 2 │    ┌───┐                   │
│  ┌───┐   ├───┤    ├───┤    │ 7 │                   │
│  │ 3 │   │ 3 │    │ 7 │    ├───┤                   │
│  └───┘   └───┘    ├───┤    │ 3 │                   │
│                   │ 3 │    └───┘                   │
│                   └───┘                             │
│                                                     │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│              QUEUE (File) - FIFO                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Enqueue(3)  Enqueue(7)  Enqueue(2)  Dequeue()     │
│                                                     │
│  Front                              Rear            │
│    │                                  │             │
│    ▼                                  ▼             │
│  ┌───┐      ┌───┬───┐      ┌───┬───┬───┐           │
│  │ 3 │      │ 3 │ 7 │      │ 3 │ 7 │ 2 │           │
│  └───┘      └───┴───┘      └───┴───┴───┘           │
│                                                     │
│              Dequeue() → 3                          │
│                                                     │
│              ┌───┬───┐                              │
│              │ 7 │ 2 │                              │
│              └───┴───┘                              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Liste chaînée simple

```c
#include <stdio.h>
#include <stdlib.h>

// Structure de noeud
typedef struct Node {
    int data;
    struct Node *next;
} Node;

// Créer un nouveau noeud
Node* create_node(int data) {
    Node *new_node = (Node*)malloc(sizeof(Node));
    if (new_node == NULL) {
        printf("Erreur allocation memoire\n");
        return NULL;
    }
    new_node->data = data;
    new_node->next = NULL;
    return new_node;
}

// Insérer en tête
void insert_head(Node **head, int data) {
    Node *new_node = create_node(data);
    new_node->next = *head;
    *head = new_node;
}

// Insérer en queue
void insert_tail(Node **head, int data) {
    Node *new_node = create_node(data);

    if (*head == NULL) {
        *head = new_node;
        return;
    }

    Node *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = new_node;
}

// Supprimer un noeud
void delete_node(Node **head, int data) {
    if (*head == NULL) return;

    // Si c'est la tête
    if ((*head)->data == data) {
        Node *temp = *head;
        *head = (*head)->next;
        free(temp);
        return;
    }

    // Chercher le noeud
    Node *current = *head;
    while (current->next != NULL && current->next->data != data) {
        current = current->next;
    }

    if (current->next != NULL) {
        Node *temp = current->next;
        current->next = current->next->next;
        free(temp);
    }
}

// Afficher la liste
void print_list(Node *head) {
    Node *current = head;
    printf("Liste: ");
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

// Libérer toute la liste
void free_list(Node **head) {
    Node *current = *head;
    while (current != NULL) {
        Node *temp = current;
        current = current->next;
        free(temp);
    }
    *head = NULL;
}

int main() {
    Node *head = NULL;

    printf("=== Operations sur liste chainee ===\n\n");

    // Insertions
    insert_head(&head, 10);
    insert_head(&head, 20);
    insert_tail(&head, 30);
    insert_tail(&head, 40);

    print_list(head);

    // Suppression
    delete_node(&head, 20);
    printf("Apres suppression de 20:\n");
    print_list(head);

    // Nettoyage
    free_list(&head);

    return 0;
}
```

### Exemple 2 : Arbre binaire de recherche

```c
#include <stdio.h>
#include <stdlib.h>

// Structure de noeud d'arbre
typedef struct TreeNode {
    int data;
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;

// Créer un nouveau noeud
TreeNode* create_tree_node(int data) {
    TreeNode *node = (TreeNode*)malloc(sizeof(TreeNode));
    node->data = data;
    node->left = NULL;
    node->right = NULL;
    return node;
}

// Insérer dans l'arbre
TreeNode* insert(TreeNode *root, int data) {
    if (root == NULL) {
        return create_tree_node(data);
    }

    if (data < root->data) {
        root->left = insert(root->left, data);
    } else if (data > root->data) {
        root->right = insert(root->right, data);
    }

    return root;
}

// Rechercher une valeur
TreeNode* search(TreeNode *root, int data) {
    if (root == NULL || root->data == data) {
        return root;
    }

    if (data < root->data) {
        return search(root->left, data);
    }

    return search(root->right, data);
}

// Trouver le minimum
TreeNode* find_min(TreeNode *root) {
    while (root && root->left != NULL) {
        root = root->left;
    }
    return root;
}

// Supprimer un noeud
TreeNode* delete_node_tree(TreeNode *root, int data) {
    if (root == NULL) return NULL;

    if (data < root->data) {
        root->left = delete_node_tree(root->left, data);
    } else if (data > root->data) {
        root->right = delete_node_tree(root->right, data);
    } else {
        // Noeud trouvé

        // Cas 1: Pas d'enfant ou un seul
        if (root->left == NULL) {
            TreeNode *temp = root->right;
            free(root);
            return temp;
        } else if (root->right == NULL) {
            TreeNode *temp = root->left;
            free(root);
            return temp;
        }

        // Cas 2: Deux enfants
        TreeNode *temp = find_min(root->right);
        root->data = temp->data;
        root->right = delete_node_tree(root->right, temp->data);
    }

    return root;
}

// Parcours in-order (gauche, racine, droite)
void inorder(TreeNode *root) {
    if (root != NULL) {
        inorder(root->left);
        printf("%d ", root->data);
        inorder(root->right);
    }
}

// Parcours pre-order (racine, gauche, droite)
void preorder(TreeNode *root) {
    if (root != NULL) {
        printf("%d ", root->data);
        preorder(root->left);
        preorder(root->right);
    }
}

// Parcours post-order (gauche, droite, racine)
void postorder(TreeNode *root) {
    if (root != NULL) {
        postorder(root->left);
        postorder(root->right);
        printf("%d ", root->data);
    }
}

int main() {
    TreeNode *root = NULL;

    printf("=== Arbre Binaire de Recherche ===\n\n");

    // Insertions
    root = insert(root, 50);
    insert(root, 30);
    insert(root, 70);
    insert(root, 20);
    insert(root, 40);
    insert(root, 60);
    insert(root, 80);

    printf("Parcours in-order: ");
    inorder(root);
    printf("\n");

    printf("Parcours pre-order: ");
    preorder(root);
    printf("\n");

    printf("Parcours post-order: ");
    postorder(root);
    printf("\n\n");

    // Recherche
    int search_val = 40;
    TreeNode *found = search(root, search_val);
    if (found) {
        printf("Valeur %d trouvee!\n", search_val);
    } else {
        printf("Valeur %d non trouvee!\n", search_val);
    }

    // Suppression
    printf("\nSuppression de 30...\n");
    root = delete_node_tree(root, 30);

    printf("Parcours in-order apres suppression: ");
    inorder(root);
    printf("\n");

    return 0;
}
```

### Exemple 3 : Table de hachage

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 10

// Structure pour un élément
typedef struct HashNode {
    char *key;
    int value;
    struct HashNode *next;
} HashNode;

// Structure pour la table de hachage
typedef struct {
    HashNode *buckets[TABLE_SIZE];
} HashTable;

// Fonction de hachage simple
unsigned int hash(const char *key) {
    unsigned int hash_value = 0;
    while (*key) {
        hash_value = (hash_value * 31) + *key;
        key++;
    }
    return hash_value % TABLE_SIZE;
}

// Initialiser la table
HashTable* create_table() {
    HashTable *table = (HashTable*)malloc(sizeof(HashTable));
    for (int i = 0; i < TABLE_SIZE; i++) {
        table->buckets[i] = NULL;
    }
    return table;
}

// Insérer un élément
void insert(HashTable *table, const char *key, int value) {
    unsigned int index = hash(key);

    // Créer un nouveau noeud
    HashNode *new_node = (HashNode*)malloc(sizeof(HashNode));
    new_node->key = strdup(key);
    new_node->value = value;
    new_node->next = NULL;

    // Insérer en tête de la liste chaînée
    if (table->buckets[index] == NULL) {
        table->buckets[index] = new_node;
    } else {
        // Vérifier si la clé existe déjà
        HashNode *current = table->buckets[index];
        while (current != NULL) {
            if (strcmp(current->key, key) == 0) {
                // Mise à jour
                current->value = value;
                free(new_node->key);
                free(new_node);
                return;
            }
            if (current->next == NULL) break;
            current = current->next;
        }
        // Insertion en fin
        current->next = new_node;
    }
}

// Rechercher un élément
int search(HashTable *table, const char *key, int *value) {
    unsigned int index = hash(key);
    HashNode *current = table->buckets[index];

    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            *value = current->value;
            return 1;  // Trouvé
        }
        current = current->next;
    }

    return 0;  // Non trouvé
}

// Supprimer un élément
void delete_key(HashTable *table, const char *key) {
    unsigned int index = hash(key);
    HashNode *current = table->buckets[index];
    HashNode *prev = NULL;

    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            if (prev == NULL) {
                // Supprimer la tête
                table->buckets[index] = current->next;
            } else {
                prev->next = current->next;
            }
            free(current->key);
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

// Afficher la table
void print_table(HashTable *table) {
    printf("\n=== Hash Table ===\n");
    for (int i = 0; i < TABLE_SIZE; i++) {
        printf("Bucket %d: ", i);
        HashNode *current = table->buckets[i];
        while (current != NULL) {
            printf("[%s:%d] -> ", current->key, current->value);
            current = current->next;
        }
        printf("NULL\n");
    }
}

int main() {
    HashTable *table = create_table();

    printf("=== Table de Hachage ===\n");

    // Insertions
    insert(table, "Alice", 25);
    insert(table, "Bob", 30);
    insert(table, "Charlie", 35);
    insert(table, "David", 28);

    print_table(table);

    // Recherche
    int value;
    if (search(table, "Bob", &value)) {
        printf("\nBob: %d ans\n", value);
    }

    // Suppression
    printf("\nSuppression de Charlie...\n");
    delete_key(table, "Charlie");

    print_table(table);

    return 0;
}
```

### Exemple 4 : Pile (Stack)

```c
#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE 100

// Structure de pile
typedef struct {
    int items[MAX_SIZE];
    int top;
} Stack;

// Initialiser la pile
void init_stack(Stack *s) {
    s->top = -1;
}

// Vérifier si vide
int is_empty(Stack *s) {
    return s->top == -1;
}

// Vérifier si pleine
int is_full(Stack *s) {
    return s->top == MAX_SIZE - 1;
}

// Empiler
void push(Stack *s, int value) {
    if (is_full(s)) {
        printf("Erreur: pile pleine\n");
        return;
    }
    s->items[++s->top] = value;
    printf("Empile: %d\n", value);
}

// Dépiler
int pop(Stack *s) {
    if (is_empty(s)) {
        printf("Erreur: pile vide\n");
        return -1;
    }
    return s->items[s->top--];
}

// Voir le sommet
int peek(Stack *s) {
    if (is_empty(s)) {
        printf("Erreur: pile vide\n");
        return -1;
    }
    return s->items[s->top];
}

// Afficher la pile
void print_stack(Stack *s) {
    if (is_empty(s)) {
        printf("Pile vide\n");
        return;
    }

    printf("Pile (sommet en haut):\n");
    for (int i = s->top; i >= 0; i--) {
        printf("  %d\n", s->items[i]);
    }
}

int main() {
    Stack stack;
    init_stack(&stack);

    printf("=== Pile (Stack) ===\n\n");

    push(&stack, 10);
    push(&stack, 20);
    push(&stack, 30);
    push(&stack, 40);

    printf("\n");
    print_stack(&stack);

    printf("\nDepile: %d\n", pop(&stack));
    printf("Depile: %d\n", pop(&stack));

    printf("\nSommet: %d\n", peek(&stack));

    printf("\n");
    print_stack(&stack);

    return 0;
}
```

### Exemple 5 : File (Queue)

```c
#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE 100

// Structure de file
typedef struct {
    int items[MAX_SIZE];
    int front;
    int rear;
    int size;
} Queue;

// Initialiser la file
void init_queue(Queue *q) {
    q->front = 0;
    q->rear = -1;
    q->size = 0;
}

// Vérifier si vide
int is_queue_empty(Queue *q) {
    return q->size == 0;
}

// Vérifier si pleine
int is_queue_full(Queue *q) {
    return q->size == MAX_SIZE;
}

// Enfiler
void enqueue(Queue *q, int value) {
    if (is_queue_full(q)) {
        printf("Erreur: file pleine\n");
        return;
    }

    q->rear = (q->rear + 1) % MAX_SIZE;
    q->items[q->rear] = value;
    q->size++;

    printf("Enfile: %d\n", value);
}

// Défiler
int dequeue(Queue *q) {
    if (is_queue_empty(q)) {
        printf("Erreur: file vide\n");
        return -1;
    }

    int value = q->items[q->front];
    q->front = (q->front + 1) % MAX_SIZE;
    q->size--;

    return value;
}

// Voir le premier élément
int peek_queue(Queue *q) {
    if (is_queue_empty(q)) {
        printf("Erreur: file vide\n");
        return -1;
    }
    return q->items[q->front];
}

// Afficher la file
void print_queue(Queue *q) {
    if (is_queue_empty(q)) {
        printf("File vide\n");
        return;
    }

    printf("File (avant -> arriere): ");
    int i = q->front;
    for (int count = 0; count < q->size; count++) {
        printf("%d ", q->items[i]);
        i = (i + 1) % MAX_SIZE;
    }
    printf("\n");
}

int main() {
    Queue queue;
    init_queue(&queue);

    printf("=== File (Queue) ===\n\n");

    enqueue(&queue, 10);
    enqueue(&queue, 20);
    enqueue(&queue, 30);
    enqueue(&queue, 40);

    printf("\n");
    print_queue(&queue);

    printf("\nDefile: %d\n", dequeue(&queue));
    printf("Defile: %d\n", dequeue(&queue));

    printf("\nPremier element: %d\n", peek_queue(&queue));

    printf("\n");
    print_queue(&queue);

    return 0;
}
```

## 🎯 Application Red Team

### 1. Rootkit - Liste chaînée de processus cachés

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Structure pour processus caché
typedef struct HiddenProcess {
    int pid;
    char name[256];
    struct HiddenProcess *next;
} HiddenProcess;

HiddenProcess *hidden_list = NULL;

// Cacher un processus
void hide_process(int pid, const char *name) {
    HiddenProcess *new = (HiddenProcess*)malloc(sizeof(HiddenProcess));
    new->pid = pid;
    strncpy(new->name, name, sizeof(new->name) - 1);
    new->next = hidden_list;
    hidden_list = new;

    printf("[ROOTKIT] Process hidden: PID %d (%s)\n", pid, name);
}

// Vérifier si un processus est caché
int is_hidden(int pid) {
    HiddenProcess *current = hidden_list;
    while (current != NULL) {
        if (current->pid == pid) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}

// Hooker la fonction de listage des processus
void list_processes() {
    // Simulation de processus
    int processes[] = {1, 100, 1234, 5678, 9999};
    char *names[] = {"init", "sshd", "malware", "apache", "backdoor"};

    printf("\n=== Liste des processus (filtree par rootkit) ===\n");

    for (int i = 0; i < 5; i++) {
        if (!is_hidden(processes[i])) {
            printf("PID: %d - %s\n", processes[i], names[i]);
        }
    }
}

int main() {
    printf("=== Rootkit - Masquage de processus ===\n");

    // Cacher des processus malveillants
    hide_process(1234, "malware");
    hide_process(9999, "backdoor");

    // Lister les processus (filtrés)
    list_processes();

    return 0;
}
```

### 2. Cache d'exploits avec table de hachage

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_SIZE 50

typedef struct ExploitNode {
    char *vulnerability;
    char *payload;
    int success_rate;
    struct ExploitNode *next;
} ExploitNode;

typedef struct {
    ExploitNode *cache[CACHE_SIZE];
} ExploitCache;

unsigned int exploit_hash(const char *vuln) {
    unsigned int hash = 0;
    while (*vuln) {
        hash = (hash * 33) + *vuln;
        vuln++;
    }
    return hash % CACHE_SIZE;
}

ExploitCache* create_exploit_cache() {
    ExploitCache *cache = (ExploitCache*)malloc(sizeof(ExploitCache));
    for (int i = 0; i < CACHE_SIZE; i++) {
        cache->cache[i] = NULL;
    }
    return cache;
}

void cache_exploit(ExploitCache *cache, const char *vuln,
                   const char *payload, int rate) {
    unsigned int index = exploit_hash(vuln);

    ExploitNode *node = (ExploitNode*)malloc(sizeof(ExploitNode));
    node->vulnerability = strdup(vuln);
    node->payload = strdup(payload);
    node->success_rate = rate;
    node->next = cache->cache[index];
    cache->cache[index] = node;

    printf("[CACHE] Exploit cached: %s (success: %d%%)\n", vuln, rate);
}

int get_exploit(ExploitCache *cache, const char *vuln, char **payload) {
    unsigned int index = exploit_hash(vuln);
    ExploitNode *current = cache->cache[index];

    while (current != NULL) {
        if (strcmp(current->vulnerability, vuln) == 0) {
            *payload = current->payload;
            return current->success_rate;
        }
        current = current->next;
    }

    return -1;
}

int main() {
    ExploitCache *cache = create_exploit_cache();

    printf("=== Cache d'exploits ===\n\n");

    // Cacher des exploits
    cache_exploit(cache, "CVE-2021-44228", "log4shell_payload", 95);
    cache_exploit(cache, "CVE-2017-0144", "eternalblue_payload", 85);
    cache_exploit(cache, "CVE-2014-0160", "heartbleed_payload", 75);

    // Récupérer un exploit
    printf("\n=== Attaque en cours ===\n");
    char *payload;
    int rate = get_exploit(cache, "CVE-2021-44228", &payload);

    if (rate >= 0) {
        printf("Exploit found!\n");
        printf("Vulnerability: CVE-2021-44228\n");
        printf("Payload: %s\n", payload);
        printf("Success rate: %d%%\n", rate);
    }

    return 0;
}
```

### 3. Arbre de shellcodes polymorphes

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ShellcodeNode {
    char *variant;
    int evasion_score;
    struct ShellcodeNode *left;
    struct ShellcodeNode *right;
} ShellcodeNode;

ShellcodeNode* create_shellcode_node(const char *variant, int score) {
    ShellcodeNode *node = (ShellcodeNode*)malloc(sizeof(ShellcodeNode));
    node->variant = strdup(variant);
    node->evasion_score = score;
    node->left = NULL;
    node->right = NULL;
    return node;
}

ShellcodeNode* insert_shellcode(ShellcodeNode *root,
                                 const char *variant, int score) {
    if (root == NULL) {
        return create_shellcode_node(variant, score);
    }

    if (score < root->evasion_score) {
        root->left = insert_shellcode(root->left, variant, score);
    } else {
        root->right = insert_shellcode(root->right, variant, score);
    }

    return root;
}

// Trouver le meilleur shellcode (score le plus élevé)
ShellcodeNode* find_best_shellcode(ShellcodeNode *root) {
    while (root && root->right != NULL) {
        root = root->right;
    }
    return root;
}

void inorder_shellcodes(ShellcodeNode *root) {
    if (root != NULL) {
        inorder_shellcodes(root->left);
        printf("  Variant: %s (Evasion: %d)\n",
               root->variant, root->evasion_score);
        inorder_shellcodes(root->right);
    }
}

int main() {
    ShellcodeNode *root = NULL;

    printf("=== Arbre de Shellcodes Polymorphes ===\n\n");

    // Insérer différentes variantes
    root = insert_shellcode(root, "xor_encoded_v1", 50);
    insert_shellcode(root, "base64_encoded", 30);
    insert_shellcode(root, "polymorphic_v2", 70);
    insert_shellcode(root, "aes_encrypted", 90);
    insert_shellcode(root, "metamorphic", 85);

    printf("Shellcodes disponibles (tri par score):\n");
    inorder_shellcodes(root);

    // Sélectionner le meilleur pour l'attaque
    ShellcodeNode *best = find_best_shellcode(root);
    printf("\n[ATTACK] Using best shellcode:\n");
    printf("  Variant: %s\n", best->variant);
    printf("  Evasion score: %d\n", best->evasion_score);

    return 0;
}
```

## 📝 Points clés à retenir

1. **Liste chaînée** : Structure dynamique, insertion/suppression rapides
2. **Arbre binaire** : Recherche efficace en O(log n) si équilibré
3. **Table de hachage** : Accès en O(1) en moyenne, gestion des collisions
4. **Pile (LIFO)** : Utile pour récursion, historique
5. **File (FIFO)** : Utile pour files d'attente, buffers

### Complexités à connaître

```
Opération          Liste    Arbre BST    Hash Table    Pile    File
─────────────────────────────────────────────────────────────────────
Insertion          O(1)     O(log n)     O(1)          O(1)    O(1)
Suppression        O(n)     O(log n)     O(1)          O(1)    O(1)
Recherche          O(n)     O(log n)     O(1)          O(n)    O(n)
Accès              O(n)     O(log n)     O(1)          O(1)    O(1)
```

### Choix de structure

- **Liste chaînée** : Taille inconnue, insertions/suppressions fréquentes
- **Arbre** : Données ordonnées, recherches fréquentes
- **Hash table** : Accès rapide par clé unique
- **Pile** : LIFO, gestion d'états, parsers
- **File** : FIFO, buffers, ordonnancement

## ➡️ Prochaine étape

Maintenant que tu maîtrises les structures de données avancées, tu es prêt pour le **Module 48 : Sockets et Programmation Réseau**, où tu apprendras à créer des communications réseau pour les C2, backdoors et exfiltration de données.

### Ce que tu as appris
- Implémenter des listes chaînées
- Créer des arbres binaires de recherche
- Développer des tables de hachage
- Utiliser des piles et files
- Applications rootkit et cache d'exploits

### Ce qui t'attend
- Programmation réseau avec sockets
- Protocoles TCP/UDP
- Serveurs et clients
- Communication C2
- Exfiltration de données

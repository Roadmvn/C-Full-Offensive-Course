# Module 21 : Structures de Données en C

## Objectifs

À la fin de ce module, tu seras capable de :
- Implémenter une liste chaînée (linked list)
- Créer et manipuler des piles (stacks) et files (queues)
- Comprendre les arbres binaires et tables de hash
- Appliquer ces structures dans un contexte offensif

---

## 1. Pourquoi les Structures de Données ?

### Le Problème des Tableaux

```c
// PROBLÈME 1 : Taille fixe
int arr[100];  // Toujours 100 éléments, même si on en utilise 3

// PROBLÈME 2 : Insertion coûteuse
// Pour insérer au milieu, il faut décaler tous les éléments
// O(n) opérations !

// PROBLÈME 3 : Suppression coûteuse
// Même problème : décalage nécessaire
```

### La Solution : Structures Dynamiques

```
TABLEAU vs LISTE CHAÎNÉE :

TABLEAU :
┌───┬───┬───┬───┬───┐
│ A │ B │ C │ D │ E │  Mémoire CONTIGUË
└───┴───┴───┴───┴───┘
  0   1   2   3   4

LISTE CHAÎNÉE :
┌───┬───┐    ┌───┬───┐    ┌───┬───┐
│ A │ ●─┼───→│ B │ ●─┼───→│ C │ ∅ │
└───┴───┘    └───┴───┘    └───┴───┘
  data next    data next    data next

Chaque nœud pointe vers le suivant
Mémoire NON contiguë
```

---

## 2. Liste Chaînée (Linked List)

### 2.1 Structure d'un Nœud

```c
// Nœud de liste chaînée
typedef struct Node {
    int data;              // Données
    struct Node *next;     // Pointeur vers le suivant
} Node;

// Tête de liste
Node *head = NULL;
```

### 2.2 Visualisation

```
head
  │
  ↓
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ data: 10     │     │ data: 20     │     │ data: 30     │
│ next: ●──────┼────→│ next: ●──────┼────→│ next: NULL   │
└──────────────┘     └──────────────┘     └──────────────┘
     Node 1               Node 2               Node 3
```

### 2.3 Opérations de Base

```c
#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
    int data;
    struct Node *next;
} Node;

// Créer un nouveau nœud
Node* create_node(int data) {
    Node *new_node = malloc(sizeof(Node));
    if (new_node == NULL) return NULL;

    new_node->data = data;
    new_node->next = NULL;
    return new_node;
}

// Insérer en tête - O(1)
void insert_head(Node **head, int data) {
    Node *new_node = create_node(data);
    if (new_node == NULL) return;

    new_node->next = *head;  // Nouveau pointe vers ancien head
    *head = new_node;        // Head devient nouveau nœud
}

// Insérer en queue - O(n)
void insert_tail(Node **head, int data) {
    Node *new_node = create_node(data);
    if (new_node == NULL) return;

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

// Supprimer un nœud - O(n)
void delete_node(Node **head, int data) {
    if (*head == NULL) return;

    // Cas spécial : supprimer la tête
    if ((*head)->data == data) {
        Node *temp = *head;
        *head = (*head)->next;
        free(temp);
        return;
    }

    // Chercher le nœud précédent
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
    printf("Liste: ");
    while (head != NULL) {
        printf("%d -> ", head->data);
        head = head->next;
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
```

---

## 3. Pile (Stack) - LIFO

### 3.1 Concept

```
PILE (Stack) - Last In, First Out

       push(30)
          ↓
    ┌─────────┐
    │   30    │  ← top (dernier entré)
    ├─────────┤
    │   20    │
    ├─────────┤
    │   10    │  ← premier entré
    └─────────┘

    pop() → retourne 30 (le dernier)
```

### 3.2 Implémentation

```c
#define MAX_SIZE 100

typedef struct {
    int data[MAX_SIZE];
    int top;
} Stack;

// Initialiser
void stack_init(Stack *s) {
    s->top = -1;
}

// Vérifier si vide
int stack_empty(Stack *s) {
    return s->top == -1;
}

// Vérifier si plein
int stack_full(Stack *s) {
    return s->top == MAX_SIZE - 1;
}

// Empiler (push)
int stack_push(Stack *s, int value) {
    if (stack_full(s)) return -1;
    s->data[++s->top] = value;
    return 0;
}

// Dépiler (pop)
int stack_pop(Stack *s, int *value) {
    if (stack_empty(s)) return -1;
    *value = s->data[s->top--];
    return 0;
}

// Voir le sommet (peek)
int stack_peek(Stack *s, int *value) {
    if (stack_empty(s)) return -1;
    *value = s->data[s->top];
    return 0;
}
```

---

## 4. File (Queue) - FIFO

### 4.1 Concept

```
FILE (Queue) - First In, First Out

enqueue(30)
    ↓
┌─────┬─────┬─────┬─────┐
│ 10  │ 20  │ 30  │     │
└─────┴─────┴─────┴─────┘
  ↑
front              rear
  │
  ↓
dequeue() → retourne 10 (le premier)
```

### 4.2 Implémentation (Circulaire)

```c
#define QUEUE_SIZE 100

typedef struct {
    int data[QUEUE_SIZE];
    int front;
    int rear;
    int count;
} Queue;

void queue_init(Queue *q) {
    q->front = 0;
    q->rear = -1;
    q->count = 0;
}

int queue_empty(Queue *q) {
    return q->count == 0;
}

int queue_full(Queue *q) {
    return q->count == QUEUE_SIZE;
}

// Enfiler
int enqueue(Queue *q, int value) {
    if (queue_full(q)) return -1;

    q->rear = (q->rear + 1) % QUEUE_SIZE;  // Circulaire
    q->data[q->rear] = value;
    q->count++;
    return 0;
}

// Défiler
int dequeue(Queue *q, int *value) {
    if (queue_empty(q)) return -1;

    *value = q->data[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;  // Circulaire
    q->count--;
    return 0;
}
```

---

## 5. Table de Hash

### 5.1 Concept

```
TABLE DE HASH :

Clé "alice" → hash("alice") = 2 → index 2
Clé "bob"   → hash("bob") = 5   → index 5

Index:  0    1    2        3    4    5      6
      ┌────┬────┬────────┬────┬────┬──────┬────┐
      │    │    │ alice  │    │    │ bob  │    │
      │    │    │ =1337  │    │    │ =42  │    │
      └────┴────┴────────┴────┴────┴──────┴────┘

Accès O(1) au lieu de O(n) !
```

### 5.2 Implémentation Simple

```c
#define TABLE_SIZE 256

typedef struct Entry {
    char *key;
    int value;
    struct Entry *next;  // Pour collisions
} Entry;

typedef struct {
    Entry *buckets[TABLE_SIZE];
} HashTable;

// Fonction de hash simple (djb2)
unsigned int hash(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % TABLE_SIZE;
}

// Créer table
HashTable* hashtable_create(void) {
    HashTable *ht = calloc(1, sizeof(HashTable));
    return ht;
}

// Insérer
void hashtable_set(HashTable *ht, const char *key, int value) {
    unsigned int index = hash(key);

    Entry *entry = malloc(sizeof(Entry));
    entry->key = strdup(key);
    entry->value = value;
    entry->next = ht->buckets[index];
    ht->buckets[index] = entry;
}

// Chercher
int hashtable_get(HashTable *ht, const char *key, int *value) {
    unsigned int index = hash(key);

    Entry *entry = ht->buckets[index];
    while (entry != NULL) {
        if (strcmp(entry->key, key) == 0) {
            *value = entry->value;
            return 0;
        }
        entry = entry->next;
    }
    return -1;  // Non trouvé
}
```

---

## 6. Applications Offensives

### 6.1 Liste Chaînée : Gestion de Processus Injectés

```c
// Tracker les processus où on a injecté du code
typedef struct InjectedProcess {
    DWORD pid;
    void *remote_addr;
    size_t payload_size;
    struct InjectedProcess *next;
} InjectedProcess;

InjectedProcess *injected_list = NULL;

void track_injection(DWORD pid, void *addr, size_t size) {
    InjectedProcess *proc = malloc(sizeof(InjectedProcess));
    proc->pid = pid;
    proc->remote_addr = addr;
    proc->payload_size = size;
    proc->next = injected_list;
    injected_list = proc;
}

void cleanup_all_injections(void) {
    InjectedProcess *current = injected_list;
    while (current != NULL) {
        // Cleanup injection in process
        // VirtualFreeEx(proc->pid, proc->remote_addr, ...)
        InjectedProcess *temp = current;
        current = current->next;
        free(temp);
    }
}
```

### 6.2 Pile : Parsing de Commandes C2

```c
// Parser des commandes imbriquées du C2
typedef struct {
    char *commands[64];
    int top;
} CommandStack;

void parse_c2_response(const char *response, CommandStack *stack) {
    // Format: "cmd1;cmd2;cmd3"
    // Push chaque commande sur la stack
    // Exécuter en ordre inverse (LIFO)
}

void execute_commands(CommandStack *stack) {
    char *cmd;
    while (stack->top >= 0) {
        cmd = stack->commands[stack->top--];
        execute_single_command(cmd);
    }
}
```

### 6.3 File : Queue de Tâches Asynchrones

```c
// Queue pour exfiltration de données
typedef struct {
    char *data;
    size_t size;
} ExfilData;

typedef struct {
    ExfilData items[100];
    int front, rear, count;
} ExfilQueue;

void queue_exfil(ExfilQueue *q, void *data, size_t size) {
    if (q->count >= 100) return;

    ExfilData *item = &q->items[q->rear];
    item->data = malloc(size);
    memcpy(item->data, data, size);
    item->size = size;

    q->rear = (q->rear + 1) % 100;
    q->count++;
}

// Thread séparé pour envoyer les données
void* exfil_thread(void *arg) {
    ExfilQueue *q = (ExfilQueue*)arg;
    ExfilData item;

    while (1) {
        if (q->count > 0) {
            item = q->items[q->front];
            q->front = (q->front + 1) % 100;
            q->count--;

            send_to_c2(item.data, item.size);
            free(item.data);
        }
        sleep(1);
    }
}
```

### 6.4 Table de Hash : Cache de Credentials

```c
// Cache les credentials récupérés
typedef struct Credential {
    char *username;
    char *domain;
    char *password_hash;
    struct Credential *next;
} Credential;

typedef struct {
    Credential *buckets[256];
} CredCache;

void cache_credential(CredCache *cache,
                      const char *user,
                      const char *domain,
                      const char *hash) {
    char key[512];
    snprintf(key, sizeof(key), "%s\\%s", domain, user);

    unsigned int index = hash_string(key);

    Credential *cred = malloc(sizeof(Credential));
    cred->username = strdup(user);
    cred->domain = strdup(domain);
    cred->password_hash = strdup(hash);
    cred->next = cache->buckets[index];
    cache->buckets[index] = cred;
}
```

---

## 7. Complexité Algorithmique

| Structure | Insertion | Suppression | Recherche | Accès |
|-----------|-----------|-------------|-----------|-------|
| Tableau | O(n) | O(n) | O(n) | O(1) |
| Liste chaînée | O(1)* | O(n) | O(n) | O(n) |
| Pile | O(1) | O(1) | O(n) | O(1)** |
| File | O(1) | O(1) | O(n) | O(1)** |
| Hash Table | O(1)*** | O(1)*** | O(1)*** | - |

\* En tête
\** Sommet/Front uniquement
\*** En moyenne, O(n) pire cas

---

## 8. Checklist

- [ ] Comprendre la différence tableau vs liste chaînée
- [ ] Savoir implémenter une liste chaînée
- [ ] Comprendre LIFO (pile) vs FIFO (file)
- [ ] Connaître le principe du hashing
- [ ] Toujours free() les nœuds alloués
- [ ] Gérer les cas limites (liste vide, etc.)

---

## Exercices

Voir [exercice.md](exercice.md)

---

**Prochaine étape :** Phase 03 - Exploitation Basics (Assembly x64).

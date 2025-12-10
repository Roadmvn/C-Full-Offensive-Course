# Module 21 - Structures de Données pour l'Offensif

## Pourquoi tu dois maîtriser ça

```c
// Tracker les processus injectés
InjectedProc *list = NULL;
add_injection(&list, pid, remote_addr);

// Cache de credentials volés
hashtable_set(creds, "DOMAIN\\admin", hash);

// Queue d'exfiltration asynchrone
enqueue(&exfil_queue, stolen_data, size);
```

**Structures de données = gérer des listes dynamiques, cacher des données, organiser des tâches.**

---

## Liste Chaînée : Le pattern de base

> **Liste chaînée** = nœuds en mémoire reliés par pointeurs. Taille dynamique, insertion O(1).

### Structure

```c
typedef struct Node {
    void *data;             // Données (générique)
    struct Node *next;      // Prochain nœud
} Node;

Node *head = NULL;
```

```
head → [data|next] → [data|next] → [data|NULL]
```

### Opérations essentielles

```c
// Créer un nœud
Node* create_node(void *data) {
    Node *n = malloc(sizeof(Node));
    n->data = data;
    n->next = NULL;
    return n;
}

// Insérer en tête - O(1)
void insert_head(Node **head, void *data) {
    Node *n = create_node(data);
    n->next = *head;
    *head = n;
}

// Parcourir
void foreach_node(Node *head, void (*func)(void*)) {
    while (head) {
        func(head->data);
        head = head->next;
    }
}

// Libérer toute la liste
void free_list(Node **head, void (*free_data)(void*)) {
    Node *current = *head;
    while (current) {
        Node *temp = current;
        current = current->next;
        if (free_data) free_data(temp->data);
        free(temp);
    }
    *head = NULL;
}
```

### Application : Tracker les injections

```c
typedef struct {
    DWORD pid;
    void *remote_addr;
    size_t size;
} Injection;

Node *injections = NULL;

void track_injection(DWORD pid, void *addr, size_t sz) {
    Injection *inj = malloc(sizeof(Injection));
    inj->pid = pid;
    inj->remote_addr = addr;
    inj->size = sz;
    insert_head(&injections, inj);
}

void cleanup_all(void) {
    Node *n = injections;
    while (n) {
        Injection *inj = n->data;
        // VirtualFreeEx(inj->pid, inj->remote_addr, ...);
        n = n->next;
    }
    free_list(&injections, free);
}
```

---

## Hash Table : Accès O(1)

> **Hash table** = tableau + fonction de hash. Accès direct par clé au lieu de recherche linéaire.

### Structure

```c
#define TABLE_SIZE 256

typedef struct Entry {
    char *key;
    void *value;
    struct Entry *next;  // Gestion des collisions
} Entry;

typedef struct {
    Entry *buckets[TABLE_SIZE];
} HashTable;
```

### Implémentation minimale

```c
// Fonction de hash (djb2)
unsigned int hash(const char *str) {
    unsigned int h = 5381;
    int c;
    while ((c = *str++))
        h = ((h << 5) + h) + c;
    return h % TABLE_SIZE;
}

// Créer
HashTable* ht_create(void) {
    return calloc(1, sizeof(HashTable));
}

// Insérer/Mettre à jour
void ht_set(HashTable *ht, const char *key, void *value) {
    unsigned int idx = hash(key);

    // Vérifier si existe déjà
    Entry *e = ht->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            e->value = value;
            return;
        }
        e = e->next;
    }

    // Nouveau
    Entry *new = malloc(sizeof(Entry));
    new->key = strdup(key);
    new->value = value;
    new->next = ht->buckets[idx];
    ht->buckets[idx] = new;
}

// Chercher
void* ht_get(HashTable *ht, const char *key) {
    unsigned int idx = hash(key);
    Entry *e = ht->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0)
            return e->value;
        e = e->next;
    }
    return NULL;
}
```

### Application : Cache de credentials

```c
typedef struct {
    char *user;
    char *domain;
    char *ntlm_hash;
} Credential;

HashTable *cred_cache = NULL;

void cache_cred(const char *domain, const char *user, const char *hash) {
    char key[256];
    snprintf(key, sizeof(key), "%s\\%s", domain, user);

    Credential *c = malloc(sizeof(Credential));
    c->user = strdup(user);
    c->domain = strdup(domain);
    c->ntlm_hash = strdup(hash);

    ht_set(cred_cache, key, c);
}

Credential* get_cred(const char *domain, const char *user) {
    char key[256];
    snprintf(key, sizeof(key), "%s\\%s", domain, user);
    return ht_get(cred_cache, key);
}
```

---

## Queue : Tâches asynchrones

> **Queue (FIFO)** = premier entré, premier sorti. Idéal pour buffer d'exfiltration.

```c
#define QUEUE_SIZE 100

typedef struct {
    void *items[QUEUE_SIZE];
    int front, rear, count;
} Queue;

void queue_init(Queue *q) {
    q->front = 0;
    q->rear = -1;
    q->count = 0;
}

int enqueue(Queue *q, void *item) {
    if (q->count >= QUEUE_SIZE) return -1;
    q->rear = (q->rear + 1) % QUEUE_SIZE;
    q->items[q->rear] = item;
    q->count++;
    return 0;
}

void* dequeue(Queue *q) {
    if (q->count == 0) return NULL;
    void *item = q->items[q->front];
    q->front = (q->front + 1) % QUEUE_SIZE;
    q->count--;
    return item;
}
```

### Application : Buffer d'exfiltration

```c
typedef struct {
    unsigned char *data;
    size_t size;
} ExfilPacket;

Queue exfil_queue;

void queue_data(void *data, size_t size) {
    ExfilPacket *pkt = malloc(sizeof(ExfilPacket));
    pkt->data = malloc(size);
    memcpy(pkt->data, data, size);
    pkt->size = size;
    enqueue(&exfil_queue, pkt);
}

// Thread d'exfiltration
void* exfil_thread(void *arg) {
    while (1) {
        ExfilPacket *pkt = dequeue(&exfil_queue);
        if (pkt) {
            send_to_c2(pkt->data, pkt->size);
            free(pkt->data);
            free(pkt);
        }
        sleep(1);
    }
}
```

---

## Complexité : Pourquoi ça compte

| Structure | Insertion | Recherche | Suppression |
|-----------|-----------|-----------|-------------|
| Tableau | O(n) | O(n) | O(n) |
| Liste chaînée | O(1)* | O(n) | O(n) |
| Hash Table | O(1) | O(1) | O(1) |
| Queue | O(1) | - | O(1) |

\* En tête

**Règle** : Beaucoup de lookups → Hash Table. Insertions fréquentes → Liste chaînée.

---

## Checklist

```
□ Je sais implémenter une liste chaînée (insert, parcours, free)
□ Je comprends le principe du hashing
□ Je sais créer une hash table avec gestion de collisions
□ Je sais utiliser une queue pour du buffering
□ Je libère toujours la mémoire (pas de leaks)
```

---

## Glossaire express

| Terme | Définition |
|-------|------------|
| **Liste chaînée** | Nœuds reliés par pointeurs |
| **Hash Table** | Tableau avec accès par clé hashée |
| **FIFO** | First In First Out (Queue) |
| **LIFO** | Last In First Out (Stack) |
| **Collision** | Deux clés avec même hash |

---

**Temps lecture :** 5 min | **Pratique :** 30 min

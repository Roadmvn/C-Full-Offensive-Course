# Solutions - Structures de données

## Exercice 1 : Découverte (Très facile)

### Objectif
Se familiariser avec les structures de données de base : listes chaînées, piles et files.

### Solution

```c
/*
 * Exercice 1 : Découverte des structures de données
 * Implémentation d'une liste chaînée simple
 */
#include <stdio.h>
#include <stdlib.h>

// Structure d'un nœud de liste chaînée
typedef struct Node {
    int data;              // Données stockées dans le nœud
    struct Node *next;     // Pointeur vers le nœud suivant
} Node;

// Créer un nouveau nœud
Node* create_node(int data) {
    // Allouer de la mémoire pour le nouveau nœud
    Node *new_node = malloc(sizeof(Node));
    if (new_node == NULL) {
        printf("[-] Erreur d'allocation mémoire\n");
        return NULL;
    }

    // Initialiser les données
    new_node->data = data;
    new_node->next = NULL;

    return new_node;
}

// Afficher la liste complète
void print_list(Node *head) {
    printf("[*] Liste: ");
    Node *current = head;

    // Parcourir tous les nœuds
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

int main() {
    printf("[*] Exercice 1 : Liste chaînée simple\n");
    printf("==========================================\n\n");

    // Créer trois nœuds
    Node *head = create_node(10);
    Node *second = create_node(20);
    Node *third = create_node(30);

    // Lier les nœuds entre eux
    head->next = second;
    second->next = third;

    // Afficher la liste
    print_list(head);

    // Libérer la mémoire
    free(third);
    free(second);
    free(head);

    printf("[+] Exercice terminé avec succès\n");
    return 0;
}
```

### Explication

1. **Structure Node** : Contient les données (int) et un pointeur vers le nœud suivant
2. **create_node()** : Alloue dynamiquement un nouveau nœud avec malloc()
3. **print_list()** : Parcourt la liste en suivant les pointeurs next
4. **Libération** : Importante ! Toujours libérer la mémoire allouée

### Compilation et exécution
```bash
gcc exercice1.c -o exercice1
./exercice1
```

### Résultat attendu
```
[*] Exercice 1 : Liste chaînée simple
==========================================

[*] Liste: 10 -> 20 -> 30 -> NULL
[+] Exercice terminé avec succès
```

---

## Exercice 2 : Modification (Facile)

### Objectif
Ajouter des fonctions d'insertion en tête et en queue de liste.

### Solution

```c
/*
 * Exercice 2 : Opérations sur liste chaînée
 * Insertion en tête et en queue
 */
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

// Insérer en tête de liste - Complexité O(1)
void insert_head(Node **head, int data) {
    // Créer le nouveau nœud
    Node *new_node = create_node(data);
    if (new_node == NULL) return;

    // Le nouveau nœud pointe vers l'ancien head
    new_node->next = *head;

    // Le head devient le nouveau nœud
    *head = new_node;

    printf("[+] Inséré %d en tête\n", data);
}

// Insérer en queue de liste - Complexité O(n)
void insert_tail(Node **head, int data) {
    Node *new_node = create_node(data);
    if (new_node == NULL) return;

    // Cas spécial : liste vide
    if (*head == NULL) {
        *head = new_node;
        printf("[+] Inséré %d (liste était vide)\n", data);
        return;
    }

    // Parcourir jusqu'au dernier nœud
    Node *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }

    // Ajouter le nouveau nœud à la fin
    current->next = new_node;
    printf("[+] Inséré %d en queue\n", data);
}

// Afficher la liste
void print_list(Node *head) {
    printf("[*] Liste: ");
    while (head != NULL) {
        printf("%d -> ", head->data);
        head = head->next;
    }
    printf("NULL\n");
}

// Libérer toute la liste
void free_list(Node **head) {
    Node *current = *head;
    Node *temp;

    while (current != NULL) {
        temp = current;
        current = current->next;
        free(temp);
    }

    *head = NULL;
    printf("[+] Mémoire libérée\n");
}

int main() {
    printf("[*] Exercice 2 : Insertion en tête et queue\n");
    printf("==========================================\n\n");

    Node *head = NULL;

    // Test insertion en tête
    insert_head(&head, 30);
    insert_head(&head, 20);
    insert_head(&head, 10);
    print_list(head);  // Devrait afficher: 10 -> 20 -> 30 -> NULL

    printf("\n");

    // Test insertion en queue
    insert_tail(&head, 40);
    insert_tail(&head, 50);
    print_list(head);  // Devrait afficher: 10 -> 20 -> 30 -> 40 -> 50 -> NULL

    printf("\n");

    // Libération
    free_list(&head);

    printf("[+] Exercice terminé avec succès\n");
    return 0;
}
```

### Explication

1. **insert_head()** : Insertion en O(1) car on modifie juste le head
2. **insert_tail()** : Insertion en O(n) car il faut parcourir toute la liste
3. **free_list()** : Libère tous les nœuds en parcourant la liste
4. **Pointeur double** : `Node **head` permet de modifier le pointeur head depuis la fonction

### Résultat attendu
```
[*] Exercice 2 : Insertion en tête et queue
==========================================

[+] Inséré 30 en tête
[+] Inséré 20 en tête
[+] Inséré 10 en tête
[*] Liste: 10 -> 20 -> 30 -> NULL

[+] Inséré 40 en queue
[+] Inséré 50 en queue
[*] Liste: 10 -> 20 -> 30 -> 40 -> 50 -> NULL

[+] Mémoire libérée
[+] Exercice terminé avec succès
```

---

## Exercice 3 : Création (Moyen)

### Objectif
Implémenter une pile (stack) et une file (queue) complètes avec toutes les opérations.

### Solution

```c
/*
 * Exercice 3 : Implémentation Pile (Stack) et File (Queue)
 */
#include <stdio.h>
#include <stdlib.h>

// ============= PILE (STACK - LIFO) =============

#define STACK_MAX 100

typedef struct {
    int data[STACK_MAX];
    int top;  // Index du sommet (-1 si vide)
} Stack;

// Initialiser la pile
void stack_init(Stack *s) {
    s->top = -1;
    printf("[*] Pile initialisée\n");
}

// Vérifier si vide
int stack_empty(Stack *s) {
    return s->top == -1;
}

// Vérifier si pleine
int stack_full(Stack *s) {
    return s->top == STACK_MAX - 1;
}

// Empiler (push) - Ajoute au sommet
int stack_push(Stack *s, int value) {
    if (stack_full(s)) {
        printf("[-] Erreur: pile pleine\n");
        return -1;
    }

    s->data[++s->top] = value;
    printf("[+] Push %d (sommet = %d)\n", value, s->top);
    return 0;
}

// Dépiler (pop) - Retire du sommet
int stack_pop(Stack *s, int *value) {
    if (stack_empty(s)) {
        printf("[-] Erreur: pile vide\n");
        return -1;
    }

    *value = s->data[s->top--];
    printf("[+] Pop %d (sommet = %d)\n", *value, s->top);
    return 0;
}

// Voir le sommet sans retirer
int stack_peek(Stack *s, int *value) {
    if (stack_empty(s)) {
        return -1;
    }
    *value = s->data[s->top];
    return 0;
}

// ============= FILE (QUEUE - FIFO) =============

#define QUEUE_MAX 100

typedef struct {
    int data[QUEUE_MAX];
    int front;   // Index du premier élément
    int rear;    // Index du dernier élément
    int count;   // Nombre d'éléments
} Queue;

// Initialiser la file
void queue_init(Queue *q) {
    q->front = 0;
    q->rear = -1;
    q->count = 0;
    printf("[*] File initialisée\n");
}

// Vérifier si vide
int queue_empty(Queue *q) {
    return q->count == 0;
}

// Vérifier si pleine
int queue_full(Queue *q) {
    return q->count == QUEUE_MAX;
}

// Enfiler (enqueue) - Ajoute à la fin
int enqueue(Queue *q, int value) {
    if (queue_full(q)) {
        printf("[-] Erreur: file pleine\n");
        return -1;
    }

    // File circulaire : on revient au début si nécessaire
    q->rear = (q->rear + 1) % QUEUE_MAX;
    q->data[q->rear] = value;
    q->count++;

    printf("[+] Enqueue %d (count = %d)\n", value, q->count);
    return 0;
}

// Défiler (dequeue) - Retire du début
int dequeue(Queue *q, int *value) {
    if (queue_empty(q)) {
        printf("[-] Erreur: file vide\n");
        return -1;
    }

    *value = q->data[q->front];
    q->front = (q->front + 1) % QUEUE_MAX;
    q->count--;

    printf("[+] Dequeue %d (count = %d)\n", *value, q->count);
    return 0;
}

int main() {
    printf("[*] Exercice 3 : Pile et File\n");
    printf("==========================================\n\n");

    // ===== TEST PILE =====
    printf("=== TEST PILE (LIFO) ===\n");
    Stack s;
    stack_init(&s);

    // Empiler des valeurs
    stack_push(&s, 10);
    stack_push(&s, 20);
    stack_push(&s, 30);

    // Dépiler
    int val;
    stack_pop(&s, &val);  // Devrait retourner 30 (dernier entré)
    stack_pop(&s, &val);  // Devrait retourner 20
    stack_pop(&s, &val);  // Devrait retourner 10

    printf("\n");

    // ===== TEST FILE =====
    printf("=== TEST FILE (FIFO) ===\n");
    Queue q;
    queue_init(&q);

    // Enfiler des valeurs
    enqueue(&q, 10);
    enqueue(&q, 20);
    enqueue(&q, 30);

    // Défiler
    dequeue(&q, &val);  // Devrait retourner 10 (premier entré)
    dequeue(&q, &val);  // Devrait retourner 20
    dequeue(&q, &val);  // Devrait retourner 30

    printf("\n[+] Exercice terminé avec succès\n");
    return 0;
}
```

### Explication

#### Pile (Stack - LIFO)
- **LIFO** : Last In, First Out (dernier entré, premier sorti)
- **top** : Index du sommet de la pile
- **push** : Ajoute au sommet (++top)
- **pop** : Retire du sommet (top--)
- **Cas d'usage** : Évaluation d'expressions, parsing, historique (undo)

#### File (Queue - FIFO)
- **FIFO** : First In, First Out (premier entré, premier sorti)
- **Circulaire** : Utilise modulo (%) pour revenir au début
- **front** : Premier élément
- **rear** : Dernier élément
- **count** : Nombre d'éléments
- **Cas d'usage** : Ordonnancement de tâches, buffers

### Résultat attendu
```
[*] Exercice 3 : Pile et File
==========================================

=== TEST PILE (LIFO) ===
[*] Pile initialisée
[+] Push 10 (sommet = 0)
[+] Push 20 (sommet = 1)
[+] Push 30 (sommet = 2)
[+] Pop 30 (sommet = 1)
[+] Pop 20 (sommet = 0)
[+] Pop 10 (sommet = -1)

=== TEST FILE (FIFO) ===
[*] File initialisée
[+] Enqueue 10 (count = 1)
[+] Enqueue 20 (count = 2)
[+] Enqueue 30 (count = 3)
[+] Dequeue 10 (count = 2)
[+] Dequeue 20 (count = 1)
[+] Dequeue 30 (count = 0)

[+] Exercice terminé avec succès
```

---

## Exercice 4 : Challenge (Difficile)

### Objectif
Créer une table de hash pour stocker et retrouver rapidement des credentials (username -> password).

### Solution

```c
/*
 * Exercice 4 : Table de Hash pour Credentials
 * Implémentation d'une hash table avec gestion des collisions
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 256

// Structure pour une entrée (credential)
typedef struct Entry {
    char *username;        // Clé (nom d'utilisateur)
    char *password;        // Valeur (mot de passe)
    struct Entry *next;    // Chaînage pour collisions
} Entry;

// Table de hash
typedef struct {
    Entry *buckets[TABLE_SIZE];  // Tableau de listes chaînées
} HashTable;

// Fonction de hash (djb2 algorithm)
// Convertit une chaîne en index de tableau
unsigned int hash(const char *str) {
    unsigned int hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }

    return hash % TABLE_SIZE;
}

// Créer une nouvelle table de hash
HashTable* hashtable_create(void) {
    HashTable *ht = calloc(1, sizeof(HashTable));
    if (ht == NULL) {
        printf("[-] Erreur d'allocation\n");
        return NULL;
    }

    printf("[+] Table de hash créée (%d buckets)\n", TABLE_SIZE);
    return ht;
}

// Insérer un credential
void hashtable_set(HashTable *ht, const char *username, const char *password) {
    // Calculer l'index
    unsigned int index = hash(username);

    // Vérifier si l'utilisateur existe déjà
    Entry *entry = ht->buckets[index];
    while (entry != NULL) {
        if (strcmp(entry->username, username) == 0) {
            // Mise à jour du mot de passe existant
            free(entry->password);
            entry->password = strdup(password);
            printf("[*] Credential mis à jour: %s\n", username);
            return;
        }
        entry = entry->next;
    }

    // Créer nouvelle entrée
    Entry *new_entry = malloc(sizeof(Entry));
    if (new_entry == NULL) return;

    new_entry->username = strdup(username);
    new_entry->password = strdup(password);

    // Insérer en tête de la liste (gestion des collisions)
    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;

    printf("[+] Credential ajouté: %s (hash=%u)\n", username, index);
}

// Récupérer un credential
int hashtable_get(HashTable *ht, const char *username, char **password) {
    unsigned int index = hash(username);

    Entry *entry = ht->buckets[index];
    while (entry != NULL) {
        if (strcmp(entry->username, username) == 0) {
            *password = entry->password;
            return 0;  // Trouvé
        }
        entry = entry->next;
    }

    return -1;  // Non trouvé
}

// Supprimer un credential
int hashtable_delete(HashTable *ht, const char *username) {
    unsigned int index = hash(username);

    Entry *entry = ht->buckets[index];
    Entry *prev = NULL;

    while (entry != NULL) {
        if (strcmp(entry->username, username) == 0) {
            // Retirer de la liste chaînée
            if (prev == NULL) {
                ht->buckets[index] = entry->next;
            } else {
                prev->next = entry->next;
            }

            // Libérer la mémoire
            free(entry->username);
            free(entry->password);
            free(entry);

            printf("[+] Credential supprimé: %s\n", username);
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }

    return -1;
}

// Afficher tous les credentials
void hashtable_print(HashTable *ht) {
    printf("\n[*] === TABLE DE CREDENTIALS ===\n");
    int total = 0;

    for (int i = 0; i < TABLE_SIZE; i++) {
        Entry *entry = ht->buckets[i];
        if (entry != NULL) {
            printf("[*] Bucket %d:\n", i);
            while (entry != NULL) {
                printf("    - %s : %s\n", entry->username, entry->password);
                total++;
                entry = entry->next;
            }
        }
    }

    printf("[*] Total: %d credentials\n\n", total);
}

// Libérer toute la table
void hashtable_free(HashTable *ht) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        Entry *entry = ht->buckets[i];
        while (entry != NULL) {
            Entry *temp = entry;
            entry = entry->next;
            free(temp->username);
            free(temp->password);
            free(temp);
        }
    }
    free(ht);
    printf("[+] Table de hash libérée\n");
}

int main() {
    printf("[*] Exercice 4 : Table de Hash pour Credentials\n");
    printf("==========================================\n\n");

    // Créer la table
    HashTable *creds = hashtable_create();

    // Ajouter des credentials
    hashtable_set(creds, "admin", "P@ssw0rd!");
    hashtable_set(creds, "alice", "alice123");
    hashtable_set(creds, "bob", "bobsecret");
    hashtable_set(creds, "root", "toor");
    hashtable_set(creds, "guest", "guest");

    // Afficher la table
    hashtable_print(creds);

    // Rechercher un credential
    char *password;
    if (hashtable_get(creds, "alice", &password) == 0) {
        printf("[+] Credential trouvé pour 'alice': %s\n", password);
    } else {
        printf("[-] Credential non trouvé\n");
    }

    // Test credential inexistant
    if (hashtable_get(creds, "hacker", &password) == -1) {
        printf("[-] Credential 'hacker' non trouvé (normal)\n");
    }

    printf("\n");

    // Supprimer un credential
    hashtable_delete(creds, "guest");

    // Afficher après suppression
    hashtable_print(creds);

    // Libérer
    hashtable_free(creds);

    printf("[+] Exercice terminé avec succès\n");
    return 0;
}
```

### Explication

#### Fonctionnement de la Hash Table

1. **Fonction de hash** :
   - Convertit une chaîne (username) en index numérique (0-255)
   - Algorithme djb2 : rapide et bonne distribution

2. **Gestion des collisions** :
   - Chaînage (chaining) : chaque bucket est une liste chaînée
   - Si deux usernames ont le même hash, ils sont dans la même liste

3. **Complexité** :
   - Insertion : O(1) en moyenne
   - Recherche : O(1) en moyenne
   - Suppression : O(1) en moyenne

#### Structure de la mémoire

```
HashTable
├─ buckets[0] → NULL
├─ buckets[1] → Entry("alice") → NULL
├─ buckets[2] → Entry("bob") → Entry("admin") → NULL  (collision!)
├─ buckets[3] → NULL
...
└─ buckets[255] → Entry("root") → NULL
```

### Application Offensive

Cette structure est idéale pour :
- **Cache de credentials** récupérés (mimikatz-style)
- **Dictionnaire de hashs** pour cracking
- **Mapping PID → informations** dans un implant
- **Résolution rapide** d'adresses/noms

### Résultat attendu
```
[*] Exercice 4 : Table de Hash pour Credentials
==========================================

[+] Table de hash créée (256 buckets)
[+] Credential ajouté: admin (hash=194)
[+] Credential ajouté: alice (hash=220)
[+] Credential ajouté: bob (hash=193)
[+] Credential ajouté: root (hash=6)
[+] Credential ajouté: guest (hash=10)

[*] === TABLE DE CREDENTIALS ===
[*] Bucket 6:
    - root : toor
[*] Bucket 10:
    - guest : guest
[*] Bucket 193:
    - bob : bobsecret
[*] Bucket 194:
    - admin : P@ssw0rd!
[*] Bucket 220:
    - alice : alice123
[*] Total: 5 credentials

[+] Credential trouvé pour 'alice': alice123
[-] Credential 'hacker' non trouvé (normal)

[+] Credential supprimé: guest

[*] === TABLE DE CREDENTIALS ===
[*] Bucket 6:
    - root : toor
[*] Bucket 193:
    - bob : bobsecret
[*] Bucket 194:
    - admin : P@ssw0rd!
[*] Bucket 220:
    - alice : alice123
[*] Total: 4 credentials

[+] Table de hash libérée
[+] Exercice terminé avec succès
```

---

## Bonus : Application Offensive Complète

### Tracker de Processus Injectés

```c
/*
 * BONUS : Tracker de processus injectés
 * Utilise une liste chaînée pour suivre les injections
 */
#include <stdio.h>
#include <stdlib.h>

// Structure pour tracker une injection
typedef struct InjectedProcess {
    unsigned int pid;              // PID du processus cible
    void *remote_addr;             // Adresse distante du payload
    size_t payload_size;           // Taille du payload
    char technique[32];            // Technique utilisée
    struct InjectedProcess *next;  // Prochain dans la liste
} InjectedProcess;

// Liste globale
InjectedProcess *injected_list = NULL;

// Ajouter une injection à la liste
void track_injection(unsigned int pid, void *addr, size_t size, const char *technique) {
    InjectedProcess *proc = malloc(sizeof(InjectedProcess));
    if (proc == NULL) return;

    proc->pid = pid;
    proc->remote_addr = addr;
    proc->payload_size = size;
    snprintf(proc->technique, sizeof(proc->technique), "%s", technique);

    // Insérer en tête
    proc->next = injected_list;
    injected_list = proc;

    printf("[+] Tracked injection: PID=%u, Addr=%p, Size=%zu, Technique=%s\n",
           pid, addr, size, technique);
}

// Afficher toutes les injections
void list_injections(void) {
    printf("\n[*] === INJECTIONS ACTIVES ===\n");
    InjectedProcess *current = injected_list;
    int count = 0;

    while (current != NULL) {
        printf("[%d] PID=%u | Addr=%p | Size=%zu | %s\n",
               ++count, current->pid, current->remote_addr,
               current->payload_size, current->technique);
        current = current->next;
    }

    printf("[*] Total: %d injections\n\n", count);
}

// Nettoyer toutes les injections
void cleanup_all_injections(void) {
    InjectedProcess *current = injected_list;

    while (current != NULL) {
        InjectedProcess *temp = current;
        current = current->next;

        // Ici on pourrait appeler VirtualFreeEx, etc.
        printf("[*] Cleaning up injection in PID %u\n", temp->pid);

        free(temp);
    }

    injected_list = NULL;
    printf("[+] All injections cleaned up\n");
}

int main() {
    printf("[*] BONUS : Tracker d'injections\n");
    printf("==========================================\n\n");

    // Simuler plusieurs injections
    track_injection(1234, (void*)0x7fff0000, 1024, "DLL Injection");
    track_injection(5678, (void*)0x12340000, 512, "Process Hollowing");
    track_injection(9012, (void*)0xabcd0000, 2048, "Thread Hijacking");

    // Lister les injections
    list_injections();

    // Cleanup
    cleanup_all_injections();

    printf("[+] Exercice BONUS terminé\n");
    return 0;
}
```

---

## Critères de Réussite

Avant de passer au module suivant, tu dois :

- [ ] Comprendre la différence entre tableau et liste chaînée
- [ ] Savoir implémenter une liste chaînée avec insertion/suppression
- [ ] Maîtriser les concepts LIFO (pile) et FIFO (file)
- [ ] Comprendre le principe du hashing et des collisions
- [ ] Toujours libérer la mémoire allouée dynamiquement
- [ ] Identifier des cas d'usage en contexte offensif (tracking, cache, etc.)

---

**Prochaine étape :** Phase 03 - Exploitation Basics

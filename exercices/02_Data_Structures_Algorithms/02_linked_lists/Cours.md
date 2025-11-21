# Cours : Listes Chaînées (Linked Lists)

## 1. Introduction - Le Concept Expliqué Simplement

### 1.1 Imaginez un Train de Wagons 🚂

Avant de parler de code, comprenons l'idée avec une **analogie concrète** :

```ascii
LISTE CHAÎNÉE = TRAIN

┌──────┐    ┌──────┐    ┌──────┐
│Wagon1│───→│Wagon2│───→│Wagon3│
│ 🎁   │    │ 📦   │    │ 🎪   │
└──────┘    └──────┘    └──────┘
   ↑
 Locomotive (tête de liste)
```

**Caractéristiques** :
- Chaque wagon contient un **colis** (= donnée)
- Chaque wagon a un **crochet** qui pointe vers le wagon suivant (= pointeur)
- On peut **facilement ajouter** un wagon au début (détacher locomotive, ajouter wagon, rattacher)
- On peut **facilement retirer** un wagon (décrocher, jeter, reconnecter)
- Mais pour accéder au wagon n°50, il faut **parcourir** les 49 premiers (pas d'accès direct)

### 1.2 Comparaison avec un Tableau (pour comprendre la différence)

#### TABLEAU = Parking avec Places Numérotées

```ascii
TABLEAU (Array) :
┌───┬───┬───┬───┬───┐
│ 🚗│ 🚙│ 🚕│ 🚗│ 🚙│  ← Places fixes, côte à côte
└───┴───┴───┴───┴───┘
  0   1   2   3   4    ← Index direct

Avantages :
✅ Accès direct à la place n°3 : O(1)
✅ Mémoire contiguë (rapide pour le CPU)

Inconvénients :
❌ Taille FIXE (10 places = 10 places, pas plus)
❌ Ajouter une place = reconstruire tout le parking
```

#### LISTE CHAÎNÉE = Train de Wagons

```ascii
LISTE CHAÎNÉE (Linked List) :
┌───┐   ┌───┐   ┌───┐
│ 🚗│──→│ 🚙│──→│ 🚕│  ← Wagons liés par des crochets
└───┘   └───┘   └───┘

Avantages :
✅ Taille DYNAMIQUE (ajouter wagons à l'infini)
✅ Insertion au début TRÈS rapide : O(1)

Inconvénients :
❌ Accès au wagon n°50 = parcourir les 49 premiers : O(n)
❌ Mémoire dispersée (moins efficace pour le CPU)
```

### 1.3 Définition Technique (maintenant que vous avez l'idée)

Une **liste chaînée** est une structure de données où :

1. Les éléments sont appelés **nœuds** (nodes)
2. Chaque nœud contient :
   - Une **donnée** (valeur stockée)
   - Un **pointeur** (adresse mémoire) vers le nœud suivant
3. Le premier nœud est appelé **head** (tête)
4. Le dernier nœud pointe vers **NULL** (fin de liste)

**Glossaire des Termes** :

| Terme | Définition Simple | Analogie |
|-------|-------------------|----------|
| **Nœud** | Un élément de la liste | Un wagon du train |
| **Données** | La valeur stockée | Le colis dans le wagon |
| **Pointeur** | Adresse mémoire du suivant | Le crochet vers wagon suivant |
| **Head** | Premier élément | La locomotive |
| **NULL** | Adresse spéciale = "rien" | Fin du train (pas de wagon après) |
| **Malloc** | Réserver mémoire pour un nœud | Construire un nouveau wagon |
| **Free** | Libérer la mémoire | Détruire un wagon |

### 1.4 Pourquoi Utiliser des Listes Chaînées ?

**Cas d'usage réels** :

1. **Historique de navigateur** : 
   - Chaque page visitée = un nœud
   - Facile d'ajouter une nouvelle page
   - Facile de revenir en arrière

2. **Gestionnaire de musique (playlist)** :
   - Ajouter des chansons facilement
   - Réorganiser l'ordre sans tout copier

3. **Système d'exploitation** :
   - Liste des processus en cours
   - Liste des fichiers ouverts
   - Queue d'impression

4. **Jeux vidéo** :
   - Liste des ennemis à l'écran
   - Inventaire du joueur

Les listes chaînées sont **omniprésentes** en informatique !

## 2. Visualisation en Plusieurs Étapes - Comprendre la Structure

### 2.1 ÉTAPE 1 : La Liste Simplifiée (Vue Logique)

Commençons par la vue la plus simple - ce que vous imaginez mentalement :

```ascii
Ma liste contient les nombres : 10, 20, 30

REPRÉSENTATION SIMPLE :
┌────┐    ┌────┐    ┌────┐
│ 10 │ → │ 20 │ → │ 30 │ → ✖ (fin)
└────┘    └────┘    └────┘

✖ = NULL (signifie "il n'y a rien après")
```

**Question** : Comment le programme sait-il où se trouve le nœud suivant ?
**Réponse** : Grâce au **pointeur** (adresse mémoire) stocké dans chaque nœud !

### 2.2 ÉTAPE 2 : Avec les Pointeurs (Vue Technique)

Ajoutons maintenant les **pointeurs** qui relient les nœuds :

```ascii
LISTE COMPLÈTE AVEC POINTEURS :

head = 0x1000 (adresse du premier nœud)
   ↓
┌──────────────┐
│  Nœud 1      │  Adresse : 0x1000
├──────────────┤
│ data: 10     │  ← Donnée stockée
│ next: 0x1234 │  ← Adresse du nœud suivant
└──────┬───────┘
       │ Ce pointeur dit : "Le prochain nœud est à l'adresse 0x1234"
       ↓
┌──────────────┐
│  Nœud 2      │  Adresse : 0x1234
├──────────────┤
│ data: 20     │
│ next: 0x5678 │  ← "Le suivant est à 0x5678"
└──────┬───────┘
       ↓
┌──────────────┐
│  Nœud 3      │  Adresse : 0x5678
├──────────────┤
│ data: 30     │
│ next: NULL   │  ← "Il n'y a rien après" (NULL = 0x0)
└──────────────┘
```

**Explications** :
- `0x1000`, `0x1234`, `0x5678` sont des **adresses mémoire**
- Ces adresses sont en **hexadécimal** (base 16, avec le préfixe `0x`)
- **NULL** est une valeur spéciale (0x0) qui signifie "pas d'adresse"
- Les nœuds peuvent être **n'importe où** en mémoire (pas forcément côte à côte)

### 2.3 ÉTAPE 3 : La Mémoire Réelle (Vue Physique)

Voyons comment c'est **vraiment** stocké en RAM :

```ascii
MÉMOIRE RAM (adresses en hexadécimal) :

       ┌─────────────────────────────────┐
0x0800 │  ... autre chose ...            │
       ├─────────────────────────────────┤
0x1000 │  ┌─────────────────────┐        │  ← Nœud 1
       │  │ int data = 10       │        │
       │  │ (4 octets)          │        │
       │  ├─────────────────────┤        │
0x1004 │  │ Node *next = 0x1234 │        │
       │  │ (8 octets sur 64-bit)│       │
       │  └─────────────────────┘        │
0x100C │  ... espace libre ...           │
       ├─────────────────────────────────┤
0x1234 │  ┌─────────────────────┐        │  ← Nœud 2
       │  │ int data = 20       │        │
       │  ├─────────────────────┤        │
0x1238 │  │ Node *next = 0x5678 │        │
       │  └─────────────────────┘        │
       ├─────────────────────────────────┤
0x3000 │  ... autre chose ...            │
       ├─────────────────────────────────┤
0x5678 │  ┌─────────────────────┐        │  ← Nœud 3
       │  │ int data = 30       │        │
       │  ├─────────────────────┤        │
0x567C │  │ Node *next = NULL   │        │
       │  │         (0x0)       │        │
       │  └─────────────────────┘        │
       └─────────────────────────────────┘

OBSERVATIONS IMPORTANTES :
1. Les nœuds ne sont PAS côte à côte (0x1000, 0x1234, 0x5678 = aléatoires)
2. Chaque nœud occupe 12 bytes (4 pour data + 8 pour pointeur)
3. Il y a plein d'espace vide entre les nœuds (mémoire fragmentée)
```

**Question** : Pourquoi les nœuds ne sont-ils pas côte à côte ?
**Réponse** : Parce qu'ils sont créés avec `malloc()` qui alloue de la mémoire **où c'est disponible** dans le Heap, pas nécessairement de façon contiguë.

### 2.4 COMPARAISON : Tableau vs Liste Chaînée

#### TABLEAU (Array)

```ascii
int tableau[3] = {10, 20, 30};

MÉMOIRE (Contiguë = côte à côte) :
┌────┬────┬────┐
│ 10 │ 20 │ 30 │  ← Tout d'un bloc
└────┴────┴────┘
0x1000  0x1004  0x1008

✅ Accès direct : tableau[2] → Calcul instant : adresse_base + (2 × 4)
❌ Taille fixe : Déclaré avec [3], ne peut pas grandir
❌ Insertion coûteuse : Décaler tous les éléments suivants
```

#### LISTE CHAÎNÉE (Linked List)

```ascii
Node *liste = ...;  // Pointeur vers le premier nœud

MÉMOIRE (Dispersée = n'importe où) :
┌────┐          ┌────┐          ┌────┐
│ 10 │ ───────→ │ 20 │ ───────→ │ 30 │
└────┘          └────┘          └────┘
0x1000          0x3500          0x2100

❌ Accès séquentiel : Pour l'élément 2 → Partir de head, suivre 2 pointeurs
✅ Taille dynamique : Ajouter des nœuds à l'infini
✅ Insertion rapide au début : Créer nœud, pointer vers ancien head, done
```

**Quelle est la meilleure ?**

**Ça dépend** de ce que vous faites :

| Besoin | Tableau | Liste Chaînée |
|--------|---------|---------------|
| Accéder souvent par index | ✅ Parfait | ❌ Lent |
| Ajouter/retirer souvent au début | ❌ Lent | ✅ Parfait |
| Taille connue à l'avance | ✅ OK | 🤷 OK aussi |
| Taille imprévisible | ❌ Problématique | ✅ Idéal |

### 2.5 Comprendre NULL - Le Pointeur Spécial

**NULL** est une valeur spéciale qui signifie **"absence d'adresse"**.

```ascii
VALEURS DE POINTEURS :

Pointeur normal :
┌──────────┐
│ 0x1234   │  ← Adresse valide (pointe vers quelque chose)
└──────────┘

Pointeur NULL :
┌──────────┐
│ 0x0000   │  ← Adresse spéciale = "je ne pointe vers rien"
└──────────┘
```

**Pourquoi NULL est crucial ?**

Dans une liste chaînée, NULL indique la **fin** :

```c
while (current != NULL) {
    printf("%d\n", current->data);
    current = current->next;  // Avancer au suivant
}
// Quand current devient NULL, on sait qu'on a tout parcouru
```

**Analogie** : Le dernier wagon du train n'a **pas de crochet** (ou son crochet est vide). C'est NULL.

## 3. Structure d'un Nœud - Décortiquer le Code

### 3.1 Le Code - Ligne par Ligne

```c
typedef struct Node {
    int data;           
    struct Node *next;  
} Node;
```

**Décortiquons CHAQUE élément** :

#### Ligne 1 : `typedef struct Node {`

Décomposons ce qui semble cryptique :

```ascii
typedef  struct  Node  {
   │        │      │    │
   │        │      │    └─ Début du bloc
   │        │      │
   │        │      └─ Nom de la structure
   │        │
   │        └─ Mot-clé pour créer une structure
   │
   └─ Créer un "alias" (raccourci de nom)
```

**Sans typedef** (ancienne méthode) :
```c
struct Node {
    int data;
    struct Node *next;
};

// Utilisation :
struct Node mon_noeud;  // Faut écrire "struct" à chaque fois
```

**Avec typedef** (moderne, pratique) :
```c
typedef struct Node {
    int data;
    struct Node *next;
} Node;  // ← Crée un alias "Node"

// Utilisation :
Node mon_noeud;  // Plus besoin d'écrire "struct" !
```

#### Ligne 2 : `int data;`

```c
int data;
```

C'est un **entier** qui stocke la **valeur** du nœud.

```ascii
┌──────────────┐
│  Nœud        │
├──────────────┤
│ data: 42     │  ← Ici on stocke notre information
│ next: ...    │
└──────────────┘
```

**Pourquoi "data" ?**
- C'est un nom de variable comme `age` ou `nombre`
- On pourrait l'appeler autrement : `value`, `info`, `contenu`
- Par convention, on utilise `data` (= donnée)

**Variantes possibles** :
```c
char data;        // Si on stocke des caractères
float data;       // Si on stocke des nombres à virgule
char name[50];    // Si on stocke des noms
```

#### Ligne 3 : `struct Node *next;` - LA CLÉS DE TOUT

```c
struct Node *next;
```

C'est un **pointeur** vers le **nœud suivant**.

**Décortiquons** :

```ascii
struct Node  *  next  ;
    │        │   │    │
    │        │   │    └─ Point-virgule (fin d'instruction)
    │        │   │
    │        │   └─ Nom de la variable (on aurait pu l'appeler "suivant")
    │        │
    │        └─ * signifie "c'est un POINTEUR" (contient une adresse)
    │
    └─ Type pointé : "pointeur vers un Node"
```

**Question** : Pourquoi `struct Node *` et pas juste `Node *` ?

**Réponse** : À la ligne 3, le compilateur ne connaît pas encore l'alias `Node` (il est défini à la fin, ligne 4). On utilise donc le nom complet `struct Node`.

**Représentation mémoire** :

```ascii
Supposons qu'un nœud existe à l'adresse 0x1000 :

┌─────────────────────────┐
│  Mémoire à 0x1000       │
├─────────────────────────┤
│  Bytes 0-3 : data       │  Exemple : 0x0000000A (10 en déci

mal)
│  ├─ Byte 0 : 0x0A       │
│  ├─ Byte 1 : 0x00       │
│  ├─ Byte 2 : 0x00       │
│  └─ Byte 3 : 0x00       │
├─────────────────────────┤
│  Bytes 4-11 : next      │  Exemple : 0x0000000000001234
│  ├─ Byte 4 : 0x34       │  (adresse 0x1234 en little-endian)
│  ├─ Byte 5 : 0x12       │
│  ├─ Byte 6 : 0x00       │
│  ├─ ...                 │
│  └─ Byte 11: 0x00       │
└─────────────────────────┘

Total : 4 + 8 = 12 bytes par nœud
        │   │
        │   └─ Pointeur (8 bytes sur système 64-bit)
        └─ int (4 bytes)
```

### 3.2 Pourquoi un Pointeur vers le Même Type ?

**Question** : Pourquoi `next` est un pointeur vers `Node` (le même type) ?

**Réponse** : Parce qu'une liste est une **structure récursive** :
- Un nœud contient... un pointeur vers un autre nœud
- Qui contient... un pointeur vers un autre nœud
- Qui contient... etc.

```ascii
C'est comme des poupées russes :
┌────────┐
│ Nœud 1 │
│ ┌────────┐
│ │ Nœud 2 │
│ │ ┌────────┐
│ │ │ Nœud 3 │
│ │ │        │
│ │ └────────┘
│ └────────┘
└────────┘

Chaque poupée (nœud) contient l'adresse de la poupée suivante
```

### 3.3 Créer un Nœud en Mémoire - Pas à Pas

Regardons ce qui se passe **exactement** quand on crée un nœud :

```c
// ÉTAPE 1 : Réserver de la mémoire
Node *new_node = malloc(sizeof(Node));
```

**Que fait `malloc(sizeof(Node))` ?**

```ascii
AVANT malloc() :

HEAP (mémoire disponible) :
┌─────────────────────────────┐
│  ... espace libre ...       │
│  ... espace libre ...       │
│  ... espace libre ...       │
└─────────────────────────────┘

APPEL malloc(12) :  // sizeof(Node) = 12 bytes
    "Hey système, j'ai besoin de 12 bytes !"

APRÈS malloc() :

HEAP :
┌─────────────────────────────┐
│  ... espace libre ...       │
├─────────────────────────────┤
│  ┌───────────────────────┐  │  ← Bloc réservé (12 bytes)
│  │ ??? (garbage)         │  │  ← Contenu indéfini
│  └───────────────────────┘  │
├─────────────────────────────┤
│  ... espace libre ...       │
└─────────────────────────────┘
       ↑
       │
  new_node = 0x5678 (adresse du bloc)
```

**Que contient `new_node` ?**
- C'est un **pointeur** (une variable qui stocke une adresse)
- Il contient `0x5678` (l'adresse où commence le bloc de 12 bytes)

```c
// ÉTAPE 2 : Initialiser la donnée
new_node->data = 42;
```

**Que signifie `->` ?**

`->` est un raccourci pour **déréférencer** un pointeur et accéder à un membre.

```c
new_node->data  ≡  (*new_node).data
     │              │
     │              └─ Déréférence puis accède au membre
     └─ Raccourci pratique
```

**En mémoire** :

```ascii
APRÈS new_node->data = 42 :

0x5678  ┌───────────────┐
        │ data: 42      │  ← On a écrit 42 ici
        ├───────────────┤
0x567C  │ next: ???     │  ← Toujours indéfini (garbage)
        └───────────────┘
```

```c
// ÉTAPE 3 : Initialiser le pointeur
new_node->next = NULL;
```

```ascii
APRÈS new_node->next = NULL :

0x5678  ┌───────────────┐
        │ data: 42      │
        ├───────────────┤
0x567C  │ next: NULL    │  ← On a mis NULL (0x0)
        └───────────────┘

Maintenant le nœud est COMPLET et SÛR !
```

### Variantes

```c
// Liste doublement chaînée
typedef struct DNode {
    int data;
    struct DNode *prev;  // Pointeur vers le précédent
    struct DNode *next;  // Pointeur vers le suivant
} DNode;

// Liste avec données complexes
typedef struct Person {
    char name[50];
    int age;
    struct Person *next;
} Person;
```

## 4. Opérations de Base

### 4.1 Créer un Nœud

```c
Node* create_node(int data) {
    Node *new_node = malloc(sizeof(Node));
    if (new_node == NULL) {
        fprintf(stderr, "Erreur allocation mémoire\n");
        exit(1);
    }
    new_node->data = data;
    new_node->next = NULL;
    return new_node;
}
```

### 4.2 Insérer au Début (O(1))

```c
void insert_at_head(Node **head, int data) {
    Node *new_node = create_node(data);
    new_node->next = *head;  // Le nouveau pointe vers l'ancien head
    *head = new_node;        // head pointe vers le nouveau
}

// Utilisation
Node *head = NULL;
insert_at_head(&head, 10);  // [10] → NULL
insert_at_head(&head, 20);  // [20] → [10] → NULL
```

**Visualisation** :
```ascii
AVANT : head → [10] → NULL
APRÈS : head → [20] → [10] → NULL
                ↑      ↑
            new_node  ancien head
```

### 4.3 Insérer à la Fin (O(n))

```c
void insert_at_tail(Node **head, int data) {
    Node *new_node = create_node(data);
    
    // Cas 1 : Liste vide
    if (*head == NULL) {
        *head = new_node;
        return;
    }
    
    // Cas 2 : Parcourir jusqu'au dernier nœud
    Node *current = *head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = new_node;
}
```

### 4.4 Afficher la Liste (O(n))

```c
void print_list(Node *head) {
    Node *current = head;
    while (current != NULL) {
        printf("%d → ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}
```

### 4.5 Rechercher un Élément (O(n))

```c
Node* search(Node *head, int target) {
    Node *current = head;
    while (current != NULL) {
        if (current->data == target) {
            return current;  // Trouvé
        }
        current = current->next;
    }
    return NULL;  // Pas trouvé
}
```

### 4.6 Supprimer un Nœud (O(n))

```c
void delete_node(Node **head, int target) {
    if (*head == NULL) return;
    
    // Cas 1 : Le nœud à supprimer est le head
    if ((*head)->data == target) {
        Node *temp = *head;
        *head = (*head)->next;
        free(temp);
        return;
    }
    
    // Cas 2 : Chercher le nœud
    Node *current = *head;
    while (current->next != NULL) {
        if (current->next->data == target) {
            Node *temp = current->next;
            current->next = current->next->next;
            free(temp);
            return;
        }
        current = current->next;
    }
}
```

**Visualisation** :
```ascii
SUPPRIMER 20 :
AVANT : [10] → [20] → [30] → NULL
              temp↑
              
APRÈS : [10] ────────→ [30] → NULL
        [20] (libéré avec free)
```

### 4.7 Libérer Toute la Liste (O(n))

```c
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

## 5. Opérations Avancées

### 5.1 Inverser la Liste (O(n))

```c
void reverse_list(Node **head) {
    Node *prev = NULL;
    Node *current = *head;
    Node *next = NULL;
    
    while (current != NULL) {
        next = current->next;    // Sauvegarder le suivant
        current->next = prev;    // Inverser le lien
        prev = current;          // Avancer prev
        current = next;          // Avancer current
    }
    *head = prev;
}
```

**Visualisation** :
```ascii
AVANT : [10] → [20] → [30] → NULL
APRÈS : [30] → [20] → [10] → NULL
```

### 5.2 Détecter un Cycle (Floyd's Algorithm)

```c
int has_cycle(Node *head) {
    Node *slow = head;
    Node *fast = head;
    
    while (fast != NULL && fast->next != NULL) {
        slow = slow->next;           // Avance de 1
        fast = fast->next->next;     // Avance de 2
        
        if (slow == fast) {
            return 1;  // Cycle détecté
        }
    }
    return 0;  // Pas de cycle
}
```

**Principe** : Si la liste a un cycle, le "lapin" (fast) rattrape la "tortue" (slow).

### 5.3 Trouver le Milieu (O(n))

```c
Node* find_middle(Node *head) {
    Node *slow = head;
    Node *fast = head;
    
    while (fast != NULL && fast->next != NULL) {
        slow = slow->next;
        fast = fast->next->next;
    }
    return slow;  // slow est au milieu
}
```

### 5.4 Fusionner Deux Listes Triées

```c
Node* merge_sorted(Node *l1, Node *l2) {
    if (l1 == NULL) return l2;
    if (l2 == NULL) return l1;
    
    if (l1->data < l2->data) {
        l1->next = merge_sorted(l1->next, l2);
        return l1;
    } else {
        l2->next = merge_sorted(l1, l2->next);
        return l2;
    }
}
```

## 6. Liste Doublement Chaînée

### Structure

```c
typedef struct DNode {
    int data;
    struct DNode *prev;
    struct DNode *next;
} DNode;
```

### Avantages

- **Navigation bidirectionnelle** : Avancer et reculer
- **Suppression plus facile** : Pas besoin de chercher le précédent

### Insertion au Début

```c
void insert_at_head_double(DNode **head, int data) {
    DNode *new_node = malloc(sizeof(DNode));
    new_node->data = data;
    new_node->prev = NULL;
    new_node->next = *head;
    
    if (*head != NULL) {
        (*head)->prev = new_node;
    }
    *head = new_node;
}
```

## 7. Applications Réelles

### Historique de Navigateur

```c
typedef struct Page {
    char url[256];
    struct Page *prev;  // Page précédente
    struct Page *next;  // Page suivante
} Page;

// current_page->prev : Bouton "Retour"
// current_page->next : Bouton "Avancer"
```

### Gestion de Processus (OS)

```c
typedef struct Process {
    int pid;
    int priority;
    struct Process *next;
} Process;

// Liste circulaire pour le scheduler
```

### Undo/Redo (Éditeur de Texte)

```c
typedef struct Action {
    char command[100];
    struct Action *prev;
    struct Action *next;
} Action;
```

## 8. Sous le Capot

### Allocation Mémoire

```c
Node *node = malloc(sizeof(Node));
```

En assembleur (simplifié) :
```asm
; Calculer la taille
mov rdi, 16              ; sizeof(Node) = 8 (data) + 8 (next*)

; Appeler malloc
call malloc              ; Retourne adresse dans RAX

; Vérifier NULL
test rax, rax
jz allocation_failed
```

### Accès aux Membres

```c
node->data = 42;
```

En assembleur :
```asm
mov qword ptr [rax + 0], 42    ; data est à l'offset 0
mov qword ptr [rax + 8], NULL  ; next est à l'offset 8
```

## 9. Complexité Temporelle

| Opération           | Tableau | Liste Chaînée |
|---------------------|---------|---------------|
| Accès (index)       | O(1)    | O(n)          |
| Recherche           | O(n)    | O(n)          |
| Insertion (début)   | O(n)    | **O(1)**      |
| Insertion (fin)     | O(1)*   | O(n)          |
| Suppression (début) | O(n)    | **O(1)**      |
| Suppression (fin)   | O(1)*   | O(n)          |

*Avec taille dynamique connue

## 10. Avantages et Inconvénients

### ✅ Avantages

- **Taille dynamique** : Pas de limite fixe
- **Insertion/Suppression rapides** au début : O(1)
- **Pas de réallocation** coûteuse (comme avec realloc)

### ❌ Inconvénients

- **Accès séquentiel** : Pas d'accès direct par index
- **Surcoût mémoire** : Pointeur(s) par nœud
- **Cache-unfriendly** : Nœuds dispersés en mémoire
- **Gestion manuelle** : Risque de memory leaks

## 11. Sécurité & Risques

### ⚠️ Memory Leaks

```c
// ERREUR : Perdre la référence au head
Node *head = create_node(10);
head = create_node(20);  // Le premier nœud est perdu !
```

### ⚠️ Dangling Pointers

```c
Node *ptr = head;
free(head);
ptr->data = 42;  // ERREUR : ptr pointe vers mémoire libérée !
```

### ⚠️ Oublier de Libérer

```c
// TOUJOURS libérer la liste avant la fin du programme
free_list(&head);
```

### ⚠️ Double Free

```c
free(node);
free(node);  // ERREUR : Déjà libéré !
```

## 12. Bonnes Pratiques

1. **Toujours vérifier malloc** : Retour NULL = échec
2. **Utiliser typedef** pour simplifier les déclarations
3. **Libérer la mémoire** : Appeler free_list() à la fin
4. **Éviter les cycles** (sauf si volontaire)
5. **Mettre NULL après free** : `*head = NULL`
6. **Documenter** : Préciser si la fonction modifie head

## 13. Exercice Mental

Que se passe-t-il ?
```c
Node *head = create_node(10);
insert_at_head(&head, 20);
delete_node(&head, 10);
print_list(head);
```

<details>
<summary>Réponse</summary>

**Affiche : 20 → NULL**

Étapes :
1. `head → [10] → NULL`
2. `head → [20] → [10] → NULL`
3. Suppression de 10 : `head → [20] → NULL`
</details>

## 14. Ressources Complémentaires

- [Linked Lists (Wikipedia)](https://en.wikipedia.org/wiki/Linked_list)
- [Visualgo : Visualisation](https://visualgo.net/en/list)
- [Floyd's Cycle Detection](https://en.wikipedia.org/wiki/Cycle_detection)
- [Memory Management in C](https://en.cppreference.com/w/c/memory)


# Cours : Arbres Binaires (Binary Trees)

## 1. Introduction - Qu'est-ce qu'un Arbre ?

### 1.1 Concept de Base

Un **arbre** est une structure de données **hiérarchique** qui ressemble à un arbre généalogique (ou un organigramme d'entreprise).

**Analogie** : Pensez à un arbre généalogique :
- **Racine** = L'ancêtre au sommet
- **Nœuds** = Les personnes
- **Enfants** = Les descendants directs
- **Feuilles** = Les personnes sans enfants

### 1.2 Pourquoi "Binaire" ?

Un arbre **binaire** signifie que chaque nœud a **au maximum 2 enfants** :
- Un enfant **gauche**
- Un enfant **droite**

**Contrairement** à :
- Un arbre général : nombre illimité d'enfants
- Un arbre ternaire : max 3 enfants
- Une liste chaînée : max 1 enfant (cas dégénéré d'arbre)

### 1.3 Pourquoi Utiliser des Arbres ?

**Avantages** :
- **Recherche rapide** : O(log n) au lieu de O(n) (liste)
- **Insertion rapide** : O(log n)
- **Structure naturelle** : Représente des hiérarchies
- **Tri automatique** : Pour les Binary Search Trees

**Applications** :
- Systèmes de fichiers (dossiers/sous-dossiers)
- Bases de données (index B-trees)
- Compilation (arbres syntaxiques)
- IA (arbres de décision)
- Jeux (arbres minimax)

## 2. Visualisation et Terminologie

### 2.1 Anatomie d'un Arbre Binaire

```ascii
                    10  ← RACINE (Root)
                   /  \
                  /    \
                 5      15  ← NŒUDS INTERNES
                / \    /  \
               /   \  /    \
              3     7 12    20  ← FEUILLES (Leaves)

TERMINOLOGIE :

• Racine (Root) : 10
  - Le nœud au sommet (pas de parent)
  
• Nœuds internes : 5, 15
  - Ont au moins un enfant
  
• Feuilles (Leaves) : 3, 7, 12, 20
  - N'ont aucun enfant
  
• Parent de 7 : 5
• Enfants de 5 : 3 et 7
• Frères (Siblings) : 3 et 7 (même parent)

• Sous-arbre gauche de 10 : tout ce qui est sous 5
• Sous-arbre droit de 10 : tout ce qui est sous 15

• Profondeur (Depth) :
  - Profondeur de 10 : 0 (racine)
  - Profondeur de 5 : 1
  - Profondeur de 3 : 2
  
• Hauteur (Height) : 2
  - Nombre maximum de niveaux - 1
  - Ou : distance max racine → feuille
```

### 2.2 Différents Types d'Arbres Binaires

#### Arbre Binaire Complet

**Tous les niveaux** sont complètement remplis sauf peut-être le dernier.

```ascii
COMPLET :
        1
       / \
      2   3
     / \  /
    4  5 6

Niveau 0 : 1 nœud  (complet)
Niveau 1 : 2 nœuds (complet)
Niveau 2 : 3 nœuds (incomplet, mais à gauche)
```

#### Arbre Binaire Parfait

**Tous les niveaux** sont complètement remplis.

```ascii
PARFAIT :
        1
       / \
      2   3
     / \ / \
    4  5 6  7

Niveau 0 : 1 nœud
Niveau 1 : 2 nœuds
Niveau 2 : 4 nœuds
Total : 2^(h+1) - 1 nœuds
```

#### Arbre Binaire de Recherche (BST)

**Propriété** : Pour chaque nœud :
- **Gauche < Nœud < Droite**

```ascii
BST :
        50
       /  \
      30   70
     / \   / \
    20 40 60  80

• Tous les nœuds à GAUCHE de 50 sont < 50
• Tous les nœuds à DROITE de 50 sont > 50
• Cette propriété est vraie pour CHAQUE nœud

C'est ce qui permet la recherche rapide !
```

#### Arbre Dégénéré (Worst Case)

L'arbre devient une **liste chaînée**.

```ascii
DÉGÉNÉRÉ :
    1
     \
      2
       \
        3
         \
          4

Hauteur = n-1 (très mauvais)
Recherche = O(n) au lieu de O(log n)
```

## 3. Représentation en Mémoire

### 3.1 Structure d'un Nœud

```c
typedef struct TreeNode {
    int data;                // Donnée stockée
    struct TreeNode *left;   // Pointeur vers enfant gauche
    struct TreeNode *right;  // Pointeur vers enfant droit
} TreeNode;
```

### 3.2 Visualisation Mémoire

```ascii
ARBRE LOGIQUE :
        10
       /  \
      5    15

MÉMOIRE PHYSIQUE (dispersée dans le Heap) :

Adresse    Contenu
0x1000  ┌──────────┐
        │ data: 10 │  ← Nœud racine
        │ left: ───┼──┐
        │ right: ──┼─┐│
        └──────────┘ ││
                     ││
0x2000  ┌──────────┐ ││
        │ data: 5  │ ← Enfant gauche
        │ left: NULL│ │
        │ right: NUL│ │
        └──────────┘ │
                     │
0x3000  ┌──────────┐ │
        │ data: 15 │ ← Enfant droit
        │ left: NULL│
        │ right: NUL│
        └──────────┘

Chaque nœud occupe :
- 4 bytes (data, int)
- 8 bytes (left, pointeur 64-bit)
- 8 bytes (right, pointeur 64-bit)
= 20 bytes (+ padding pour alignement = 24)
```

### 2.3 Pourquoi des Pointeurs ?

Les enfants peuvent être **n'importe où** en mémoire (allocation dynamique avec `malloc`).

**Contrairement à un tableau** :
- Tableau : éléments contigus
- Arbre : nœuds dispersés, liés par pointeurs

## 3. Modèle OSI et TCP/IP - Les 7 Couches

```ascii
┌─────────────────┬──────────────────────────────────────────┐
│  COUCHE         │  RÔLE                                    │
├─────────────────┼──────────────────────────────────────────┤
│  7. APPLICATION │  HTTP, FTP, SSH, DNS                     │
│                 │  ← Votre code avec socket()              │
├─────────────────┼──────────────────────────────────────────┤
│  6. PRÉSENTATION│  Chiffrement (TLS/SSL), compression      │
├─────────────────┼──────────────────────────────────────────┤
│  5. SESSION     │  Maintien de la session                  │
├─────────────────┼──────────────────────────────────────────┤
│  4. TRANSPORT   │  TCP (fiable) / UDP (rapide)             │
│                 │  Ports (source/destination)              │
├─────────────────┼──────────────────────────────────────────┤
│  3. RÉSEAU      │  IP (adressage, routage)                 │
│                 │  192.168.1.1 → 8.8.8.8                   │
├─────────────────┼──────────────────────────────────────────┤
│  2. LIAISON     │  Ethernet, WiFi (MAC address)            │
│                 │  Trames, switches                        │
├─────────────────┼──────────────────────────────────────────┤
│  1. PHYSIQUE    │  Câbles, ondes, bits physiques           │
└─────────────────┴──────────────────────────────────────────┘
```

### 2.4 Encapsulation des Données

Chaque couche **ajoute son propre header** :

```ascii
DONNÉES ENVOYÉES : "Hello"

Couche Application :
┌──────┐
│Hello │
└──────┘

Couche Transport (TCP) :
┌──────────┬──────┐
│ TCP Head │Hello │  ← Ajout port source/dest
└──────────┴──────┘

Couche Réseau (IP) :
┌─────────┬──────────┬──────┐
│ IP Head │ TCP Head │Hello │  ← Ajout IP source/dest
└─────────┴──────────┴──────┘

Couche Liaison (Ethernet) :
┌────────┬─────────┬──────────┬──────┬─────────┐
│ Eth H  │ IP Head │ TCP Head │Hello │ Eth CRC │
└────────┴─────────┴──────────┴──────┴─────────┘

Sur le câble : Tout est envoyé en bits
```

## 3. Structure

```c
typedef struct TreeNode {
    int data;
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;
```

## 4. Opérations de Base

### Créer un Nœud

```c
TreeNode* create_node(int value) {
    TreeNode *node = malloc(sizeof(TreeNode));
    node->data = value;
    node->left = NULL;
    node->right = NULL;
    return node;
}
```

### Insérer (BST - Binary Search Tree)

```c
TreeNode* insert(TreeNode *root, int value) {
    if (root == NULL) {
        return create_node(value);
    }
    
    if (value < root->data) {
        root->left = insert(root->left, value);
    } else {
        root->right = insert(root->right, value);
    }
    
    return root;
}
```

### Rechercher

```c
TreeNode* search(TreeNode *root, int value) {
    if (root == NULL || root->data == value) {
        return root;
    }
    
    if (value < root->data) {
        return search(root->left, value);
    } else {
        return search(root->right, value);
    }
}
```

## 5. Parcours (Traversals)

### In-Order (Gauche → Racine → Droite)

```c
void inorder(TreeNode *root) {
    if (root != NULL) {
        inorder(root->left);
        printf("%d ", root->data);
        inorder(root->right);
    }
}
// Résultat trié pour un BST : 3 5 7 10 12 15 20
```

### Pre-Order (Racine → Gauche → Droite)

```c
void preorder(TreeNode *root) {
    if (root != NULL) {
        printf("%d ", root->data);
        preorder(root->left);
        preorder(root->right);
    }
}
// Résultat : 10 5 3 7 15 12 20
```

### Post-Order (Gauche → Droite → Racine)

```c
void postorder(TreeNode *root) {
    if (root != NULL) {
        postorder(root->left);
        postorder(root->right);
        printf("%d ", root->data);
    }
}
// Résultat : 3 7 5 12 20 15 10
```

### Level-Order (Par Niveau)

```c
void levelorder(TreeNode *root) {
    if (root == NULL) return;
    
    Queue q;
    init_queue(&q);
    enqueue(&q, root);
    
    while (!is_empty(&q)) {
        TreeNode *node = dequeue(&q);
        printf("%d ", node->data);
        
        if (node->left) enqueue(&q, node->left);
        if (node->right) enqueue(&q, node->right);
    }
}
// Résultat : 10 5 15 3 7 12 20
```

## 6. Hauteur et Profondeur

```c
int height(TreeNode *root) {
    if (root == NULL) return -1;
    
    int left_height = height(root->left);
    int right_height = height(root->right);
    
    return 1 + (left_height > right_height ? left_height : right_height);
}
```

## 7. Complexité

| Opération  | BST Équilibré | BST Déséquilibré |
|------------|---------------|------------------|
| Recherche  | O(log n)      | O(n)             |
| Insertion  | O(log n)      | O(n)             |
| Suppression| O(log n)      | O(n)             |

## 8. Applications

- Systèmes de fichiers (arborescences)
- Bases de données (index B-trees)
- Compilation (arbres syntaxiques)
- Recherche efficace

## Ressources

- [Binary Trees (Wikipedia)](https://en.wikipedia.org/wiki/Binary_tree)
- [Binary Search Tree](https://en.wikipedia.org/wiki/Binary_search_tree)


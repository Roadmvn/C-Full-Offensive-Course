# Arbres Binaires (Binary Trees)

Structure hiérarchique avec au plus 2 enfants par nœud.

## Structure

```c
typedef struct TreeNode {
    int data;
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;
```

## BST (Binary Search Tree)

**Propriété** : Gauche < Racine < Droite

## Parcours

- **In-Order** : G → R → D (trié pour BST)
- **Pre-Order** : R → G → D
- **Post-Order** : G → D → R
- **Level-Order** : Par niveau (BFS)

## Complexité (BST équilibré)

| Opération  | Complexité |
|------------|------------|
| Recherche  | O(log n)   |
| Insertion  | O(log n)   |
| Suppression| O(log n)   |

## Compilation

```bash
gcc example.c -o tree
./tree
```


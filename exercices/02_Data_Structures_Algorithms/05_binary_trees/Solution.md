# SOLUTION : ARBRES BINAIRES

IMPLÉMENTATION COMPLÈTE D'UN BST


---


```c
#include <stdio.h>
#include <stdlib.h>
```


```c
typedef struct TreeNode {
    int data;
```
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;


```c
// Créer un nœud
```
TreeNode* create_node(int value) {
    TreeNode *node = malloc(sizeof(TreeNode));
    node->data = value;
    node->left = NULL;
    node->right = NULL;
    return node;
}


```c
// Insérer (récursif)
```
TreeNode* insert(TreeNode *root, int value) {
    if (root == NULL) {
        return create_node(value);
    }
    
    if (value < root->data) {
        root->left = insert(root->left, value);
    } else if (value > root->data) {
        root->right = insert(root->right, value);
    }
    
    return root;
}


```c
// Trouver le minimum
```
TreeNode* find_min(TreeNode *root) {
    while (root && root->left != NULL) {
        root = root->left;
    }
    return root;
}


```c
// Supprimer un nœud
```
TreeNode* delete_node(TreeNode *root, int value) {
    if (root == NULL) return NULL;
    
    if (value < root->data) {
        root->left = delete_node(root->left, value);
    } else if (value > root->data) {
        root->right = delete_node(root->right, value);
    } else {

```c
        // Nœud trouvé
```
        if (root->left == NULL) {
            TreeNode *temp = root->right;
            free(root);
            return temp;
        } else if (root->right == NULL) {
            TreeNode *temp = root->left;
            free(root);
            return temp;
        }
        

```c
        // Deux enfants : remplacer par le successeur
```
        TreeNode *temp = find_min(root->right);
        root->data = temp->data;
        root->right = delete_node(root->right, temp->data);
    }
    
    return root;
}


```c
// Hauteur
int height(TreeNode *root) {
```
    if (root == NULL) return -1;
    
    int left_h = height(root->left);
    int right_h = height(root->right);
    
    return 1 + (left_h > right_h ? left_h : right_h);
}


```c
// Compter les feuilles
int count_leaves(TreeNode *root) {
```
    if (root == NULL) return 0;
    if (root->left == NULL && root->right == NULL) return 1;
    return count_leaves(root->left) + count_leaves(root->right);
}


```c
// Vérifier si BST
int is_bst_util(TreeNode *root, int min, int max) {
```
    if (root == NULL) return 1;
    
    if (root->data < min || root->data > max) return 0;
    
    return is_bst_util(root->left, min, root->data - 1) &&
           is_bst_util(root->right, root->data + 1, max);
}

int is_bst(TreeNode *root) {
    return is_bst_util(root, INT_MIN, INT_MAX);
}


```c
// Miroir
```
TreeNode* mirror_tree(TreeNode *root) {
    if (root == NULL) return NULL;
    
    TreeNode *temp = root->left;
    root->left = mirror_tree(root->right);
    root->right = mirror_tree(temp);
    
    return root;
}


```c
// Affichage visuel (simplifié)
void print_tree(TreeNode *root, int space) {
```
    if (root == NULL) return;
    
    space += 5;
    print_tree(root->right, space);
    
    printf("\n");
    for (int i = 5; i < space; i++) printf(" ");
    printf("%d\n", root->data);
    
    print_tree(root->left, space);
}


```c
// Libérer
void free_tree(TreeNode *root) {
```
    if (root != NULL) {
        free_tree(root->left);
        free_tree(root->right);
        free(root);
    }
}


```c
int main() {
```
    TreeNode *root = NULL;
    

```c
    // Construction
    int values[] = {10, 5, 15, 3, 7, 12, 20};
```
    for (int i = 0; i < 7; i++) {
        root = insert(root, values[i]);
    }
    
    printf("Arbre créé\n");
    print_tree(root, 0);
    
    printf("\nHauteur : %d\n", height(root));
    printf("Feuilles : %d\n", count_leaves(root));
    printf("Est BST ? %s\n", is_bst(root) ? "OUI" : "NON");
    
    free_tree(root);
    
    return 0;
}


---
FIN DE LA SOLUTION

---



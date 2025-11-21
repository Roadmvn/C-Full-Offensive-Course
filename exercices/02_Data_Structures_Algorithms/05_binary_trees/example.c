#include <stdio.h>
#include <stdlib.h>

typedef struct TreeNode {
    int data;
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;

TreeNode* create_node(int value) {
    TreeNode *node = malloc(sizeof(TreeNode));
    node->data = value;
    node->left = NULL;
    node->right = NULL;
    return node;
}

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

void inorder(TreeNode *root) {
    if (root != NULL) {
        inorder(root->left);
        printf("%d ", root->data);
        inorder(root->right);
    }
}

void preorder(TreeNode *root) {
    if (root != NULL) {
        printf("%d ", root->data);
        preorder(root->left);
        preorder(root->right);
    }
}

void postorder(TreeNode *root) {
    if (root != NULL) {
        postorder(root->left);
        postorder(root->right);
        printf("%d ", root->data);
    }
}

int height(TreeNode *root) {
    if (root == NULL) return -1;
    
    int left_h = height(root->left);
    int right_h = height(root->right);
    
    return 1 + (left_h > right_h ? left_h : right_h);
}

int count_nodes(TreeNode *root) {
    if (root == NULL) return 0;
    return 1 + count_nodes(root->left) + count_nodes(root->right);
}

void free_tree(TreeNode *root) {
    if (root != NULL) {
        free_tree(root->left);
        free_tree(root->right);
        free(root);
    }
}

int main() {
    printf("╔════════════════════════════════════════╗\n");
    printf("║         BINARY TREE DEMO               ║\n");
    printf("╚════════════════════════════════════════╝\n\n");
    
    TreeNode *root = NULL;
    
    printf("1. INSERTION\n");
    root = insert(root, 10);
    root = insert(root, 5);
    root = insert(root, 15);
    root = insert(root, 3);
    root = insert(root, 7);
    root = insert(root, 12);
    root = insert(root, 20);
    
    printf("Arbre créé avec : 10, 5, 15, 3, 7, 12, 20\n");
    
    printf("\n2. PARCOURS\n");
    printf("In-order   : ");
    inorder(root);
    printf("\n");
    
    printf("Pre-order  : ");
    preorder(root);
    printf("\n");
    
    printf("Post-order : ");
    postorder(root);
    printf("\n");
    
    printf("\n3. STATISTIQUES\n");
    printf("Hauteur : %d\n", height(root));
    printf("Nombre de nœuds : %d\n", count_nodes(root));
    
    printf("\n4. RECHERCHE\n");
    TreeNode *found = search(root, 7);
    printf("Recherche 7 : %s\n", found ? "TROUVÉ" : "NON TROUVÉ");
    
    found = search(root, 99);
    printf("Recherche 99 : %s\n", found ? "TROUVÉ" : "NON TROUVÉ");
    
    free_tree(root);
    
    printf("\n════════════════════════════════════════\n");
    return 0;
}


#include <stdio.h>
#include <stdlib.h>

// Définition de la structure du nœud
typedef struct Node {
    int data;
    struct Node *next;
} Node;

// Créer un nouveau nœud
Node* create_node(int data) {
    Node *new_node = malloc(sizeof(Node));
    if (new_node == NULL) {
        fprintf(stderr, "Erreur d'allocation mémoire\n");
        exit(1);
    }
    new_node->data = data;
    new_node->next = NULL;
    return new_node;
}

// Insérer au début
void insert_at_head(Node **head, int data) {
    Node *new_node = create_node(data);
    new_node->next = *head;
    *head = new_node;
}

// Insérer à la fin
void insert_at_tail(Node **head, int data) {
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

// Afficher la liste
void print_list(Node *head) {
    Node *current = head;
    printf("Liste : ");
    while (current != NULL) {
        printf("%d → ", current->data);
        current = current->next;
    }
    printf("NULL\n");
}

// Rechercher un élément
Node* search(Node *head, int target) {
    Node *current = head;
    while (current != NULL) {
        if (current->data == target) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Supprimer un nœud
void delete_node(Node **head, int target) {
    if (*head == NULL) return;
    
    // Cas spécial : supprimer le head
    if ((*head)->data == target) {
        Node *temp = *head;
        *head = (*head)->next;
        free(temp);
        return;
    }
    
    // Chercher le nœud à supprimer
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

// Compter les éléments
int count_nodes(Node *head) {
    int count = 0;
    Node *current = head;
    while (current != NULL) {
        count++;
        current = current->next;
    }
    return count;
}

// Inverser la liste
void reverse_list(Node **head) {
    Node *prev = NULL;
    Node *current = *head;
    Node *next = NULL;
    
    while (current != NULL) {
        next = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }
    *head = prev;
}

// Trouver le milieu
Node* find_middle(Node *head) {
    if (head == NULL) return NULL;
    
    Node *slow = head;
    Node *fast = head;
    
    while (fast != NULL && fast->next != NULL) {
        slow = slow->next;
        fast = fast->next->next;
    }
    return slow;
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
    printf("╔════════════════════════════════════════╗\n");
    printf("║      DÉMONSTRATION LISTE CHAÎNÉE       ║\n");
    printf("╚════════════════════════════════════════╝\n\n");

    Node *head = NULL;
    
    // 1. Insertion au début
    printf("1. INSERTION AU DÉBUT\n");
    insert_at_head(&head, 10);
    print_list(head);
    insert_at_head(&head, 20);
    print_list(head);
    insert_at_head(&head, 30);
    print_list(head);
    
    // 2. Insertion à la fin
    printf("\n2. INSERTION À LA FIN\n");
    insert_at_tail(&head, 5);
    print_list(head);
    insert_at_tail(&head, 3);
    print_list(head);
    
    // 3. Compter les éléments
    printf("\n3. NOMBRE D'ÉLÉMENTS\n");
    printf("Taille de la liste : %d\n", count_nodes(head));
    
    // 4. Recherche
    printf("\n4. RECHERCHE\n");
    int target = 20;
    Node *found = search(head, target);
    if (found != NULL) {
        printf("Élément %d trouvé à l'adresse %p\n", target, (void*)found);
    } else {
        printf("Élément %d non trouvé\n", target);
    }
    
    target = 99;
    found = search(head, target);
    if (found != NULL) {
        printf("Élément %d trouvé\n", target);
    } else {
        printf("Élément %d non trouvé\n", target);
    }
    
    // 5. Trouver le milieu
    printf("\n5. TROUVER LE MILIEU\n");
    Node *middle = find_middle(head);
    if (middle != NULL) {
        printf("Élément du milieu : %d\n", middle->data);
    }
    
    // 6. Suppression
    printf("\n6. SUPPRESSION\n");
    printf("Liste avant suppression : ");
    print_list(head);
    
    delete_node(&head, 20);
    printf("Après suppression de 20 : ");
    print_list(head);
    
    delete_node(&head, 3);
    printf("Après suppression de 3  : ");
    print_list(head);
    
    // 7. Inversion
    printf("\n7. INVERSION\n");
    printf("Liste avant inversion : ");
    print_list(head);
    
    reverse_list(&head);
    printf("Liste après inversion : ");
    print_list(head);
    
    // 8. Nouvelle liste pour démonstration
    printf("\n8. CRÉATION D'UNE NOUVELLE LISTE\n");
    free_list(&head);  // Libérer l'ancienne
    
    for (int i = 1; i <= 10; i++) {
        insert_at_tail(&head, i * 10);
    }
    print_list(head);
    printf("Taille : %d\n", count_nodes(head));
    
    // Milieu
    middle = find_middle(head);
    if (middle != NULL) {
        printf("Milieu : %d\n", middle->data);
    }
    
    // 9. Libération finale
    printf("\n9. LIBÉRATION DE LA MÉMOIRE\n");
    free_list(&head);
    printf("Liste libérée : ");
    print_list(head);
    printf("Taille : %d\n", count_nodes(head));
    
    printf("\n════════════════════════════════════════\n");
    printf("Programme terminé avec succès.\n");
    
    return 0;
}


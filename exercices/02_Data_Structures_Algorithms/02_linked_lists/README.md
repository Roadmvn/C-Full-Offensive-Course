# Listes Chaînées (Linked Lists)

Structure de données dynamique où chaque élément pointe vers le suivant.

## Structure d'un Nœud

```c
typedef struct Node {
    int data;
    struct Node *next;
} Node;
```

## Opérations de Base

```c
// Créer un nœud
Node* node = malloc(sizeof(Node));
node->data = 42;
node->next = NULL;

// Insérer au début (O(1))
new_node->next = head;
head = new_node;

// Parcourir la liste (O(n))
while (current != NULL) {
    printf("%d ", current->data);
    current = current->next;
}

// Libérer la liste
while (head != NULL) {
    Node *temp = head;
    head = head->next;
    free(temp);
}
```

## Complexité

| Opération        | Complexité |
|------------------|------------|
| Accès (index)    | O(n)       |
| Insertion (début)| O(1)       |
| Insertion (fin)  | O(n)       |
| Suppression      | O(n)       |
| Recherche        | O(n)       |

## Avantages

- Taille dynamique (pas de limite fixe)
- Insertion/Suppression rapides au début
- Pas de réallocation coûteuse

## Inconvénients

- Accès séquentiel (pas d'indexation directe)
- Surcoût mémoire (pointeurs)
- Cache-unfriendly (mémoire non contiguë)

## Compilation

```bash
gcc example.c -o linkedlist
./linkedlist
```

## Applications

- Gestionnaires de mémoire (malloc/free)
- Historique de navigateur
- Undo/Redo dans les éditeurs
- Files d'attente (queues)
- Piles (stacks)


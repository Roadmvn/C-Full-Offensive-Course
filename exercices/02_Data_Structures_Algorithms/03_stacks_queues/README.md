# Piles et Files (Stacks & Queues)

Structures de données abstraites avec ordre d'accès spécifique.

## Stack (Pile) - LIFO

**Last In, First Out** : Le dernier ajouté est le premier retiré.

```c
// Structure
typedef struct Stack {
    int items[MAX];
    int top;
} Stack;

// Opérations O(1)
push(&stack, value);      // Empiler
int val = pop(&stack);    // Dépiler
int top = peek(&stack);   // Consulter sommet
```

### Applications

- Call stack (appels de fonctions)
- Undo/Redo
- Vérification de parenthèses
- Parsing d'expressions
- Navigation (historique)

## Queue (File) - FIFO

**First In, First Out** : Le premier ajouté est le premier retiré.

```c
// Structure (Tableau Circulaire)
typedef struct Queue {
    int items[MAX];
    int front, rear, count;
} Queue;

// Opérations O(1)
enqueue(&queue, value);     // Enfiler
int val = dequeue(&queue);  // Défiler
int front = peek(&queue);   // Consulter premier
```

### Applications

- Ordonnanceur de processus
- Buffer de messages
- Gestion d'événements
- Parcours en largeur (BFS)
- File d'attente d'impression

## Complexité

| Opération   | Stack | Queue |
|-------------|-------|-------|
| Push/Enqueue| O(1)  | O(1)  |
| Pop/Dequeue | O(1)  | O(1)  |
| Peek        | O(1)  | O(1)  |
| Search      | O(n)  | O(n)  |

## Compilation

```bash
gcc example.c -o stacks
./stacks
```

## Variantes

- **Priority Queue** : File avec priorités
- **Deque** : Double-ended queue (insertion/suppression aux 2 bouts)
- **Circular Queue** : File circulaire (optimisation mémoire)


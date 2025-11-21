# Cours : Piles et Files (Stacks & Queues)

## 1. Introduction - Deux Façons d'Organiser une Liste

### 1.1 Le Concept Expliqué avec des Objets Physiques

Imaginez que vous avez une **pile d'assiettes** et une **file d'attente** au supermarché.

#### PILE (Stack) = Empilement d'Assiettes 🍽️

```ascii
Vue de côté d'une pile d'assiettes :

        ┌─────────┐
        │Assiette4│  ← DERNIER ajouté (TOP)
        ├─────────┤
        │Assiette3│
        ├─────────┤
        │Assiette2│
        ├─────────┤
        │Assiette1│  ← PREMIER ajouté
        └─────────┘
          Table
```

**Comment ça fonctionne ?**

1. **Ajouter** une assiette :
   - On la pose **au-dessus** de la pile
   - C'est maintenant la **nouvelle assiette du dessus**

2. **Retirer** une assiette :
   - On peut seulement prendre **celle du dessus**
   - On ne peut PAS prendre celle du milieu (sinon tout tombe !)

**Ordre** : **LIFO** = Last In, First Out
- La **dernière** assiette ajoutée est la **première** retirée
- L'assiette du bas sera la **dernière** à sortir

#### FILE (Queue) = File d'Attente au Supermarché 🛒

```ascii
Vue du dessus d'une file d'attente :

SORTIE ←  [👤] [👤] [👤] [👤]  ← ENTRÉE
   ↑         1    2    3    4      ↑
PREMIER                      DERNIER
 sorti                        entré
```

**Comment ça fonctionne ?**

1. **Ajouter** quelqu'un :
   - Il se place à la **fin** de la file
   - C'est le **dernier** arrivé

2. **Retirer** quelqu'un :
   - La personne **au début** (arrivée en premier) part
   - Les autres avancent

**Ordre** : **FIFO** = First In, First Out
- Le **premier** arrivé est le **premier** servi
- Comme dans une vraie file d'attente !

### 1.2 Glossaire des Acronymes

| Acronyme | Signification | Traduction | Structure |
|----------|---------------|------------|-----------|
| **LIFO** | Last In, First Out | Dernier Entré, Premier Sorti | **Pile** |
| **FIFO** | First In, First Out | Premier Entré, Premier Sorti | **File** |

**Astuce Mnémotechnique** :
- **LIFO** = Pile d'assiettes (Last In = dessus, First Out = on prend le dessus)
- **FIFO** = File au cinéma (First In = devant, First Out = sort en premier)

### 1.3 Pourquoi Deux Structures Différentes ?

**Question** : Pourquoi ne pas toujours utiliser la même ?

**Réponse** : Parce que **l'ordre** a de l'importance selon le problème !

#### Exemples où l'ORDRE LIFO est crucial :

1. **Appels de fonctions** (Call Stack)
   ```
   main() appelle fonction_a()
   fonction_a() appelle fonction_b()
   fonction_b() appelle fonction_c()
   
   Pile :
   ┌────────────┐
   │fonction_c()│  ← Dernière appelée, première à terminer
   ├────────────┤
   │fonction_b()│
   ├────────────┤
   │fonction_a()│
   ├────────────┤
   │main()      │  ← Première appelée, dernière à terminer
   └────────────┘
   ```

2. **Undo/Redo** (éditeur de texte)
   - Dernière action = première annulée

3. **Vérification de parenthèses**
   - `{[()]}` → Dernière ouverte = première fermée

#### Exemples où l'ORDRE FIFO est crucial :

1. **File d'impression**
   - Premier document envoyé = premier imprimé (équité)

2. **Buffer de messages**
   - Premier message reçu = premier traité (ordre chronologique)

3. **Parcours en largeur** (algorithme de graphe)
   - Explorer les voisins dans l'ordre de découverte

### 1.4 Structures Abstraites vs Implémentation

**Important** : Pile et File sont des **concepts** (abstractions), pas des implémentations.

```ascii
CONCEPT (Abstrait) :          IMPLÉMENTATION (Concrète) :

┌──────────┐                  ┌──────────────────┐
│  PILE    │                  │  Avec Tableau    │
│  (LIFO)  │  ───peut être──→ │  int[100]        │
└──────────┘                  └──────────────────┘
                                     OU
                              ┌──────────────────┐
                              │  Avec Liste      │
                              │  Chaînée         │
                              └──────────────────┘

Même concept, deux façons de le réaliser en code
```

**On peut implémenter** :
- Une Pile avec un tableau
- Une Pile avec une liste chaînée
- Une File avec un tableau circulaire
- Une File avec une liste chaînée

**Le concept (LIFO ou FIFO) reste le même, seule l'implémentation change !**

## 2. Visualisation

### Pile (Stack)

```ascii
PILE = Empilement d'assiettes

         TOP
          ↓
      ┌───────┐
PUSH  │   3   │  ← Dernier ajouté
─────→│───────│
      │   2   │
      │───────│
      │   1   │  ← Premier ajouté
      └───────┘
         ↓
        POP (retire 3)

LIFO : Last In, First Out
```

### File (Queue)

```ascii
FILE = File d'attente au guichet

    FRONT              REAR
      ↓                 ↓
    ┌───┬───┬───┬───┬───┐
    │ 1 │ 2 │ 3 │ 4 │ 5 │
    └───┴───┴───┴───┴───┘
      ↑                 ↑
   DEQUEUE          ENQUEUE
  (retire 1)       (ajoute 6)

FIFO : First In, First Out
```

## 3. Pile (Stack)

### 3.1 Structure

Implémentation avec **tableau** :

```c
#define MAX_SIZE 100

typedef struct Stack {
    int items[MAX_SIZE];
    int top;  // Index du sommet (-1 si vide)
} Stack;
```

Implémentation avec **liste chaînée** :

```c
typedef struct StackNode {
    int data;
    struct StackNode *next;
} StackNode;

typedef struct Stack {
    StackNode *top;
} Stack;
```

### 3.2 Opérations de Base (Tableau)

#### Initialiser

```c
void init_stack(Stack *s) {
    s->top = -1;
}
```

#### Push (Empiler) - O(1)

```c
void push(Stack *s, int value) {
    if (s->top >= MAX_SIZE - 1) {
        printf("Stack overflow!\n");
        return;
    }
    s->items[++s->top] = value;
}
```

#### Pop (Dépiler) - O(1)

```c
int pop(Stack *s) {
    if (s->top < 0) {
        printf("Stack underflow!\n");
        return -1;
    }
    return s->items[s->top--];
}
```

#### Peek (Consulter le sommet) - O(1)

```c
int peek(Stack *s) {
    if (s->top < 0) {
        printf("Stack vide!\n");
        return -1;
    }
    return s->items[s->top];
}
```

#### Is Empty - O(1)

```c
int is_empty(Stack *s) {
    return s->top < 0;
}
```

### 3.3 Implémentation avec Liste Chaînée

```c
void push(Stack *s, int value) {
    StackNode *new_node = malloc(sizeof(StackNode));
    new_node->data = value;
    new_node->next = s->top;
    s->top = new_node;
}

int pop(Stack *s) {
    if (s->top == NULL) {
        printf("Stack vide!\n");
        return -1;
    }
    StackNode *temp = s->top;
    int value = temp->data;
    s->top = s->top->next;
    free(temp);
    return value;
}
```

### 3.4 Applications de la Pile

#### 1. Call Stack (Appels de Fonctions)

```c
void fonction_a() {
    fonction_b();
}
void fonction_b() {
    fonction_c();
}
void fonction_c() {
    // ...
}

// Call stack :
// fonction_c()  ← top
// fonction_b()
// fonction_a()
// main()
```

#### 2. Vérification des Parenthèses

```c
int check_parentheses(char *expr) {
    Stack s;
    init_stack(&s);
    
    for (int i = 0; expr[i]; i++) {
        if (expr[i] == '(') {
            push(&s, '(');
        } else if (expr[i] == ')') {
            if (is_empty(&s)) return 0;  // Pas équilibré
            pop(&s);
        }
    }
    
    return is_empty(&s);  // Équilibré si vide
}
```

#### 3. Évaluation d'Expression Postfixée (RPN)

```c
// "3 4 + 2 *" → (3 + 4) * 2 = 14
int eval_postfix(char *expr) {
    Stack s;
    init_stack(&s);
    
    for (int i = 0; expr[i]; i++) {
        if (isdigit(expr[i])) {
            push(&s, expr[i] - '0');
        } else if (expr[i] == '+') {
            int b = pop(&s);
            int a = pop(&s);
            push(&s, a + b);
        }
        // ... autres opérateurs
    }
    
    return pop(&s);
}
```

## 4. File (Queue)

### 4.1 Structure

Implémentation avec **tableau circulaire** :

```c
#define MAX_SIZE 100

typedef struct Queue {
    int items[MAX_SIZE];
    int front;  // Index du premier élément
    int rear;   // Index du dernier élément
    int count;  // Nombre d'éléments
} Queue;
```

Implémentation avec **liste chaînée** :

```c
typedef struct QueueNode {
    int data;
    struct QueueNode *next;
} QueueNode;

typedef struct Queue {
    QueueNode *front;
    QueueNode *rear;
} Queue;
```

### 4.2 Opérations de Base (Tableau Circulaire)

#### Initialiser

```c
void init_queue(Queue *q) {
    q->front = 0;
    q->rear = -1;
    q->count = 0;
}
```

#### Enqueue (Enfiler) - O(1)

```c
void enqueue(Queue *q, int value) {
    if (q->count >= MAX_SIZE) {
        printf("Queue pleine!\n");
        return;
    }
    q->rear = (q->rear + 1) % MAX_SIZE;  // Circulaire
    q->items[q->rear] = value;
    q->count++;
}
```

#### Dequeue (Défiler) - O(1)

```c
int dequeue(Queue *q) {
    if (q->count <= 0) {
        printf("Queue vide!\n");
        return -1;
    }
    int value = q->items[q->front];
    q->front = (q->front + 1) % MAX_SIZE;  // Circulaire
    q->count--;
    return value;
}
```

#### Peek (Front) - O(1)

```c
int peek_queue(Queue *q) {
    if (q->count <= 0) {
        printf("Queue vide!\n");
        return -1;
    }
    return q->items[q->front];
}
```

### 4.3 Pourquoi Tableau Circulaire ?

```ascii
PROBLÈME : Tableau linéaire

Après plusieurs enqueue/dequeue :
  0   1   2   3   4
┌───┬───┬───┬───┬───┐
│   │   │   │ 7 │ 8 │  ← Espace gaspillé au début !
└───┴───┴───┴───┴───┘
              ↑   ↑
           front rear

SOLUTION : Tableau circulaire

  0   1   2   3   4
┌───┬───┬───┬───┬───┐
│ 9 │10 │   │ 7 │ 8 │  ← rear revient au début
└───┴───┴───┴───┴───┘
          ↑   ↑
       rear front

Formule : (index + 1) % MAX_SIZE
```

### 4.4 Applications de la File

#### 1. Ordonnanceur de Processus

```c
// OS scheduler avec round-robin
Queue ready_queue;
Process *current = dequeue(&ready_queue);
execute(current);
enqueue(&ready_queue, current);  // Remettre à la fin
```

#### 2. Buffer de Messages

```c
// Serveur réseau
Queue message_buffer;
enqueue(&message_buffer, new_message);
// Thread de traitement
Message *msg = dequeue(&message_buffer);
process_message(msg);
```

#### 3. Parcours en Largeur (BFS)

```c
void bfs(Graph *g, int start) {
    Queue q;
    init_queue(&q);
    enqueue(&q, start);
    
    while (!is_empty_queue(&q)) {
        int node = dequeue(&q);
        visit(node);
        
        for (int neighbor : neighbors(node)) {
            enqueue(&q, neighbor);
        }
    }
}
```

## 5. File de Priorité (Priority Queue)

Extension de la file où chaque élément a une **priorité**.

```c
typedef struct PQNode {
    int data;
    int priority;
    struct PQNode *next;
} PQNode;

void enqueue_priority(PQNode **head, int data, int priority) {
    PQNode *new_node = malloc(sizeof(PQNode));
    new_node->data = data;
    new_node->priority = priority;
    
    // Insérer selon la priorité
    if (*head == NULL || priority > (*head)->priority) {
        new_node->next = *head;
        *head = new_node;
    } else {
        PQNode *current = *head;
        while (current->next && current->next->priority >= priority) {
            current = current->next;
        }
        new_node->next = current->next;
        current->next = new_node;
    }
}
```

**Application** : Ordonnancement de tâches, Algorithme de Dijkstra

## 6. Deque (Double-Ended Queue)

File à **deux extrémités** (insertion/suppression aux deux bouts).

```c
void push_front(Deque *d, int value);
void push_back(Deque *d, int value);
int pop_front(Deque *d);
int pop_back(Deque *d);
```

**Application** : Historique de navigation (avancer/reculer)

## 7. Comparaison

| Opération   | Stack | Queue | Priority Queue |
|-------------|-------|-------|----------------|
| Insertion   | O(1)  | O(1)  | O(n) ou O(log n)* |
| Suppression | O(1)  | O(1)  | O(1)           |
| Accès       | Top O(1) | Front O(1) | Max O(1) |

*Avec tas binaire (heap)

## 8. Sous le Capot : Call Stack

```c
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
```

Call stack pour `factorial(3)` :

```ascii
┌─────────────────┐
│ factorial(1)    │  ← Retourne 1
├─────────────────┤
│ factorial(2)    │  ← Attend 1, calcule 2*1
├─────────────────┤
│ factorial(3)    │  ← Attend 2, calcule 3*2
└─────────────────┘
```

En assembleur :
```asm
call factorial      ; Push return address sur stack
; ...
ret                 ; Pop return address et saute
```

## 9. Sécurité & Risques

### ⚠️ Stack Overflow

```c
void infinite_recursion() {
    infinite_recursion();  // Stack overflow !
}
```

### ⚠️ Vérifier Avant Pop/Dequeue

```c
if (!is_empty(&stack)) {
    int value = pop(&stack);
}
```

## 10. Bonnes Pratiques

1. **Toujours vérifier** si vide avant pop/dequeue
2. **Vérifier** si plein avant push/enqueue (tableau)
3. **Libérer la mémoire** (liste chaînée)
4. **Utiliser typedef** pour simplifier
5. **Documenter** les invariants (front, rear, top)

## 11. Exercice Mental

Quelle est la sortie ?
```c
Stack s;
init_stack(&s);
push(&s, 10);
push(&s, 20);
push(&s, 30);
pop(&s);
push(&s, 40);
printf("%d\n", pop(&s));
```

<details>
<summary>Réponse</summary>

**40**

État de la pile :
1. [10]
2. [10, 20]
3. [10, 20, 30]
4. pop() → [10, 20]
5. [10, 20, 40]
6. pop() → 40
</details>

## 12. Ressources

- [Stack (Wikipedia)](https://en.wikipedia.org/wiki/Stack_(abstract_data_type))
- [Queue (Wikipedia)](https://en.wikipedia.org/wiki/Queue_(abstract_data_type))
- [Call stack](https://en.wikipedia.org/wiki/Call_stack)


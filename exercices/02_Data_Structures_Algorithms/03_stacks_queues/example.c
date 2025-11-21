#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE 10

// ============= STACK (Tableau) =============

typedef struct Stack {
    int items[MAX_SIZE];
    int top;
} Stack;

void init_stack(Stack *s) {
    s->top = -1;
}

int is_stack_empty(Stack *s) {
    return s->top < 0;
}

int is_stack_full(Stack *s) {
    return s->top >= MAX_SIZE - 1;
}

void push(Stack *s, int value) {
    if (is_stack_full(s)) {
        printf("Stack overflow!\n");
        return;
    }
    s->items[++s->top] = value;
}

int pop(Stack *s) {
    if (is_stack_empty(s)) {
        printf("Stack underflow!\n");
        return -1;
    }
    return s->items[s->top--];
}

int peek_stack(Stack *s) {
    if (is_stack_empty(s)) {
        printf("Stack vide!\n");
        return -1;
    }
    return s->items[s->top];
}

void print_stack(Stack *s) {
    if (is_stack_empty(s)) {
        printf("Stack : (vide)\n");
        return;
    }
    printf("Stack : [");
    for (int i = 0; i <= s->top; i++) {
        printf("%d", s->items[i]);
        if (i < s->top) printf(", ");
    }
    printf("] ← TOP\n");
}

// ============= QUEUE (Tableau Circulaire) =============

typedef struct Queue {
    int items[MAX_SIZE];
    int front;
    int rear;
    int count;
} Queue;

void init_queue(Queue *q) {
    q->front = 0;
    q->rear = -1;
    q->count = 0;
}

int is_queue_empty(Queue *q) {
    return q->count == 0;
}

int is_queue_full(Queue *q) {
    return q->count >= MAX_SIZE;
}

void enqueue(Queue *q, int value) {
    if (is_queue_full(q)) {
        printf("Queue pleine!\n");
        return;
    }
    q->rear = (q->rear + 1) % MAX_SIZE;
    q->items[q->rear] = value;
    q->count++;
}

int dequeue(Queue *q) {
    if (is_queue_empty(q)) {
        printf("Queue vide!\n");
        return -1;
    }
    int value = q->items[q->front];
    q->front = (q->front + 1) % MAX_SIZE;
    q->count--;
    return value;
}

int peek_queue(Queue *q) {
    if (is_queue_empty(q)) {
        printf("Queue vide!\n");
        return -1;
    }
    return q->items[q->front];
}

void print_queue(Queue *q) {
    if (is_queue_empty(q)) {
        printf("Queue : (vide)\n");
        return;
    }
    printf("Queue : FRONT → [");
    int i = q->front;
    for (int c = 0; c < q->count; c++) {
        printf("%d", q->items[i]);
        if (c < q->count - 1) printf(", ");
        i = (i + 1) % MAX_SIZE;
    }
    printf("] ← REAR\n");
}

// ============= MAIN =============

int main() {
    printf("╔════════════════════════════════════════╗\n");
    printf("║         STACK & QUEUE DEMO             ║\n");
    printf("╚════════════════════════════════════════╝\n\n");
    
    // ===== STACK =====
    printf("═══ STACK (Pile - LIFO) ═══\n\n");
    
    Stack stack;
    init_stack(&stack);
    
    printf("1. Push 10, 20, 30\n");
    push(&stack, 10);
    push(&stack, 20);
    push(&stack, 30);
    print_stack(&stack);
    
    printf("\n2. Peek (consulter sommet)\n");
    printf("Top : %d\n", peek_stack(&stack));
    print_stack(&stack);
    
    printf("\n3. Pop\n");
    printf("Valeur retirée : %d\n", pop(&stack));
    print_stack(&stack);
    
    printf("\n4. Push 40, 50\n");
    push(&stack, 40);
    push(&stack, 50);
    print_stack(&stack);
    
    printf("\n5. Vider la stack\n");
    while (!is_stack_empty(&stack)) {
        printf("Pop : %d\n", pop(&stack));
    }
    print_stack(&stack);
    
    // ===== QUEUE =====
    printf("\n\n═══ QUEUE (File - FIFO) ═══\n\n");
    
    Queue queue;
    init_queue(&queue);
    
    printf("1. Enqueue 10, 20, 30\n");
    enqueue(&queue, 10);
    enqueue(&queue, 20);
    enqueue(&queue, 30);
    print_queue(&queue);
    
    printf("\n2. Peek (consulter front)\n");
    printf("Front : %d\n", peek_queue(&queue));
    print_queue(&queue);
    
    printf("\n3. Dequeue\n");
    printf("Valeur retirée : %d\n", dequeue(&queue));
    print_queue(&queue);
    
    printf("\n4. Enqueue 40, 50\n");
    enqueue(&queue, 40);
    enqueue(&queue, 50);
    print_queue(&queue);
    
    printf("\n5. Démonstration circulaire\n");
    dequeue(&queue);
    dequeue(&queue);
    print_queue(&queue);
    
    enqueue(&queue, 60);
    enqueue(&queue, 70);
    enqueue(&queue, 80);
    print_queue(&queue);
    
    printf("\n6. Vider la queue\n");
    while (!is_queue_empty(&queue)) {
        printf("Dequeue : %d\n", dequeue(&queue));
    }
    print_queue(&queue);
    
    // ===== COMPARAISON =====
    printf("\n\n═══ COMPARAISON STACK vs QUEUE ═══\n\n");
    
    printf("STACK (LIFO) - Last In, First Out\n");
    init_stack(&stack);
    push(&stack, 1);
    push(&stack, 2);
    push(&stack, 3);
    printf("Ajout : 1, 2, 3\n");
    printf("Retrait : %d, %d, %d (inverse !)\n", 
           pop(&stack), pop(&stack), pop(&stack));
    
    printf("\nQUEUE (FIFO) - First In, First Out\n");
    init_queue(&queue);
    enqueue(&queue, 1);
    enqueue(&queue, 2);
    enqueue(&queue, 3);
    printf("Ajout : 1, 2, 3\n");
    printf("Retrait : %d, %d, %d (même ordre !)\n", 
           dequeue(&queue), dequeue(&queue), dequeue(&queue));
    
    printf("\n════════════════════════════════════════\n");
    printf("Programme terminé avec succès.\n");
    
    return 0;
}


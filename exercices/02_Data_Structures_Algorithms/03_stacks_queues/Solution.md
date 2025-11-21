# SOLUTION : STACKS & QUEUES

Solution complète des exercices sur les piles et files.


---

### PARTIE 1 : VÉRIFICATEUR DE PARENTHÈSES

---


```c
#include <stdio.h>
#include <string.h>
```


```bash
#define MAX 100
```


```c
typedef struct {
    char items[MAX];
    int top;
} CharStack;
```


```c
void init(CharStack *s) { s->top = -1; }
int is_empty(CharStack *s) { return s->top < 0; }
void push_char(CharStack *s, char c) { s->items[++s->top] = c; }
char pop_char(CharStack *s) { return s->items[s->top--]; }
char peek_char(CharStack *s) { return s->items[s->top]; }
```

int is_matching(char open, char close) {
    return (open == '(' && close == ')') ||
           (open == '[' && close == ']') ||
           (open == '{' && close == '}');
}

int is_balanced(char *expr) {
    CharStack s;
    init(&s);
    
    for (int i = 0; expr[i]; i++) {
        char c = expr[i];
        

```c
        // Si ouverture : empiler
```
        if (c == '(' || c == '[' || c == '{') {
            push_char(&s, c);
        }

```c
        // Si fermeture : vérifier
```
        else if (c == ')' || c == ']' || c == '}') {
            if (is_empty(&s)) return 0;  // Pas d'ouverture
            char open = pop_char(&s);
            if (!is_matching(open, c)) return 0;  // Mauvais type
        }
    }
    
    return is_empty(&s);  // Doit être vide à la fin
}


```c
int main() {
```
    printf("VÉRIFICATEUR DE PARENTHÈSES\n\n");
    
    char *tests[] = {
        "(a + b)",
        "[(a + b) * c]",
        "{[()]}",
        "((a + b)",
        "(a + b]",
        "((a + b)))",
        NULL
    };
    
    for (int i = 0; tests[i]; i++) {
        printf("%s → %s\n", tests[i], 
               is_balanced(tests[i]) ? "VALIDE" : "INVALIDE");
    }
    
    return 0;
}


---

### PARTIE 2 : ÉVALUATEUR POSTFIXÉ (RPN)

---


```c
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
```


```c
typedef struct {
    int items[MAX];
    int top;
} IntStack;
```


```c
void init_int(IntStack *s) { s->top = -1; }
int is_empty_int(IntStack *s) { return s->top < 0; }
void push_int(IntStack *s, int val) { s->items[++s->top] = val; }
int pop_int(IntStack *s) { return s->items[s->top--]; }
```

int eval_postfix(char *expr) {
    IntStack s;
    init_int(&s);
    
    for (int i = 0; expr[i]; i++) {

```c
        // Ignorer les espaces
```
        if (expr[i] == ' ') continue;
        

```c
        // Si chiffre : empiler
```
        if (isdigit(expr[i])) {
            int num = 0;
            while (isdigit(expr[i])) {
                num = num * 10 + (expr[i] - '0');
                i++;
            }
            i--;  // Reculer d'un caractère
            push_int(&s, num);
        }

```c
        // Si opérateur : calculer
```
        else if (expr[i] == '+' || expr[i] == '-' || 
                 expr[i] == '*' || expr[i] == '/') {
            int b = pop_int(&s);
            int a = pop_int(&s);
            int result;
            
            switch (expr[i]) {
                case '+': result = a + b; break;
                case '-': result = a - b; break;
                case '*': result = a * b; break;
                case '/': result = a / b; break;
            }
            
            push_int(&s, result);
        }
    }
    
    return pop_int(&s);
}


```c
int main() {
```
    printf("ÉVALUATEUR POSTFIXÉ (RPN)\n\n");
    
    printf("3 4 + = %d\n", eval_postfix("3 4 +"));           // 7
    printf("5 2 * 3 + = %d\n", eval_postfix("5 2 * 3 +"));   // 13
    printf("10 5 / 2 * = %d\n", eval_postfix("10 5 / 2 *")); // 4
    
    return 0;
}


---

### PARTIE 3 : HISTORIQUE DE NAVIGATION

---


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
```


```bash
#define MAX_URL 256
```


```c
typedef struct {
    char urls[MAX][MAX_URL];
    int top;
} URLStack;
```


```c
typedef struct {
```
    URLStack back;
    URLStack forward;
    char current[MAX_URL];
} BrowserHistory;


```c
void init_browser(BrowserHistory *h) {
```
    h->back.top = -1;
    h->forward.top = -1;
    strcpy(h->current, "");
}


```c
void visit_page(BrowserHistory *h, const char *url) {
    // Si on a une page courante, la sauver dans "back"
```
    if (strlen(h->current) > 0) {
        strcpy(h->back.urls[++h->back.top], h->current);
    }
    

```c
    // Nouvelle page devient courante
```
    strcpy(h->current, url);
    

```c
    // Effacer l'historique "forward"
```
    h->forward.top = -1;
    
    printf("Visite : %s\n", url);
}


```c
void go_back(BrowserHistory *h) {
```
    if (h->back.top < 0) {
        printf("Pas de page précédente\n");
        return;
    }
    

```c
    // Sauver current dans forward
```
    strcpy(h->forward.urls[++h->forward.top], h->current);
    

```c
    // Récupérer de back
```
    strcpy(h->current, h->back.urls[h->back.top--]);
    
    printf("← Retour : %s\n", h->current);
}


```c
void go_forward(BrowserHistory *h) {
```
    if (h->forward.top < 0) {
        printf("Pas de page suivante\n");
        return;
    }
    

```c
    // Sauver current dans back
```
    strcpy(h->back.urls[++h->back.top], h->current);
    

```c
    // Récupérer de forward
```
    strcpy(h->current, h->forward.urls[h->forward.top--]);
    
    printf("→ Avancer : %s\n", h->current);
}


```c
void print_current(BrowserHistory *h) {
```
    printf("Page actuelle : %s\n", h->current);
}


```c
int main() {
```
    printf("HISTORIQUE DE NAVIGATION\n\n");
    
    BrowserHistory history;
    init_browser(&history);
    
    visit_page(&history, "google.com");
    visit_page(&history, "github.com");
    visit_page(&history, "stackoverflow.com");
    
    printf("\n");
    go_back(&history);
    go_back(&history);
    
    printf("\n");
    go_forward(&history);
    
    printf("\n");
    visit_page(&history, "reddit.com");
    
    printf("\n");
    go_back(&history);
    go_back(&history);
    
    return 0;
}


---

### PARTIE 4 : FILE D'IMPRESSION

---


```c
#include <stdio.h>
#include <string.h>
```


```bash
#define MAX_JOBS 20
```


```c
typedef struct {
    char document[100];
    char owner[50];
    int pages;
    int priority;
} PrintJob;
```


```c
typedef struct {
```
    PrintJob jobs[MAX_JOBS];
    int front, rear, count;
} PrintQueue;


```c
void init_queue(PrintQueue *q) {
```
    q->front = 0;
    q->rear = -1;
    q->count = 0;
}


```c
void add_job(PrintQueue *q, PrintJob job) {
```
    if (q->count >= MAX_JOBS) {
        printf("File pleine!\n");
        return;
    }
    q->rear = (q->rear + 1) % MAX_JOBS;
    q->jobs[q->rear] = job;
    q->count++;
    printf("Ajouté : %s (%d pages)\n", job.document, job.pages);
}


```c
void process_job(PrintQueue *q) {
```
    if (q->count == 0) {
        printf("File vide!\n");
        return;
    }
    
    PrintJob job = q->jobs[q->front];
    q->front = (q->front + 1) % MAX_JOBS;
    q->count--;
    
    printf("Impression de '%s' pour %s - %d pages\n", 
           job.document, job.owner, job.pages);
}


```c
void print_queue(PrintQueue *q) {
```
    if (q->count == 0) {
        printf("File d'impression vide\n");
        return;
    }
    
    printf("\nFile d'impression (%d travaux) :\n", q->count);
    int i = q->front;
    for (int c = 0; c < q->count; c++) {
        PrintJob j = q->jobs[i];
        printf("  %d. %s - %s (%d pages)\n", 
               c+1, j.document, j.owner, j.pages);
        i = (i + 1) % MAX_JOBS;
    }
}


```c
int main() {
```
    printf("SYSTÈME D'IMPRESSION\n\n");
    
    PrintQueue queue;
    init_queue(&queue);
    
    PrintJob j1 = {"rapport.pdf", "Alice", 10, 2};
    PrintJob j2 = {"presentation.pptx", "Bob", 25, 3};
    PrintJob j3 = {"code.c", "Charlie", 5, 1};
    
    add_job(&queue, j1);
    add_job(&queue, j2);
    add_job(&queue, j3);
    
    print_queue(&queue);
    
    printf("\nTraitement :\n");
    process_job(&queue);
    process_job(&queue);
    
    print_queue(&queue);
    
    process_job(&queue);
    print_queue(&queue);
    
    return 0;
}


---
EXPLICATION DES ALGORITHMES

---

1. VÉRIFICATION PARENTHÈSES :
   - Empiler les ouvertures
   - Dépiler et vérifier le type lors des fermetures
   - À la fin, la pile doit être vide

2. ÉVALUATION POSTFIXÉE :
   - Empiler les nombres
   - Pour chaque opérateur : dépiler 2, calculer, empiler résultat
   - Le résultat final est sur la pile

3. HISTORIQUE NAVIGATION :
   - 2 piles : back et forward
   - Visite → efface forward, sauve current dans back
   - Back → déplace current vers forward, récupère de back
   - Forward → inverse de back

4. FILE D'IMPRESSION :
   - File FIFO simple
   - Peut être étendue avec priorités


---
COMPILATION

---

gcc solution.c -o stacks_queues
./stacks_queues


---
FIN DE LA SOLUTION

---



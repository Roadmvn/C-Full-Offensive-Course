/*
 * Module 18 : Debugging avec GDB/LLDB
 * Programme exemple pour pratiquer le debugging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Fonction avec bug classique
void vulnerable_function(char *input) {
    char buffer[32];
    printf("Input length: %zu\n", strlen(input));
    strcpy(buffer, input);  // Potentiel buffer overflow
    printf("Buffer content: %s\n", buffer);
}

// Fonction récursive pour tester backtrace
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// Fonction pour tester watchpoints
void modify_variable(int *ptr) {
    printf("Before: %d\n", *ptr);
    *ptr = 42;  // Mettre watchpoint ici
    printf("After: %d\n", *ptr);
}

// Fonction avec logique complexe
int complex_calculation(int a, int b, int c) {
    int result = 0;
    
    for (int i = 0; i < a; i++) {
        result += i;
    }
    
    for (int j = 0; j < b; j++) {
        result *= 2;
    }
    
    result -= c;
    
    return result;
}

// Fonction pour examiner la mémoire
void memory_operations(void) {
    char stack_var[] = "Stack variable";
    char *heap_var = malloc(32);
    strcpy(heap_var, "Heap variable");
    
    printf("Stack: %p -> %s\n", (void*)stack_var, stack_var);
    printf("Heap:  %p -> %s\n", (void*)heap_var, heap_var);
    
    free(heap_var);
}

// Structure pour examiner en mémoire
typedef struct {
    int id;
    char name[32];
    float score;
} Student;

void structure_demo(void) {
    Student s1 = {1, "Alice", 95.5};
    Student s2 = {2, "Bob", 87.3};
    
    printf("Student 1: ID=%d, Name=%s, Score=%.1f\n", 
           s1.id, s1.name, s1.score);
    printf("Student 2: ID=%d, Name=%s, Score=%.1f\n", 
           s2.id, s2.name, s2.score);
}

// Fonction avec conditions multiples
int conditional_logic(int x) {
    if (x < 0) {
        printf("Negative\n");
        return -1;
    } else if (x == 0) {
        printf("Zero\n");
        return 0;
    } else if (x < 10) {
        printf("Small positive\n");
        return 1;
    } else if (x < 100) {
        printf("Medium positive\n");
        return 2;
    } else {
        printf("Large positive\n");
        return 3;
    }
}

// Fonction qui accède à différentes sections mémoire
void memory_sections_demo(void) {
    // .text (code)
    printf("Code address: %p\n", (void*)memory_sections_demo);
    
    // .data (initialisée)
    static int initialized = 42;
    printf("Data address: %p = %d\n", (void*)&initialized, initialized);
    
    // .bss (non-initialisée)
    static int uninitialized;
    printf("BSS address:  %p = %d\n", (void*)&uninitialized, uninitialized);
    
    // Stack
    int stack_var = 123;
    printf("Stack address: %p = %d\n", (void*)&stack_var, stack_var);
    
    // Heap
    int *heap_var = malloc(sizeof(int));
    *heap_var = 456;
    printf("Heap address:  %p = %d\n", (void*)heap_var, *heap_var);
    free(heap_var);
}

int main(int argc, char *argv[]) {
    printf("=== MODULE 18: GDB/LLDB DEBUGGING ===\n\n");
    
    // Test 1: Fonctions simples
    printf("[Test 1] Factorial\n");
    int fact = factorial(5);
    printf("5! = %d\n\n", fact);
    
    // Test 2: Calcul complexe
    printf("[Test 2] Complex calculation\n");
    int calc = complex_calculation(10, 3, 5);
    printf("Result: %d\n\n", calc);
    
    // Test 3: Watchpoint demo
    printf("[Test 3] Variable modification\n");
    int watch_me = 100;
    modify_variable(&watch_me);
    printf("\n");
    
    // Test 4: Mémoire
    printf("[Test 4] Memory operations\n");
    memory_operations();
    printf("\n");
    
    // Test 5: Structures
    printf("[Test 5] Structure demo\n");
    structure_demo();
    printf("\n");
    
    // Test 6: Logique conditionnelle
    printf("[Test 6] Conditional logic\n");
    conditional_logic(5);
    conditional_logic(50);
    conditional_logic(500);
    printf("\n");
    
    // Test 7: Sections mémoire
    printf("[Test 7] Memory sections\n");
    memory_sections_demo();
    printf("\n");
    
    // Test 8: Buffer overflow (commenté par sécurité)
    // if (argc > 1) {
    //     printf("[Test 8] Buffer overflow test\n");
    //     vulnerable_function(argv[1]);
    // }
    
    printf("=== FIN DES TESTS ===\n");
    return 0;
}

/*
 * GUIDE DE DEBUGGING:
 *
 * === GDB (Linux) ===
 *
 * 1. Compiler avec symboles:
 *    gcc -g -O0 example.c -o example
 *
 * 2. Démarrer GDB:
 *    gdb ./example
 *
 * 3. Commandes de base:
 *    (gdb) break main
 *    (gdb) run
 *    (gdb) next
 *    (gdb) step
 *    (gdb) continue
 *    (gdb) quit
 *
 * 4. Examiner variables:
 *    (gdb) print fact
 *    (gdb) print/x fact
 *    (gdb) info locals
 *
 * 5. Examiner mémoire:
 *    (gdb) x/10x $rsp
 *    (gdb) x/s stack_var
 *    (gdb) x/10i main
 *
 * 6. Breakpoints:
 *    (gdb) break factorial
 *    (gdb) break example.c:42
 *    (gdb) break *0x401234
 *    (gdb) info breakpoints
 *
 * 7. Backtrace:
 *    (gdb) backtrace
 *    (gdb) backtrace full
 *    (gdb) frame 2
 *
 * 8. Watchpoints:
 *    (gdb) watch watch_me
 *    (gdb) continue
 *
 * 9. Registres:
 *    (gdb) info registers
 *    (gdb) print $rax
 *    (gdb) set $rax=0
 *
 * 10. Désassemblage:
 *     (gdb) disassemble main
 *     (gdb) disassemble factorial
 *
 * === LLDB (macOS) ===
 *
 * 1. Compiler:
 *    clang -g -O0 example.c -o example
 *
 * 2. Démarrer LLDB:
 *    lldb ./example
 *
 * 3. Commandes de base:
 *    (lldb) breakpoint set -n main
 *    (lldb) run
 *    (lldb) next
 *    (lldb) step
 *    (lldb) continue
 *
 * 4. Examiner variables:
 *    (lldb) print fact
 *    (lldb) frame variable
 *
 * 5. Examiner mémoire:
 *    (lldb) memory read $rsp
 *    (lldb) x/10x $rsp
 *    (lldb) disassemble -n main
 *
 * 6. Breakpoints:
 *    (lldb) breakpoint set -n factorial
 *    (lldb) breakpoint set -f example.c -l 42
 *    (lldb) breakpoint list
 *
 * 7. Backtrace:
 *    (lldb) thread backtrace
 *    (lldb) bt
 *
 * 8. Watchpoints:
 *    (lldb) watchpoint set variable watch_me
 *
 * 9. Registres:
 *    (lldb) register read
 *    (lldb) register read rax
 *
 * === EXERCICES PRATIQUES ===
 *
 * 1. Mettre un breakpoint sur main et examiner les arguments
 * 2. Step through factorial() et observer la récursion
 * 3. Mettre un watchpoint sur watch_me et voir quand il change
 * 4. Examiner la différence entre stack et heap variables
 * 5. Désassembler complex_calculation et comprendre l'assembleur
 * 6. Utiliser backtrace pendant l'appel récursif
 * 7. Modifier une variable pendant l'exécution avec set
 * 8. Dumper une région mémoire en fichier
 */

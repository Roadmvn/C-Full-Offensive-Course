# Exercice : Opérations sur la Stack x64

## Objectif

Mettre en pratique les opérations sur la stack et comprendre les mécanismes d'exploitation.

---

## Exercice 1 : Implémentation de PUSH/POP manuel (Facile)

Implémente deux fonctions `mon_push` et `mon_pop` qui reproduisent le comportement de PUSH et POP **sans utiliser ces instructions**.

```c
// Utilise SUB RSP et MOV pour push
void mon_push(uint64_t valeur);

// Utilise MOV et ADD RSP pour pop
uint64_t mon_pop(void);

// Test
int main() {
    mon_push(0xAAAA);
    mon_push(0xBBBB);
    printf("Pop: 0x%lx\n", mon_pop());  // Doit afficher 0xBBBB
    printf("Pop: 0x%lx\n", mon_pop());  // Doit afficher 0xAAAA
}
```

---

## Exercice 2 : Compteur d'appels avec la stack (Moyen)

Crée une fonction récursive `countdown` qui utilise la stack pour compter les appels sans utiliser de variable globale.

```c
void countdown(int n) {
    // Affiche n, puis appelle countdown(n-1) jusqu'à 0
    // Utilise la stack pour stocker n
    // Affiche "Fin!" quand n == 0
}

// Test: countdown(5) doit afficher 5, 4, 3, 2, 1, Fin!
```

---

## Exercice 3 : Stack Frame Inspector (Moyen)

Écris une fonction `inspect_stack_frame` qui affiche :
- L'adresse de RBP
- L'adresse de RSP  
- L'adresse de retour
- La valeur du saved RBP

```c
void inspect_stack_frame(void) {
    // Utilise l'assembleur inline pour lire RBP, RSP
    // et les valeurs stockées sur la stack
}
```

---

## Exercice 4 : Fonction avec prologue/épilogue manuel (Avancé)

Écris une fonction complète en assembleur inline avec :
1. Prologue manuel (push rbp, mov rbp rsp, sub rsp)
2. Allocation de variables locales
3. Code qui utilise ces variables
4. Épilogue manuel (mov rsp rbp, pop rbp, ret)

```c
int calcul_manuel(int a, int b) {
    int resultat;
    
    __asm__ __volatile__ (
        // Prologue
        // ...
        
        // Calcul: resultat = a * 2 + b
        // Stocke dans une variable locale sur la stack
        // ...
        
        // Épilogue
        // ...
    );
    
    return resultat;
}
```

---

## Exercice 5 : Détection de Stack Canary (Avancé)

Écris un programme qui :
1. Détecte si un stack canary est présent
2. Affiche sa valeur (si trouvé)

```c
void detect_canary(void) {
    char buffer[64];
    // Le canary est généralement entre le buffer et saved RBP
    // Compile avec -fstack-protector pour avoir un canary
    
    // Trouve et affiche le canary
}
```

**Indice** : Le canary se termine souvent par un byte nul (0x00) pour empêcher les string overflows.

---

## Exercice 6 : Mini ROP Chain (Avancé)

Crée une structure simulant une ROP chain et explique ce qu'elle ferait :

```c
struct rop_chain {
    uint64_t gadget1;  // Adresse de "pop rdi; ret"
    uint64_t arg1;     // Argument pour RDI
    uint64_t gadget2;  // Adresse de "pop rsi; ret"  
    uint64_t arg2;     // Argument pour RSI
    uint64_t target;   // Adresse de la fonction cible
};

void explain_rop_chain(struct rop_chain *chain) {
    // Explique ce que chaque élément fait
    // et comment la chaîne s'exécuterait
}
```

---

## Critères de réussite

- [ ] Exercice 1 : PUSH/POP manuel fonctionne correctement
- [ ] Exercice 2 : Le countdown affiche les nombres correctement
- [ ] Exercice 3 : Les informations du stack frame sont correctes
- [ ] Exercice 4 : La fonction avec prologue manuel retourne le bon résultat
- [ ] Exercice 5 : Le canary est détecté et affiché
- [ ] Exercice 6 : L'explication de la ROP chain est correcte

---

## Compilation

```bash
# Standard
gcc -o exercice exercice.c -masm=intel

# Sans stack protector (pour exercice 5)
gcc -o exercice exercice.c -masm=intel -fno-stack-protector

# Avec stack protector (pour exercice 5)
gcc -o exercice exercice.c -masm=intel -fstack-protector-all

# Pour debug
gcc -g -o exercice exercice.c -masm=intel
```

---

## Ressources utiles

- `objdump -d executable` : voir le code assembleur
- `gdb` : debugger pour inspecter la stack
- `readelf -s executable` : voir les symboles

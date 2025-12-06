# 10 - Fonctions

## 🎯 Ce que tu vas apprendre

- Ce qu'est une fonction et pourquoi elle existe
- Déclaration vs définition d'une fonction
- Le passage de paramètres (par valeur vs par référence)
- La stack frame et comment les fonctions fonctionnent en mémoire
- Les fonctions récursives
- Le scope (portée) des variables

## 📚 Théorie

### Concept 1 : C'est quoi une fonction ?

**C'est quoi ?**
Une fonction est un **bloc de code réutilisable** qui effectue une tâche spécifique. Tu l'appelles par son nom, elle exécute son code, puis retourne un résultat.

**Pourquoi ça existe ?**
Imagine que tu dois calculer la somme de deux nombres 100 fois dans ton programme. Sans fonctions, tu devrais copier-coller le même code 100 fois. Avec une fonction :
- Écris le code UNE SEULE FOIS
- Appelle-le autant de fois que nécessaire
- Code plus lisible et maintenable

**Comment ça marche ?**

```c
// Définition
int add(int a, int b) {
    return a + b;
}

// Appel
int result = add(5, 3);  // result = 8
```

**Avantages** :
- **Réutilisabilité** : N'écris le code qu'une fois
- **Modularité** : Découpe ton programme en morceaux logiques
- **Lisibilité** : Plus facile à comprendre
- **Déboggage** : Localise les bugs plus facilement
- **Maintenance** : Modifie le code à un seul endroit

### Concept 2 : Structure d'une fonction

**Anatomie** :
```c
type_retour nom_fonction(type_param1 param1, type_param2 param2) {
    // Corps de la fonction
    return valeur;
}
```

**Composants** :
- **type_retour** : Type de la valeur retournée (`int`, `float`, `void`, etc.)
- **nom_fonction** : Nom que tu donnes à la fonction
- **paramètres** : Données d'entrée (optionnel)
- **corps** : Code à exécuter
- **return** : Valeur de sortie (sauf si `void`)

**Exemple détaillé** :
```c
int multiply(int x, int y) {
    int result = x * y;
    return result;
}
```

**Décomposition** :
```
int           → Type de retour (entier)
multiply      → Nom de la fonction
(int x, int y)→ Paramètres (deux entiers)
{...}         → Corps de la fonction
return result → Retourne la valeur calculée
```

### Concept 3 : Déclaration vs Définition

**Déclaration (prototype)** :
Annonce l'existence d'une fonction. Dit au compilateur : "Cette fonction existe, je la définirai plus tard".

```c
int add(int a, int b);  // Prototype (pas de corps)
```

**Définition** :
Implémentation complète avec le corps de la fonction.

```c
int add(int a, int b) {
    return a + b;  // Corps de la fonction
}
```

**Pourquoi séparer ?**

```c
// Prototypes en haut du fichier
int add(int a, int b);
int multiply(int a, int b);

int main() {
    int x = add(5, 3);        // OK : fonction déclarée avant
    int y = multiply(2, 4);   // OK
    return 0;
}

// Définitions après main()
int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}
```

Sans prototype :
```c
int main() {
    int x = add(5, 3);  // ERREUR : add() pas encore déclarée
    return 0;
}

int add(int a, int b) {
    return a + b;
}
```

### Concept 4 : Types de retour

**Retourner un int** :
```c
int get_age() {
    return 25;
}
```

**Retourner un float** :
```c
float calculate_average(float a, float b) {
    return (a + b) / 2.0f;
}
```

**Retourner un char** :
```c
char get_grade(int score) {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    return 'C';
}
```

**Ne rien retourner (void)** :
```c
void print_banner() {
    printf("============\n");
    printf(" RED TEAM   \n");
    printf("============\n");
    // Pas de return
}
```

### Concept 5 : Paramètres

**Sans paramètres** :
```c
int get_random() {
    return 42;  // Toujours 42 ;)
}
```

**Un paramètre** :
```c
int square(int x) {
    return x * x;
}
```

**Plusieurs paramètres** :
```c
int power(int base, int exponent) {
    int result = 1;
    for (int i = 0; i < exponent; i++) {
        result *= base;
    }
    return result;
}

// Utilisation :
int x = power(2, 3);  // 2^3 = 8
```

### Concept 6 : Passage par valeur

**C'est quoi ?**
Par défaut, le C passe les paramètres **par valeur** : une COPIE de la variable est envoyée à la fonction.

**Conséquence** : Modifier le paramètre dans la fonction ne modifie PAS l'original.

```c
void modify(int x) {
    x = 100;  // Modifie la copie locale
    printf("Dans modify: x = %d\n", x);  // 100
}

int main() {
    int a = 5;
    modify(a);
    printf("Dans main: a = %d\n", a);  // 5 (inchangé !)
    return 0;
}
```

**Schéma** :
```
main() :
┌────────┐
│ a = 5  │
└────────┘
    │ Passage par valeur
    ↓ Copie de a
modify(x) :
┌────────┐
│ x = 5  │  ← Copie
└────────┘
    │
    ↓ x = 100
┌────────┐
│ x = 100│  ← Modifie la copie
└────────┘

Retour dans main :
┌────────┐
│ a = 5  │  ← Original inchangé
└────────┘
```

### Concept 7 : Passage par référence (pointeurs)

**C'est quoi ?**
Pour modifier l'original, passe un **pointeur** (l'adresse de la variable).

```c
void modify(int* x) {
    *x = 100;  // Modifie la valeur à l'adresse pointée
    printf("Dans modify: *x = %d\n", *x);  // 100
}

int main() {
    int a = 5;
    modify(&a);  // Passe l'ADRESSE de a
    printf("Dans main: a = %d\n", a);  // 100 (modifié !)
    return 0;
}
```

**Schéma** :
```
main() :
┌────────────┐
│ a = 5      │  Adresse : 0x1000
└────────────┘
    │ Passage par référence
    ↓ Passe l'adresse (0x1000)
modify(x) :
┌────────────┐
│ x = 0x1000 │  Pointeur vers a
└────────────┘
    │
    ↓ *x = 100
┌────────────┐
│ a = 100    │  Adresse : 0x1000 (original modifié)
└────────────┘
```

### Concept 8 : Tableaux en paramètres

**Rappel** : Un tableau est un pointeur vers son premier élément.

```c
void print_array(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main() {
    int numbers[] = {1, 2, 3, 4, 5};
    print_array(numbers, 5);
    return 0;
}
```

**Les tableaux sont toujours passés par référence** (implicite) :

```c
void modify_array(int arr[], int size) {
    arr[0] = 999;  // Modifie l'original !
}

int main() {
    int numbers[] = {1, 2, 3};
    modify_array(numbers, 3);
    printf("%d\n", numbers[0]);  // 999 (modifié)
    return 0;
}
```

**Pourquoi ?**
Parce que `int arr[]` est en réalité un `int*` (pointeur). Pas de copie du tableau.

### Concept 9 : La stack frame

**C'est quoi ?**
Quand tu appelles une fonction, le système crée une **stack frame** : un espace sur la pile (stack) pour stocker :
- Les paramètres
- Les variables locales
- L'adresse de retour

**Comment ça marche ?**

```c
int add(int a, int b) {
    int result = a + b;
    return result;
}

int main() {
    int x = add(5, 3);
    return 0;
}
```

**Schéma de la stack** :
```
1. main() démarre :
┌──────────────┐
│ main()       │
│ x = ?        │
└──────────────┘

2. Appel add(5, 3) :
┌──────────────┐
│ add()        │  ← Nouvelle frame
│ a = 5        │
│ b = 3        │
│ result = 8   │
│ return addr  │
├──────────────┤
│ main()       │
│ x = ?        │
└──────────────┘

3. add() retourne 8 :
┌──────────────┐
│ main()       │
│ x = 8        │  ← Reçoit la valeur de retour
└──────────────┘
Frame de add() détruite
```

**Adresse de retour** :
Quand `add()` se termine, le CPU doit savoir où reprendre dans `main()`. Cette adresse est stockée dans la stack frame.

### Concept 10 : Récursivité

**C'est quoi ?**
Une fonction **récursive** s'appelle elle-même.

**Exemple : Factorielle** :
```c
int factorial(int n) {
    if (n <= 1) {
        return 1;  // Cas de base
    }
    return n * factorial(n - 1);  // Appel récursif
}

// factorial(5) = 5 * factorial(4)
//              = 5 * 4 * factorial(3)
//              = 5 * 4 * 3 * factorial(2)
//              = 5 * 4 * 3 * 2 * factorial(1)
//              = 5 * 4 * 3 * 2 * 1
//              = 120
```

**Stack frames pour factorial(3)** :
```
factorial(3) :
┌──────────────┐
│ factorial()  │  n = 1, return 1
├──────────────┤
│ factorial()  │  n = 2, return 2 * factorial(1) = 2
├──────────────┤
│ factorial()  │  n = 3, return 3 * factorial(2) = 6
└──────────────┘
```

**ATTENTION : Cas de base obligatoire !**

Sans cas de base → Récursion infinie → Stack overflow :

```c
int buggy_factorial(int n) {
    return n * buggy_factorial(n - 1);  // Jamais de cas de base
    // CRASH : Stack overflow
}
```

### Concept 11 : Scope (portée) des variables

**Variables locales** :
Déclarées dans une fonction, visibles uniquement dans cette fonction.

```c
void func1() {
    int x = 10;  // Locale à func1
    printf("%d\n", x);  // OK
}

void func2() {
    printf("%d\n", x);  // ERREUR : x n'existe pas ici
}
```

**Variables globales** :
Déclarées en dehors des fonctions, visibles partout.

```c
int counter = 0;  // Globale

void increment() {
    counter++;  // Accès OK
}

int main() {
    printf("%d\n", counter);  // Accès OK
    increment();
    printf("%d\n", counter);  // 1
    return 0;
}
```

**Bonne pratique** : Éviter les variables globales (sauf constantes).

Pourquoi ?
- Difficile à déboguer
- Couplage fort entre fonctions
- Risque de conflits de noms

### Concept 12 : Fonctions de la bibliothèque standard

**stdio.h** :
```c
printf()   // Afficher
scanf()    // Lire
fopen()    // Ouvrir un fichier
fclose()   // Fermer un fichier
```

**string.h** :
```c
strlen()   // Longueur
strcpy()   // Copier
strcmp()   // Comparer
```

**stdlib.h** :
```c
malloc()   // Allouer mémoire
free()     // Libérer mémoire
exit()     // Quitter le programme
atoi()     // String → int
```

**math.h** (compiler avec `-lm`) :
```c
pow(x, y)  // x^y
sqrt(x)    // Racine carrée
sin(x)     // Sinus
cos(x)     // Cosinus
```

## 🔍 Visualisation : Appel de fonction avec la stack

```c
int add(int a, int b) {
    int result = a + b;
    return result;
}

int multiply(int x, int y) {
    int temp = add(x, y);
    return temp * 2;
}

int main() {
    int value = multiply(3, 4);
    return 0;
}
```

**Évolution de la stack** :
```
1. main() démarre :
┌──────────────┐
│ main()       │
│ value = ?    │
└──────────────┘

2. Appel multiply(3, 4) :
┌──────────────┐
│ multiply()   │
│ x = 3, y = 4 │
│ temp = ?     │
├──────────────┤
│ main()       │
│ value = ?    │
└──────────────┘

3. multiply() appelle add(3, 4) :
┌──────────────┐
│ add()        │
│ a = 3, b = 4 │
│ result = 7   │
├──────────────┤
│ multiply()   │
│ temp = 7     │
├──────────────┤
│ main()       │
│ value = ?    │
└──────────────┘

4. add() retourne, multiply() continue :
┌──────────────┐
│ multiply()   │
│ temp = 7     │
│ return 14    │
├──────────────┤
│ main()       │
│ value = ?    │
└──────────────┘

5. multiply() retourne :
┌──────────────┐
│ main()       │
│ value = 14   │
└──────────────┘
```

## 🎯 Application Red Team

### 1. Modularité : Séparer les étapes d'exploitation

```c
// Reconnaissance
int scan_target(char* ip);

// Exploitation
int exploit_vulnerability(char* target);

// Post-exploitation
void exfiltrate_data(char* data);
void maintain_persistence();

int main() {
    char* target = "192.168.1.100";

    if (scan_target(target) == 0) {
        if (exploit_vulnerability(target) == 0) {
            exfiltrate_data("/etc/passwd");
            maintain_persistence();
        }
    }
    return 0;
}
```

### 2. Shellcode loader

```c
void* allocate_executable_memory(size_t size);
void copy_shellcode(void* dest, unsigned char* src, size_t size);
void execute_code(void* code_ptr);

void inject_shellcode(unsigned char* shellcode, size_t size) {
    void* mem = allocate_executable_memory(size);
    if (mem) {
        copy_shellcode(mem, shellcode, size);
        execute_code(mem);
    }
}
```

### 3. Obfuscation avec fonctions

```c
// Découper le code malveillant pour rendre l'analyse plus difficile
void step1() { /* ... */ }
void step2() { /* ... */ }
void step3() { /* ... */ }

int main() {
    step1();
    sleep(random() % 10);  // Timing aléatoire
    step2();
    step3();
    return 0;
}
```

### 4. API wrapping pour évasion

```c
// Encapsuler les appels système pour les masquer
void* my_alloc(size_t size) {
    // Au lieu d'appeler directement malloc()
    // Utiliser VirtualAlloc (Windows) ou mmap (Linux)
    return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

void my_free(void* ptr, size_t size) {
    VirtualFree(ptr, 0, MEM_RELEASE);
}
```

### 5. Fonctions de chiffrement

```c
void xor_encrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void xor_decrypt(unsigned char* data, size_t len, unsigned char key) {
    xor_encrypt(data, len, key);  // XOR est symétrique
}

// Utilisation :
unsigned char payload[] = {/* shellcode */};
xor_encrypt(payload, sizeof(payload), 0xAA);  // Chiffre
send_to_target(payload);
xor_decrypt(payload, sizeof(payload), 0xAA);  // Déchiffre
execute(payload);
```

### 6. Callbacks et hooks

```c
// Type de fonction callback
typedef void (*callback_t)(char* data);

void process_packet(char* packet, callback_t handler) {
    // Traitement...
    handler(packet);  // Appel du callback
}

void my_handler(char* data) {
    printf("Packet received: %s\n", data);
}

int main() {
    process_packet("malicious_data", my_handler);
    return 0;
}
```

### 7. Récursion pour traverser des structures

```c
// Traverser un système de fichiers récursivement
void scan_directory(char* path) {
    DIR* dir = opendir(path);
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0) {
                char subpath[1024];
                sprintf(subpath, "%s/%s", path, entry->d_name);
                scan_directory(subpath);  // Récursif
            }
        } else {
            printf("File: %s/%s\n", path, entry->d_name);
        }
    }
    closedir(dir);
}
```

### 8. Return-Oriented Programming (ROP)

```c
// Construire une chaîne ROP
unsigned long* build_ropchain(unsigned long* stack_ptr) {
    *stack_ptr++ = 0x00000000004005a3;  // pop rdi; ret
    *stack_ptr++ = 0x0000000000601040;  // @ "/bin/sh"
    *stack_ptr++ = 0x00000000004005a1;  // pop rsi; ret
    *stack_ptr++ = 0x0000000000000000;  // NULL
    *stack_ptr++ = 0x0000000000400430;  // execve() PLT
    return stack_ptr;
}
```

## 📝 Points clés à retenir

- Une fonction = bloc de code réutilisable
- Déclaration (prototype) vs Définition (implémentation)
- Passage par valeur : copie des paramètres
- Passage par référence : passe l'adresse (pointeur)
- Les tableaux sont toujours passés par référence (implicite)
- Stack frame : espace mémoire pour paramètres, variables locales, adresse de retour
- Récursion : fonction qui s'appelle elle-même (cas de base obligatoire !)
- Variables locales : visibles dans la fonction
- Variables globales : visibles partout (à éviter)
- Les fonctions permettent la modularité, obfuscation, réutilisabilité

## ➡️ Prochaine étape

Félicitations ! Tu as terminé les fondamentaux du C. Tu es maintenant prêt pour la [PHASE 2 - Sécurité et Exploitation](../../PHASE_2_SECURITE/README.md) où tu vas apprendre :
- Les pointeurs avancés
- La gestion de la mémoire (malloc/free)
- Les vulnérabilités classiques (buffer overflow, format string, etc.)
- L'exploitation binaire

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)

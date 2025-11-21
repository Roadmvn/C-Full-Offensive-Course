# Cours : Pointeurs Avancés

## 1. Introduction - Au-Delà des Bases

Vous connaissez maintenant les pointeurs simples (`int *ptr`). Passons aux concepts avancés qui sont **cruciaux** pour la programmation système et l'exploitation :
- Pointeurs de pointeurs (`**`)
- Pointeurs vers tableaux
- Pointeurs de fonctions
- Pointeurs `void*`
- Arithmétique de pointeurs

## 2. Pointeurs de Pointeurs (`**`) - Explications Multi-Niveaux

### 2.1 Analogie Concrète

**Imaginez** : Vous cherchez un trésor 🏴‍☠️

```ascii
NIVEAU 1 - Trésor Direct :
Vous → 💎
Direct, simple

NIVEAU 2 - Carte au Trésor :
Vous → 🗺️ → 💎
       (adresse du trésor)

NIVEAU 3 - Carte vers une Carte :
Vous → 🗺️ → 🗺️ → 💎
       (adresse    (adresse
        d'une carte) du trésor)
```

**En programmation** :
- Trésor💎 = Donnée (valeur)
- Carte🗺️ = Pointeur (adresse)
- Carte vers carte = Pointeur de pointeur

### 2.2 Syntaxe et Visualisation Mémoire

```c
int valeur = 42;
int *ptr = &valeur;          // Pointeur vers int
int **ptr_ptr = &ptr;        // Pointeur vers pointeur
```

**Visualisation Complète** :

```ascii
┌─────────────────────────────────────────────────────────┐
│                    NIVEAU 3 : Donnée                    │
├─────────────────────────────────────────────────────────┤
│  Adresse: 0x1000                                        │
│  ┌──────────┐                                           │
│  │ valeur   │                                           │
│  │   42     │  ← La vraie donnée                        │
│  └──────────┘                                           │
└────────────────────┬────────────────────────────────────┘
                     ↑
                     │ ptr pointe ici
                     │
┌────────────────────┴────────────────────────────────────┐
│                    NIVEAU 2 : Pointeur                  │
├─────────────────────────────────────────────────────────┤
│  Adresse: 0x2000                                        │
│  ┌──────────┐                                           │
│  │ ptr      │                                           │
│  │ 0x1000   │  ← Contient l'adresse de "valeur"         │
│  └──────────┘                                           │
└────────────────────┬────────────────────────────────────┘
                     ↑
                     │ ptr_ptr pointe ici
                     │
┌────────────────────┴────────────────────────────────────┐
│                NIVEAU 1 : Pointeur de Pointeur          │
├─────────────────────────────────────────────────────────┤
│  Adresse: 0x3000                                        │
│  ┌──────────┐                                           │
│  │ ptr_ptr  │                                           │
│  │ 0x2000   │  ← Contient l'adresse de "ptr"            │
│  └──────────┘                                           │
└─────────────────────────────────────────────────────────┘

ACCÈS AUX DONNÉES :

valeur     → Accès direct            → 42
*ptr       → Déréférence 1 fois      → 42
**ptr_ptr  → Déréférence 2 fois      → 42

ptr        → Adresse de valeur       → 0x1000
*ptr_ptr   → Adresse de valeur       → 0x1000

ptr_ptr    → Adresse de ptr          → 0x2000
&ptr       → Adresse de ptr          → 0x2000
```

### 2.3 Tableau des Opérations

```ascii
┌──────────────┬────────────────┬─────────────────────┐
│  Expression  │  Type          │  Valeur/Résultat    │
├──────────────┼────────────────┼─────────────────────┤
│  valeur      │  int           │  42                 │
│  &valeur     │  int*          │  0x1000             │
├──────────────┼────────────────┼─────────────────────┤
│  ptr         │  int*          │  0x1000             │
│  *ptr        │  int           │  42                 │
│  &ptr        │  int**         │  0x2000             │
├──────────────┼────────────────┼─────────────────────┤
│  ptr_ptr     │  int**         │  0x2000             │
│  *ptr_ptr    │  int*          │  0x1000             │
│  **ptr_ptr   │  int           │  42                 │
│  &ptr_ptr    │  int***        │  0x3000             │
└──────────────┴────────────────┴─────────────────────┘
```

### 2.4 Cas d'Usage Réel - Modifier un Pointeur dans une Fonction

**Problème** : Comment une fonction peut-elle modifier un pointeur passé en argument ?

```c
void creer_noeud(Node **head, int data) {
    Node *new_node = malloc(sizeof(Node));
    new_node->data = data;
    new_node->next = *head;
    *head = new_node;
}
```

**Pourquoi `Node **head` ?**

```ascii
SI ON UTILISAIT Node *head (ERREUR) :

main() :
┌──────────────┐
│ Node *liste  │
│   = NULL     │  0x1000
└──────────────┘
       │
       │ Passage par valeur (copie)
       ↓
creer_noeud(liste) :
┌──────────────┐
│ Node *head   │
│   = NULL     │  0x2000 ← COPIE !
└──────────────┘
       │
       ↓ head = new_node
┌──────────────┐
│ Node *head   │
│   = 0x5000   │  ← Modifie la COPIE
└──────────────┘

Retour à main() :
┌──────────────┐
│ Node *liste  │
│   = NULL     │  ← Inchangé ! ❌
└──────────────┘

════════════════════════════════════════

AVEC Node **head (CORRECT) :

main() :
┌──────────────┐
│ Node *liste  │
│   = NULL     │  Adresse: 0x1000
└──────────────┘
       ↑
       │ On passe l'ADRESSE de liste
       │
creer_noeud(&liste) :
┌──────────────┐
│ Node **head  │
│   = 0x1000   │  ← Contient l'adresse de "liste"
└──────────────┘
       │
       ↓ *head = new_node
       │ (modifier ce qui est À l'adresse 0x1000)
       ↓
┌──────────────┐
│ 0x1000:      │
│ liste=0x5000 │  ← Modifie l'ORIGINAL ! ✅
└──────────────┘

Retour à main() :
┌──────────────┐
│ Node *liste  │
│   = 0x5000   │  ← Modifié ! ✅
└──────────────┘
```

## 3. Pointeurs et Tableaux - La Relation Intime

### 3.1 Un Tableau EST (presque) un Pointeur

```c
int ages[5] = {10, 20, 30, 40, 50};
int *ptr = ages;  // ages se "dégrade" en pointeur vers ages[0]
```

```ascii
MÉMOIRE :

Adresse    Contenu      Variable
┌────────┬──────────┬────────────┐
│0x1000  │    10    │  ages[0]   │
├────────┼──────────┼────────────┤
│0x1004  │    20    │  ages[1]   │
├────────┼──────────┼────────────┤
│0x1008  │    30    │  ages[2]   │
├────────┼──────────┼────────────┤
│0x100C  │    40    │  ages[3]   │
├────────┼──────────┼────────────┤
│0x1010  │    50    │  ages[4]   │
└────────┴──────────┴────────────┘
   ↑
   │
   ages = 0x1000 (adresse du premier élément)
   ptr  = 0x1000 (même adresse)
```

### 3.2 Arithmétique de Pointeurs Expliquée

```ascii
PRINCIPE : pointeur + N avance de N × sizeof(type)

ages + 0  → 0x1000 (ages[0])
ages + 1  → 0x1004 (ages[1])  ← Avance de 4 bytes (sizeof(int))
ages + 2  → 0x1008 (ages[2])  ← Encore +4
ages + 3  → 0x100C (ages[3])
ages + 4  → 0x1010 (ages[4])

┌─────────────────────────────────────────────────────┐
│  ages[i]  ≡  *(ages + i)                            │
│  &ages[i] ≡  (ages + i)                             │
└─────────────────────────────────────────────────────┘

EXEMPLE CONCRET :

printf("%d\n", ages[2]);      // 30
printf("%d\n", *(ages + 2));  // 30 (identique)

printf("%p\n", &ages[2]);     // 0x1008
printf("%p\n", ages + 2);     // 0x1008 (identique)
```

**Visualisation de l'Avancement** :

```ascii
ptr = ages;  // ptr à 0x1000

ptr++  (Incrémente de 1) :

AVANT :                        APRÈS :
ptr → 0x1000  ┌────┐          ┌────┐  ptr → 0x1004
              │ 10 │          │ 10 │
              └────┘          └────┘
              ┌────┐          ┌────┐
              │ 20 │          │ 20 │
              └────┘          └────┘

ptr avance de 4 bytes (sizeof(int))
NON pas de 1 byte !
```

## 4. Pointeurs de Fonctions - Le Concept Avancé

### 4.1 Les Fonctions Aussi Ont des Adresses !

```ascii
MÉMOIRE D'UN PROGRAMME :

┌──────────────────────────────┐  Adresses basses
│  Segment CODE (.text)        │
│                              │
│  0x100000: int add(a,b) {    │  ← Fonction add()
│                return a+b;   │
│            }                 │
│                              │
│  0x100020: int sub(a,b) {    │  ← Fonction sub()
│                return a-b;   │
│            }                 │
│                              │
│  0x100040: int main() {      │  ← Fonction main()
│                ...           │
│            }                 │
│                              │
└──────────────────────────────┘

Chaque fonction a une ADRESSE en mémoire !
On peut créer un pointeur vers cette adresse
```

### 4.2 Syntaxe et Utilisation

```c
// Déclaration d'un pointeur de fonction
int (*func_ptr)(int, int);  // Pointeur vers fonction(int, int) qui retourne int

// Affecter une adresse de fonction
func_ptr = &add;  // ou simplement : func_ptr = add;

// Appeler via le pointeur
int resultat = func_ptr(10, 20);  // Appelle add(10, 20)
```

**Décortiquons la syntaxe** :

```ascii
int  (*func_ptr)  (int, int)
│     │    │       │
│     │    │       └─ Paramètres : deux int
│     │    └─ Nom du pointeur
│     └─ * = c'est un POINTEUR
└─ Type de retour : int

(*func_ptr) = pointeur vers fonction
  └─ Parenthèses obligatoires !
  
Sans parenthèses :
int *func_ptr(int, int)  ← Fonction qui retourne int* (différent !)
```

### 4.3 Cas d'Usage - Tableau de Fonctions

```ascii
APPLICATION : Calculatrice avec menu

┌──────────────────────────────────────┐
│  TABLEAU DE POINTEURS DE FONCTIONS   │
├───┬──────────────────────────────────┤
│ 0 │  add_ptr    → int add(a,b)       │
│ 1 │  sub_ptr    → int sub(a,b)       │
│ 2 │  mul_ptr    → int mul(a,b)       │
│ 3 │  div_ptr    → int div(a,b)       │
└───┴──────────────────────────────────┘

Code :
int (*operations[4])(int, int) = {add, sub, mul, div};

int choix = 2;  // Multiplication
int resultat = operations[choix](10, 5);  // Appelle mul(10, 5)
```

## 5. Pointeur void* - Le Pointeur Générique

### 5.1 Qu'est-ce que void* ?

`void*` est un **pointeur générique** qui peut pointer vers **n'importe quel type**.

```ascii
┌──────────────────────────────────────┐
│  int *ptr_int     → PEUT SEULEMENT   │
│                     pointer vers int │
├──────────────────────────────────────┤
│  char *ptr_char   → PEUT SEULEMENT   │
│                     pointer vers char│
├──────────────────────────────────────┤
│  void *ptr_void   → PEUT pointer     │
│                     vers N'IMPORTE   │
│                     QUOI !           │
└──────────────────────────────────────┘
```

**Utilisation** :

```c
void *generic_ptr;

int x = 42;
generic_ptr = &x;  // Pointer vers int

char c = 'A';
generic_ptr = &c;  // Pointer vers char (réutilisé)
```

**⚠️ Mais il faut caster pour utiliser** :

```c
void *ptr = malloc(sizeof(int));  // malloc retourne void*
int *int_ptr = (int*)ptr;          // Cast obligatoire
*int_ptr = 42;
```

### 5.2 Pourquoi malloc() retourne void* ?

```ascii
malloc() ne sait PAS quel type vous voulez stocker :

┌────────────────────────────────────┐
│  malloc(12 bytes)                  │
│  ↓                                 │
│  "Ok, voici 12 bytes à 0x5000"     │
│  ↓                                 │
│  void *ptr = 0x5000                │
└────────────────────────────────────┘

C'est VOUS qui décidez :

int *i_ptr = (int*)ptr;     // 12 bytes = 3 ints
char *c_ptr = (char*)ptr;   // 12 bytes = 12 chars
float *f_ptr = (float*)ptr; // 12 bytes = 3 floats

Le système ne sait pas, il donne juste de l'espace brut
```

## 6. Arithmétique de Pointeurs - Les Mathématiques Spéciales

### 6.1 Addition et Soustraction

```c
int ages[5] = {10, 20, 30, 40, 50};
int *ptr = ages;
```

```ascii
OPÉRATION : ptr + 2

┌─────────────────────────────────────────────────────┐
│  CALCUL AUTOMATIQUE :                               │
│                                                     │
│  ptr + 2                                            │
│    = 0x1000 + (2 × sizeof(int))                    │
│    = 0x1000 + (2 × 4)                              │
│    = 0x1000 + 8                                     │
│    = 0x1008                                         │
└─────────────────────────────────────────────────────┘

MÉMOIRE :

0x1000  ┌────┐
   ptr→ │ 10 │  ages[0]
        └────┘
0x1004  ┌────┐
        │ 20 │  ages[1]
        └────┘
0x1008  ┌────┐
ptr+2 → │ 30 │  ages[2]  ← Pointeur avancé de 2 positions
        └────┘
0x100C  ┌────┐
        │ 40 │  ages[3]
        └────┘
0x1010  ┌────┐
        │ 50 │  ages[4]
        └────┘
```

### 6.2 Différence entre Pointeurs

```ascii
int *p1 = &ages[4];  // 0x1010
int *p2 = &ages[1];  // 0x1004

Différence : p1 - p2

┌─────────────────────────────────────────────────────┐
│  CALCUL :                                           │
│                                                     │
│  p1 - p2                                            │
│    = (0x1010 - 0x1004) / sizeof(int)               │
│    = 12 bytes / 4                                   │
│    = 3 positions                                    │
└─────────────────────────────────────────────────────┘

VISUALISATION :

0x1004  ┌────┐
   p2 → │ 20 │  Position 1
        └────┘
           ↓  Distance = 3 éléments
        ┌────┐
        │ 30 │  Position 2
        └────┘
           ↓
        ┌────┐
        │ 40 │  Position 3
        └────┘
           ↓
0x1010  ┌────┐
   p1 → │ 50 │  Position 4
        └────┘

p1 - p2 = 3 (nombre d'éléments entre eux)
```

## 7. Résumé Visuel - Hiérarchie des Pointeurs

```ascii
┌─────────────────────────────────────────────────────┐
│           NIVEAUX DE POINTEURS                      │
├─────────────────────────────────────────────────────┤
│                                                     │
│  NIVEAU 0 : int valeur = 42                         │
│            └─ Donnée directe                        │
│                                                     │
│  NIVEAU 1 : int *ptr = &valeur                      │
│            └─ Pointeur vers donnée                  │
│                                                     │
│  NIVEAU 2 : int **ptr_ptr = &ptr                    │
│            └─ Pointeur vers pointeur                │
│                                                     │
│  NIVEAU 3 : int ***ptr_ptr_ptr = &ptr_ptr           │
│            └─ Pointeur vers pointeur de pointeur    │
│                 (rarement utilisé)                  │
│                                                     │
└─────────────────────────────────────────────────────┘

Chaque * ajoute un niveau d'indirection
```

## Ressources

- [Pointers (cppreference)](https://en.cppreference.com/w/c/language/pointer)
- [Function pointers](https://www.geeksforgeeks.org/function-pointer-in-c/)


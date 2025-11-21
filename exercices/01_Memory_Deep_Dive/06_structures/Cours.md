# Cours : Structures (struct) - Regrouper des Données

## 1. Introduction - Le Problème des Données Éparpillées

### 1.1 Sans Structures (Le Chaos)

Imaginez que vous gérez une liste d'étudiants avec leurs infos :

```c
// Méthode chaotique
char nom1[50] = "Alice";
int age1 = 20;
float note1 = 15.5;

char nom2[50] = "Bob";
int age2 = 22;
float note2 = 14.0;

char nom3[50] = "Charlie";
int age3 = 19;
float note3 = 16.5;

// Cauchemar à gérer ! 🤯
```

**Problèmes** :
- ❌ Variables éparpillées (nom1, age1, note1, nom2, age2...)
- ❌ Impossible de passer "un étudiant" à une fonction
- ❌ Difficile d'avoir un tableau d'étudiants
- ❌ Code illisible et non maintenable

### 1.2 Avec Structures (Organisation)

```c
// Méthode propre
struct Etudiant {
    char nom[50];
    int age;
    float note;
};

struct Etudiant alice = {"Alice", 20, 15.5};
struct Etudiant bob = {"Bob", 22, 14.0};
struct Etudiant charlie = {"Charlie", 19, 16.5};

// Propre, organisé ! ✅
```

**Avantages** :
- ✅ Données **regroupées logiquement**
- ✅ Facile à passer à des fonctions
- ✅ Peut créer des tableaux de structures
- ✅ Code lisible et maintenable

### 1.3 Analogie - La Fiche d'Identité

**Structure** = **Fiche** avec plusieurs champs

```ascii
┌─────────────────────────────────┐
│   CARTE D'ÉTUDIANT              │
├─────────────────────────────────┤
│  Nom    : Alice Dupont          │  ← Champ 1 (char[50])
│  Âge    : 20 ans                │  ← Champ 2 (int)
│  Note   : 15.5/20               │  ← Champ 3 (float)
│  Classe : L3 Informatique       │  ← Champ 4 (char[20])
└─────────────────────────────────┘

Une seule "carte" regroupe TOUTES les infos
```

## 2. Syntaxe et Déclaration - Étape par Étape

### 2.1 Créer une Structure (Le Moule)

```c
struct Etudiant {
    char nom[50];
    int age;
    float note;
};
```

**Décortiquons** :

```ascii
struct    Etudiant    {  ...  }  ;
  │          │        │       │  │
  │          │        │       │  └─ Point-virgule OBLIGATOIRE
  │          │        │       │
  │          │        │       └─ Fermeture accolade
  │          │        │
  │          │        └─ Corps : liste des champs (membres)
  │          │
  │          └─ Nom de la structure (comme un nom de type)
  │
  └─ Mot-clé pour déclarer une structure
```

**À ce stade** : Vous avez créé un **"moule"**, mais aucune donnée n'existe encore !

```ascii
struct Etudiant = MOULE (Template)

┌─────────────────────────────┐
│         MOULE               │  ← Définition
│   ┌─────────────────────┐   │
│   │ char nom[50]        │   │
│   │ int age             │   │
│   │ float note          │   │
│   └─────────────────────┘   │
└─────────────────────────────┘

Aucune mémoire allouée !
C'est juste une recette pour créer des variables
```

### 2.2 Créer une Variable de Type Structure

```c
struct Etudiant alice;
```

**Maintenant** la mémoire est allouée !

```ascii
MÉMOIRE ALLOUÉE pour "alice" :

┌─────────────────────────────────────────────────────┐
│  struct Etudiant alice                              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  0x1000  ┌───────────────────────────────────────┐  │
│          │  nom[50]                              │  │
│          │  50 bytes (chaîne de caractères)      │  │
│  0x1031  └───────────────────────────────────────┘  │
│                                                     │
│  0x1032  ┌──────────┐                               │
│          │  age     │  4 bytes (int)                │
│  0x1035  └──────────┘                               │
│                                                     │
│  0x1036  ┌──────────┐                               │
│          │  note    │  4 bytes (float)              │
│  0x1039  └──────────┘                               │
│                                                     │
└─────────────────────────────────────────────────────┘

Total : 50 + 4 + 4 = 58 bytes
(+ padding possible pour alignement)
```

### 2.3 Initialisation

#### Méthode 1 : Tout en une ligne

```c
struct Etudiant alice = {"Alice Dupont", 20, 15.5};
```

#### Méthode 2 : Champ par champ

```c
struct Etudiant bob;
strcpy(bob.nom, "Bob Martin");
bob.age = 22;
bob.note = 14.0;
```

#### Méthode 3 : Designated Initializers (C99+)

```c
struct Etudiant charlie = {
    .nom = "Charlie",
    .age = 19,
    .note = 16.5
};
```

## 3. Accès aux Membres - Le Point et la Flèche

### 3.1 Avec Variable Directe : Opérateur `.`

```c
struct Etudiant alice;
alice.age = 20;               // Accès avec .
printf("%d\n", alice.age);
```

```ascii
alice est une VARIABLE DIRECTE

┌──────────────┐
│ alice        │  Variable complète
│  ├─ nom      │
│  ├─ age: 20  │  ← alice.age accède ici
│  └─ note     │
└──────────────┘

Syntaxe : variable.membre
```

### 3.2 Avec Pointeur : Opérateur `->`

```c
struct Etudiant *ptr = &alice;
ptr->age = 21;                // Accès avec ->
printf("%d\n", ptr->age);
```

```ascii
ptr est un POINTEUR vers une structure

        ptr = 0x1000
           ↓
0x1000  ┌──────────────┐
        │ alice        │
        │  ├─ nom      │
        │  ├─ age: 21  │  ← ptr->age accède ici
        │  └─ note     │
        └──────────────┘

Syntaxe : pointeur->membre

ÉQUIVALENCE :
ptr->age  ≡  (*ptr).age
   │            │     │
   │            │     └─ Accès membre
   │            └─ Déréférence
   └─ Raccourci pratique
```

**Pourquoi deux syntaxes ?**

```ascii
CAS 1 : Variable directe → Utiliser .

struct Etudiant alice;
alice.age = 20;

CAS 2 : Pointeur vers structure → Utiliser ->

struct Etudiant *ptr = &alice;
ptr->age = 20;

ERREUR COURANTE :
ptr.age    ❌ (ptr est un pointeur, pas une structure)
alice->age ❌ (alice est une structure, pas un pointeur)
```

## 4. Structures en Mémoire - Détails Techniques

### 4.1 Alignement Mémoire (Padding)

Le compilateur ajoute parfois des **bytes vides** pour optimiser l'accès CPU.

```ascii
STRUCTURE DÉFINIE :

struct Example {
    char a;      // 1 byte
    int b;       // 4 bytes
    char c;      // 1 byte
};

VOUS PENSEZ : 1 + 4 + 1 = 6 bytes

RÉALITÉ EN MÉMOIRE :

0x1000  ┌────┬───┬───┬───┐
        │ a  │PAD│PAD│PAD│  4 bytes (aligné)
        └────┴───┴───┴───┘
0x1004  ┌────┬────┬────┬────┐
        │ b  │ b  │ b  │ b  │  4 bytes
        └────┴────┴────┴────┘
0x1008  ┌────┬───┬───┬───┐
        │ c  │PAD│PAD│PAD│  4 bytes (aligné)
        └────┴───┴───┴───┘

TOTAL RÉEL : 12 bytes (pas 6 !)

PAD = Padding (bytes vides pour alignement)
```

**Pourquoi ?**

Le CPU préfère lire par blocs de 4 ou 8 bytes. L'alignement améliore les performances.

### 4.2 Optimiser l'Ordre des Champs

```ascii
MAUVAIS ORDRE (beaucoup de padding) :

struct Bad {
    char a;    // 1 + 3 padding
    int b;     // 4
    char c;    // 1 + 3 padding
    int d;     // 4
};  // Total : 16 bytes

┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ a │░░░│ b │ b │ b │ b │ c │░░░│ d │ d │ d │ d │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
  1   3   4               1   3   4        = 16 bytes

BON ORDRE (moins de padding) :

struct Good {
    int b;     // 4
    int d;     // 4
    char a;    // 1
    char c;    // 1 + 2 padding
};  // Total : 12 bytes

┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ b │ b │ b │ b │ d │ d │ d │ d │ a │ c │░░│
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
  4               4               1   1   2    = 12 bytes

GAIN : 25% de mémoire économisée !
```

## 5. Structures et Pointeurs - Combinaison Puissante

### 5.1 Pointeur vers Structure

```c
struct Etudiant alice = {"Alice", 20, 15.5};
struct Etudiant *ptr = &alice;

printf("%s\n", ptr->nom);
printf("%d\n", ptr->age);
```

```ascii
MÉMOIRE :

STACK :
┌──────────────┐
│ ptr          │
│   = 0x1000   │───┐
└──────────────┘   │
                   ↓
STACK (ou HEAP) :
0x1000  ┌─────────────────────┐
        │ alice               │
        │  ├─ nom: "Alice"    │
        │  ├─ age: 20         │
        │  └─ note: 15.5      │
        └─────────────────────┘

ptr->nom   accède à alice.nom
ptr->age   accède à alice.age
ptr->note  accède à alice.note
```

### 5.2 Structure avec Pointeur Interne

```c
struct Personne {
    char *nom;      // Pointeur vers string
    int age;
};
```

```ascii
MÉMOIRE DÉTAILLÉE :

struct Personne p;
p.nom = malloc(50);
strcpy(p.nom, "Jean");
p.age = 30;

STACK :
0x1000  ┌──────────────────────┐
        │ p (structure)        │
        │  ├─ nom: 0x5000      │───┐
        │  └─ age: 30          │   │
        └──────────────────────┘   │
                                   │
HEAP :                             │
0x5000  ┌──────────────────────┐ ← ┘
        │ "Jean\0"             │
        │  J  e  a  n  \0      │
        └──────────────────────┘

Le pointeur "nom" pointe vers une string sur le HEAP
```

## 6. typedef - Simplifier les Déclarations

### 6.1 Sans typedef (Verbeux)

```c
struct Etudiant {
    char nom[50];
    int age;
};

struct Etudiant alice;      // Doit écrire "struct" à chaque fois
struct Etudiant bob;
struct Etudiant *ptr;
```

### 6.2 Avec typedef (Concis)

```c
typedef struct {
    char nom[50];
    int age;
} Etudiant;  // ← Crée un alias

Etudiant alice;   // Plus besoin de "struct" !
Etudiant bob;
Etudiant *ptr;
```

**Comparaison Visuelle** :

```ascii
SANS typedef :
┌──────────────────────────────────────┐
│ struct Etudiant alice;               │  7 mots
│ struct Etudiant bob;                 │  7 mots
│ struct Etudiant *ptr;                │  8 mots
└──────────────────────────────────────┘

AVEC typedef :
┌──────────────────────────────────────┐
│ Etudiant alice;                      │  2 mots
│ Etudiant bob;                        │  2 mots
│ Etudiant *ptr;                       │  3 mots
└──────────────────────────────────────┘

Plus court = plus lisible !
```

## 7. Structures Imbriquées - Structures dans Structures

```c
struct Adresse {
    char rue[100];
    int numero;
    char ville[50];
};

struct Personne {
    char nom[50];
    int age;
    struct Adresse domicile;  // Structure dans structure !
};
```

```ascii
MÉMOIRE HIÉRARCHIQUE :

┌──────────────────────────────────────────────────┐
│  struct Personne jean                            │
├──────────────────────────────────────────────────┤
│                                                  │
│  0x1000  ┌────────────────┐                      │
│          │ nom: "Jean"    │  50 bytes            │
│  0x1032  └────────────────┘                      │
│                                                  │
│  0x1034  ┌────────────────┐                      │
│          │ age: 35        │  4 bytes             │
│  0x1037  └────────────────┘                      │
│                                                  │
│  0x1038  ┌─────────────────────────────────────┐ │
│          │ domicile (struct Adresse)           │ │
│          │  ├─ 0x1038: rue "Rue de la Paix"    │ │  100 bytes
│          │  ├─ 0x109C: numero: 42              │ │  4 bytes
│          │  └─ 0x10A0: ville "Paris"           │ │  50 bytes
│  0x10D1  └─────────────────────────────────────┘ │
│                                                  │
└──────────────────────────────────────────────────┘

ACCÈS :
jean.nom                    → "Jean"
jean.age                    → 35
jean.domicile.rue           → "Rue de la Paix"
jean.domicile.numero        → 42
jean.domicile.ville         → "Paris"
```

## 8. Tableaux de Structures

```c
struct Etudiant classe[30];  // 30 étudiants
```

```ascii
MÉMOIRE :

┌─────────────────┐
│ classe[0]       │  ← Premier étudiant
│  ├─ nom         │
│  ├─ age         │
│  └─ note        │
├─────────────────┤
│ classe[1]       │  ← Deuxième étudiant
│  ├─ nom         │
│  ├─ age         │
│  └─ note        │
├─────────────────┤
│ classe[2]       │
│  ...            │
├─────────────────┤
│ ...             │
├─────────────────┤
│ classe[29]      │  ← Trentième étudiant
│  ├─ nom         │
│  ├─ age         │
│  └─ note        │
└─────────────────┘

Accès :
classe[0].nom → Nom du premier étudiant
classe[5].age → Âge du sixième étudiant
```

## 9. Passer des Structures aux Fonctions

### 9.1 Par Valeur (Copie Complète)

```c
void afficher(struct Etudiant e) {  // Copie toute la structure
    printf("%s : %d ans\n", e.nom, e.age);
}
```

```ascii
AVANT appel afficher(alice) :

main() :
┌────────────────┐
│ alice          │  58 bytes
│  ├─ nom        │
│  ├─ age: 20    │
│  └─ note       │
└────────────────┘

PENDANT afficher() :

STACK :
┌────────────────┐
│ e (COPIE)      │  58 bytes copiés !
│  ├─ nom        │  ← Copie complète
│  ├─ age: 20    │
│  └─ note       │
└────────────────┘

❌ PROBLÈME : Copier 58 bytes à chaque appel = LENT
❌ Modifications de "e" n'affectent pas "alice"
```

### 9.2 Par Pointeur (Efficient)

```c
void afficher(struct Etudiant *e) {  // Juste un pointeur (8 bytes)
    printf("%s : %d ans\n", e->nom, e->age);
}
```

```ascii
PENDANT afficher(&alice) :

STACK :
┌────────────────┐
│ e = 0x1000     │  Seulement 8 bytes !
└────────┬───────┘
         │
         ↓
┌────────────────┐
│ alice          │  ← Original (pas de copie)
│  ├─ nom        │
│  ├─ age: 20    │
│  └─ note       │
└────────────────┘

✅ RAPIDE : 8 bytes au lieu de 58
✅ Modifications possibles via e->age = 21
```

## 10. Structures Auto-Référentes - Linked Lists

```c
struct Node {
    int data;
    struct Node *next;  // Pointeur vers MÊME type !
};
```

```ascii
POURQUOI C'EST POSSIBLE ?

┌──────────────────────────────────────┐
│  struct Node                         │
│  ├─ data: 10                         │
│  └─ next: ──────────┐                │
└────────────────────┬┘                │
                     │                 │
                     ↓                 │
┌──────────────────────────────────────┤
│  struct Node                         │
│  ├─ data: 20                         │
│  └─ next: ──────────┐                │
└────────────────────┬┘                │
                     │                 │
                     ↓                 │
┌──────────────────────────────────────┤
│  struct Node                         │
│  ├─ data: 30                         │
│  └─ next: NULL                       │
└──────────────────────────────────────┘

Chaque nœud "pointe" vers un autre nœud du même type
C'est la BASE des listes chaînées !
```

## 11. Bonnes Pratiques

```ascii
✅ Utiliser typedef pour simplifier
✅ Grouper champs par taille (gros → petits) pour minimiser padding
✅ Passer par pointeur aux fonctions (éviter copies)
✅ Utiliser -> avec pointeurs, . avec variables
✅ Initialiser tous les champs (éviter garbage)
✅ Commenter chaque champ (expliquer son rôle)
```

## Ressources

- [Structures (cppreference)](https://en.cppreference.com/w/c/language/struct)
- [Memory Alignment](https://en.wikipedia.org/wiki/Data_structure_alignment)


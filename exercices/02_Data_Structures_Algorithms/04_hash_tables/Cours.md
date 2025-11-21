# Cours : Tables de Hachage (Hash Tables)

## 1. Introduction

Une **table de hachage** est une structure de données qui permet des opérations **extrêmement rapides** :
- **Recherche** : O(1) en moyenne
- **Insertion** : O(1) en moyenne
- **Suppression** : O(1) en moyenne

Le principe : utiliser une **fonction de hachage** pour convertir une clé en index de tableau.

**Applications** : Dictionnaires, caches, bases de données, sets, compteurs, etc.

## 2. Le Principe Magique

### 2.1 De la Clé à l'Index

```ascii
FLUX DE DONNÉES :

CLÉ (texte) → FONCTION HASH → NOMBRE → MODULO → INDEX
                  |              |         |        |
"john"         hash()      2947583    % 10      = 3

"john"  → hash("john")   → 2947583 → 2947583 % 10 → Index 3
"mary"  → hash("mary")   → 8372941 → 8372941 % 10 → Index 1
"bob"   → hash("bob")    → 5029384 → 5029384 % 10 → Index 4
```

### 2.2 Visualisation de la Table

```ascii
TABLE DE HACHAGE (Taille 10) :

Index  Contenu
┌───┬───────────────┐
│ 0 │  (vide)       │
├───┼───────────────┤
│ 1 │  Mary → 30    │  ← hash("mary") % 10 = 1
├───┼───────────────┤
│ 2 │  (vide)       │
├───┼───────────────┤
│ 3 │  John → 25    │  ← hash("john") % 10 = 3
├───┼───────────────┤
│ 4 │  Bob → 35     │  ← hash("bob") % 10 = 4
├───┼───────────────┤
│ 5 │  (vide)       │
├───┼───────────────┤
│ 6 │  (vide)       │
├───┼───────────────┤
│ 7 │  (vide)       │
├───┼───────────────┤
│ 8 │  (vide)       │
├───┼───────────────┤
│ 9 │  (vide)       │
└───┴───────────────┘

RECHERCHE de "john" :
1. Calculer hash("john") % 10 = 3
2. Aller directement à index 3
3. Vérifier si c'est "john" → OUI
4. Retourner 25

Total : O(1) - Temps constant !
```

### 2.3 Comparaison avec Autres Structures

```ascii
RECHERCHE de "john" dans une liste de 1000 éléments :

TABLEAU NON TRIÉ :
[Alice] [Bob] [Charlie] ... [John] ... [Zoe]
  ↓       ↓       ↓         ↓          ↓
  1       2       3    ... 523    ... 1000
  
Recherche linéaire : O(n) = jusqu'à 1000 comparaisons

TABLEAU TRIÉ :
[Alice] [Bob] [Charlie] ... [John] ... [Zoe]
          ↓ Recherche binaire
          O(log n) = ~10 comparaisons
          
HASH TABLE :
hash("john") % size → Index direct
O(1) = 1 opération
```

## 3. Fonction de Hachage

### Principes

Une bonne fonction de hachage doit :
1. **Être déterministe** : Même clé → Même hash
2. **Distribuer uniformément** : Minimiser les collisions
3. **Être rapide** : O(1)

### Exemples

```c
// Hash simple pour entiers
unsigned int hash_int(int key, int table_size) {
    return abs(key) % table_size;
}

// Hash pour strings (djb2)
unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

// Conversion en index
unsigned int get_index(const char *key, int table_size) {
    return hash_string(key) % table_size;
}
```

## 4. Gestion des Collisions

Que faire quand **deux clés** ont le **même hash** ?

### Méthode 1 : Chaînage (Separate Chaining)

Chaque case contient une **liste chaînée**.

```ascii
TABLE
┌────┬────┬────┬────┐
│    │ →  │    │ →  │
└────┴─|──┴────┴─|──┘
       ↓          ↓
     [A:10]     [C:20]
       ↓          ↓
     [B:15]     [D:25]
```

```c
typedef struct Entry {
    char *key;
    int value;
    struct Entry *next;
} Entry;

typedef struct HashTable {
    Entry **buckets;  // Tableau de listes chaînées
    int size;
} HashTable;
```

**Insertion** :
```c
void insert(HashTable *ht, const char *key, int value) {
    unsigned int index = get_index(key, ht->size);
    
    // Créer nouvelle entrée
    Entry *new_entry = malloc(sizeof(Entry));
    new_entry->key = strdup(key);
    new_entry->value = value;
    
    // Insérer au début de la liste
    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;
}
```

**Recherche** :
```c
int search(HashTable *ht, const char *key) {
    unsigned int index = get_index(key, ht->size);
    Entry *current = ht->buckets[index];
    
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            return current->value;  // Trouvé
        }
        current = current->next;
    }
    
    return -1;  // Non trouvé
}
```

### Méthode 2 : Adressage Ouvert (Open Addressing)

Stockage direct dans le tableau. En cas de collision, chercher la **prochaine case libre**.

#### Sondage Linéaire

```c
// Si index occupé → essayer index+1, index+2, etc.
unsigned int linear_probe(int index, int i, int size) {
    return (index + i) % size;
}
```

#### Sondage Quadratique

```c
unsigned int quadratic_probe(int index, int i, int size) {
    return (index + i*i) % size;
}
```

#### Double Hachage

```c
unsigned int double_hash(int index, int i, int size, int key) {
    int hash2 = 7 - (key % 7);  // Fonction secondaire
    return (index + i * hash2) % size;
}
```

## 5. Implémentation Complète (Chaînage)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 10

typedef struct Entry {
    char *key;
    int value;
    struct Entry *next;
} Entry;

typedef struct HashTable {
    Entry **buckets;
    int size;
} HashTable;

// Créer une table
HashTable* create_table(int size) {
    HashTable *ht = malloc(sizeof(HashTable));
    ht->size = size;
    ht->buckets = calloc(size, sizeof(Entry*));
    return ht;
}

// Fonction de hachage
unsigned long hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

unsigned int get_index(const char *key, int size) {
    return hash(key) % size;
}

// Insérer
void insert(HashTable *ht, const char *key, int value) {
    unsigned int index = get_index(key, ht->size);
    
    // Vérifier si clé existe déjà (mise à jour)
    Entry *current = ht->buckets[index];
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            current->value = value;  // Mise à jour
            return;
        }
        current = current->next;
    }
    
    // Nouvelle entrée
    Entry *new_entry = malloc(sizeof(Entry));
    new_entry->key = strdup(key);
    new_entry->value = value;
    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;
}

// Rechercher
int search(HashTable *ht, const char *key, int *found) {
    unsigned int index = get_index(key, ht->size);
    Entry *current = ht->buckets[index];
    
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            *found = 1;
            return current->value;
        }
        current = current->next;
    }
    
    *found = 0;
    return -1;
}

// Supprimer
void delete(HashTable *ht, const char *key) {
    unsigned int index = get_index(key, ht->size);
    Entry *current = ht->buckets[index];
    Entry *prev = NULL;
    
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            if (prev == NULL) {
                ht->buckets[index] = current->next;
            } else {
                prev->next = current->next;
            }
            free(current->key);
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

// Libérer
void free_table(HashTable *ht) {
    for (int i = 0; i < ht->size; i++) {
        Entry *current = ht->buckets[i];
        while (current != NULL) {
            Entry *temp = current;
            current = current->next;
            free(temp->key);
            free(temp);
        }
    }
    free(ht->buckets);
    free(ht);
}
```

## 6. Facteur de Charge

**Load Factor** = nombre d'éléments / taille de la table

```c
float load_factor(HashTable *ht, int num_elements) {
    return (float)num_elements / ht->size;
}
```

- **< 0.7** : Performance optimale
- **> 0.7** : Envisager **rehashing** (agrandir la table)

### Rehashing

```c
void rehash(HashTable *ht) {
    int old_size = ht->size;
    Entry **old_buckets = ht->buckets;
    
    // Doubler la taille
    ht->size *= 2;
    ht->buckets = calloc(ht->size, sizeof(Entry*));
    
    // Réinsérer tous les éléments
    for (int i = 0; i < old_size; i++) {
        Entry *current = old_buckets[i];
        while (current != NULL) {
            insert(ht, current->key, current->value);
            Entry *temp = current;
            current = current->next;
            free(temp->key);
            free(temp);
        }
    }
    
    free(old_buckets);
}
```

## 7. Applications Réelles

### Compteur de Mots

```c
void count_words(char *text) {
    HashTable *ht = create_table(100);
    
    char *word = strtok(text, " \n\t");
    while (word != NULL) {
        int found, count = search(ht, word, &found);
        insert(ht, word, found ? count + 1 : 1);
        word = strtok(NULL, " \n\t");
    }
    
    // Afficher les compteurs
    print_table(ht);
}
```

### Cache LRU (Least Recently Used)

```c
// Combiner hash table + liste doublement chaînée
typedef struct CacheEntry {
    char *key;
    int value;
    struct CacheEntry *prev, *next;
} CacheEntry;
```

### Set (Ensemble)

```c
// Hash table où value = 1 (présence)
void add_to_set(HashTable *set, const char *item) {
    insert(set, item, 1);
}

int in_set(HashTable *set, const char *item) {
    int found;
    search(set, item, &found);
    return found;
}
```

## 8. Complexité

| Opération  | Average | Worst Case |
|------------|---------|------------|
| Recherche  | O(1)    | O(n)       |
| Insertion  | O(1)    | O(n)       |
| Suppression| O(1)    | O(n)       |

**Worst case** = toutes les clés dans le même bucket (hash collision)

## 9. Comparaison

| Structure   | Recherche | Insertion | Suppression | Ordre |
|-------------|-----------|-----------|-------------|-------|
| Array       | O(n)      | O(1)*     | O(n)        | Oui   |
| Linked List | O(n)      | O(1)      | O(n)        | Oui   |
| **Hash Table** | **O(1)** | **O(1)** | **O(1)** | **Non** |
| Binary Tree | O(log n)  | O(log n)  | O(log n)    | Oui   |

*À la fin

## 10. Bonnes Pratiques

1. **Choisir une bonne fonction de hachage**
2. **Surveiller le load factor** (< 0.7)
3. **Rehash** quand nécessaire
4. **Libérer toute la mémoire**
5. **Gérer les collisions** correctement

## 11. Ressources

- [Hash Tables (Wikipedia)](https://en.wikipedia.org/wiki/Hash_table)
- [Hash Functions](https://en.wikipedia.org/wiki/Hash_function)
- [djb2 algorithm](http://www.cse.yorku.ca/~oz/hash.html)


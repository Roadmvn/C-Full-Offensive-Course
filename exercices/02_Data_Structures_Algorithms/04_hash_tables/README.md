# Tables de Hachage (Hash Tables)

Structure de données ultra-rapide pour recherche, insertion et suppression.

## Principe

**Clé → Fonction Hash → Index → Valeur**

```c
hash("john") % 10 = 3
table[3] = "john:25"
```

## Complexité

| Opération  | Moyenne | Pire Cas |
|------------|---------|----------|
| Recherche  | O(1)    | O(n)     |
| Insertion  | O(1)    | O(n)     |
| Suppression| O(1)    | O(n)     |

## Gestion des Collisions

### Chaînage (Separate Chaining)
Chaque case contient une liste chaînée.

```c
table[3] → [John:25] → [Jane:30] → NULL
```

### Adressage Ouvert
Chercher la prochaine case libre.

```c
// Sondage linéaire
index = (hash + i) % size
```

## Applications

- **Dictionnaires** : Clé → Valeur
- **Sets** : Vérifier existence
- **Caches** : Accès rapide
- **Compteurs** : Fréquence des éléments
- **Déduplication** : Détecter doublons

## Fonction de Hachage

```c
// djb2 pour strings
unsigned long hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}
```

## Load Factor

```
load_factor = éléments / taille
```

- < 0.7 : Performance optimale
- \> 0.7 : Rehashing recommandé

## Compilation

```bash
gcc example.c -o hashtable
./hashtable
```


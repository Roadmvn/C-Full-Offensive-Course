# Tri et Recherche (Sorting & Searching)

Algorithmes fondamentaux pour organiser et trouver des données.

## Algorithmes de Tri

### Simples - O(n²)
- **Bubble Sort** : Échange adjacents
- **Selection Sort** : Trouve minimum
- **Insertion Sort** : Insère à la place

### Efficaces - O(n log n)
- **Merge Sort** : Diviser pour régner
- **Quick Sort** : Partition autour pivot

## Comparaison

| Algorithme | Meilleur | Moyen | Pire | Espace |
|-----------|----------|-------|------|--------|
| Bubble    | O(n)     | O(n²) | O(n²)| O(1)   |
| Insertion | O(n)     | O(n²) | O(n²)| O(1)   |
| Merge     | O(n log n)| O(n log n)| O(n log n)| O(n)|
| Quick     | O(n log n)| O(n log n)| O(n²)| O(log n)|

## Recherche

### Linéaire - O(n)
Parcourt tout le tableau.

### Binaire - O(log n)
**Nécessite un tableau trié**.

```c
// Binaire itérative
int mid = left + (right - left) / 2;
if (arr[mid] == target) return mid;
if (arr[mid] < target) left = mid + 1;
else right = mid - 1;
```

## Quand Utiliser ?

- **Petit tableau** : Insertion Sort
- **Garantie** : Merge Sort
- **Performance** : Quick Sort
- **Recherche** : Binary Search (si trié)

## Compilation

```bash
gcc example.c -o sorting
./sorting
```


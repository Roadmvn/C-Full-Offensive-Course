# Cours : Tri et Recherche (Sorting & Searching)

## 1. Introduction - Pourquoi Trier ?

### 1.1 Le Problème

Imaginez une bibliothèque avec **10,000 livres** placés au hasard sur les étagères. Comment trouver rapidement "Les Misérables" ?

**Sans tri** :
- Parcourir livre par livre : **10,000 vérifications** dans le pire cas
- Temps : **TRÈS LONG** ⏳

**Avec tri alphabétique** :
- Recherche binaire : **~14 comparaisons** maximum
- Temps : **QUASI-INSTANTANÉ** ⚡

**C'est la puissance du tri !**

### 1.2 Qu'est-ce que Trier ?

**Trier** = Réorganiser des éléments dans un **ordre spécifique** (croissant ou décroissant).

```ascii
AVANT TRI :
[64, 25, 12, 22, 11, 90, 34]
 ↓   ↓   ↓   ↓   ↓   ↓   ↓
Ordre aléatoire (chaos)

APRÈS TRI (croissant) :
[11, 12, 22, 25, 34, 64, 90]
 ↓   ↓   ↓   ↓   ↓   ↓   ↓
Ordre organisé (structure)
```

### 1.3 Applications Réelles

- **Bases de données** : Requêtes SQL avec `ORDER BY`
- **Systèmes de fichiers** : Tri par nom, date, taille
- **E-commerce** : Trier produits par prix
- **Réseaux sociaux** : Trier posts par date
- **Recherche** : Pré-requis pour recherche binaire

### 1.4 Complexité - Le Concept de Big-O

La **complexité** mesure comment le **temps d'exécution** évolue quand la **taille des données** augmente.

```ascii
NOTATION BIG-O :

O(1) - Constant
    Temps →
    │ ─────────  Parfait ! (hash table)
    │
    └───────────→ Taille données

O(log n) - Logarithmique
    │      ╱
    │    ╱    Excellent ! (recherche binaire, arbres)
    │  ╱
    └───────────→

O(n) - Linéaire
    │         ╱
    │       ╱  Acceptable (parcours tableau)
    │     ╱
    └───────────→

O(n log n) - Linéarithmique
    │           ╱╱
    │         ╱╱  Bon pour tri (merge sort, quick sort)
    │       ╱╱
    └───────────→

O(n²) - Quadratique
    │             ╱│
    │           ╱  │  Lent ! (bubble sort, boucles imbriquées)
    │         ╱    │
    └───────────→
```

**Exemples concrets** :

| Taille (n) | O(log n) | O(n) | O(n log n) | O(n²) |
|------------|----------|------|------------|-------|
| 10         | ~3       | 10   | ~33        | 100   |
| 100        | ~7       | 100  | ~664       | 10,000|
| 1000       | ~10      | 1000 | ~9,966     | 1,000,000|
| 1,000,000  | ~20      | 1M   | ~20M       | 1,000,000,000,000|

**Conclusion** : O(n²) devient **impraticable** pour de grandes données !

## 2. Algorithmes de Tri - Du Plus Simple au Plus Efficace

### 2.1 Bubble Sort - O(n²) - Le Plus Simple

**Principe** : Compare et échange les éléments **adjacents** jusqu'à ce que tout soit trié.

**Analogie** : Des bulles qui remontent à la surface (les plus grandes valeurs "flottent" vers la fin).

#### Visualisation Pas-à-Pas

```ascii
TABLEAU INITIAL : [5, 2, 8, 1, 9]

PASSE 1 :
Compare 5 et 2 → Échange      [2, 5, 8, 1, 9]
Compare 5 et 8 → OK           [2, 5, 8, 1, 9]
Compare 8 et 1 → Échange      [2, 5, 1, 8, 9]
Compare 8 et 9 → OK           [2, 5, 1, 8, 9]
                              └─────────────┘
                              9 est à sa place !

PASSE 2 :
Compare 2 et 5 → OK           [2, 5, 1, 8, 9]
Compare 5 et 1 → Échange      [2, 1, 5, 8, 9]
Compare 5 et 8 → OK           [2, 1, 5, 8, 9]
                                 └────────┘
                                 8 est à sa place !

PASSE 3 :
Compare 2 et 1 → Échange      [1, 2, 5, 8, 9]
Compare 2 et 5 → OK           [1, 2, 5, 8, 9]
                                 └─────────┘
                                 5, 8, 9 en place !

PASSE 4 :
Compare 1 et 2 → OK           [1, 2, 5, 8, 9]
                              └──────────────┘
                              TRIÉ ! ✅
```

#### Animation ASCII

```ascii
Itération 1 : [5̲, 2̲, 8, 1, 9]  → [2̲, 5̲, 8, 1, 9]
Itération 2 : [2, 5̲, 8̲, 1, 9]  → [2, 5̲, 8̲, 1, 9] (pas d'échange)
Itération 3 : [2, 5, 8̲, 1̲, 9]  → [2, 5, 1̲, 8̲, 9]
Itération 4 : [2, 5, 1, 8̲, 9̲]  → [2, 5, 1, 8̲, 9̲] (pas d'échange)

Plus grande valeur "bulle" vers la fin à chaque passe
```

Échange les éléments adjacents si mal ordonnés.

```c
void bubble_sort(int arr[], int n) {
    for (int i = 0; i < n-1; i++) {
        for (int j = 0; j < n-i-1; j++) {
            if (arr[j] > arr[j+1]) {
                int temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
        }
    }
}
```

### Selection Sort - O(n²)

Trouve le minimum et le place au début.

```c
void selection_sort(int arr[], int n) {
    for (int i = 0; i < n-1; i++) {
        int min_idx = i;
        for (int j = i+1; j < n; j++) {
            if (arr[j] < arr[min_idx]) {
                min_idx = j;
            }
        }
        int temp = arr[i];
        arr[i] = arr[min_idx];
        arr[min_idx] = temp;
    }
}
```

### Insertion Sort - O(n²)

Insère chaque élément à sa place.

```c
void insertion_sort(int arr[], int n) {
    for (int i = 1; i < n; i++) {
        int key = arr[i];
        int j = i - 1;
        
        while (j >= 0 && arr[j] > key) {
            arr[j+1] = arr[j];
            j--;
        }
        arr[j+1] = key;
    }
}
```

### Merge Sort - O(n log n)

Divise récursivement puis fusionne.

```c
void merge(int arr[], int l, int m, int r) {
    int n1 = m - l + 1;
    int n2 = r - m;
    
    int L[n1], R[n2];
    
    for (int i = 0; i < n1; i++) L[i] = arr[l + i];
    for (int j = 0; j < n2; j++) R[j] = arr[m + 1 + j];
    
    int i = 0, j = 0, k = l;
    
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            arr[k++] = L[i++];
        } else {
            arr[k++] = R[j++];
        }
    }
    
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];
}

void merge_sort(int arr[], int l, int r) {
    if (l < r) {
        int m = l + (r - l) / 2;
        merge_sort(arr, l, m);
        merge_sort(arr, m+1, r);
        merge(arr, l, m, r);
    }
}
```

### Quick Sort - O(n log n) moyenne, O(n²) pire cas

Partition autour d'un pivot.

```c
int partition(int arr[], int low, int high) {
    int pivot = arr[high];
    int i = low - 1;
    
    for (int j = low; j < high; j++) {
        if (arr[j] < pivot) {
            i++;
            int temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }
    }
    
    int temp = arr[i+1];
    arr[i+1] = arr[high];
    arr[high] = temp;
    
    return i + 1;
}

void quick_sort(int arr[], int low, int high) {
    if (low < high) {
        int pi = partition(arr, low, high);
        quick_sort(arr, low, pi - 1);
        quick_sort(arr, pi + 1, high);
    }
}
```

## 3. Comparaison des Tris

| Algorithme     | Meilleur | Moyen    | Pire     | Espace   | Stable |
|----------------|----------|----------|----------|----------|--------|
| Bubble Sort    | O(n)     | O(n²)    | O(n²)    | O(1)     | Oui    |
| Selection Sort | O(n²)    | O(n²)    | O(n²)    | O(1)     | Non    |
| Insertion Sort | O(n)     | O(n²)    | O(n²)    | O(1)     | Oui    |
| **Merge Sort** | **O(n log n)** | **O(n log n)** | **O(n log n)** | **O(n)** | **Oui** |
| **Quick Sort** | **O(n log n)** | **O(n log n)** | **O(n²)** | **O(log n)** | **Non** |

## 4. Algorithmes de Recherche

### Recherche Linéaire - O(n)

Parcourt séquentiellement.

```c
int linear_search(int arr[], int n, int target) {
    for (int i = 0; i < n; i++) {
        if (arr[i] == target) {
            return i;
        }
    }
    return -1;
}
```

### Recherche Binaire - O(log n)

**Nécessite un tableau trié**.

```c
int binary_search(int arr[], int n, int target) {
    int left = 0, right = n - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        
        if (arr[mid] == target) {
            return mid;
        }
        
        if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    return -1;
}
```

### Recherche Binaire Récursive

```c
int binary_search_recursive(int arr[], int left, int right, int target) {
    if (left > right) return -1;
    
    int mid = left + (right - left) / 2;
    
    if (arr[mid] == target) return mid;
    
    if (arr[mid] < target) {
        return binary_search_recursive(arr, mid+1, right, target);
    } else {
        return binary_search_recursive(arr, left, mid-1, target);
    }
}
```

## 5. Quand Utiliser Quel Tri ?

- **Petit tableau (< 50)** : Insertion Sort
- **Garantie O(n log n)** : Merge Sort
- **Performance moyenne** : Quick Sort
- **Presque trié** : Insertion Sort
- **Pas d'espace mémoire** : Quick Sort ou Selection Sort

## 6. Applications

### Tri par Comptage - O(n+k)

Pour petites plages d'entiers.

```c
void counting_sort(int arr[], int n, int max) {
    int count[max+1];
    int output[n];
    
    for (int i = 0; i <= max; i++) count[i] = 0;
    for (int i = 0; i < n; i++) count[arr[i]]++;
    for (int i = 1; i <= max; i++) count[i] += count[i-1];
    
    for (int i = n-1; i >= 0; i--) {
        output[count[arr[i]]-1] = arr[i];
        count[arr[i]]--;
    }
    
    for (int i = 0; i < n; i++) arr[i] = output[i];
}
```

## 7. Optimisations

### Quick Sort avec Médiane de 3

```c
int median_of_three(int arr[], int low, int high) {
    int mid = low + (high - low) / 2;
    
    if (arr[low] > arr[mid]) swap(&arr[low], &arr[mid]);
    if (arr[low] > arr[high]) swap(&arr[low], &arr[high]);
    if (arr[mid] > arr[high]) swap(&arr[mid], &arr[high]);
    
    return mid;
}
```

## 8. Complexité Spatiale

- **In-place** : O(1) - Bubble, Selection, Insertion, Quick
- **Extra space** : O(n) - Merge

## Ressources

- [Sorting Algorithms (Wikipedia)](https://en.wikipedia.org/wiki/Sorting_algorithm)
- [Visualization](https://www.toptal.com/developers/sorting-algorithms)
- [Binary Search](https://en.wikipedia.org/wiki/Binary_search_algorithm)


# EXERCICE : TRI ET RECHERCHE


### OBJECTIF :
Implémenter et comparer différents algorithmes de tri et recherche.

═══════════════════════════════════════════════════════════════

### PARTIE 1 : ALGORITHMES DE TRI
═══════════════════════════════════════════════════════════════

Implémenter les algorithmes suivants :

1. bubble_sort(arr, n)
2. selection_sort(arr, n)
3. insertion_sort(arr, n)
4. merge_sort(arr, left, right)
5. quick_sort(arr, low, high)

Pour chaque algorithme :
- Mesurer le temps d'exécution
- Compter le nombre de comparaisons
- Compter le nombre d'échanges

═══════════════════════════════════════════════════════════════

### PARTIE 2 : ALGORITHMES DE RECHERCHE
═══════════════════════════════════════════════════════════════

1. linear_search(arr, n, target)
2. binary_search(arr, n, target) - itératif
3. binary_search_recursive(arr, left, right, target)
4. interpolation_search(arr, n, target) - bonus
5. jump_search(arr, n, target) - bonus

═══════════════════════════════════════════════════════════════

### PARTIE 3 : COMPARAISON DES PERFORMANCES
═══════════════════════════════════════════════════════════════

Créer une fonction benchmark :

benchmark_sorting(size) :
- Génère un tableau aléatoire de taille "size"
- Teste tous les algorithmes de tri
- Affiche le temps d'exécution de chacun
- Affiche les statistiques (comparaisons, échanges)

TAILLES À TESTER : 100, 1000, 10000

═══════════════════════════════════════════════════════════════

### PARTIE 4 : CAS SPÉCIAUX
═══════════════════════════════════════════════════════════════

Tester avec :
1. Tableau déjà trié
2. Tableau trié en ordre inverse
3. Tableau avec beaucoup de doublons
4. Tableau avec un seul élément
5. Tableau vide

═══════════════════════════════════════════════════════════════

### PARTIE 5 : APPLICATIONS PRATIQUES
═══════════════════════════════════════════════════════════════

1. Trier une liste de personnes par âge puis par nom
2. Trouver le k-ième plus petit élément
3. Fusionner deux tableaux triés
4. Trouver la médiane d'un tableau
5. Détecter si un tableau est trié

═══════════════════════════════════════════════════════════════

### EXERCICES BONUS
═══════════════════════════════════════════════════════════════

1. Implémenter heap_sort
2. Implémenter radix_sort
3. Implémenter counting_sort
4. Tri de strings alphabétique
5. Tri personnalisé avec fonction de comparaison

FICHIER : main.c

**COMPILATION : gcc main.c -o sorting -Wall**
MESURE TEMPS : #include <time.h>



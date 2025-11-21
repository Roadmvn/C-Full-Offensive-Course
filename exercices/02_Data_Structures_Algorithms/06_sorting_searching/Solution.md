# SOLUTION : TRI ET RECHERCHE

IMPLÉMENTATION COMPLÈTE AVEC BENCHMARK


---


```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
```


```c
void print_array(int arr[], int n) {
```
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}


```c
// ========== TRIS ==========
```


```c
void bubble_sort(int arr[], int n) {
```
    for (int i = 0; i < n-1; i++) {
        int swapped = 0;
        for (int j = 0; j < n-i-1; j++) {
            if (arr[j] > arr[j+1]) {
                int temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
                swapped = 1;
            }
        }
        if (!swapped) break;  // Optimisation
    }
}


```c
void insertion_sort(int arr[], int n) {
```
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


```c
void merge(int arr[], int l, int m, int r) {
    int n1 = m - l + 1;
    int n2 = r - m;
```

    int *L = malloc(n1 * sizeof(int));
    int *R = malloc(n2 * sizeof(int));
    
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
    
    free(L);
    free(R);
}


```c
void merge_sort(int arr[], int l, int r) {
```
    if (l < r) {
        int m = l + (r - l) / 2;
        merge_sort(arr, l, m);
        merge_sort(arr, m+1, r);
        merge(arr, l, m, r);
    }
}

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


```c
void quick_sort(int arr[], int low, int high) {
```
    if (low < high) {
        int pi = partition(arr, low, high);
        quick_sort(arr, low, pi - 1);
        quick_sort(arr, pi + 1, high);
    }
}


```c
// ========== RECHERCHE ==========
```

int linear_search(int arr[], int n, int target) {
    for (int i = 0; i < n; i++) {
        if (arr[i] == target) return i;
    }
    return -1;
}

int binary_search(int arr[], int n, int target) {
    int left = 0, right = n - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        
        if (arr[mid] == target) return mid;
        
        if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    return -1;
}


```c
// ========== BENCHMARK ==========
```


```c
void benchmark_sorting(int size) {
```
    printf("\n╔════════════════════════════════════════╗\n");
    printf("║ BENCHMARK - Taille : %d\n", size);
    printf("╚════════════════════════════════════════╝\n");
    
    int *original = malloc(size * sizeof(int));
    srand(time(NULL));
    
    for (int i = 0; i < size; i++) {
        original[i] = rand() % 1000;
    }
    

```c
    // Bubble Sort
    int *arr = malloc(size * sizeof(int));
```
    memcpy(arr, original, size * sizeof(int));
    clock_t start = clock();
    bubble_sort(arr, size);
    clock_t end = clock();
    printf("Bubble Sort   : %.6f secondes\n", 
           (double)(end - start) / CLOCKS_PER_SEC);
    free(arr);
    

```c
    // Insertion Sort
```
    arr = malloc(size * sizeof(int));
    memcpy(arr, original, size * sizeof(int));
    start = clock();
    insertion_sort(arr, size);
    end = clock();
    printf("Insertion Sort: %.6f secondes\n", 
           (double)(end - start) / CLOCKS_PER_SEC);
    free(arr);
    

```c
    // Merge Sort
```
    arr = malloc(size * sizeof(int));
    memcpy(arr, original, size * sizeof(int));
    start = clock();
    merge_sort(arr, 0, size-1);
    end = clock();
    printf("Merge Sort    : %.6f secondes\n", 
           (double)(end - start) / CLOCKS_PER_SEC);
    free(arr);
    

```c
    // Quick Sort
```
    arr = malloc(size * sizeof(int));
    memcpy(arr, original, size * sizeof(int));
    start = clock();
    quick_sort(arr, 0, size-1);
    end = clock();
    printf("Quick Sort    : %.6f secondes\n", 
           (double)(end - start) / CLOCKS_PER_SEC);
    free(arr);
    
    free(original);
}


```c
int main() {
```
    printf("╔════════════════════════════════════════╗\n");
    printf("║   TRI ET RECHERCHE - DÉMONSTRATION     ║\n");
    printf("╚════════════════════════════════════════╝\n");
    
    int arr[] = {64, 34, 25, 12, 22, 11, 90};
    int n = 7;
    
    printf("\nTableau initial : ");
    print_array(arr, n);
    
    quick_sort(arr, 0, n-1);
    printf("Après tri      : ");
    print_array(arr, n);
    
    int target = 22;
    int index = binary_search(arr, n, target);
    printf("\nRecherche de %d : %s (index %d)\n", 
           target, index != -1 ? "TROUVÉ" : "NON TROUVÉ", index);
    

```c
    // Benchmarks
```
    benchmark_sorting(100);
    benchmark_sorting(1000);
    
    return 0;
}


---
COMPILATION

---

gcc solution.c -o sorting -Wall -Wextra -O2
./sorting


---
FIN DE LA SOLUTION

---



#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void print_array(int arr[], int n) {
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

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

int main() {
    printf("╔════════════════════════════════════════╗\n");
    printf("║       SORTING & SEARCHING DEMO         ║\n");
    printf("╚════════════════════════════════════════╝\n\n");
    
    int arr1[] = {64, 34, 25, 12, 22, 11, 90};
    int n = 7;
    
    printf("1. BUBBLE SORT\n");
    printf("Avant : ");
    print_array(arr1, n);
    bubble_sort(arr1, n);
    printf("Après : ");
    print_array(arr1, n);
    
    int arr2[] = {64, 34, 25, 12, 22, 11, 90};
    printf("\n2. INSERTION SORT\n");
    printf("Avant : ");
    print_array(arr2, n);
    insertion_sort(arr2, n);
    printf("Après : ");
    print_array(arr2, n);
    
    int arr3[] = {64, 34, 25, 12, 22, 11, 90};
    printf("\n3. QUICK SORT\n");
    printf("Avant : ");
    print_array(arr3, n);
    quick_sort(arr3, 0, n-1);
    printf("Après : ");
    print_array(arr3, n);
    
    printf("\n4. RECHERCHE LINÉAIRE\n");
    int target = 25;
    int index = linear_search(arr3, n, target);
    printf("Recherche %d : %s (index %d)\n", 
           target, index != -1 ? "TROUVÉ" : "NON TROUVÉ", index);
    
    printf("\n5. RECHERCHE BINAIRE (sur tableau trié)\n");
    index = binary_search(arr3, n, target);
    printf("Recherche %d : %s (index %d)\n", 
           target, index != -1 ? "TROUVÉ" : "NON TROUVÉ", index);
    
    printf("\n════════════════════════════════════════\n");
    
    return 0;
}


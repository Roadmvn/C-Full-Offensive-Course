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

HashTable* create_table(int size) {
    HashTable *ht = malloc(sizeof(HashTable));
    ht->size = size;
    ht->buckets = calloc(size, sizeof(Entry*));
    return ht;
}

void insert(HashTable *ht, const char *key, int value) {
    unsigned int index = get_index(key, ht->size);
    
    Entry *current = ht->buckets[index];
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            current->value = value;
            return;
        }
        current = current->next;
    }
    
    Entry *new_entry = malloc(sizeof(Entry));
    new_entry->key = strdup(key);
    new_entry->value = value;
    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;
}

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

void print_table(HashTable *ht) {
    printf("\nTable de Hachage :\n");
    for (int i = 0; i < ht->size; i++) {
        printf("[%d] ", i);
        Entry *current = ht->buckets[i];
        if (current == NULL) {
            printf("(vide)\n");
        } else {
            while (current != NULL) {
                printf("(%s:%d) → ", current->key, current->value);
                current = current->next;
            }
            printf("NULL\n");
        }
    }
}

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

int main() {
    printf("╔════════════════════════════════════════╗\n");
    printf("║        HASH TABLE DEMONSTRATION        ║\n");
    printf("╚════════════════════════════════════════╝\n");
    
    HashTable *ht = create_table(TABLE_SIZE);
    
    printf("\n1. INSERTION\n");
    insert(ht, "John", 25);
    insert(ht, "Mary", 30);
    insert(ht, "Bob", 35);
    insert(ht, "Alice", 28);
    insert(ht, "Charlie", 40);
    
    print_table(ht);
    
    printf("\n2. RECHERCHE\n");
    int found;
    int age = search(ht, "Mary", &found);
    if (found) {
        printf("Mary : %d ans\n", age);
    }
    
    age = search(ht, "David", &found);
    if (!found) {
        printf("David : non trouvé\n");
    }
    
    printf("\n3. MISE À JOUR\n");
    insert(ht, "John", 26);
    printf("John mis à jour\n");
    print_table(ht);
    
    free_table(ht);
    printf("\n════════════════════════════════════════\n");
    
    return 0;
}


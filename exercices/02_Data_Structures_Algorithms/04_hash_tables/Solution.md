# SOLUTION : HASH TABLES

COMPTEUR DE MOTS AVEC HASH TABLE


---


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
```


```bash
#define TABLE_SIZE 100
```


```c
typedef struct Entry {
    char *word;
    int count;
```
    struct Entry *next;
} Entry;


```c
typedef struct HashTable {
```
    Entry **buckets;
    int size;
} HashTable;

unsigned long hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + tolower(c);
    }
    return hash;
}

HashTable* create_table(int size) {
    HashTable *ht = malloc(sizeof(HashTable));
    ht->size = size;
    ht->buckets = calloc(size, sizeof(Entry*));
    return ht;
}


```c
void increment_word(HashTable *ht, const char *word) {
```
    unsigned int index = hash(word) % ht->size;
    

```c
    // Chercher si le mot existe
```
    Entry *current = ht->buckets[index];
    while (current != NULL) {
        if (strcasecmp(current->word, word) == 0) {
            current->count++;
            return;
        }
        current = current->next;
    }
    

```c
    // Nouveau mot
```
    Entry *new_entry = malloc(sizeof(Entry));
    new_entry->word = strdup(word);
    new_entry->count = 1;
    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;
}


```c
void count_words(HashTable *ht, char *text) {
    char *word = strtok(text, " \n\t.,;:!?\"'()[]{}");
```
    while (word != NULL) {
        increment_word(ht, word);
        word = strtok(NULL, " \n\t.,;:!?\"'()[]{}");
    }
}


```c
void print_statistics(HashTable *ht) {
```
    printf("\nStatistiques des mots :\n");
    printf("%-20s %s\n", "Mot", "Fréquence");
    printf("────────────────────────────────\n");
    
    for (int i = 0; i < ht->size; i++) {
        Entry *current = ht->buckets[i];
        while (current != NULL) {
            printf("%-20s %d\n", current->word, current->count);
            current = current->next;
        }
    }
}


```c
int main() {
```
    printf("COMPTEUR DE MOTS\n\n");
    
    HashTable *ht = create_table(TABLE_SIZE);
    
    char text[] = "the cat and the dog play with the cat "
                  "the dog runs and the cat sleeps";
    
    printf("Texte : %s\n", text);
    
    char *text_copy = strdup(text);
    count_words(ht, text_copy);
    free(text_copy);
    
    print_statistics(ht);
    

```c
    // Libérer la mémoire
```
    for (int i = 0; i < ht->size; i++) {
        Entry *current = ht->buckets[i];
        while (current != NULL) {
            Entry *temp = current;
            current = current->next;
            free(temp->word);
            free(temp);
        }
    }
    free(ht->buckets);
    free(ht);
    
    return 0;
}


---
DICTIONNAIRE DE TRADUCTION

---


```c
typedef struct Translation {
    char *english;
    char *french;
```
    struct Translation *next;
} Translation;


```c
typedef struct Dictionary {
```
    Translation **buckets;
    int size;
} Dictionary;


```c
void add_translation(Dictionary *dict, const char *en, const char *fr) {
```
    unsigned int index = hash(en) % dict->size;
    
    Translation *new_trans = malloc(sizeof(Translation));
    new_trans->english = strdup(en);
    new_trans->french = strdup(fr);
    new_trans->next = dict->buckets[index];
    dict->buckets[index] = new_trans;
}

char* translate(Dictionary *dict, const char *english) {
    unsigned int index = hash(english) % dict->size;
    Translation *current = dict->buckets[index];
    
    while (current != NULL) {
        if (strcmp(current->english, english) == 0) {
            return current->french;
        }
        current = current->next;
    }
    
    return NULL;
}


```c
// Exemple d'utilisation
```
Dictionary *dict = create_dictionary(50);
add_translation(dict, "hello", "bonjour");
add_translation(dict, "world", "monde");
add_translation(dict, "cat", "chat");
add_translation(dict, "dog", "chien");

char *trans = translate(dict, "hello");
printf("%s\n", trans);  // "bonjour"


---
DÉTECTION DE DOUBLONS

---

int has_duplicates(int arr[], int size) {
    HashTable *set = create_table(size);
    
    for (int i = 0; i < size; i++) {
        char key[20];
        sprintf(key, "%d", arr[i]);
        
        int found;
        search(set, key, &found);
        
        if (found) {
            free_table(set);
            return 1;  // Doublon trouvé
        }
        
        insert(set, key, 1);
    }
    
    free_table(set);
    return 0;  // Pas de doublons
}


---
ANAGRAMMES

---


```c
// Trier les caractères d'un mot
char* sort_string(const char *str) {
    char *sorted = strdup(str);
    int len = strlen(sorted);
```

    for (int i = 0; i < len-1; i++) {
        for (int j = i+1; j < len; j++) {
            if (sorted[i] > sorted[j]) {
                char temp = sorted[i];
                sorted[i] = sorted[j];
                sorted[j] = temp;
            }
        }
    }
    
    return sorted;
}


```c
void group_anagrams(char *words[], int count) {
```
    HashTable *groups = create_table(count);
    
    for (int i = 0; i < count; i++) {
        char *key = sort_string(words[i]);
        

```c
        // Ajouter le mot au groupe (simplifié)
```
        printf("%s → groupe [%s]\n", words[i], key);
        
        free(key);
    }
}


```c
// Exemple
char *words[] = {"eat", "tea", "tan", "ate", "nat", "bat"};
```
group_anagrams(words, 6);


---
COMPILATION

---

gcc solution.c -o hashtable -Wall -Wextra
./hashtable


---
FIN DE LA SOLUTION

---



# Module 05 - Boucles (Patterns Avancés)

> **Note :** Les fondamentaux des boucles (for, while, do-while, break, continue) sont couverts dans le **[Module 04 - Control Flow](../04_conditionals/cours.md)**.
>
> Ce module contient uniquement des patterns avancés complémentaires.

---

## Patterns avancés pour l'offensive

### Fisher-Yates Shuffle (randomiser l'ordre)

```c
void shuffle(int* arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

// Usage: randomiser l'ordre des ports pour évasion
int ports[] = {22, 80, 443, 3306, 3389};
shuffle(ports, 5);
for (int i = 0; i < 5; i++) scan_port(ports[i]);
```

### Multi-key XOR decoder

```c
void xor_multi_key(unsigned char* data, int data_len,
                   unsigned char* key, int key_len) {
    for (int i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];  // Clé cyclique
    }
}
```

### Timing anti-debug avancé

```c
int timing_check_loop(void) {
    int detections = 0;

    for (int i = 0; i < 5; i++) {
        clock_t start = clock();
        volatile int sum = 0;
        for (int j = 0; j < 100000; j++) sum += j;
        clock_t elapsed = clock() - start;

        if (elapsed > CLOCKS_PER_SEC / 10) detections++;
        Sleep(rand() % 100);  // Jitter
    }

    return detections >= 3;  // 3/5 = probable debugger
}
```

### Loop unrolling (optimisation)

```c
// Normal
for (int i = 0; i < 1000; i++) process(data[i]);

// Déroulé (4x moins de comparaisons)
for (int i = 0; i < 1000; i += 4) {
    process(data[i]);
    process(data[i+1]);
    process(data[i+2]);
    process(data[i+3]);
}
```

---

## Exercices

Voir [exercice.md](exercice.md) ou retourner au **[Module 04](../04_conditionals/)** pour les exercices fondamentaux.

---

**Module suivant →** [06 - Fonctions](../06_functions/)

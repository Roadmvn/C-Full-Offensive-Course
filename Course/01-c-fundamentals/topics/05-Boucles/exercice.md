# Exercices - Module 05 : Boucles (Loops)

## Exercice 1 : Compteurs de base (Très facile)

**Objectif** : Maîtriser les différentes formes de boucle for.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // TODO:
    // 1. Affiche les nombres de 1 à 10
    // 2. Affiche les nombres de 10 à 1 (rebours)
    // 3. Affiche les multiples de 5 de 0 à 50
    // 4. Affiche les puissances de 2 de 1 à 512

    return 0;
}
```

### Sortie attendue

```
1 à 10 : 1 2 3 4 5 6 7 8 9 10
10 à 1 : 10 9 8 7 6 5 4 3 2 1
Multiples de 5 : 0 5 10 15 20 25 30 35 40 45 50
Puissances de 2 : 1 2 4 8 16 32 64 128 256 512
```

---

## Exercice 2 : Somme et moyenne (Facile)

**Objectif** : Accumuler des valeurs dans une boucle.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int numbers[] = {15, 42, 8, 23, 16, 4, 37, 99};
    int size = 8;

    // TODO:
    // 1. Calcule la somme de tous les nombres
    // 2. Calcule la moyenne
    // 3. Trouve le minimum et le maximum

    return 0;
}
```

---

## Exercice 3 : Recherche linéaire (Facile)

**Objectif** : Utiliser while pour une recherche.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int data[] = {15, 42, 8, 23, 16, 4, 42, 99};
    int size = 8;
    int target = 42;

    // TODO avec while:
    // 1. Trouve la première occurrence de target
    // 2. Affiche l'index ou "Non trouvé"
    // 3. BONUS: Compte le nombre d'occurrences de target

    return 0;
}
```

---

## Exercice 4 : Validation d'entrée (Facile)

**Objectif** : Utiliser do-while pour valider une entrée.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int choice;

    // TODO: Demande un nombre entre 1 et 5
    // Répète tant que l'entrée n'est pas valide
    // Utilise do-while

    // Simule des entrées : 0, 7, -1, 3 (valide)

    return 0;
}
```

---

## Exercice 5 : Table de multiplication (Moyen)

**Objectif** : Maîtriser les boucles imbriquées.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // TODO: Affiche la table de multiplication de 1 à 10
    // Format :
    //    1   2   3   4   5   6   7   8   9  10
    //    2   4   6   8  10  12  14  16  18  20
    //    ...
    //   10  20  30  40  50  60  70  80  90 100

    return 0;
}
```

---

## Exercice 6 : Nombres premiers (Moyen)

**Objectif** : Combiner boucles et conditions.

### Instructions

```c
#include <stdio.h>

int is_prime(int n) {
    // TODO: Retourne 1 si n est premier, 0 sinon
    // Un nombre est premier s'il n'est divisible que par 1 et lui-même
    return 0;
}

int main(void) {
    // TODO: Affiche tous les nombres premiers de 2 à 100

    return 0;
}
```

---

## Exercice 7 : break et continue (Moyen)

**Objectif** : Maîtriser le contrôle de boucle.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // PARTIE 1: Utilise continue pour afficher seulement les nombres
    // divisibles par 3 de 1 à 30
    printf("Divisibles par 3: ");
    // TODO

    // PARTIE 2: Utilise break pour trouver le premier nombre > 100
    // qui est à la fois divisible par 7 et par 11
    printf("\nPremier > 100 divisible par 7 et 11: ");
    // TODO

    // PARTIE 3: Dans ce tableau, affiche les nombres positifs
    // et arrête dès que tu rencontres -999 (sentinelle)
    int values[] = {5, 12, -3, 8, -999, 15, 20};
    printf("\nValeurs jusqu'à sentinelle: ");
    // TODO

    return 0;
}
```

---

## Exercice 8 : Bruteforce PIN (Moyen)

**Objectif** : Utiliser les boucles imbriquées pour le bruteforce.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int check_pin(const char* pin) {
    return strcmp(pin, "573") == 0;
}

int main(void) {
    char pin[4];
    int attempts = 0;

    // TODO:
    // 1. Utilise 3 boucles imbriquées pour tester toutes les combinaisons
    // 2. Compte le nombre d'essais
    // 3. Affiche le PIN trouvé et le nombre d'essais

    printf("[*] Bruteforcing 3-digit PIN...\n");

    // TODO: Triple boucle de 0 à 9

    return 0;
}
```

---

## Exercice 9 : Port Scanner (Moyen)

**Objectif** : Simuler un scan de ports.

### Instructions

```c
#include <stdio.h>

int is_port_open(int port) {
    // Simule des ports ouverts
    int open_ports[] = {21, 22, 25, 80, 110, 443, 3306, 3389, 8080};
    for (int i = 0; i < 9; i++) {
        if (port == open_ports[i]) return 1;
    }
    return 0;
}

int main(void) {
    // TODO:
    // 1. Scanne les ports de 1 à 1000
    // 2. Affiche uniquement les ports ouverts
    // 3. Affiche le total de ports ouverts
    // 4. BONUS: Classe les ports par catégorie
    //    - 1-1023: Well-known
    //    - 1024-49151: Registered
    //    - 49152-65535: Dynamic

    return 0;
}
```

---

## Exercice 10 : XOR Decoder (Challenge)

**Objectif** : Implémenter un décodeur XOR avec boucle.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Message encodé avec XOR 0x55
    unsigned char encoded[] = {
        0x36, 0x30, 0x38, 0x38, 0x3A, 0x75, 0x22, 0x3A, 0x27, 0x38, 0x31, 0x00
    };
    // Le message décodé devrait être "hello_world" (c'est "cenna&}n|na" XOR 0x55)

    unsigned char key = 0x55;

    // TODO:
    // 1. Affiche le message encodé en hex
    // 2. Décode avec XOR
    // 3. Affiche le message décodé

    return 0;
}
```

**Note** : Le vrai message encodé pour "hello_world" avec clé 0x55 serait :
```
'h' ^ 0x55 = 0x3D
'e' ^ 0x55 = 0x30
'l' ^ 0x55 = 0x39
'l' ^ 0x55 = 0x39
'o' ^ 0x55 = 0x3A
'_' ^ 0x55 = 0x0A
'w' ^ 0x55 = 0x22
'o' ^ 0x55 = 0x3A
'r' ^ 0x55 = 0x27
'l' ^ 0x55 = 0x39
'd' ^ 0x55 = 0x31
```

---

## Exercice 11 : Recherche de signature (Challenge)

**Objectif** : Chercher un pattern en mémoire.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // Simule une zone mémoire
    unsigned char memory[] = {
        0x00, 0x00, 0x90, 0x90, 0xCC, 0x31, 0xC0, 0xC3,
        0x00, 0x00, 0x90, 0xCC, 0x31, 0xC0, 0x50, 0x90
    };
    int mem_size = sizeof(memory);

    // Signature à chercher : CC 31 C0 (int3 + xor eax, eax)
    unsigned char signature[] = {0xCC, 0x31, 0xC0};
    int sig_size = sizeof(signature);

    // TODO:
    // 1. Cherche TOUTES les occurrences de la signature
    // 2. Affiche l'offset de chaque occurrence
    // 3. Affiche le nombre total d'occurrences

    return 0;
}
```

---

## Exercice 12 : Retry avec backoff (Challenge)

**Objectif** : Implémenter un pattern de retry avec délai exponentiel.

### Instructions

```c
#include <stdio.h>

int try_connect(void) {
    static int attempts = 0;
    attempts++;
    // Simule : réussite après 5 tentatives
    return (attempts >= 5);
}

int main(void) {
    int max_retries = 10;
    int delay = 1;  // En secondes (simulé)
    int success = 0;

    // TODO:
    // 1. Tente de se connecter jusqu'à max_retries fois
    // 2. Si échec, affiche le délai et double-le (max 60s)
    // 3. Si succès, affiche le nombre de tentatives
    // 4. Si tous les essais échouent, affiche "Connection failed"

    return 0;
}
```

---

## Exercice 13 : Générateur de wordlist (Challenge)

**Objectif** : Générer toutes les combinaisons de caractères.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char charset[] = "abc";  // Charset réduit pour la démo
    int charset_len = strlen(charset);
    int password_len = 3;

    // TODO:
    // 1. Génère toutes les combinaisons de 3 caractères
    // 2. Affiche chaque combinaison
    // 3. Compte le nombre total de combinaisons

    // Exemple de sortie :
    // aaa
    // aab
    // aac
    // aba
    // ...
    // ccc

    return 0;
}
```

---

## Exercice 14 : Timing anti-debug (Challenge)

**Objectif** : Utiliser le timing pour détecter un debugger.

### Instructions

```c
#include <stdio.h>
#include <time.h>

int main(void) {
    clock_t start, end;
    double elapsed;
    int iterations = 1000000;

    // TODO:
    // 1. Mesure le temps d'exécution d'une boucle
    // 2. Si le temps est anormalement long (> 0.5s),
    //    affiche "Debugger détecté!"
    // 3. Sinon, affiche "Environnement normal"

    // Note: utilise volatile pour empêcher l'optimisation

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Écrire une boucle for (croissante, décroissante, avec pas)
- [ ] Écrire une boucle while pour une condition dynamique
- [ ] Écrire une boucle do-while pour garantir une exécution
- [ ] Utiliser des boucles imbriquées
- [ ] Utiliser break pour sortir d'une boucle
- [ ] Utiliser continue pour sauter une itération
- [ ] Implémenter un bruteforce simple
- [ ] Implémenter un décodeur XOR
- [ ] Chercher un pattern en mémoire
- [ ] Utiliser le timing dans une boucle

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.

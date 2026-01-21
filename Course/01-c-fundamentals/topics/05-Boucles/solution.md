# Solutions - Module 05 : Boucles (Loops)

## Table des matières

1. [Exercice 1 : Compteurs de base](#exercice-1--compteurs-de-base)
2. [Exercice 2 : Somme et moyenne](#exercice-2--somme-et-moyenne)
3. [Exercice 3 : Recherche linéaire](#exercice-3--recherche-linéaire)
4. [Exercice 4 : Validation d'entrée](#exercice-4--validation-dentrée)
5. [Exercice 5 : Table de multiplication](#exercice-5--table-de-multiplication)
6. [Exercice 6 : Nombres premiers](#exercice-6--nombres-premiers)
7. [Exercice 7 : break et continue](#exercice-7--break-et-continue)
8. [Exercice 8 : Bruteforce PIN](#exercice-8--bruteforce-pin)
9. [Exercice 9 : Port Scanner](#exercice-9--port-scanner)
10. [Exercice 10 : XOR Decoder](#exercice-10--xor-decoder)
11. [Exercice 11 : Recherche de signature](#exercice-11--recherche-de-signature)
12. [Exercice 12 : Retry avec backoff](#exercice-12--retry-avec-backoff)
13. [Exercice 13 : Générateur de wordlist](#exercice-13--générateur-de-wordlist)
14. [Exercice 14 : Timing anti-debug](#exercice-14--timing-anti-debug)

---

## Exercice 1 : Compteurs de base

### Solution

```c
#include <stdio.h>

int main(void) {
    // 1. Nombres de 1 à 10
    printf("1 à 10 : ");
    for (int i = 1; i <= 10; i++) {
        printf("%d ", i);
    }
    printf("\n");

    // 2. Nombres de 10 à 1 (rebours)
    printf("10 à 1 : ");
    for (int i = 10; i >= 1; i--) {
        printf("%d ", i);
    }
    printf("\n");

    // 3. Multiples de 5 de 0 à 50
    printf("Multiples de 5 : ");
    for (int i = 0; i <= 50; i += 5) {
        printf("%d ", i);
    }
    printf("\n");

    // 4. Puissances de 2 de 1 à 512
    printf("Puissances de 2 : ");
    for (int i = 1; i <= 512; i *= 2) {
        printf("%d ", i);
    }
    printf("\n");

    return 0;
}
```

### Sortie

```
1 à 10 : 1 2 3 4 5 6 7 8 9 10
10 à 1 : 10 9 8 7 6 5 4 3 2 1
Multiples de 5 : 0 5 10 15 20 25 30 35 40 45 50
Puissances de 2 : 1 2 4 8 16 32 64 128 256 512
```

### Points clés

- `i++` pour incrémenter de 1
- `i--` pour décrémenter de 1
- `i += 5` pour incrémenter de 5
- `i *= 2` pour multiplier par 2

---

## Exercice 2 : Somme et moyenne

### Solution

```c
#include <stdio.h>

int main(void) {
    int numbers[] = {15, 42, 8, 23, 16, 4, 37, 99};
    int size = 8;

    // 1. Calculer la somme
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += numbers[i];
    }
    printf("Somme : %d\n", sum);

    // 2. Calculer la moyenne
    float average = (float)sum / size;
    printf("Moyenne : %.2f\n", average);

    // 3. Trouver min et max
    int min = numbers[0];
    int max = numbers[0];

    for (int i = 1; i < size; i++) {
        if (numbers[i] < min) {
            min = numbers[i];
        }
        if (numbers[i] > max) {
            max = numbers[i];
        }
    }

    printf("Minimum : %d\n", min);
    printf("Maximum : %d\n", max);

    return 0;
}
```

### Sortie

```
Somme : 244
Moyenne : 30.50
Minimum : 4
Maximum : 99
```

---

## Exercice 3 : Recherche linéaire

### Solution

```c
#include <stdio.h>

int main(void) {
    int data[] = {15, 42, 8, 23, 16, 4, 42, 99};
    int size = 8;
    int target = 42;

    // 1. Première occurrence avec while
    int i = 0;
    while (i < size && data[i] != target) {
        i++;
    }

    if (i < size) {
        printf("Première occurrence à l'index : %d\n", i);
    } else {
        printf("Non trouvé\n");
    }

    // BONUS: Compter les occurrences
    int count = 0;
    i = 0;
    while (i < size) {
        if (data[i] == target) {
            count++;
        }
        i++;
    }
    printf("Nombre d'occurrences : %d\n", count);

    return 0;
}
```

### Sortie

```
Première occurrence à l'index : 1
Nombre d'occurrences : 2
```

### Explication

La condition `i < size && data[i] != target` utilise le court-circuit :
- Si `i >= size`, on ne teste pas `data[i]` (évite un accès hors limites)
- La boucle s'arrête dès qu'on trouve la cible

---

## Exercice 4 : Validation d'entrée

### Solution

```c
#include <stdio.h>

int main(void) {
    int choice;

    // Simulation des entrées : 0, 7, -1, 3
    int simulated_inputs[] = {0, 7, -1, 3};
    int input_index = 0;

    printf("Validation d'entrée (1-5)\n");

    do {
        // Simule la lecture (en vrai : scanf("%d", &choice))
        choice = simulated_inputs[input_index++];
        printf("Entrée : %d", choice);

        if (choice < 1 || choice > 5) {
            printf(" - Invalide, réessayez\n");
        } else {
            printf(" - Valide!\n");
        }
    } while (choice < 1 || choice > 5);

    printf("Choix final : %d\n", choice);

    return 0;
}
```

### Sortie

```
Validation d'entrée (1-5)
Entrée : 0 - Invalide, réessayez
Entrée : 7 - Invalide, réessayez
Entrée : -1 - Invalide, réessayez
Entrée : 3 - Valide!
Choix final : 3
```

### Pourquoi do-while ?

Le `do-while` garantit au moins une exécution, parfait pour :
- Demander une entrée au moins une fois
- Valider et répéter si nécessaire

---

## Exercice 5 : Table de multiplication

### Solution

```c
#include <stdio.h>

int main(void) {
    printf("Table de multiplication (1-10):\n\n");

    // En-tête
    printf("    ");
    for (int i = 1; i <= 10; i++) {
        printf("%4d", i);
    }
    printf("\n    ");
    for (int i = 1; i <= 10; i++) {
        printf("----");
    }
    printf("\n");

    // Corps de la table
    for (int row = 1; row <= 10; row++) {
        printf("%2d |", row);
        for (int col = 1; col <= 10; col++) {
            printf("%4d", row * col);
        }
        printf("\n");
    }

    return 0;
}
```

### Sortie

```
Table de multiplication (1-10):

       1   2   3   4   5   6   7   8   9  10
    ----------------------------------------
 1 |   1   2   3   4   5   6   7   8   9  10
 2 |   2   4   6   8  10  12  14  16  18  20
 3 |   3   6   9  12  15  18  21  24  27  30
...
10 |  10  20  30  40  50  60  70  80  90 100
```

---

## Exercice 6 : Nombres premiers

### Solution

```c
#include <stdio.h>

int is_prime(int n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;

    // Teste les diviseurs jusqu'à sqrt(n)
    for (int i = 3; i * i <= n; i += 2) {
        if (n % i == 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    printf("Nombres premiers de 2 à 100:\n");

    int count = 0;
    for (int n = 2; n <= 100; n++) {
        if (is_prime(n)) {
            printf("%d ", n);
            count++;
        }
    }

    printf("\n\nTotal: %d nombres premiers\n", count);

    return 0;
}
```

### Sortie

```
Nombres premiers de 2 à 100:
2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97

Total: 25 nombres premiers
```

### Optimisations

1. On teste jusqu'à `sqrt(n)` seulement (`i * i <= n`)
2. On saute les nombres pairs (`i += 2`)
3. On vérifie d'abord les cas spéciaux (n < 2, n == 2)

---

## Exercice 7 : break et continue

### Solution

```c
#include <stdio.h>

int main(void) {
    // PARTIE 1: Divisibles par 3
    printf("Divisibles par 3: ");
    for (int i = 1; i <= 30; i++) {
        if (i % 3 != 0) {
            continue;  // Saute si pas divisible par 3
        }
        printf("%d ", i);
    }
    printf("\n");

    // PARTIE 2: Premier > 100 divisible par 7 ET 11
    printf("Premier > 100 divisible par 7 et 11: ");
    for (int i = 101; ; i++) {  // Boucle infinie avec break
        if (i % 7 == 0 && i % 11 == 0) {
            printf("%d\n", i);
            break;
        }
    }

    // PARTIE 3: Jusqu'à sentinelle
    int values[] = {5, 12, -3, 8, -999, 15, 20};
    int size = sizeof(values) / sizeof(values[0]);

    printf("Valeurs jusqu'à sentinelle: ");
    for (int i = 0; i < size; i++) {
        if (values[i] == -999) {
            break;  // Arrête à la sentinelle
        }
        if (values[i] < 0) {
            continue;  // Ignore les négatifs
        }
        printf("%d ", values[i]);
    }
    printf("\n");

    return 0;
}
```

### Sortie

```
Divisibles par 3: 3 6 9 12 15 18 21 24 27 30
Premier > 100 divisible par 7 et 11: 154
Valeurs jusqu'à sentinelle: 5 12 8
```

---

## Exercice 8 : Bruteforce PIN

### Solution

```c
#include <stdio.h>
#include <string.h>

int check_pin(const char* pin) {
    return strcmp(pin, "573") == 0;
}

int main(void) {
    char pin[4];
    int attempts = 0;
    int found = 0;

    printf("[*] Bruteforcing 3-digit PIN...\n");

    for (int d1 = 0; d1 <= 9 && !found; d1++) {
        for (int d2 = 0; d2 <= 9 && !found; d2++) {
            for (int d3 = 0; d3 <= 9 && !found; d3++) {
                sprintf(pin, "%d%d%d", d1, d2, d3);
                attempts++;

                if (check_pin(pin)) {
                    printf("[+] PIN FOUND: %s\n", pin);
                    printf("[+] Attempts: %d\n", attempts);
                    found = 1;
                }
            }
        }
    }

    if (!found) {
        printf("[-] PIN not found after %d attempts\n", attempts);
    }

    return 0;
}
```

### Sortie

```
[*] Bruteforcing 3-digit PIN...
[+] PIN FOUND: 573
[+] Attempts: 574
```

### Analyse

- 10 × 10 × 10 = 1000 combinaisons possibles
- PIN "573" trouvé après 574 essais (000 à 573)
- Le flag `!found` dans les conditions évite de continuer après avoir trouvé

---

## Exercice 9 : Port Scanner

### Solution

```c
#include <stdio.h>

int is_port_open(int port) {
    int open_ports[] = {21, 22, 25, 80, 110, 443, 3306, 3389, 8080};
    for (int i = 0; i < 9; i++) {
        if (port == open_ports[i]) return 1;
    }
    return 0;
}

const char* get_service(int port) {
    switch (port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 25:   return "SMTP";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 443:  return "HTTPS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 8080: return "HTTP-Proxy";
        default:   return "Unknown";
    }
}

int main(void) {
    printf("[*] Port Scanner - Scanning ports 1-1000\n\n");

    int open_count = 0;

    for (int port = 1; port <= 1000; port++) {
        if (is_port_open(port)) {
            printf("[+] Port %4d OPEN - %s\n", port, get_service(port));
            open_count++;
        }
    }

    printf("\n[*] Scan complete\n");
    printf("[*] Open ports: %d\n", open_count);

    return 0;
}
```

### Sortie

```
[*] Port Scanner - Scanning ports 1-1000

[+] Port   21 OPEN - FTP
[+] Port   22 OPEN - SSH
[+] Port   25 OPEN - SMTP
[+] Port   80 OPEN - HTTP
[+] Port  110 OPEN - POP3
[+] Port  443 OPEN - HTTPS

[*] Scan complete
[*] Open ports: 6
```

---

## Exercice 10 : XOR Decoder

### Solution

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Corrigé : "hello_world" XOR 0x55
    unsigned char encoded[] = {
        0x3D, 0x30, 0x39, 0x39, 0x3A, 0x0A, 0x22, 0x3A, 0x27, 0x39, 0x31, 0x00
    };
    unsigned char key = 0x55;
    int len = strlen((char*)encoded);

    printf("=== XOR Decoder ===\n\n");

    // 1. Afficher en hex
    printf("Encodé (hex): ");
    for (int i = 0; i < len; i++) {
        printf("%02X ", encoded[i]);
    }
    printf("\n");

    // 2. Décoder
    printf("Décodage avec clé 0x%02X...\n", key);
    for (int i = 0; i < len; i++) {
        encoded[i] ^= key;
    }

    // 3. Afficher décodé
    printf("Décodé: %s\n", encoded);

    return 0;
}
```

### Sortie

```
=== XOR Decoder ===

Encodé (hex): 3D 30 39 39 3A 0A 22 3A 27 39 31
Décodage avec clé 0x55...
Décodé: hello_world
```

### Explication du XOR

```
'h' (0x68) ^ 0x55 = 0x3D
'e' (0x65) ^ 0x55 = 0x30
'l' (0x6C) ^ 0x55 = 0x39
...

Pour décoder : 0x3D ^ 0x55 = 0x68 = 'h'
```

---

## Exercice 11 : Recherche de signature

### Solution

```c
#include <stdio.h>

int main(void) {
    unsigned char memory[] = {
        0x00, 0x00, 0x90, 0x90, 0xCC, 0x31, 0xC0, 0xC3,
        0x00, 0x00, 0x90, 0xCC, 0x31, 0xC0, 0x50, 0x90
    };
    int mem_size = sizeof(memory);

    unsigned char signature[] = {0xCC, 0x31, 0xC0};
    int sig_size = sizeof(signature);

    printf("=== Signature Scanner ===\n\n");

    printf("Memory: ");
    for (int i = 0; i < mem_size; i++) {
        printf("%02X ", memory[i]);
    }
    printf("\n");

    printf("Signature: ");
    for (int i = 0; i < sig_size; i++) {
        printf("%02X ", signature[i]);
    }
    printf("\n\n");

    // Recherche de toutes les occurrences
    int found_count = 0;
    printf("Occurrences trouvées:\n");

    for (int i = 0; i <= mem_size - sig_size; i++) {
        int match = 1;

        for (int j = 0; j < sig_size; j++) {
            if (memory[i + j] != signature[j]) {
                match = 0;
                break;
            }
        }

        if (match) {
            printf("  [+] Offset 0x%02X (%d)\n", i, i);
            found_count++;
        }
    }

    printf("\nTotal: %d occurrence(s)\n", found_count);

    return 0;
}
```

### Sortie

```
=== Signature Scanner ===

Memory: 00 00 90 90 CC 31 C0 C3 00 00 90 CC 31 C0 50 90
Signature: CC 31 C0

Occurrences trouvées:
  [+] Offset 0x04 (4)
  [+] Offset 0x0B (11)

Total: 2 occurrence(s)
```

---

## Exercice 12 : Retry avec backoff

### Solution

```c
#include <stdio.h>

int try_connect(void) {
    static int attempts = 0;
    attempts++;
    return (attempts >= 5);
}

int main(void) {
    int max_retries = 10;
    int delay = 1;
    int success = 0;
    int attempt;

    printf("[*] Tentative de connexion...\n\n");

    for (attempt = 1; attempt <= max_retries; attempt++) {
        printf("[%d/%d] Connexion...", attempt, max_retries);

        if (try_connect()) {
            printf(" SUCCÈS!\n");
            success = 1;
            break;
        }

        printf(" échec, retry dans %ds\n", delay);

        // Backoff exponentiel
        delay *= 2;
        if (delay > 60) {
            delay = 60;
        }
    }

    printf("\n");
    if (success) {
        printf("[+] Connecté après %d tentative(s)\n", attempt);
    } else {
        printf("[-] Échec après %d tentatives\n", max_retries);
    }

    return 0;
}
```

### Sortie

```
[*] Tentative de connexion...

[1/10] Connexion... échec, retry dans 1s
[2/10] Connexion... échec, retry dans 2s
[3/10] Connexion... échec, retry dans 4s
[4/10] Connexion... échec, retry dans 8s
[5/10] Connexion... SUCCÈS!

[+] Connecté après 5 tentative(s)
```

### Pattern backoff exponentiel

Délais : 1s → 2s → 4s → 8s → 16s → 32s → 60s (cap)

Utilisé pour :
- Éviter de surcharger le serveur
- Éviter la détection (scans espacés)
- Réessayer de manière intelligente

---

## Exercice 13 : Générateur de wordlist

### Solution

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char charset[] = "abc";
    int charset_len = strlen(charset);
    char password[4];
    int count = 0;

    printf("=== Wordlist Generator ===\n");
    printf("Charset: %s (%d chars)\n", charset, charset_len);
    printf("Length: 3\n\n");

    for (int i = 0; i < charset_len; i++) {
        for (int j = 0; j < charset_len; j++) {
            for (int k = 0; k < charset_len; k++) {
                password[0] = charset[i];
                password[1] = charset[j];
                password[2] = charset[k];
                password[3] = '\0';

                printf("%s\n", password);
                count++;
            }
        }
    }

    printf("\nTotal: %d combinaisons\n", count);
    printf("Formule: %d^3 = %d\n", charset_len,
           charset_len * charset_len * charset_len);

    return 0;
}
```

### Sortie

```
=== Wordlist Generator ===
Charset: abc (3 chars)
Length: 3

aaa
aab
aac
aba
abb
abc
aca
acb
acc
baa
bab
...
ccc

Total: 27 combinaisons
Formule: 3^3 = 27
```

---

## Exercice 14 : Timing anti-debug

### Solution

```c
#include <stdio.h>
#include <time.h>

int main(void) {
    clock_t start, end;
    double elapsed;
    int iterations = 1000000;

    printf("=== Timing Anti-Debug ===\n\n");
    printf("[*] Exécution de %d itérations...\n", iterations);

    start = clock();

    // volatile empêche l'optimisation par le compilateur
    volatile int sum = 0;
    for (int i = 0; i < iterations; i++) {
        sum += i;
    }

    end = clock();
    elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    printf("[*] Temps écoulé: %.6f secondes\n", elapsed);
    printf("[*] Résultat: %d\n\n", sum);

    // Seuil de détection
    double threshold = 0.5;

    if (elapsed > threshold) {
        printf("[!] ALERTE: Temps anormalement long!\n");
        printf("[!] Debugger potentiellement détecté!\n");
        printf("[!] Seuil: %.2fs, Mesuré: %.2fs\n", threshold, elapsed);
    } else {
        printf("[+] Temps normal - Environnement OK\n");
        printf("[+] Seuil: %.2fs, Mesuré: %.2fs\n", threshold, elapsed);
    }

    return 0;
}
```

### Sortie (sans debugger)

```
=== Timing Anti-Debug ===

[*] Exécution de 1000000 itérations...
[*] Temps écoulé: 0.003245 secondes
[*] Résultat: 1783293664

[+] Temps normal - Environnement OK
[+] Seuil: 0.50s, Mesuré: 0.00s
```

### Sortie (avec debugger simulé)

```
[!] ALERTE: Temps anormalement long!
[!] Debugger potentiellement détecté!
[!] Seuil: 0.50s, Mesuré: 2.34s
```

### Pourquoi ça marche ?

- Un debugger single-step ralentit énormément l'exécution
- Les points d'arrêt ajoutent du délai
- Le timing normal devrait être très rapide

---

## Points clés du module

### 1. Types de boucles

| Type | Usage |
|------|-------|
| `for` | Nombre d'itérations connu |
| `while` | Condition dynamique |
| `do-while` | Au moins une exécution |

### 2. Contrôle de boucle

| Instruction | Effet |
|-------------|-------|
| `break` | Sort de la boucle |
| `continue` | Passe à l'itération suivante |

### 3. Patterns offensifs

- **Port scanning** : for sur plage de ports
- **Bruteforce** : boucles imbriquées pour combinaisons
- **XOR decode** : for sur chaque byte
- **Signature search** : for avec comparaison de pattern
- **Anti-debug timing** : mesure du temps d'exécution

---

## Checklist finale

- [ ] Je maîtrise for (croissant, décroissant, pas variable)
- [ ] Je maîtrise while et do-while
- [ ] Je sais utiliser break et continue
- [ ] Je sais faire des boucles imbriquées
- [ ] Je peux implémenter un bruteforce
- [ ] Je peux implémenter un XOR decoder
- [ ] Je peux chercher un pattern en mémoire
- [ ] Je comprends le timing anti-debug

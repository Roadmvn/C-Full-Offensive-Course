# Module 05 : Boucles (Loops)

## Partie 0 : Pourquoi les boucles en sécurité offensive ?

Les boucles sont **l'ADN de l'exploitation**. Voici pourquoi chaque hacker doit les maîtriser parfaitement :

### Applications directes

| Technique | Type de boucle | Exemple |
|-----------|---------------|---------|
| Port scanning | for | Scanner les ports 1-65535 |
| Bruteforce | for imbriqués | Générer toutes combinaisons de passwords |
| Keylogger | while infini | Capturer les frappes en continu |
| Beacon C2 | do-while | Contacter le serveur jusqu'à réponse |
| Memory scanning | for | Chercher un pattern en mémoire |
| Anti-debug timing | for | Mesurer le temps d'exécution |
| Shellcode decoder | for | Déchiffrer le payload byte par byte |
| Process injection | while | Attendre que la cible soit prête |

### Pourquoi maîtriser les boucles ?

```c
// Sans boucle : scanner 5 ports manuellement
scan_port(22);
scan_port(80);
scan_port(443);
scan_port(8080);
scan_port(3389);

// Avec boucle : scanner 65535 ports automatiquement
for (int port = 1; port <= 65535; port++) {
    scan_port(port);
}
```

**Ce module te fera passer de débutant à expert en boucles.**

---

## Partie 1 : La boucle for - Le cheval de bataille

### Anatomie d'une boucle for

```c
for (initialisation; condition; incrémentation) {
    // Corps de la boucle
}
```

**Les 3 parties :**

```
┌─────────────────────────────────────────────────────────────┐
│                     for (i = 0; i < 10; i++)               │
│                          ↓     ↓       ↓                    │
│                          │     │       │                    │
│                    ┌─────┘     │       └──────┐             │
│                    ↓           ↓              ↓             │
│              INITIALISATION  CONDITION   INCRÉMENTATION     │
│              (une seule fois) (chaque tour) (après chaque   │
│                                             tour)           │
└─────────────────────────────────────────────────────────────┘
```

### Flux d'exécution

```
Étape 1 : Initialisation (i = 0)
    ↓
Étape 2 : Test condition (i < 10 ?)
    ↓ Vrai
Étape 3 : Exécuter le corps
    ↓
Étape 4 : Incrémentation (i++)
    ↓
    ← Retour à l'étape 2

Si condition FAUX → Sortie de boucle
```

### Exemples de base

```c
#include <stdio.h>

int main(void) {
    // Compteur croissant
    printf("Croissant : ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);  // 0 1 2 3 4
    }
    printf("\n");

    // Compteur décroissant
    printf("Décroissant : ");
    for (int i = 10; i > 0; i--) {
        printf("%d ", i);  // 10 9 8 7 6 5 4 3 2 1
    }
    printf("\n");

    // Pas de 2
    printf("Pairs : ");
    for (int i = 0; i <= 10; i += 2) {
        printf("%d ", i);  // 0 2 4 6 8 10
    }
    printf("\n");

    // Puissances de 2
    printf("Puissances : ");
    for (int i = 1; i <= 256; i *= 2) {
        printf("%d ", i);  // 1 2 4 8 16 32 64 128 256
    }
    printf("\n");

    return 0;
}
```

### Variables de boucle - Scope

```c
// Variable déclarée DANS le for : scope limité
for (int i = 0; i < 10; i++) {
    printf("%d\n", i);
}
// printf("%d\n", i);  // ERREUR : i n'existe plus ici

// Variable déclarée AVANT le for : accessible après
int j;
for (j = 0; j < 10; j++) {
    printf("%d\n", j);
}
printf("Valeur finale : %d\n", j);  // OK : j = 10
```

### Application offensive : Port Scanner

```c
#include <stdio.h>

// Simule la vérification d'un port
int check_port(const char* ip, int port) {
    // En vrai : socket() + connect()
    // Ici on simule des ports ouverts
    int open_ports[] = {22, 80, 443, 3306, 8080};
    for (int i = 0; i < 5; i++) {
        if (port == open_ports[i]) return 1;
    }
    return 0;
}

int main(void) {
    const char* target = "192.168.1.100";

    printf("[*] Scanning %s...\n", target);

    // Scan des well-known ports (1-1024)
    for (int port = 1; port <= 1024; port++) {
        if (check_port(target, port)) {
            printf("[+] Port %d OPEN\n", port);
        }
    }

    printf("[*] Scan complete\n");
    return 0;
}
```

---

## Partie 2 : La boucle while - Condition dynamique

### Syntaxe

```c
while (condition) {
    // Corps exécuté tant que condition est VRAIE
}
```

### Différence avec for

```
┌─────────────────────────────────────────────────────────────┐
│  for  : Quand tu CONNAIS le nombre d'itérations            │
│         "Pour i de 0 à 99"                                  │
│                                                             │
│  while : Quand tu NE SAIS PAS combien de fois              │
│          "Tant que je n'ai pas trouvé..."                  │
│          "Tant que l'utilisateur ne quitte pas..."         │
└─────────────────────────────────────────────────────────────┘
```

### Exemples de base

```c
#include <stdio.h>

int main(void) {
    // Compter jusqu'à condition
    int count = 0;
    while (count < 5) {
        printf("Count: %d\n", count);
        count++;
    }

    // Chercher une valeur
    int numbers[] = {3, 7, 2, 9, 4, 1};
    int size = 6;
    int target = 9;
    int i = 0;

    while (i < size && numbers[i] != target) {
        i++;
    }

    if (i < size) {
        printf("Trouvé à l'index %d\n", i);
    } else {
        printf("Non trouvé\n");
    }

    return 0;
}
```

### Attention aux boucles infinies !

```c
// BOUCLE INFINIE - Le programme ne s'arrête jamais
while (1) {
    printf("Infini !\n");
}

// Oubli d'incrémenter - BOUCLE INFINIE
int i = 0;
while (i < 10) {
    printf("%d\n", i);
    // Oops, oublié : i++;
}

// Condition toujours vraie - BOUCLE INFINIE
int x = 5;
while (x > 0) {
    printf("%d\n", x);
    x++;  // Oops, devrait être x--
}
```

### Application offensive : Attendre un processus

```c
#include <stdio.h>
#include <unistd.h>  // Pour sleep()

// Simule la recherche d'un processus
int find_process(const char* name) {
    static int attempts = 0;
    attempts++;
    // Simule : le processus apparaît après 3 tentatives
    return (attempts >= 3) ? 12345 : 0;
}

int main(void) {
    const char* target_process = "target.exe";
    int pid = 0;

    printf("[*] Waiting for %s...\n", target_process);

    // Attendre que le processus cible démarre
    while ((pid = find_process(target_process)) == 0) {
        printf("[.] Process not found, waiting...\n");
        sleep(1);  // Attendre 1 seconde
    }

    printf("[+] Found! PID = %d\n", pid);
    printf("[*] Ready for injection\n");

    return 0;
}
```

---

## Partie 3 : La boucle do-while - Au moins une fois

### Syntaxe

```c
do {
    // Corps exécuté AU MOINS une fois
} while (condition);  // Note le point-virgule !
```

### Différence cruciale

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  while : Teste d'ABORD, exécute ENSUITE                    │
│          → Peut ne jamais s'exécuter (0 fois)              │
│                                                             │
│  do-while : Exécute d'ABORD, teste ENSUITE                 │
│             → S'exécute TOUJOURS au moins 1 fois           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Démonstration

```c
#include <stdio.h>

int main(void) {
    int x = 0;

    // while avec condition fausse dès le départ
    printf("while (x > 0) : ");
    while (x > 0) {
        printf("Exécuté\n");  // JAMAIS affiché
    }
    printf("Pas exécuté\n");

    // do-while avec même condition
    printf("do-while (x > 0) : ");
    do {
        printf("Exécuté une fois\n");  // Affiché !
    } while (x > 0);

    return 0;
}
```

### Cas d'usage typiques

```c
// 1. Validation d'entrée utilisateur
int choice;
do {
    printf("Choix (1-4) : ");
    scanf("%d", &choice);
} while (choice < 1 || choice > 4);

// 2. Menu interactif
do {
    afficher_menu();
    choice = lire_choix();
    traiter_choix(choice);
} while (choice != QUITTER);

// 3. Retry avec limite
int attempts = 0;
int success = 0;
do {
    success = try_connection();
    attempts++;
} while (!success && attempts < 3);
```

### Application offensive : Beacon C2

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    int type;
    char data[256];
} Command;

// Simule la récupération de commande du C2
Command* fetch_command(void) {
    static int call_count = 0;
    call_count++;

    // Simule : commande reçue après quelques appels
    if (call_count >= 3 && call_count <= 5) {
        Command* cmd = malloc(sizeof(Command));
        cmd->type = 1;  // EXECUTE
        snprintf(cmd->data, sizeof(cmd->data), "whoami");
        return cmd;
    } else if (call_count > 7) {
        Command* cmd = malloc(sizeof(Command));
        cmd->type = 0xFF;  // EXIT
        return cmd;
    }
    return NULL;
}

int main(void) {
    printf("[*] Beacon started\n");

    Command* cmd;
    int running = 1;

    do {
        // 1. Contacter le C2
        printf("[.] Checking for commands...\n");
        cmd = fetch_command();

        // 2. Traiter la commande
        if (cmd != NULL) {
            switch (cmd->type) {
                case 1:  // EXECUTE
                    printf("[+] Executing: %s\n", cmd->data);
                    break;
                case 0xFF:  // EXIT
                    printf("[!] Exit command received\n");
                    running = 0;
                    break;
            }
            free(cmd);
        }

        // 3. Attendre avant prochain beacon
        if (running) {
            sleep(2);  // Beacon interval
        }

    } while (running);

    printf("[*] Beacon terminated\n");
    return 0;
}
```

---

## Partie 4 : Boucles imbriquées - La puissance

### Concept

Des boucles dans des boucles. Chaque tour de la boucle externe déclenche une exécution COMPLÈTE de la boucle interne.

```c
for (externe) {
    for (interne) {
        // Exécuté (externe × interne) fois
    }
}
```

### Visualisation

```
┌──────────────────────────────────────────────────────┐
│  for (i = 0; i < 3; i++)                             │
│      for (j = 0; j < 3; j++)                         │
│                                                      │
│  Exécution :                                         │
│  i=0: j=0, j=1, j=2                                  │
│  i=1: j=0, j=1, j=2                                  │
│  i=2: j=0, j=1, j=2                                  │
│                                                      │
│  Total : 3 × 3 = 9 itérations                        │
└──────────────────────────────────────────────────────┘
```

### Application offensive : Bruteforce PIN

```c
#include <stdio.h>
#include <string.h>

// Simule la vérification d'un PIN
int check_pin(const char* pin) {
    return strcmp(pin, "742") == 0;
}

int main(void) {
    char pin[5];
    int found = 0;
    int attempts = 0;

    printf("[*] Bruteforcing 3-digit PIN...\n");

    // Triple boucle imbriquée : 0-9 × 0-9 × 0-9 = 1000 combinaisons
    for (int i = 0; i <= 9 && !found; i++) {
        for (int j = 0; j <= 9 && !found; j++) {
            for (int k = 0; k <= 9 && !found; k++) {
                // Construire le PIN
                sprintf(pin, "%d%d%d", i, j, k);
                attempts++;

                // Tester
                if (check_pin(pin)) {
                    printf("[+] PIN FOUND: %s\n", pin);
                    printf("[+] Attempts: %d\n", attempts);
                    found = 1;
                }
            }
        }
    }

    if (!found) {
        printf("[-] PIN not found\n");
    }

    return 0;
}
```

### Application offensive : Password bruteforce

```c
#include <stdio.h>
#include <string.h>

int check_password(const char* password) {
    return strcmp(password, "abc") == 0;
}

int main(void) {
    // Charset réduit pour la démo
    char charset[] = "abcdefghij";
    int charset_len = strlen(charset);
    char password[4];
    int found = 0;
    long attempts = 0;

    printf("[*] Bruteforcing 3-char password...\n");
    printf("[*] Charset: %s (%d chars)\n", charset, charset_len);
    printf("[*] Combinations: %d\n", charset_len * charset_len * charset_len);

    // Triple boucle pour 3 caractères
    for (int i = 0; i < charset_len && !found; i++) {
        for (int j = 0; j < charset_len && !found; j++) {
            for (int k = 0; k < charset_len && !found; k++) {
                password[0] = charset[i];
                password[1] = charset[j];
                password[2] = charset[k];
                password[3] = '\0';
                attempts++;

                if (check_password(password)) {
                    printf("[+] PASSWORD FOUND: %s\n", password);
                    printf("[+] Attempts: %ld\n", attempts);
                    found = 1;
                }
            }
        }
    }

    return 0;
}
```

### Pattern : Matrice/Grille

```c
#include <stdio.h>

int main(void) {
    // Afficher une grille 5x5
    printf("Grille 5x5:\n");
    for (int row = 0; row < 5; row++) {
        for (int col = 0; col < 5; col++) {
            printf("[%d,%d] ", row, col);
        }
        printf("\n");
    }

    // Afficher un triangle
    printf("\nTriangle:\n");
    for (int i = 1; i <= 5; i++) {
        for (int j = 0; j < i; j++) {
            printf("* ");
        }
        printf("\n");
    }

    return 0;
}
```

---

## Partie 5 : Contrôle de boucle - break, continue, goto

### break : Sortir immédiatement

```c
for (int i = 0; i < 100; i++) {
    if (i == 42) {
        break;  // Sort de la boucle immédiatement
    }
    printf("%d ", i);  // Affiche 0 à 41
}
// Continue ici après break
```

### continue : Passer à l'itération suivante

```c
for (int i = 0; i < 10; i++) {
    if (i % 2 == 0) {
        continue;  // Saute les nombres pairs
    }
    printf("%d ", i);  // Affiche 1 3 5 7 9
}
```

### Visualisation break vs continue

```
┌─────────────────────────────────────────────────────────────┐
│  for (i = 0; i < 5; i++)                                   │
│                                                             │
│  BREAK à i=2:                    CONTINUE à i=2:           │
│  i=0 → traite                    i=0 → traite              │
│  i=1 → traite                    i=1 → traite              │
│  i=2 → BREAK! ───────────┐       i=2 → CONTINUE! ──┐       │
│  i=3 → jamais             │      i=3 → traite      │       │
│  i=4 → jamais             │      i=4 → traite      │       │
│                           ↓                        ↓       │
│  Sort de la boucle         │      Passe à i=3             │
│  ────────────────────────  │                               │
│  Output: 0 1               │      Output: 0 1 3 4         │
└─────────────────────────────────────────────────────────────┘
```

### break dans boucles imbriquées

**Attention** : `break` ne sort que de la boucle **immédiate** !

```c
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (j == 1) {
            break;  // Sort seulement de la boucle j
        }
        printf("i=%d, j=%d\n", i, j);
    }
    // Continue ici, la boucle i continue
}

// Output:
// i=0, j=0
// i=1, j=0
// i=2, j=0
```

### Solution : Flag ou goto

```c
// Solution 1 : Flag
int found = 0;
for (int i = 0; i < 10 && !found; i++) {
    for (int j = 0; j < 10 && !found; j++) {
        if (condition) {
            found = 1;  // Les deux boucles vont s'arrêter
        }
    }
}

// Solution 2 : goto (acceptable dans ce cas)
for (int i = 0; i < 10; i++) {
    for (int j = 0; j < 10; j++) {
        if (condition) {
            goto found;  // Sort des deux boucles
        }
    }
}
found:
    printf("Trouvé!\n");
```

### Application offensive : Recherche avec early exit

```c
#include <stdio.h>

// Chercher une signature de malware en mémoire
unsigned char* find_signature(unsigned char* memory, size_t mem_size,
                              unsigned char* sig, size_t sig_size) {
    for (size_t i = 0; i <= mem_size - sig_size; i++) {
        int match = 1;

        for (size_t j = 0; j < sig_size; j++) {
            if (memory[i + j] != sig[j]) {
                match = 0;
                break;  // Pas la peine de continuer cette comparaison
            }
        }

        if (match) {
            return &memory[i];  // Trouvé !
        }
    }

    return NULL;  // Non trouvé
}

int main(void) {
    unsigned char memory[] = {0x00, 0x90, 0x90, 0xCC, 0x31, 0xC0, 0x50, 0x90};
    unsigned char sig[] = {0xCC, 0x31, 0xC0};  // int3 + xor eax, eax

    unsigned char* found = find_signature(memory, sizeof(memory),
                                          sig, sizeof(sig));

    if (found) {
        printf("[+] Signature found at offset: %ld\n",
               found - memory);
    } else {
        printf("[-] Signature not found\n");
    }

    return 0;
}
```

---

## Partie 6 : Patterns offensifs avancés

### Pattern 1 : Scan avec randomisation

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    int ports[] = {22, 80, 443, 3306, 3389, 8080, 8443};
    int num_ports = sizeof(ports) / sizeof(ports[0]);

    // Mélanger l'ordre des ports (Fisher-Yates shuffle)
    srand(time(NULL));
    for (int i = num_ports - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = ports[i];
        ports[i] = ports[j];
        ports[j] = temp;
    }

    printf("[*] Randomized port scan:\n");
    for (int i = 0; i < num_ports; i++) {
        printf("[.] Scanning port %d...\n", ports[i]);
        // scan_port(target, ports[i]);
        // sleep(rand() % 3);  // Délai aléatoire
    }

    return 0;
}
```

### Pattern 2 : Retry avec backoff exponentiel

```c
#include <stdio.h>
#include <unistd.h>

int try_connect(const char* host) {
    static int attempts = 0;
    attempts++;
    return (attempts >= 4);  // Réussit après 4 essais
}

int main(void) {
    const char* c2_server = "evil.com";
    int max_retries = 10;
    int delay = 1;  // Secondes

    for (int attempt = 1; attempt <= max_retries; attempt++) {
        printf("[%d/%d] Connecting to %s...\n",
               attempt, max_retries, c2_server);

        if (try_connect(c2_server)) {
            printf("[+] Connected!\n");
            break;
        }

        printf("[-] Failed, waiting %d seconds...\n", delay);
        sleep(delay);

        // Backoff exponentiel : 1, 2, 4, 8, 16... (max 60)
        delay *= 2;
        if (delay > 60) delay = 60;
    }

    return 0;
}
```

### Pattern 3 : XOR decode avec boucle

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Shellcode "chiffré" avec XOR 0x42
    unsigned char encoded[] = {
        0xD3, 0x9E, 0x93, 0x9E, 0x2D, 0x27, 0x3C, 0x27, 0x00
    };
    // Original: "calc.exe" XOR 0x42

    unsigned char key = 0x42;
    int len = sizeof(encoded) - 1;  // -1 pour le null

    printf("Encoded: ");
    for (int i = 0; i < len; i++) {
        printf("%02X ", encoded[i]);
    }
    printf("\n");

    // Décodage XOR
    printf("Decoding...\n");
    for (int i = 0; i < len; i++) {
        encoded[i] ^= key;
    }

    printf("Decoded: %s\n", encoded);

    return 0;
}
```

### Pattern 4 : Polling avec timeout

```c
#include <stdio.h>
#include <time.h>

int check_condition(void) {
    static int counter = 0;
    return (++counter >= 5);
}

int main(void) {
    time_t start = time(NULL);
    int timeout_seconds = 10;
    int poll_interval_ms = 500;

    printf("[*] Waiting for condition (timeout: %ds)...\n", timeout_seconds);

    while (1) {
        // Vérifier le timeout
        if (time(NULL) - start >= timeout_seconds) {
            printf("[-] Timeout!\n");
            break;
        }

        // Vérifier la condition
        if (check_condition()) {
            printf("[+] Condition met!\n");
            break;
        }

        // Attendre avant de re-vérifier
        printf("[.] Polling...\n");
        // usleep(poll_interval_ms * 1000);
    }

    return 0;
}
```

### Pattern 5 : Boucle infinie pour persistence

```c
#include <stdio.h>
#include <unistd.h>

void maintain_persistence(void) {
    printf("[*] Persistence loop started\n");

    // Boucle infinie intentionnelle
    for (;;) {  // Équivalent à while(1)
        // 1. Vérifier si toujours persistant
        printf("[.] Checking persistence...\n");

        // 2. Se réinstaller si nécessaire
        // if (!check_autorun()) reinstall_autorun();

        // 3. Attendre
        sleep(60);
    }

    // Ce code n'est jamais atteint
    printf("Never reached\n");
}

int main(void) {
    maintain_persistence();
    return 0;
}
```

### Pattern 6 : Timing attack detection

```c
#include <stdio.h>
#include <time.h>

int main(void) {
    clock_t start, end;
    double cpu_time_used;
    int iterations = 1000000;

    // Mesurer le temps d'exécution
    start = clock();

    volatile int sum = 0;  // volatile empêche l'optimisation
    for (int i = 0; i < iterations; i++) {
        sum += i;
    }

    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("Iterations: %d\n", iterations);
    printf("Time: %f seconds\n", cpu_time_used);

    // Anti-debug : un debugger ralentit l'exécution
    if (cpu_time_used > 0.1) {
        printf("[!] Possible debugger detected (too slow)\n");
    } else {
        printf("[+] No debugger detected\n");
    }

    return 0;
}
```

---

## Partie 7 : Optimisation des boucles

### Sortir les calculs invariants

```c
// MAUVAIS : strlen() appelé à chaque itération
for (int i = 0; i < strlen(str); i++) {
    // ...
}

// BON : calculé une seule fois
int len = strlen(str);
for (int i = 0; i < len; i++) {
    // ...
}
```

### Réduire les accès mémoire

```c
// MAUVAIS : accès indirect répété
for (int i = 0; i < n; i++) {
    array[index]++;  // Charge index à chaque fois
}

// BON : variable locale
int* ptr = &array[index];
for (int i = 0; i < n; i++) {
    (*ptr)++;
}
```

### Loop unrolling (déroulage)

```c
// Normal : 1000 itérations
for (int i = 0; i < 1000; i++) {
    process(i);
}

// Déroulé : 250 itérations (4x moins de comparaisons)
for (int i = 0; i < 1000; i += 4) {
    process(i);
    process(i + 1);
    process(i + 2);
    process(i + 3);
}
```

### Direction du compteur

```c
// Décompter vers 0 peut être plus rapide
// La comparaison avec 0 est optimisée par le CPU

// Au lieu de :
for (int i = 0; i < n; i++) { ... }

// Préférer (quand l'ordre n'importe pas) :
for (int i = n; i > 0; i--) { ... }

// Ou avec i-- postfixé :
for (int i = n; i--;) { ... }  // i va de n-1 à 0
```

---

## Partie 8 : Pièges courants

### Piège 1 : Off-by-one errors

```c
int array[10];  // Indices valides : 0 à 9

// ERREUR : accès à array[10] (hors limites)
for (int i = 0; i <= 10; i++) {  // <= au lieu de <
    array[i] = 0;  // Buffer overflow à i=10 !
}

// CORRECT
for (int i = 0; i < 10; i++) {
    array[i] = 0;
}
```

### Piège 2 : Modification de la variable de boucle

```c
// Comportement imprévisible
for (int i = 0; i < 10; i++) {
    printf("%d\n", i);
    i = 5;  // MAUVAIS : modifie la variable de contrôle
}

// Sortie : 0, 6, 7, 8, 9, 10 (sort à 10)
// Pas ce qu'on voulait !
```

### Piège 3 : Integer overflow

```c
// ERREUR : i ne dépassera jamais 255
for (unsigned char i = 0; i < 256; i++) {
    // Boucle infinie ! Quand i=255, i++ → i=0
}

// CORRECT : utiliser un type assez grand
for (int i = 0; i < 256; i++) {
    // OK
}
```

### Piège 4 : Virgule au mauvais endroit

```c
// ERREUR : le point-virgule termine la boucle !
for (int i = 0; i < 10; i++);  // Boucle vide !
{
    printf("Affiché une seule fois\n");
}

// CORRECT
for (int i = 0; i < 10; i++) {
    printf("Affiché 10 fois\n");
}
```

### Piège 5 : Comparaison de flottants

```c
// DANGEREUX : les flottants sont imprécis
for (float f = 0.0; f != 1.0; f += 0.1) {
    // Peut ne jamais s'arrêter !
    // 0.1 n'est pas représentable exactement en binaire
}

// CORRECT : utiliser < ou >
for (float f = 0.0; f < 1.0; f += 0.1) {
    // OK
}
```

---

## Résumé visuel

```
┌─────────────────────────────────────────────────────────────┐
│                   CHOIX DE LA BOUCLE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Tu connais le nombre d'itérations ?                       │
│        OUI → for (i = 0; i < n; i++)                       │
│        NON → while ou do-while                             │
│                                                             │
│  Tu dois exécuter au moins une fois ?                      │
│        OUI → do { } while (condition);                     │
│        NON → while (condition) { }                         │
│                                                             │
│  Tu veux sortir en plein milieu ?                          │
│        → break;                                             │
│                                                             │
│  Tu veux sauter une itération ?                            │
│        → continue;                                          │
│                                                             │
│  Tu veux sortir de plusieurs boucles ?                     │
│        → flag + condition ou goto                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Exercices

Voir [exercice.md](exercice.md) pour pratiquer ces concepts.

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.

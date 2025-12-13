# Solutions - Module 04 : Control Flow

## Table des matières

1. [Exercice 1 : Vrai/Faux en C](#exercice-1--vraifaux-en-c)
2. [Exercice 2 : If/else if/else](#exercice-2--ifelseifelse)
3. [Exercice 3 : Switch basique](#exercice-3--switch-basique)
4. [Exercice 4 : Fall-through intentionnel](#exercice-4--fall-through-intentionnel)
5. [Exercice 5 : Boucle for - Compteurs](#exercice-5--boucle-for---compteurs)
6. [Exercice 6 : Boucle while - Recherche](#exercice-6--boucle-while---recherche)
7. [Exercice 7 : Do-while - Menu interactif](#exercice-7--do-while---menu-interactif)
8. [Exercice 8 : Boucles imbriquées - Pattern](#exercice-8--boucles-imbriquées---pattern)
9. [Exercice 9 : break et continue](#exercice-9--break-et-continue)
10. [Exercice 10 : XOR Encryption avec for](#exercice-10--xor-encryption-avec-for)
11. [Exercice 11 : Command Dispatcher](#exercice-11--command-dispatcher)
12. [Exercice 12 : Port Scanner Simulé](#exercice-12--port-scanner-simulé)
13. [Exercice 13 : State Machine](#exercice-13--state-machine)
14. [Exercice 14 : Goto pour cleanup](#exercice-14--goto-pour-cleanup)

---

## Exercice 1 : Vrai/Faux en C

### Solution

```c
#include <stdio.h>

int main(void) {
    int values[] = {0, 1, -1, 100, 42};

    printf("=== Vrai/Faux en C ===\n\n");

    for (int i = 0; i < 5; i++) {
        printf("Valeur %d : ", values[i]);

        if (values[i]) {
            printf("VRAI (non-zéro)\n");
        } else {
            printf("FAUX (zéro)\n");
        }
    }

    return 0;
}
```

### Sortie attendue

```
=== Vrai/Faux en C ===

Valeur 0 : FAUX (zéro)
Valeur 1 : VRAI (non-zéro)
Valeur -1 : VRAI (non-zéro)
Valeur 100 : VRAI (non-zéro)
Valeur 42 : VRAI (non-zéro)
```

### Réponses aux questions

1. **Pourquoi -1 est considéré comme VRAI ?**
   - En C, seul 0 est considéré comme FAUX
   - Toute autre valeur, y compris -1, est considérée comme VRAI
   - Le signe n'a aucune importance pour la valeur booléenne

2. **Quelle est la seule valeur FAUX en C ?**
   - La valeur `0` (zéro)
   - Cela inclut le pointeur NULL qui vaut 0

3. **Que retourne `5 > 3` ? Et `5 < 3` ?**
   - `5 > 3` retourne `1` (vrai)
   - `5 < 3` retourne `0` (faux)
   - Les opérateurs de comparaison retournent toujours 0 ou 1

### Application offensive

```c
// Anti-debug : vérifier si un debugger modifie une valeur
int check = 0xDEADBEEF;
// Si un debugger change cette valeur...
if (check != 0xDEADBEEF) {
    // ...on le détecte et on réagit
}
```

---

## Exercice 2 : If/else if/else

### Solution

```c
#include <stdio.h>

int main(void) {
    // Teste avec différentes valeurs
    int ports[] = {-1, 22, 443, 3389, 50000, 70000};
    int num_ports = sizeof(ports) / sizeof(ports[0]);

    printf("=== Catégorisation des ports ===\n\n");

    for (int i = 0; i < num_ports; i++) {
        int port = ports[i];
        printf("Port %d : ", port);

        if (port < 0 || port > 65535) {
            printf("Port invalide\n");
        } else if (port <= 1023) {
            printf("Port privilégié (well-known)\n");
        } else if (port <= 49151) {
            printf("Port enregistré (registered)\n");
        } else {
            printf("Port dynamique (private)\n");
        }
    }

    return 0;
}
```

### Sortie attendue

```
=== Catégorisation des ports ===

Port -1 : Port invalide
Port 22 : Port privilégié (well-known)
Port 443 : Port privilégié (well-known)
Port 3389 : Port enregistré (registered)
Port 50000 : Port dynamique (private)
Port 70000 : Port invalide
```

### Explication

L'ordre des conditions est crucial :

1. **Validation d'abord** : On vérifie les valeurs invalides en premier
2. **Du plus restrictif au moins restrictif** : 0-1023, puis 1024-49151, puis le reste
3. **else final** : Capture tout ce qui n'a pas été géré (49152-65535)

### Application offensive

```c
// Classification pour un scanner de ports
const char* get_port_info(int port) {
    if (port < 0 || port > 65535) return "INVALID";

    // Ports communs pour attaques
    if (port == 22)   return "SSH - Bruteforce possible";
    if (port == 23)   return "TELNET - Non sécurisé!";
    if (port == 445)  return "SMB - EternalBlue?";
    if (port == 3389) return "RDP - BlueKeep?";

    if (port <= 1023) return "Well-known";
    if (port <= 49151) return "Registered";
    return "Dynamic";
}
```

---

## Exercice 3 : Switch basique

### Solution

```c
#include <stdio.h>

int main(void) {
    // Teste plusieurs mois
    int months[] = {1, 3, 7, 12, 13, 0};
    int num_months = sizeof(months) / sizeof(months[0]);

    printf("=== Noms des mois ===\n\n");

    for (int i = 0; i < num_months; i++) {
        int month = months[i];
        printf("Mois %2d : ", month);

        switch (month) {
            case 1:  printf("Janvier\n");   break;
            case 2:  printf("Février\n");   break;
            case 3:  printf("Mars\n");      break;
            case 4:  printf("Avril\n");     break;
            case 5:  printf("Mai\n");       break;
            case 6:  printf("Juin\n");      break;
            case 7:  printf("Juillet\n");   break;
            case 8:  printf("Août\n");      break;
            case 9:  printf("Septembre\n"); break;
            case 10: printf("Octobre\n");   break;
            case 11: printf("Novembre\n");  break;
            case 12: printf("Décembre\n");  break;
            default: printf("Mois invalide\n"); break;
        }
    }

    return 0;
}
```

### Sortie attendue

```
=== Noms des mois ===

Mois  1 : Janvier
Mois  3 : Mars
Mois  7 : Juillet
Mois 12 : Décembre
Mois 13 : Mois invalide
Mois  0 : Mois invalide
```

### Réponses aux questions

1. **Que se passe-t-il si on oublie le `break` ?**
   - Le code "tombe" dans le case suivant (fall-through)
   - Tous les cases suivants s'exécutent jusqu'au prochain break
   - C'est une source fréquente de bugs !

2. **Peut-on utiliser une string dans un switch en C ?**
   - **NON !** Switch ne supporte que les types entiers (int, char, enum)
   - Pour les strings, il faut utiliser if/else avec strcmp()
   - C++ moderne a switch sur types plus variés

3. **Quand préférer switch à if/else if ?**
   - Quand on compare une variable à plusieurs valeurs constantes
   - Quand les cases sont nombreux (plus lisible)
   - Le compilateur peut optimiser switch en jump table

---

## Exercice 4 : Fall-through intentionnel

### Solution

```c
#include <stdio.h>

int main(void) {
    // Teste tous les jours
    printf("=== Classification des jours ===\n\n");

    for (int day = 0; day <= 8; day++) {
        printf("Jour %d : ", day);

        switch (day) {
            case 1:  // Lundi
            case 2:  // Mardi
            case 3:  // Mercredi
            case 4:  // Jeudi
            case 5:  // Vendredi
                printf("Jour de semaine\n");
                break;

            case 6:  // Samedi
            case 7:  // Dimanche
                printf("Weekend\n");
                break;

            default:
                printf("Jour invalide\n");
                break;
        }
    }

    return 0;
}
```

### Sortie attendue

```
=== Classification des jours ===

Jour 0 : Jour invalide
Jour 1 : Jour de semaine
Jour 2 : Jour de semaine
Jour 3 : Jour de semaine
Jour 4 : Jour de semaine
Jour 5 : Jour de semaine
Jour 6 : Weekend
Jour 7 : Weekend
Jour 8 : Jour invalide
```

### Explication du fall-through

```c
case 1:
case 2:
case 3:
    // Ce code s'exécute pour 1, 2 OU 3
    printf("Cas 1, 2 ou 3\n");
    break;
```

Sans `break` après un case, l'exécution continue dans le case suivant.
C'est utile pour grouper des cas qui ont le même traitement.

### Application offensive

```c
// Classification de commandes C2
switch (cmd_type) {
    // Commandes de reconnaissance
    case CMD_SYSINFO:
    case CMD_WHOAMI:
    case CMD_IPCONFIG:
        log_recon_activity();
        // Fall-through intentionnel

    // Toutes les commandes passent par l'exécution
    case CMD_SHELL:
        execute_command(cmd);
        break;

    // Commandes critiques
    case CMD_EXFIL:
    case CMD_DESTROY:
        require_confirmation();
        break;
}
```

---

## Exercice 5 : Boucle for - Compteurs

### Solution

```c
#include <stdio.h>

int main(void) {
    printf("=== Boucles for - Compteurs ===\n\n");

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

    // 3. Multiples de 3 de 0 à 30
    printf("Multiples de 3 (0-30) : ");
    for (int i = 0; i <= 30; i += 3) {
        printf("%d ", i);
    }
    printf("\n");

    // 4. Puissances de 2 jusqu'à 256
    printf("Puissances de 2 : ");
    for (int i = 1; i <= 256; i *= 2) {
        printf("%d ", i);
    }
    printf("\n");

    return 0;
}
```

### Sortie attendue

```
=== Boucles for - Compteurs ===

1 à 10 : 1 2 3 4 5 6 7 8 9 10
10 à 1 : 10 9 8 7 6 5 4 3 2 1
Multiples de 3 (0-30) : 0 3 6 9 12 15 18 21 24 27 30
Puissances de 2 : 1 2 4 8 16 32 64 128 256
```

### Anatomie d'une boucle for

```c
for (init; condition; step) {
    // corps
}

// Équivalent à :
init;
while (condition) {
    // corps
    step;
}
```

### Application offensive

```c
// Scan de ports avec différents patterns
// Scan linéaire (détectable)
for (int port = 1; port <= 1024; port++) {
    scan_port(target, port);
}

// Scan avec intervalle (moins détectable)
for (int port = 1; port <= 1024; port += rand() % 10 + 1) {
    scan_port(target, port);
    sleep_random();  // Délai aléatoire
}

// Scan des ports communs seulement
int common[] = {21, 22, 23, 25, 80, 443, 3389};
for (int i = 0; i < sizeof(common)/sizeof(common[0]); i++) {
    scan_port(target, common[i]);
}
```

---

## Exercice 6 : Boucle while - Recherche

### Solution

```c
#include <stdio.h>

int main(void) {
    int numbers[] = {15, 42, 8, 23, 16, 4, 42, 99};
    int size = 8;
    int target = 42;

    printf("=== Recherche avec while ===\n\n");
    printf("Tableau : ");
    for (int i = 0; i < size; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\nCible : %d\n\n", target);

    // PARTIE 1 : Première occurrence
    int i = 0;
    while (i < size && numbers[i] != target) {
        i++;
    }

    if (i < size) {
        printf("Première occurrence trouvée à l'index %d\n", i);
    } else {
        printf("Non trouvé\n");
    }

    // BONUS : Toutes les occurrences
    printf("\nToutes les occurrences : ");
    int count = 0;
    i = 0;
    while (i < size) {
        if (numbers[i] == target) {
            printf("index %d ", i);
            count++;
        }
        i++;
    }

    if (count == 0) {
        printf("Aucune");
    }
    printf("\n(Total : %d occurrence(s))\n", count);

    return 0;
}
```

### Sortie attendue

```
=== Recherche avec while ===

Tableau : 15 42 8 23 16 4 42 99
Cible : 42

Première occurrence trouvée à l'index 1

Toutes les occurrences : index 1 index 6
(Total : 2 occurrence(s))
```

### Explication

La condition `i < size && numbers[i] != target` utilise l'évaluation court-circuit :
- Si `i >= size`, on ne teste pas `numbers[i]` (évite buffer overflow)
- On s'arrête dès qu'on trouve la cible

### Application offensive

```c
// Recherche de pattern en mémoire (signature d'antivirus, etc.)
unsigned char* find_pattern(unsigned char* memory, size_t mem_size,
                           unsigned char* pattern, size_t pat_size) {
    size_t i = 0;

    while (i <= mem_size - pat_size) {
        size_t j = 0;

        // Compare le pattern
        while (j < pat_size && memory[i + j] == pattern[j]) {
            j++;
        }

        if (j == pat_size) {
            return &memory[i];  // Pattern trouvé!
        }

        i++;
    }

    return NULL;  // Non trouvé
}
```

---

## Exercice 7 : Do-while - Menu interactif

### Solution

```c
#include <stdio.h>

int main(void) {
    int choice;

    printf("=== Menu Interactif (do-while) ===\n");

    do {
        // Affiche le menu
        printf("\n--- MENU ---\n");
        printf("1. Scanner\n");
        printf("2. Exploiter\n");
        printf("3. Rapport\n");
        printf("4. Quitter\n");
        printf("Choix : ");

        scanf("%d", &choice);

        // Traite le choix
        switch (choice) {
            case 1:
                printf("[*] Lancement du scan...\n");
                printf("[+] Scan terminé : 5 hôtes trouvés\n");
                break;

            case 2:
                printf("[*] Sélection de l'exploit...\n");
                printf("[!] Exploitation simulée\n");
                break;

            case 3:
                printf("[*] Génération du rapport...\n");
                printf("[+] Rapport sauvegardé\n");
                break;

            case 4:
                printf("[*] Fermeture du programme...\n");
                break;

            default:
                printf("[!] Choix invalide, réessayez\n");
                break;
        }

    } while (choice != 4);

    printf("\n[+] Programme terminé\n");

    return 0;
}
```

### Pourquoi do-while ?

- **do-while** garantit au moins une exécution
- Parfait pour les menus : on veut toujours afficher le menu au moins une fois
- La condition est testée APRÈS le corps de la boucle

### Comparaison while vs do-while

```c
// while : peut ne jamais s'exécuter
int x = 0;
while (x > 0) {
    printf("Jamais affiché\n");
}

// do-while : s'exécute au moins une fois
int y = 0;
do {
    printf("Affiché une fois\n");
} while (y > 0);
```

### Application offensive

```c
// Boucle principale d'un implant/RAT
do {
    // Vérifie les commandes du C2
    command = check_c2_server();

    if (command != NULL) {
        result = execute_command(command);
        send_result_to_c2(result);
    }

    // Délai avant prochaine vérification
    sleep(beacon_interval);

} while (command != CMD_UNINSTALL);

// Nettoyage avant de quitter
cleanup_and_exit();
```

---

## Exercice 8 : Boucles imbriquées - Pattern

### Solution

```c
#include <stdio.h>

int main(void) {
    int rows = 5;

    printf("=== Patterns avec boucles imbriquées ===\n\n");

    // Triangle croissant
    printf("Triangle croissant :\n");
    for (int i = 1; i <= rows; i++) {
        for (int j = 1; j <= i; j++) {
            printf("*");
        }
        printf("\n");
    }

    printf("\n");

    // BONUS : Triangle décroissant
    printf("Triangle décroissant :\n");
    for (int i = rows; i >= 1; i--) {
        for (int j = 1; j <= i; j++) {
            printf("*");
        }
        printf("\n");
    }

    printf("\n");

    // BONUS 2 : Rectangle
    printf("Rectangle 5x10 :\n");
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 10; j++) {
            printf("*");
        }
        printf("\n");
    }

    return 0;
}
```

### Sortie attendue

```
=== Patterns avec boucles imbriquées ===

Triangle croissant :
*
**
***
****
*****

Triangle décroissant :
*****
****
***
**
*

Rectangle 5x10 :
**********
**********
**********
**********
**********
```

### Explication

```
Ligne 1 : i=1, j va de 1 à 1 → 1 étoile
Ligne 2 : i=2, j va de 1 à 2 → 2 étoiles
Ligne 3 : i=3, j va de 1 à 3 → 3 étoiles
...
```

### Application offensive

```c
// Génération de combinaisons pour bruteforce
char charset[] = "0123456789";
int charset_len = 10;

// Génère toutes les combinaisons de 3 chiffres (000-999)
for (int i = 0; i < charset_len; i++) {
    for (int j = 0; j < charset_len; j++) {
        for (int k = 0; k < charset_len; k++) {
            char pin[4];
            pin[0] = charset[i];
            pin[1] = charset[j];
            pin[2] = charset[k];
            pin[3] = '\0';

            if (try_pin(pin)) {
                printf("[+] PIN trouvé : %s\n", pin);
                return 0;
            }
        }
    }
}
```

---

## Exercice 9 : break et continue

### Solution

```c
#include <stdio.h>

int main(void) {
    printf("=== break et continue ===\n\n");

    // PARTIE 1 : Nombres impairs de 1 à 20 (avec continue)
    printf("Nombres impairs (1-20) : ");
    for (int i = 1; i <= 20; i++) {
        if (i % 2 == 0) {
            continue;  // Saute les nombres pairs
        }
        printf("%d ", i);
    }
    printf("\n");

    // PARTIE 2 : Premier nombre > 50 divisible par 7 (avec break)
    printf("Premier > 50 divisible par 7 : ");
    for (int i = 51; ; i++) {  // Boucle infinie
        if (i % 7 == 0) {
            printf("%d\n", i);
            break;  // Arrête dès qu'on trouve
        }
    }

    // PARTIE 3 : Positifs jusqu'à 0
    int values[] = {5, -2, 8, -1, 12, 0, 7, 9};
    int size = sizeof(values) / sizeof(values[0]);

    printf("Valeurs positives jusqu'à 0 : ");
    for (int i = 0; i < size; i++) {
        if (values[i] == 0) {
            break;  // Arrête à 0
        }
        if (values[i] < 0) {
            continue;  // Saute les négatifs
        }
        printf("%d ", values[i]);
    }
    printf("\n");

    return 0;
}
```

### Sortie attendue

```
=== break et continue ===

Nombres impairs (1-20) : 1 3 5 7 9 11 13 15 17 19
Premier > 50 divisible par 7 : 56
Valeurs positives jusqu'à 0 : 5 8 12
```

### Différence break vs continue

```
break    : Sort complètement de la boucle
continue : Passe à l'itération suivante

for (i = 0; i < 10; i++) {
    if (i == 5) break;     // Affiche 0 1 2 3 4
    printf("%d ", i);
}

for (i = 0; i < 10; i++) {
    if (i == 5) continue;  // Affiche 0 1 2 3 4 6 7 8 9
    printf("%d ", i);
}
```

### Application offensive

```c
// Scan de ports avec gestion des erreurs
for (int port = 1; port <= 65535; port++) {
    // Skip les ports blacklistés
    if (is_blacklisted(port)) {
        continue;
    }

    int result = scan_port(target, port);

    // Arrête si détecté par IDS
    if (result == DETECTED) {
        log_warning("IDS detected, stopping scan");
        break;
    }

    // Skip si timeout (pas intéressant)
    if (result == TIMEOUT) {
        continue;
    }

    // Port ouvert !
    if (result == OPEN) {
        log_open_port(port);
    }
}
```

---

## Exercice 10 : XOR Encryption avec for

### Solution

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char message[] = "ATTACK_AT_DAWN";
    unsigned char key = 0x42;
    int len = strlen(message);

    printf("=== XOR Encryption ===\n\n");

    // 1. Message original
    printf("Message original : %s\n", message);
    printf("Clé              : 0x%02X\n\n", key);

    // 2. Chiffrement XOR
    printf("Chiffrement...\n");
    for (int i = 0; i < len; i++) {
        message[i] ^= key;
    }

    // 3. Affichage en hex (car caractères non-imprimables)
    printf("Message chiffré (hex) : ");
    for (int i = 0; i < len; i++) {
        printf("%02X ", (unsigned char)message[i]);
    }
    printf("\n\n");

    // 4. Déchiffrement (même opération)
    printf("Déchiffrement...\n");
    for (int i = 0; i < len; i++) {
        message[i] ^= key;
    }

    // 5. Message déchiffré
    printf("Message déchiffré : %s\n", message);

    return 0;
}
```

### Sortie attendue

```
=== XOR Encryption ===

Message original : ATTACK_AT_DAWN
Clé              : 0x42

Chiffrement...
Message chiffré (hex) : 03 16 16 03 01 0D 1D 03 16 1D 06 03 17 0C

Déchiffrement...
Message déchiffré : ATTACK_AT_DAWN
```

### Explication du XOR

```
'A' = 0x41 = 01000001
Key = 0x42 = 01000010
XOR        = 00000011 = 0x03

// Propriété fondamentale :
A ^ K ^ K = A
```

### Application offensive

```c
// Obfuscation de strings sensibles dans un malware
// À la compilation, les strings sont chiffrées
// Au runtime, elles sont déchiffrées juste avant usage

void decrypt_string(char* str, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

int main(void) {
    // "cmd.exe" XOR 0x42 (pré-calculé)
    char cmd[] = {0x21, 0x2F, 0x26, 0x2C, 0x27, 0x3C, 0x27, 0x00};

    decrypt_string(cmd, 7, 0x42);
    // cmd contient maintenant "cmd.exe"

    system(cmd);  // Exécute

    return 0;
}
```

---

## Exercice 11 : Command Dispatcher

### Solution

```c
#include <stdio.h>
#include <stdint.h>

#define CMD_PING     0x01
#define CMD_SHELL    0x02
#define CMD_UPLOAD   0x03
#define CMD_DOWNLOAD 0x04
#define CMD_EXIT     0xFF

void handle_command(uint8_t cmd) {
    switch (cmd) {
        case CMD_PING:
            printf("PONG - Connexion active\n");
            break;

        case CMD_SHELL:
            printf("SHELL - Ouverture d'un shell interactif\n");
            break;

        case CMD_UPLOAD:
            printf("UPLOAD - Envoi de fichier vers le serveur\n");
            break;

        case CMD_DOWNLOAD:
            printf("DOWNLOAD - Téléchargement de fichier\n");
            break;

        case CMD_EXIT:
            printf("EXIT - Fermeture de la connexion\n");
            break;

        default:
            printf("UNKNOWN (0x%02X) - Commande ignorée\n", cmd);
            break;
    }
}

int main(void) {
    uint8_t commands[] = {CMD_PING, CMD_SHELL, CMD_DOWNLOAD, 0x99, CMD_EXIT};
    int num_cmds = sizeof(commands) / sizeof(commands[0]);

    printf("=== Command Dispatcher ===\n\n");

    for (int i = 0; i < num_cmds; i++) {
        printf("[%d] Commande 0x%02X : ", i, commands[i]);
        handle_command(commands[i]);
    }

    return 0;
}
```

### Sortie attendue

```
=== Command Dispatcher ===

[0] Commande 0x01 : PONG - Connexion active
[1] Commande 0x02 : SHELL - Ouverture d'un shell interactif
[2] Commande 0x04 : DOWNLOAD - Téléchargement de fichier
[3] Commande 0x99 : UNKNOWN (0x99) - Commande ignorée
[4] Commande 0xFF : EXIT - Fermeture de la connexion
```

### Application offensive

```c
// Dispatcher réaliste d'un RAT
typedef struct {
    uint8_t cmd_id;
    uint16_t data_len;
    uint8_t data[];  // Flexible array member
} Command;

int dispatch_command(Command* cmd) {
    switch (cmd->cmd_id) {
        case CMD_PING:
            return send_pong();

        case CMD_SHELL:
            return execute_shell_command((char*)cmd->data);

        case CMD_UPLOAD:
            return upload_file((char*)cmd->data);

        case CMD_DOWNLOAD:
            return download_file((char*)cmd->data);

        case CMD_SCREENSHOT:
            return capture_and_send_screenshot();

        case CMD_KEYLOG:
            return toggle_keylogger(cmd->data[0]);

        case CMD_EXIT:
            cleanup();
            return TERMINATE;

        default:
            return ERROR_UNKNOWN_CMD;
    }
}
```

---

## Exercice 12 : Port Scanner Simulé

### Solution

```c
#include <stdio.h>

int is_port_open(int port) {
    // Simule des ports ouverts
    int open_ports[] = {22, 80, 443, 3306, 8080};
    int num_open = sizeof(open_ports) / sizeof(open_ports[0]);

    for (int i = 0; i < num_open; i++) {
        if (port == open_ports[i]) {
            return 1;
        }
    }
    return 0;
}

const char* get_service(int port) {
    switch (port) {
        case 22:   return "SSH";
        case 80:   return "HTTP";
        case 443:  return "HTTPS";
        case 3306: return "MySQL";
        case 8080: return "HTTP-Proxy";
        default:   return "Unknown";
    }
}

int main(void) {
    printf("=== Port Scanner Simulé ===\n");
    printf("Scanning ports 1-100...\n\n");

    int open_count = 0;

    // 1. Scanne les ports de 1 à 100
    for (int port = 1; port <= 100; port++) {
        // 2. Affiche seulement les ports ouverts
        if (is_port_open(port)) {
            printf("[OPEN] Port %d - %s\n", port, get_service(port));
            open_count++;
        }
    }

    // 3. Compte le nombre total
    printf("\n=== Scan terminé ===\n");
    printf("Ports ouverts trouvés : %d\n", open_count);

    return 0;
}
```

### Sortie attendue

```
=== Port Scanner Simulé ===
Scanning ports 1-100...

[OPEN] Port 22 - SSH
[OPEN] Port 80 - HTTP

=== Scan terminé ===
Ports ouverts trouvés : 2
```

### Application offensive

```c
// Scanner de ports réel (simplifié)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int scan_port(const char* ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    // Configure timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    return (result == 0) ? 1 : 0;  // 1 = open, 0 = closed
}

int main(void) {
    const char* target = "192.168.1.1";

    for (int port = 1; port <= 1024; port++) {
        if (scan_port(target, port, 100)) {
            printf("[+] Port %d OPEN\n", port);
        }
    }

    return 0;
}
```

---

## Exercice 13 : State Machine

### Solution

```c
#include <stdio.h>

typedef enum {
    STATE_INIT,
    STATE_CONNECT,
    STATE_AUTH,
    STATE_READY,
    STATE_DONE
} State;

const char* state_name(State s) {
    switch (s) {
        case STATE_INIT:    return "INIT";
        case STATE_CONNECT: return "CONNECT";
        case STATE_AUTH:    return "AUTH";
        case STATE_READY:   return "READY";
        case STATE_DONE:    return "DONE";
        default:            return "UNKNOWN";
    }
}

int main(void) {
    State state = STATE_INIT;
    int step = 0;

    printf("=== State Machine ===\n\n");

    while (state != STATE_DONE) {
        printf("[Step %d] État actuel : %s\n", step++, state_name(state));

        switch (state) {
            case STATE_INIT:
                printf("  → Initialisation du système...\n");
                printf("  → Chargement de la configuration...\n");
                state = STATE_CONNECT;
                break;

            case STATE_CONNECT:
                printf("  → Tentative de connexion au serveur...\n");
                printf("  → Connexion établie!\n");
                state = STATE_AUTH;
                break;

            case STATE_AUTH:
                printf("  → Envoi des credentials...\n");
                printf("  → Authentification réussie!\n");
                state = STATE_READY;
                break;

            case STATE_READY:
                printf("  → Système prêt, exécution des tâches...\n");
                printf("  → Tâches terminées, fermeture...\n");
                state = STATE_DONE;
                break;

            default:
                printf("  → État invalide, arrêt!\n");
                state = STATE_DONE;
                break;
        }

        printf("\n");
    }

    printf("[Final] État : %s\n", state_name(state));
    printf("Machine à états terminée.\n");

    return 0;
}
```

### Sortie attendue

```
=== State Machine ===

[Step 0] État actuel : INIT
  → Initialisation du système...
  → Chargement de la configuration...

[Step 1] État actuel : CONNECT
  → Tentative de connexion au serveur...
  → Connexion établie!

[Step 2] État actuel : AUTH
  → Envoi des credentials...
  → Authentification réussie!

[Step 3] État actuel : READY
  → Système prêt, exécution des tâches...
  → Tâches terminées, fermeture...

[Final] État : DONE
Machine à états terminée.
```

### Application offensive

```c
// Machine à états d'un implant/RAT
typedef enum {
    IMPLANT_DORMANT,      // Attend le réveil
    IMPLANT_BEACON,       // Contacte le C2
    IMPLANT_EXECUTE,      // Exécute une commande
    IMPLANT_EXFILTRATE,   // Envoie des données
    IMPLANT_MIGRATE,      // Change de processus
    IMPLANT_TERMINATE     // S'auto-détruit
} ImplantState;

void run_implant(void) {
    ImplantState state = IMPLANT_DORMANT;

    while (state != IMPLANT_TERMINATE) {
        switch (state) {
            case IMPLANT_DORMANT:
                if (is_wake_time()) {
                    state = IMPLANT_BEACON;
                } else {
                    sleep_random();
                }
                break;

            case IMPLANT_BEACON:
                Command* cmd = contact_c2();
                if (cmd) {
                    current_command = cmd;
                    state = IMPLANT_EXECUTE;
                } else {
                    state = IMPLANT_DORMANT;
                }
                break;

            case IMPLANT_EXECUTE:
                Result* result = execute(current_command);
                if (result->has_data) {
                    state = IMPLANT_EXFILTRATE;
                } else {
                    state = IMPLANT_BEACON;
                }
                break;

            case IMPLANT_EXFILTRATE:
                send_to_c2(result->data);
                state = IMPLANT_BEACON;
                break;

            case IMPLANT_MIGRATE:
                if (migrate_to_process(target_pid)) {
                    state = IMPLANT_DORMANT;
                } else {
                    state = IMPLANT_TERMINATE;
                }
                break;
        }
    }

    cleanup_traces();
    exit(0);
}
```

---

## Exercice 14 : Goto pour cleanup

### Solution

```c
#include <stdio.h>
#include <stdlib.h>

int process(int simulate_failure) {
    char *buf1 = NULL;
    char *buf2 = NULL;
    int result = -1;

    printf("=== Allocation avec goto cleanup ===\n\n");

    // Étape 1 : Alloue buf1
    printf("[1] Allocation de buf1 (1024 octets)...\n");
    buf1 = malloc(1024);
    if (buf1 == NULL) {
        printf("[!] Échec allocation buf1\n");
        goto cleanup;
    }
    printf("[+] buf1 alloué à %p\n", (void*)buf1);

    // Simule une erreur si demandé
    if (simulate_failure == 1) {
        printf("[!] Simulation d'erreur après buf1\n");
        goto cleanup;
    }

    // Étape 2 : Alloue buf2
    printf("[2] Allocation de buf2 (2048 octets)...\n");
    buf2 = malloc(2048);
    if (buf2 == NULL) {
        printf("[!] Échec allocation buf2\n");
        goto cleanup;
    }
    printf("[+] buf2 alloué à %p\n", (void*)buf2);

    // Simule une erreur si demandé
    if (simulate_failure == 2) {
        printf("[!] Simulation d'erreur après buf2\n");
        goto cleanup;
    }

    // Étape 3 : Traitement (succès)
    printf("[3] Traitement en cours...\n");
    sprintf(buf1, "Données dans buf1");
    sprintf(buf2, "Données dans buf2");
    printf("[+] Traitement terminé avec succès!\n");

    // Succès
    result = 0;

cleanup:
    // Libère les ressources (dans l'ordre inverse)
    printf("\n[Cleanup]\n");

    if (buf2 != NULL) {
        printf("  → Libération de buf2\n");
        free(buf2);
    }

    if (buf1 != NULL) {
        printf("  → Libération de buf1\n");
        free(buf1);
    }

    return result;
}

int main(void) {
    int r;

    // Test 1 : Succès
    printf("========== TEST 1 : Succès ==========\n");
    r = process(0);
    printf("\nRésultat : %d (%s)\n\n", r, r == 0 ? "OK" : "ERREUR");

    // Test 2 : Échec après buf1
    printf("========== TEST 2 : Échec après buf1 ==========\n");
    r = process(1);
    printf("\nRésultat : %d (%s)\n\n", r, r == 0 ? "OK" : "ERREUR");

    // Test 3 : Échec après buf2
    printf("========== TEST 3 : Échec après buf2 ==========\n");
    r = process(2);
    printf("\nRésultat : %d (%s)\n", r, r == 0 ? "OK" : "ERREUR");

    return 0;
}
```

### Sortie attendue

```
========== TEST 1 : Succès ==========
=== Allocation avec goto cleanup ===

[1] Allocation de buf1 (1024 octets)...
[+] buf1 alloué à 0x55a1234567890
[2] Allocation de buf2 (2048 octets)...
[+] buf2 alloué à 0x55a1234567c90
[3] Traitement en cours...
[+] Traitement terminé avec succès!

[Cleanup]
  → Libération de buf2
  → Libération de buf1

Résultat : 0 (OK)

========== TEST 2 : Échec après buf1 ==========
=== Allocation avec goto cleanup ===

[1] Allocation de buf1 (1024 octets)...
[+] buf1 alloué à 0x55a1234567890
[!] Simulation d'erreur après buf1

[Cleanup]
  → Libération de buf1

Résultat : -1 (ERREUR)

========== TEST 3 : Échec après buf2 ==========
=== Allocation avec goto cleanup ===

[1] Allocation de buf1 (1024 octets)...
[+] buf1 alloué à 0x55a1234567890
[2] Allocation de buf2 (2048 octets)...
[+] buf2 alloué à 0x55a1234567c90
[!] Simulation d'erreur après buf2

[Cleanup]
  → Libération de buf2
  → Libération de buf1

Résultat : -1 (ERREUR)
```

### Pourquoi goto pour le cleanup ?

1. **Un seul point de sortie** : Le cleanup est toujours exécuté
2. **Pas de duplication** : Le code de libération n'est écrit qu'une fois
3. **Pattern standard** : Utilisé dans le kernel Linux et beaucoup de projets C
4. **Évite les fuites mémoire** : Chaque ressource est libérée même en cas d'erreur

### Application offensive

```c
// Pattern réel utilisé dans un exploit
int exploit_target(const char* target_ip) {
    int sock = -1;
    char* payload = NULL;
    char* shellcode = NULL;
    int result = -1;

    // Créer le socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        goto cleanup;
    }

    // Allouer le payload
    payload = malloc(PAYLOAD_SIZE);
    if (!payload) {
        perror("malloc payload");
        goto cleanup;
    }

    // Générer le shellcode
    shellcode = generate_shellcode(callback_ip, callback_port);
    if (!shellcode) {
        fprintf(stderr, "shellcode generation failed\n");
        goto cleanup;
    }

    // Connecter
    if (connect_to_target(sock, target_ip) < 0) {
        goto cleanup;
    }

    // Construire et envoyer l'exploit
    build_payload(payload, shellcode);
    if (send(sock, payload, PAYLOAD_SIZE, 0) < 0) {
        goto cleanup;
    }

    result = 0;  // Succès

cleanup:
    // Toujours nettoyer, même en cas d'erreur
    if (shellcode) {
        memset(shellcode, 0, SHELLCODE_SIZE);  // Efface les traces
        free(shellcode);
    }
    if (payload) {
        memset(payload, 0, PAYLOAD_SIZE);
        free(payload);
    }
    if (sock >= 0) {
        close(sock);
    }

    return result;
}
```

---

## Points clés du module

### 1. Vrai/Faux en C
- `0` = FAUX
- Tout autre valeur = VRAI (y compris -1, -100, etc.)

### 2. if/else if/else
- Tester les cas invalides en premier
- Ordre du plus restrictif au moins restrictif
- `else` capture tout le reste

### 3. switch
- Uniquement pour types entiers (int, char, enum)
- Toujours mettre `break` sauf fall-through intentionnel
- Toujours avoir un `default`

### 4. Boucles
```c
for (init; cond; step)  // Quand on connaît le nombre d'itérations
while (cond)            // Quand la condition peut être fausse dès le départ
do { } while (cond)     // Quand on veut au moins une exécution
```

### 5. break vs continue
- `break` : Sort de la boucle complètement
- `continue` : Passe à l'itération suivante

### 6. goto
- Acceptable pour le cleanup / gestion d'erreurs
- Un seul label `cleanup:` à la fin
- Évite la duplication de code de libération

---

## Checklist finale

- [ ] Je comprends que seul 0 est FAUX en C
- [ ] Je sais utiliser if/else if/else correctement
- [ ] Je sais utiliser switch avec break et default
- [ ] Je comprends le fall-through et quand l'utiliser
- [ ] Je maîtrise les 3 types de boucles (for, while, do-while)
- [ ] Je sais utiliser break et continue
- [ ] Je comprends le pattern goto cleanup
- [ ] Je peux implémenter un XOR cipher
- [ ] Je peux créer un command dispatcher
- [ ] Je peux implémenter une state machine

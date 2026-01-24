# Exercices - Module 07 : Tableaux (Arrays)

## Exercice 1 : Déclaration et parcours (Très facile)

**Objectif** : Maîtriser la déclaration et l'accès aux éléments.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // TODO:
    // 1. Crée un tableau de 5 ports : 22, 80, 443, 3306, 8080
    // 2. Affiche chaque port avec son index
    // 3. Modifie le port à l'index 2 (remplace 443 par 8443)
    // 4. Affiche le tableau modifié

    return 0;
}
```

### Sortie attendue

```
Port[0] = 22
Port[1] = 80
Port[2] = 443
Port[3] = 3306
Port[4] = 8080

Après modification:
Port[2] = 8443
```

---

## Exercice 2 : Calcul de taille avec sizeof (Facile)

**Objectif** : Utiliser sizeof pour obtenir le nombre d'éléments.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int data[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};

    // TODO:
    // 1. Calcule la taille totale en bytes
    // 2. Calcule la taille d'un élément
    // 3. Calcule le nombre d'éléments
    // 4. Parcours le tableau avec une boucle for en utilisant le calcul de taille

    return 0;
}
```

---

## Exercice 3 : Somme, moyenne, min et max (Facile)

**Objectif** : Effectuer des opérations statistiques sur un tableau.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int response_times[] = {45, 120, 32, 89, 156, 23, 67, 234, 12, 78};
    int size = sizeof(response_times) / sizeof(response_times[0]);

    // TODO:
    // 1. Calcule la somme de tous les temps de réponse
    // 2. Calcule la moyenne
    // 3. Trouve le temps minimum
    // 4. Trouve le temps maximum
    // 5. Affiche les statistiques

    return 0;
}
```

---

## Exercice 4 : Recherche linéaire (Facile)

**Objectif** : Implémenter une recherche dans un tableau.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int open_ports[] = {21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080};
    int size = sizeof(open_ports) / sizeof(open_ports[0]);

    // Ports à chercher
    int targets[] = {22, 445, 3389, 8888};
    int num_targets = sizeof(targets) / sizeof(targets[0]);

    // TODO:
    // Pour chaque port cible:
    // 1. Cherche s'il existe dans open_ports
    // 2. Si trouvé, affiche "[+] Port XXX OPEN (index: Y)"
    // 3. Si non trouvé, affiche "[-] Port XXX CLOSED"

    return 0;
}
```

---

## Exercice 5 : Copie et inversion (Facile)

**Objectif** : Manipuler les tableaux (copie, inversion).

### Instructions

```c
#include <stdio.h>

int main(void) {
    int original[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int size = 10;
    int copy[10];
    int reversed[10];

    // TODO:
    // 1. Copie original dans copy (avec boucle)
    // 2. Copie original dans reversed mais en inversant l'ordre
    // 3. Affiche les trois tableaux

    return 0;
}
```

---

## Exercice 6 : Tableau 2D - Matrice (Moyen)

**Objectif** : Manipuler des tableaux bidimensionnels.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // Matrice représentant un scan réseau (0 = down, 1 = up)
    int network[4][4] = {
        {1, 0, 1, 1},
        {0, 0, 1, 0},
        {1, 1, 1, 0},
        {0, 1, 0, 1}
    };

    // TODO:
    // 1. Affiche la matrice comme une grille
    // 2. Compte le nombre d'hôtes UP (valeur 1)
    // 3. Pour chaque hôte UP, affiche ses coordonnées (ligne, colonne)
    // 4. Calcule le pourcentage d'hôtes UP

    return 0;
}
```

---

## Exercice 7 : Shellcode storage (Moyen)

**Objectif** : Manipuler des tableaux de bytes pour le shellcode.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // Shellcode simulé (NOP sled + instructions)
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0x31, 0xC0,              // xor eax, eax
        0x50,                    // push eax
        0x68, 0x2F, 0x2F, 0x73, 0x68,  // push "//sh"
        0x68, 0x2F, 0x62, 0x69, 0x6E,  // push "/bin"
        0x89, 0xE3,              // mov ebx, esp
        0x50,                    // push eax
        0x53,                    // push ebx
        0x89, 0xE1,              // mov ecx, esp
        0xB0, 0x0B,              // mov al, 11
        0xCD, 0x80               // int 0x80
    };

    // TODO:
    // 1. Calcule et affiche la taille du shellcode
    // 2. Affiche le shellcode en format hexadécimal (style \x90\x90...)
    // 3. Compte le nombre de NOP (0x90)
    // 4. Trouve et affiche la position de l'instruction syscall (0xCD, 0x80)

    return 0;
}
```

---

## Exercice 8 : XOR encoder (Moyen)

**Objectif** : Encoder un payload avec XOR.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char payload[] = "ATTACK_NOW";
    int size = strlen((char*)payload);
    unsigned char key = 0x42;

    // TODO:
    // 1. Affiche le payload original en ASCII et en HEX
    // 2. Encode chaque byte avec XOR key
    // 3. Affiche le payload encodé en HEX
    // 4. Décode le payload (XOR à nouveau)
    // 5. Vérifie que le payload décodé = original

    return 0;
}
```

---

## Exercice 9 : Rolling XOR avec tableau de clés (Moyen)

**Objectif** : Implémenter un XOR avec plusieurs clés.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char payload[] = "PAYLOAD_DATA_TO_HIDE";
    int payload_size = strlen((char*)payload);

    unsigned char keys[] = {0xDE, 0xAD, 0xBE, 0xEF};
    int key_size = sizeof(keys);

    // TODO:
    // 1. Affiche le payload original
    // 2. Encode avec rolling XOR:
    //    payload[i] ^= keys[i % key_size]
    // 3. Affiche le payload encodé en HEX
    // 4. Décode et vérifie

    return 0;
}
```

---

## Exercice 10 : Recherche de signature (Challenge)

**Objectif** : Chercher un pattern de bytes dans un buffer.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // Simule une zone mémoire
    unsigned char memory[] = {
        0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0xCC, 0x31,
        0xC0, 0x00, 0x00, 0xCC, 0x31, 0xC0, 0x50, 0x90,
        0x00, 0x00, 0x00, 0xCC, 0x31, 0xC0, 0x89, 0xE3,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    int mem_size = sizeof(memory);

    // Signature à chercher : CC 31 C0 (int3 + xor eax, eax)
    unsigned char signature[] = {0xCC, 0x31, 0xC0};
    int sig_size = sizeof(signature);

    // TODO:
    // 1. Cherche TOUTES les occurrences de la signature
    // 2. Pour chaque occurrence, affiche l'offset
    // 3. Affiche le nombre total d'occurrences

    return 0;
}
```

---

## Exercice 11 : Buffer overflow simulation (Challenge)

**Objectif** : Comprendre le dépassement de buffer.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Simule une stack
    int canary = 0xDEADBEEF;          // Protection
    char buffer[16];                   // Buffer vulnérable
    int secret_flag = 0;              // Flag à modifier
    unsigned long return_addr = 0x00401234;  // Adresse de retour simulée

    printf("[*] État initial:\n");
    printf("    canary      = 0x%X\n", canary);
    printf("    buffer      = '%s'\n", buffer);
    printf("    secret_flag = %d\n", secret_flag);
    printf("    return_addr = 0x%lX\n\n", return_addr);

    // TODO:
    // 1. Affiche les adresses de chaque variable
    // 2. Affiche la distance entre buffer et les autres variables
    // 3. Simule un overflow en écrivant 24 bytes dans buffer
    // 4. Montre comment les autres variables sont écrasées

    // Note: En vrai, ceci causerait un crash ou comportement indéfini
    // Cet exercice est pédagogique pour comprendre le concept

    return 0;
}
```

---

## Exercice 12 : Port scanner results (Challenge)

**Objectif** : Stocker et analyser les résultats d'un scan.

### Instructions

```c
#include <stdio.h>

// Structure pour un port
typedef struct {
    int port;
    int is_open;
    const char *service;
} PortResult;

int main(void) {
    // Résultats d'un scan
    PortResult results[] = {
        {21, 1, "FTP"},
        {22, 1, "SSH"},
        {23, 0, "Telnet"},
        {25, 1, "SMTP"},
        {80, 1, "HTTP"},
        {110, 0, "POP3"},
        {143, 0, "IMAP"},
        {443, 1, "HTTPS"},
        {445, 0, "SMB"},
        {3306, 1, "MySQL"},
        {3389, 0, "RDP"},
        {5432, 1, "PostgreSQL"},
        {8080, 1, "HTTP-Proxy"}
    };
    int num_ports = sizeof(results) / sizeof(results[0]);

    // TODO:
    // 1. Affiche un rapport de scan formaté
    // 2. Compte les ports ouverts vs fermés
    // 3. Liste uniquement les ports ouverts avec leur service
    // 4. Identifie les services "critiques" (SSH, MySQL, etc.)

    return 0;
}
```

---

## Exercice 13 : IP subnet scanner simulation (Challenge)

**Objectif** : Simuler un scan de sous-réseau avec tableau 2D.

### Instructions

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // Résultats de scan pour 192.168.1.0/24
    // scan[x] représente l'hôte 192.168.1.x
    // Valeur: 0=down, 1=up

    int scan_results[256] = {0};  // Tous à 0 par défaut

    // Simule quelques hôtes UP
    int live_hosts[] = {1, 10, 50, 100, 150, 200, 254};
    int num_live = sizeof(live_hosts) / sizeof(live_hosts[0]);

    // TODO:
    // 1. Marque les hôtes live_hosts comme UP (valeur 1)
    // 2. Affiche tous les hôtes UP avec leur IP complète
    // 3. Calcule le pourcentage d'hôtes UP
    // 4. BONUS: Groupe les hôtes par plage (/25, /26, etc.)

    return 0;
}
```

---

## Exercice 14 : Tableau de commandes C2 (Challenge)

**Objectif** : Gérer une liste de commandes avec tableaux.

### Instructions

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    int id;
    const char *command;
    int executed;
    int result;  // 0=pending, 1=success, -1=failed
} C2Command;

int main(void) {
    C2Command queue[] = {
        {1, "whoami", 0, 0},
        {2, "hostname", 0, 0},
        {3, "ipconfig /all", 0, 0},
        {4, "dir C:\\Users", 0, 0},
        {5, "net user", 0, 0}
    };
    int queue_size = sizeof(queue) / sizeof(queue[0]);

    // TODO:
    // 1. Affiche la queue de commandes (statut: pending)
    // 2. Simule l'exécution de chaque commande:
    //    - Marque executed = 1
    //    - Simule un résultat (1 ou -1 aléatoirement)
    // 3. Affiche le rapport d'exécution
    // 4. Compte succès vs échecs

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Déclarer et initialiser un tableau
- [ ] Accéder aux éléments par index
- [ ] Calculer la taille avec sizeof
- [ ] Parcourir un tableau avec une boucle
- [ ] Copier un tableau (boucle ou memcpy)
- [ ] Utiliser des tableaux 2D (matrices)
- [ ] Stocker et manipuler du shellcode
- [ ] Encoder avec XOR (simple et rolling)
- [ ] Chercher une signature dans un buffer
- [ ] Comprendre les dépassements de buffer

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.

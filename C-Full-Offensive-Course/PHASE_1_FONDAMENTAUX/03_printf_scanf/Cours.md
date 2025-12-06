# 03 - Printf et Scanf

## 🎯 Ce que tu vas apprendre

- Comment printf() fonctionne en interne
- Les format specifiers et leur fonctionnement
- Comment lire des données avec scanf()
- Les dangers de scanf() (buffer overflow)
- Les alternatives sécurisées (fgets)
- Format string vulnerabilities

## 📚 Théorie

### Concept 1 : Comment fonctionne printf() ?

**C'est quoi ?**
`printf()` (print formatted) est une fonction qui affiche du texte formaté dans le terminal (stdout).

**Pourquoi ça existe ?**
Pour communiquer avec l'utilisateur et afficher des informations pendant l'exécution du programme.

**Comment ça marche ?**

Quand tu écris :
```c
printf("Age: %d\n", 25);
```

Voici ce qui se passe :

```
1. PARSING de la format string
   printf parcourt "Age: %d\n" caractère par caractère

2. IDENTIFICATION des specifiers
   'A', 'g', 'e', ':', ' ' → Affiche tel quel
   '%d' → Specifier détecté : attend un int
   '\n' → Caractère spécial : retour à la ligne

3. RÉCUPÉRATION des arguments
   Regarde le 2ème paramètre : 25 (int)

4. CONVERSION et AFFICHAGE
   Convertit 25 en chaîne "25"
   Affiche : "Age: 25\n"
```

**Schéma du processus** :
```
printf("Port: %d", 4444);
         ↓
┌────────────────────────────┐
│ 1. Parse format string     │
│    "Port: %d"              │
├────────────────────────────┤
│ 2. Trouve %d               │
│    → Attend un int         │
├────────────────────────────┤
│ 3. Récupère argument       │
│    → 4444                  │
├────────────────────────────┤
│ 4. Convertit int→string    │
│    4444 → "4444"           │
├────────────────────────────┤
│ 5. Affiche                 │
│    "Port: 4444"            │
└────────────────────────────┘
```

### Concept 2 : Les format specifiers

**C'est quoi ?**
Un format specifier est un code qui commence par `%` et indique à printf() quel type de donnée afficher et comment.

**Pourquoi ça existe ?**
Parce qu'en mémoire, tout est des bytes. Printf() doit savoir comment interpréter ces bytes : nombre ? caractère ? adresse ?

**Comment ça marche ?**

#### Specifiers de base

| Specifier | Type | Description | Exemple |
|-----------|------|-------------|---------|
| `%d` ou `%i` | int | Entier signé (décimal) | `printf("%d", 42);` → `42` |
| `%u` | unsigned int | Entier non signé | `printf("%u", 4294967295);` → `4294967295` |
| `%x` | int | Hexadécimal (minuscules) | `printf("%x", 255);` → `ff` |
| `%X` | int | Hexadécimal (majuscules) | `printf("%X", 255);` → `FF` |
| `%o` | int | Octal | `printf("%o", 8);` → `10` |
| `%f` | float/double | Décimal flottant | `printf("%f", 3.14);` → `3.140000` |
| `%c` | char | Caractère unique | `printf("%c", 65);` → `A` |
| `%s` | char* | Chaîne de caractères | `printf("%s", "hello");` → `hello` |
| `%p` | void* | Adresse mémoire (pointeur) | `printf("%p", &var);` → `0x7fff...` |
| `%%` | - | Caractère % littéral | `printf("100%%");` → `100%` |

**Exemple avec le même nombre affiché différemment** :
```c
int num = 65;
printf("Décimal: %d\n", num);    // 65
printf("Hexa:    %x\n", num);    // 41
printf("Octal:   %o\n", num);    // 101
printf("Char:    %c\n", num);    // A
```

Output :
```
Décimal: 65
Hexa:    41
Octal:   101
Char:    A
```

**Pourquoi le même nombre donne des résultats différents ?**

En mémoire : `65` = `0x41` = `01000001` (binaire)

```
%d → Interprète comme entier décimal    → 65
%x → Interprète comme hexa              → 41
%o → Interprète comme octal             → 101
%c → Interprète comme code ASCII        → 'A'
```

### Concept 3 : Les modificateurs de format

**C'est quoi ?**
Des options qu'on ajoute entre `%` et la lettre du specifier pour contrôler l'affichage (largeur, padding, précision).

#### Largeur minimale

```c
printf("%5d", 42);      // "   42" (5 caractères, rempli avec espaces)
printf("%-5d", 42);     // "42   " (aligné à gauche)
printf("%05d", 42);     // "00042" (rempli avec des zéros)
```

**Schéma** :
```
%5d avec valeur 42 :
┌───┬───┬───┬───┬───┐
│   │   │   │ 4 │ 2 │  Largeur 5, aligné à droite
└───┴───┴───┴───┴───┘

%-5d avec valeur 42 :
┌───┬───┬───┬───┬───┐
│ 4 │ 2 │   │   │   │  Largeur 5, aligné à gauche
└───┴───┴───┴───┴───┘

%05d avec valeur 42 :
┌───┬───┬───┬───┬───┐
│ 0 │ 0 │ 0 │ 4 │ 2 │  Largeur 5, padding avec 0
└───┴───┴───┴───┴───┘
```

#### Précision pour les flottants

```c
printf("%.2f", 3.14159);   // "3.14" (2 décimales)
printf("%.4f", 3.14159);   // "3.1416" (4 décimales, arrondi)
printf("%10.2f", 3.14);    // "      3.14" (largeur 10, 2 décimales)
```

**Exemple concret** :
```c
float price = 19.99f;
printf("Prix: %6.2f EUR\n", price);  // "Prix:  19.99 EUR"
//             ↑   ↑
//          largeur 6
//              précision 2
```

### Concept 4 : Comment fonctionne scanf() ?

**C'est quoi ?**
`scanf()` (scan formatted) est une fonction qui lit des données formatées depuis le clavier (stdin) et les stocke dans des variables.

**Pourquoi ça existe ?**
Pour permettre à l'utilisateur d'interagir avec le programme en entrant des données.

**Comment ça marche ?**

```c
int age;
scanf("%d", &age);
```

Processus :
```
1. ATTENTE d'input utilisateur
   Programme bloqué, attend la saisie

2. LECTURE de stdin
   Utilisateur tape "25" puis Enter

3. PARSING selon format string
   "%d" → Attend un nombre décimal

4. CONVERSION
   Chaîne "25" → Entier 25

5. STOCKAGE à l'adresse fournie
   Écrit 25 à l'adresse de age (&age)
```

**Attention CRITIQUE : Le & est OBLIGATOIRE**

```c
int x;
scanf("%d", &x);   // CORRECT : passe l'adresse de x
scanf("%d", x);    // ERREUR : passe la valeur de x (non initialisée)
```

**Pourquoi & ?**

Scanf() a besoin de savoir OÙ écrire la valeur. Sans &, tu lui donnes la valeur au lieu de l'adresse.

```
Avec & (CORRECT) :
┌──────────────┐
│ Variable: x  │
│ Adresse: 0x1000 │
│ Valeur: ?    │
└──────────────┘
scanf("%d", &x);  → Donne 0x1000 à scanf
                  → scanf écrit à 0x1000
                  → x = 25

Sans & (ERREUR) :
scanf("%d", x);   → Donne la valeur de x (garbage)
                  → scanf essaie d'écrire à une adresse random
                  → CRASH (Segmentation fault)
```

### Concept 5 : Exemples d'utilisation de scanf()

#### Lire un entier

```c
int age;
printf("Ton age: ");
scanf("%d", &age);
printf("Tu as %d ans\n", age);
```

#### Lire plusieurs valeurs

```c
int x, y;
printf("Entre deux nombres: ");
scanf("%d %d", &x, &y);  // Input: "10 20"
printf("x=%d, y=%d\n", x, y);
```

#### Lire un caractère

```c
char grade;
printf("Ta note: ");
scanf(" %c", &grade);  // Note l'espace avant %c pour ignorer whitespace
printf("Note: %c\n", grade);
```

#### Lire un float

```c
float price;
printf("Prix: ");
scanf("%f", &price);
printf("Prix: %.2f EUR\n", price);
```

### Concept 6 : Les dangers de scanf()

**C'est quoi le problème ?**

`scanf()` ne vérifie PAS la taille du buffer. Si l'utilisateur entre plus de données que prévu, **buffer overflow** garanti.

**Exemple VULNÉRABLE** :

```c
char name[10];  // Buffer de 10 bytes
scanf("%s", name);  // PAS de limite !

// Utilisateur entre "ThisIsAVeryLongName"
// → Écrit 19 bytes dans un buffer de 10
// → OVERFLOW : écrase la mémoire adjacente
```

**Schéma de l'overflow** :
```
Buffer name[10] en mémoire :
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│   │   │   │   │   │   │   │   │   │   │  10 bytes alloués
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
                                          ↓ Autres variables

Input : "ThisIsAVeryLongName" (19 bytes)
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ T │ h │ i │ s │ I │ s │ A │ V │ e │ r │ y │ L │ o │ n │ g │ N │ a │ m │ e │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
                                          ↑ DÉBORDEMENT ↑
                                    Écrase d'autres variables !
```

**Conséquences** :
- Crash du programme (segfault)
- Corruption de données
- Exploitation possible (injection de code)

### Concept 7 : Sécuriser les lectures avec fgets()

**C'est quoi ?**
`fgets()` lit une ligne complète en limitant la taille, évitant ainsi les overflows.

**Syntaxe** :
```c
fgets(buffer, taille_max, stdin);
```

**Exemple SÉCURISÉ** :

```c
char name[50];
printf("Ton nom: ");
fgets(name, sizeof(name), stdin);  // Limite à 50 bytes
printf("Bonjour %s", name);
```

**Pourquoi c'est mieux ?**

```
scanf("%s", name) :
❌ Pas de limite → overflow possible
❌ S'arrête aux espaces
❌ Dangereux

fgets(name, 50, stdin) :
✓ Limite stricte de 50 bytes
✓ Lit toute la ligne (avec espaces)
✓ Sécurisé
```

**Petit problème de fgets() : le \n**

fgets() garde le `\n` final. Pour l'enlever :

```c
char input[50];
fgets(input, sizeof(input), stdin);

// Enlever le \n
input[strcspn(input, "\n")] = '\0';
```

**Comment ça marche ?**

```
Input utilisateur: "Alice\n"

Avant nettoyage :
┌───┬───┬───┬───┬───┬───┬───┐
│ A │ l │ i │ c │ e │\n │\0 │
└───┴───┴───┴───┴───┴───┴───┘

strcspn(input, "\n") → retourne 5 (position de \n)
input[5] = '\0';

Après nettoyage :
┌───┬───┬───┬───┬───┬───┬───┐
│ A │ l │ i │ c │ e │\0 │\0 │
└───┴───┴───┴───┴───┴───┴───┘
```

### Concept 8 : Différence scanf() vs fgets()

| Critère | scanf("%s", ...) | fgets() |
|---------|------------------|---------|
| Limite de taille | ❌ Non | ✓ Oui |
| Lit les espaces | ❌ Non (s'arrête) | ✓ Oui |
| Sécurité | ❌ Dangereux | ✓ Sûr |
| Garde le \n | ❌ Non | ✓ Oui (à nettoyer) |
| Usage | Éviter | Recommandé |

## 🔍 Visualisation : printf() avec plusieurs arguments

```c
printf("User: %s, Age: %d, Balance: %.2f EUR\n", "Alice", 25, 1234.56);
```

**Processus interne** :
```
1. Parse format string:
   "User: " → Affiche tel quel
   "%s"     → Lit arg 1 : "Alice"
   ", Age: "→ Affiche tel quel
   "%d"     → Lit arg 2 : 25
   ", Balance: " → Affiche tel quel
   "%.2f"   → Lit arg 3 : 1234.56
   " EUR\n" → Affiche tel quel

2. Résultat:
   "User: Alice, Age: 25, Balance: 1234.56 EUR\n"
```

**En mémoire (stack)** :
```
Stack lors de l'appel printf() :
┌─────────────────────┐
│ 1234.56 (double)    │ ← arg 3
├─────────────────────┤
│ 25 (int)            │ ← arg 2
├─────────────────────┤
│ "Alice" (char*)     │ ← arg 1
├─────────────────────┤
│ "User: %s..." (char*) │ ← format string
└─────────────────────┘
printf() lit les arguments dans l'ordre
```

## 🎯 Application Red Team

### 1. Format String Vulnerability

**Le problème** :

```c
// CODE VULNÉRABLE
char user_input[100];
gets(user_input);            // Dangereux : buffer overflow
printf(user_input);          // TRÈS DANGEREUX : format string attack
```

**Pourquoi c'est dangereux ?**

Si l'utilisateur entre `"%p %p %p %p"`, printf() va lire la stack et afficher des adresses mémoire.

```c
// CODE VULNÉRABLE
printf(user_input);  // user_input = "%p %p %p %p"

// Output : 0x7fff0001 0x7fff0020 0x12345678 0xdeadbeef
// → LEAK de la stack !
// → Peut révéler des adresses ASLR, return addresses, etc.
```

**CODE SÉCURISÉ** :

```c
printf("%s", user_input);  // Toujours utiliser %s pour afficher input
```

### 2. Buffer Overflow via scanf()

**Exploit classique** :

```c
// Vulnérable
char password[8];
scanf("%s", password);  // Pas de limite

// Attaquant entre : "AAAAAAAAAAAAAAAA\x78\x56\x34\x12"
// → Overflow password
// → Écrase la return address sur la stack
// → Contrôle du flux d'exécution
```

**Schéma de l'attaque** :
```
Stack avant scanf() :
┌──────────────────┐
│ Return address   │ ← 0x00400567
├──────────────────┤
│ password[8]      │ ← Buffer vulnérable
└──────────────────┘

Input malveillant : "AAAAAAAAAAAAAAAA\x78\x56\x34\x12"

Stack après scanf() :
┌──────────────────┐
│ 0x12345678       │ ← Return address écrasée !
├──────────────────┤
│ AAAAAAAAAAAAAAAA │ ← Buffer overflow
└──────────────────┘

Quand la fonction retourne → saute à 0x12345678
→ Contrôle du flux d'exécution
```

### 3. Leak d'adresses mémoire

**Exploitation de format string** :

```c
// Vulnérable
void vuln() {
    char buf[100];
    fgets(buf, 100, stdin);
    printf(buf);  // Pas de %s !
}

// Attaque :
// Input: "%p %p %p %p %p %p"
// Output: 0x7fff0001 0x7fff0020 0x555555554000 ...
//                                 ↑ Adresse du code (leak ASLR)
```

### 4. Defensive Coding - Pattern sécurisé

**Pattern recommandé pour lire un input** :

```c
#define MAX_INPUT 256

char input[MAX_INPUT];

// Méthode 1 : fgets() sécurisé
if (fgets(input, sizeof(input), stdin) != NULL) {
    input[strcspn(input, "\n")] = '\0';  // Enlève \n
    printf("Input: %s\n", input);         // Affichage sécurisé
} else {
    fprintf(stderr, "Erreur de lecture\n");
}

// Méthode 2 : scanf() avec limite (moins recommandé)
scanf("%255s", input);  // Limite à 255 chars (+ \0)
```

### 5. Format string pour fuzzing

En Red Team, on peut exploiter les format strings pour :

```c
// Leak de la stack
"%p %p %p %p %p %p"

// Lire à une adresse arbitraire
"%s" (si un pointeur est sur la stack)

// Écrire en mémoire (avancé)
"%n" (écrit le nombre de bytes écrits jusqu'ici)
```

### 6. Obfuscation de strings

Pour éviter la détection :

```c
// Au lieu de :
printf("Connecting to C2 server...");

// Encoder la string :
unsigned char msg[] = {0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, ...};
for (int i = 0; i < sizeof(msg); i++) {
    msg[i] ^= 0xAA;  // Décode avec XOR
}
printf("%s", msg);
```

## 📝 Points clés à retenir

- `printf()` parse la format string et affiche selon les specifiers
- Les specifiers : `%d` (int), `%s` (string), `%p` (pointeur), `%x` (hexa)
- `scanf()` lit depuis stdin et stocke dans des variables
- Le `&` est OBLIGATOIRE avec scanf() (sauf pour les strings)
- `scanf("%s", ...)` est DANGEREUX : buffer overflow possible
- Utiliser `fgets()` à la place de `scanf()` pour les strings
- Ne JAMAIS faire `printf(user_input)` : format string vulnerability
- Toujours faire `printf("%s", user_input)`
- Les format string vulns peuvent leak la mémoire et contrôler le flux

## ➡️ Prochaine étape

Maintenant que tu sais afficher et lire des données, tu vas apprendre à les manipuler avec les [opérateurs](../04_operateurs/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)

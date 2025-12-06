# 04 - Opérateurs

## 🎯 Ce que tu vas apprendre

- Ce qu'est un opérateur et pourquoi il existe
- Les opérateurs arithmétiques et leur fonctionnement
- Les opérateurs de comparaison et logiques
- La priorité des opérateurs
- Les pièges courants (= vs ==, division entière, etc.)
- Applications en Red Team

## 📚 Théorie

### Concept 1 : C'est quoi un opérateur ?

**C'est quoi ?**
Un opérateur est un symbole qui dit au compilateur d'effectuer une opération mathématique, logique ou de manipulation de données.

**Pourquoi ça existe ?**
Pour transformer et comparer des données. Sans opérateurs, tu ne pourrais ni calculer, ni comparer, ni prendre de décisions.

**Comment ça marche ?**
```c
int result = 5 + 3;
//           ↑ ↑ ↑
//           │ │ └─ Opérande (donnée)
//           │ └─── Opérateur
//           └───── Opérande (donnée)
```

### Concept 2 : Opérateurs arithmétiques

**C'est quoi ?**
Les opérateurs qui font des calculs mathématiques de base.

| Opérateur | Nom | Exemple | Résultat |
|-----------|-----|---------|----------|
| `+` | Addition | `5 + 3` | `8` |
| `-` | Soustraction | `5 - 3` | `2` |
| `*` | Multiplication | `5 * 3` | `15` |
| `/` | Division | `5 / 2` | `2` (division entière !) |
| `%` | Modulo (reste) | `5 % 2` | `1` |
| `++` | Incrémentation | `x++` | `x = x + 1` |
| `--` | Décrémentation | `x--` | `x = x - 1` |

#### Division entière vs flottante

**C'est quoi le piège ?**

En C, si tu divises deux entiers, le résultat est un entier (la partie décimale est tronquée).

```c
int a = 5 / 2;       // a = 2 (pas 2.5 !)
float b = 5 / 2;     // b = 2.0 (toujours entier car 5 et 2 sont int)
float c = 5.0 / 2;   // c = 2.5 (au moins un float)
float d = 5 / 2.0;   // d = 2.5
float e = (float)5 / 2; // e = 2.5 (cast explicite)
```

**Schéma** :
```
Division entière (int / int) :
5 / 2 → Résultat brut : 2.5
        Tronque la partie décimale : 2
        Retourne : 2

Division flottante (float / int ou int / float) :
5.0 / 2 → Convertit 2 en 2.0
        → Calcule 5.0 / 2.0
        → Retourne : 2.5
```

#### Modulo (%)

**C'est quoi ?**
Le modulo retourne le RESTE d'une division entière.

```c
10 % 3 = 1   // 10 ÷ 3 = 3 reste 1
17 % 5 = 2   // 17 ÷ 5 = 3 reste 2
8 % 2 = 0    // 8 ÷ 2 = 4 reste 0 (pair)
9 % 2 = 1    // 9 ÷ 2 = 4 reste 1 (impair)
```

**Applications** :
```c
// Vérifier si un nombre est pair
if (x % 2 == 0) {
    printf("%d est pair\n", x);
}

// Cycler dans un intervalle (0 à 9)
int index = (index + 1) % 10;

// Extraire le dernier chiffre
int last_digit = number % 10;
```

#### Incrémentation et décrémentation

**C'est quoi la différence entre `x++` et `++x` ?**

```c
// Pré-incrémentation : incrémente PUIS retourne
int x = 5;
int y = ++x;  // x devient 6, puis y = 6
// Résultat : x=6, y=6

// Post-incrémentation : retourne PUIS incrémente
int x = 5;
int y = x++;  // y = 5, puis x devient 6
// Résultat : x=6, y=5
```

**Schéma** :
```
Pré-incrémentation (++x) :
1. x = x + 1
2. Retourner x

x = 5 → ++x → x devient 6 → retourne 6

Post-incrémentation (x++) :
1. Sauvegarder la valeur de x
2. x = x + 1
3. Retourner la valeur sauvegardée

x = 5 → x++ → sauve 5 → x devient 6 → retourne 5
```

### Concept 3 : Opérateurs d'affectation

**C'est quoi ?**
Des raccourcis pour modifier une variable en utilisant sa propre valeur.

| Opérateur | Équivalent | Exemple |
|-----------|------------|---------|
| `=` | Affectation simple | `x = 5` |
| `+=` | `x = x + ...` | `x += 3` → `x = x + 3` |
| `-=` | `x = x - ...` | `x -= 2` → `x = x - 2` |
| `*=` | `x = x * ...` | `x *= 4` → `x = x * 4` |
| `/=` | `x = x / ...` | `x /= 2` → `x = x / 2` |
| `%=` | `x = x % ...` | `x %= 3` → `x = x % 3` |

**Exemple concret** :
```c
int score = 100;
score += 50;   // score = 150
score *= 2;    // score = 300
score /= 3;    // score = 100
score %= 30;   // score = 10
```

### Concept 4 : Opérateurs de comparaison

**C'est quoi ?**
Opérateurs qui comparent deux valeurs et retournent 1 (vrai) ou 0 (faux).

| Opérateur | Signification | Exemple | Résultat |
|-----------|---------------|---------|----------|
| `==` | Égal à | `5 == 5` | `1` (vrai) |
| `!=` | Différent de | `5 != 3` | `1` (vrai) |
| `>` | Supérieur à | `5 > 3` | `1` (vrai) |
| `<` | Inférieur à | `5 < 3` | `0` (faux) |
| `>=` | Supérieur ou égal | `5 >= 5` | `1` (vrai) |
| `<=` | Inférieur ou égal | `3 <= 5` | `1` (vrai) |

**PIÈGE FRÉQUENT : = vs ==**

```c
int x = 5;

// ERREUR FRÉQUENTE (affectation au lieu de comparaison)
if (x = 10) {  // ❌ Affecte 10 à x, toujours vrai
    printf("Exécuté\n");
}

// CORRECT (comparaison)
if (x == 10) {  // ✓ Compare x avec 10
    printf("x vaut 10\n");
}
```

**Astuce pour éviter l'erreur (style Yoda)** :
```c
if (10 == x) {  // Si tu fais "if (10 = x)", erreur de compilation
    // ...
}
```

### Concept 5 : Opérateurs logiques

**C'est quoi ?**
Opérateurs pour combiner plusieurs conditions.

| Opérateur | Nom | Description | Exemple |
|-----------|-----|-------------|---------|
| `&&` | AND (ET) | Vrai si TOUTES les conditions sont vraies | `(x > 0) && (x < 10)` |
| `\|\|` | OR (OU) | Vrai si AU MOINS UNE condition est vraie | `(x == 0) \|\| (x == 1)` |
| `!` | NOT (NON) | Inverse la condition | `!(x > 10)` |

**Tables de vérité** :

```
AND (&&) :
A    B    A && B
0    0      0
0    1      0
1    0      0
1    1      1    ← Vrai seulement si TOUTES vraies

OR (||) :
A    B    A || B
0    0      0
0    1      1    ← Vrai si AU MOINS UNE vraie
1    0      1
1    1      1

NOT (!) :
A    !A
0    1
1    0
```

**Short-circuit (court-circuit)** :

**C'est quoi ?**
Le C évalue les conditions de gauche à droite et s'arrête dès que le résultat est connu.

```c
// Avec && : si la première est fausse, pas besoin de vérifier les autres
if (ptr != NULL && ptr->value == 42) {
    // Sûr : vérifie d'abord que ptr n'est pas NULL
}

// Avec || : si la première est vraie, pas besoin de vérifier les autres
if (x == 0 || y / x > 10) {
    // Sûr : si x==0, ne calcule pas y/x (évite division par 0)
}
```

**Schéma** :
```
Expression : (x == 0) && (y > 10)

Si x != 0 :
   Évalue (x == 0) → Faux
   ↓
   Court-circuit : ne vérifie pas (y > 10)
   ↓
   Retourne Faux

Si x == 0 :
   Évalue (x == 0) → Vrai
   ↓
   Continue : évalue (y > 10)
   ↓
   Retourne le résultat de (y > 10)
```

### Concept 6 : Opérateur ternaire

**C'est quoi ?**
Un if-else condensé en une seule ligne.

**Syntaxe** :
```c
condition ? valeur_si_vrai : valeur_si_faux;
```

**Exemple** :
```c
int max = (a > b) ? a : b;

// Équivalent à :
int max;
if (a > b) {
    max = a;
} else {
    max = b;
}
```

**Cas d'usage** :
```c
// Déterminer si un nombre est pair ou impair
char* parity = (num % 2 == 0) ? "pair" : "impair";

// Limiter une valeur
int clamped = (x > 100) ? 100 : x;

// Statut HTTP
int status = (error) ? 500 : 200;
```

### Concept 7 : Priorité des opérateurs

**C'est quoi ?**
L'ordre dans lequel le compilateur évalue les opérateurs.

**De la plus haute priorité à la plus basse** :

```
1.  ()                 Parenthèses (forcer l'ordre)
2.  !, ++, --          Unaires
3.  *, /, %            Multiplicatifs
4.  +, -               Additifs
5.  <, <=, >, >=       Relationnels
6.  ==, !=             Égalité
7.  &&                 AND logique
8.  ||                 OR logique
9.  ?:                 Ternaire
10. =, +=, -=, etc.    Affectation
```

**Exemples** :
```c
int x = 5 + 3 * 2;      // x = 11 (pas 16)
// Car * prioritaire sur +
// Calcul : 5 + (3 * 2) = 5 + 6 = 11

int y = (5 + 3) * 2;    // y = 16
// Les parenthèses forcent l'addition en premier

int z = 10 > 5 + 2;     // z = 1 (vrai)
// Calcul : 10 > (5 + 2) = 10 > 7 = vrai

if (x = 5 || y == 3) {  // Piège : affectation, pas comparaison
    // x vaut 1 (résultat de 5 || y==3), pas 5 !
}
```

**Règle d'or** : En cas de doute, utilise des parenthèses !

## 🔍 Visualisation : Évaluation d'expressions complexes

```c
int result = (10 + 5) * 2 - 8 / 4;
```

**Étapes d'évaluation** :
```
Expression : (10 + 5) * 2 - 8 / 4

Étape 1 : Parenthèses
(10 + 5) → 15
Expression : 15 * 2 - 8 / 4

Étape 2 : Multiplication et division (même priorité, de gauche à droite)
15 * 2 → 30
8 / 4 → 2
Expression : 30 - 2

Étape 3 : Soustraction
30 - 2 → 28

Résultat final : 28
```

## 🎯 Application Red Team

### 1. Modulo pour masking et wraparound

**Limiter un index dans un buffer** :
```c
unsigned int index = user_input % MAX_SIZE;
buffer[index] = data;  // Empêche l'overflow
```

**Rotation circulaire** :
```c
// XOR cipher avec rotation de clé
unsigned char key[] = "SECRET";
int key_len = 6;

for (int i = 0; i < data_len; i++) {
    data[i] ^= key[i % key_len];  // Cycle sur la clé
}
```

### 2. Opérateur ternaire pour obfuscation

**Code compact et moins lisible** :
```c
// Au lieu de :
if (is_admin) {
    access_level = 3;
} else {
    access_level = 0;
}

// Version obfusquée :
access_level = is_admin ? 3 : 0;
```

### 3. Short-circuit pour checks de sécurité

**Vérifications en chaîne** :
```c
if (ptr != NULL && ptr->is_valid && ptr->data != NULL && ptr->size > 0) {
    // Sûr : chaque vérification protège la suivante
    process(ptr->data, ptr->size);
}
```

### 4. Division et modulo pour calculs d'offset

**Parser des structures binaires** :
```c
int page_number = byte_offset / PAGE_SIZE;     // Quelle page ?
int offset_in_page = byte_offset % PAGE_SIZE;  // Offset dans la page

// Exemple : byte 5000 avec PAGE_SIZE = 4096
// page_number = 5000 / 4096 = 1
// offset_in_page = 5000 % 4096 = 904
```

### 5. Bitwise déguisé en arithmétique

**Multiplication/division par puissances de 2** :
```c
// Au lieu de :
x = x * 8;   // Détectable
x = x / 4;

// Obfusqué (équivalent avec shifts) :
x = x << 3;  // *8 (plus rapide)
x = x >> 2;  // /4
```

### 6. Integer overflow intentionnel

**Exploit de wraparound** :
```c
unsigned char counter = 255;
counter++;  // Wraparound : counter = 0

// Si le code fait :
if (counter > 0) {
    // Accès à buffer[counter - 1]
    // counter = 0 → buffer[-1] → Vulnérabilité
}
```

### 7. Comparaisons pour time-attack

**Éviter le timing attack** :
```c
// VULNÉRABLE (s'arrête au premier différent)
if (strcmp(password, input) == 0) { ... }

// SÉCURISÉ (compare toujours tout)
int compare_secure(char* a, char* b, int len) {
    int diff = 0;
    for (int i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);  // Accumule les différences
    }
    return (diff == 0);  // Temps constant
}
```

### 8. Opérateurs pour encoding/decoding

**ROT13 cipher** :
```c
char encode_rot13(char c) {
    if (c >= 'a' && c <= 'z') {
        return 'a' + (c - 'a' + 13) % 26;
    }
    if (c >= 'A' && c <= 'Z') {
        return 'A' + (c - 'A' + 13) % 26;
    }
    return c;
}
```

## 📝 Points clés à retenir

- Les opérateurs permettent de calculer, comparer et manipuler des données
- Division entière : `5 / 2 = 2` (pas 2.5)
- Modulo `%` retourne le reste : `10 % 3 = 1`
- `++x` (pré) vs `x++` (post) : ordre d'incrémentation différent
- `=` affecte, `==` compare (piège fréquent !)
- `&&` = ET, `||` = OU, `!` = NON
- Short-circuit : évaluation s'arrête dès que le résultat est connu
- Opérateur ternaire : `condition ? vrai : faux`
- Priorité : `* / %` avant `+ -`, utilise des `()` en cas de doute
- Modulo et division sont cruciaux pour les calculs d'offset et le masking

## ➡️ Prochaine étape

Maintenant que tu maîtrises les opérateurs de base, tu vas découvrir les [opérations bitwise](../05_bitwise/) pour manipuler les bits directement

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)

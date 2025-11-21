# Cours 04 : Opérateurs en C

## 1. Introduction

Les opérateurs sont les **verbes** de votre programme. Ils permettent d'effectuer des calculs, comparer des valeurs, combiner des conditions et manipuler des bits. Le C offre une grande variété d'opérateurs, certains hérités directement de l'assembleur.

Comprendre les opérateurs, c'est comprendre comment le processeur **manipule les données**.

## 2. Visualisation : Classification des Opérateurs

```ascii
OPÉRATEURS EN C
├── Arithmétiques    : +  -  *  /  %  ++  --
├── Comparaison      : ==  !=  <  >  <=  >=
├── Logiques         : &&  ||  !
├── Binaires (bits)  : &  |  ^  ~  <<  >>
├── Affectation      : =  +=  -=  *=  /=  %=
├── Autres           : ?:  ,  sizeof  &  *
└── Précédence       : ( ) pour forcer l'ordre
```

## 3. Opérateurs Arithmétiques

### Opérateurs de Base

```c
int a = 15, b = 4;

int somme = a + b;           // 19 - Addition
int diff = a - b;            // 11 - Soustraction
int produit = a * b;         // 60 - Multiplication
int quotient = a / b;        // 3  - Division (entière si les 2 sont int)
int reste = a % b;           // 3  - Modulo (reste de la division)
```

### ⚠️ Piège : Division Entière

```c
int a = 10, b = 3;
int resultat = a / b;        // 3 (pas 3.333...)

// Pour obtenir un float :
float correct = (float)a / b;  // 3.333...
```

### Incrémentation et Décrémentation

```c
int x = 10;

// Post-incrémentation (utilise puis incrémente)
int y = x++;    // y = 10, puis x = 11
printf("y=%d, x=%d\n", y, x);  // y=10, x=11

// Pré-incrémentation (incrémente puis utilise)
int z = ++x;    // x = 12, puis z = 12
printf("z=%d, x=%d\n", z, x);  // z=12, x=12

// Pareil avec décrémentation
x--;   // x = x - 1
--x;   // x = x - 1
```

### En Assembleur

```asm
; a + b
mov eax, [a]        ; Charge a dans EAX
add eax, [b]        ; Ajoute b à EAX

; a++
inc dword ptr [a]   ; Incrémente directement en mémoire
```

## 4. Opérateurs de Comparaison

Retournent `1` (vrai) ou `0` (faux).

```c
int a = 10, b = 20;

printf("%d\n", a == b);    // 0 (faux) - Égalité
printf("%d\n", a != b);    // 1 (vrai) - Différent
printf("%d\n", a < b);     // 1 (vrai) - Plus petit
printf("%d\n", a > b);     // 0 (faux) - Plus grand
printf("%d\n", a <= b);    // 1 (vrai) - Inférieur ou égal
printf("%d\n", a >= b);    // 0 (faux) - Supérieur ou égal
```

### ⚠️ Piège : `=` vs `==`

```c
int x = 10;

if (x = 5) {              // ERREUR ! Affectation, pas comparaison
    printf("Toujours vrai\n");  // x vaut maintenant 5
}

if (x == 5) {             // CORRECT : Comparaison
    printf("x vaut 5\n");
}
```

## 5. Opérateurs Logiques

Utilisés pour combiner des conditions.

```c
int age = 25;
int permis = 1;  // 1 = true, 0 = false

// ET logique (&&) : les DEUX doivent être vrais
if (age >= 18 && permis) {
    printf("Peut conduire\n");
}

// OU logique (||) : au moins UN doit être vrai
if (age < 18 || age > 65) {
    printf("Tarif réduit\n");
}

// NON logique (!) : inverse
if (!permis) {
    printf("Pas de permis\n");
}
```

### Short-Circuit Evaluation

```c
int x = 0;

// && : Si le premier est faux, le second n'est PAS évalué
if (x != 0 && 10/x > 2) {  // Sûr : pas de division par zéro
    // ...
}

// || : Si le premier est vrai, le second n'est PAS évalué
if (x == 0 || 10/x > 2) {  // Sûr
    // ...
}
```

## 6. Opérateurs d'Affectation

### Affectation Simple

```c
int x = 10;   // Affecte 10 à x
```

### Affectations Composées

```c
int x = 100;

x += 20;      // x = x + 20  → 120
x -= 10;      // x = x - 10  → 110
x *= 2;       // x = x * 2   → 220
x /= 4;       // x = x / 4   → 55
x %= 10;      // x = x % 10  → 5
```

### Affectations Multiples

```c
int a, b, c;
a = b = c = 10;    // Tous valent 10 (associativité droite→gauche)
```

## 7. Opérateur Ternaire

Syntaxe compacte pour `if-else`.

```c
// Syntaxe : condition ? si_vrai : si_faux
int a = 10, b = 20;
int max = (a > b) ? a : b;    // max = 20

// Équivalent à :
int max;
if (a > b) {
    max = a;
} else {
    max = b;
}
```

### Cas d'Usage

```c
// Affichage conditionnel
printf("Vous êtes %s\n", age >= 18 ? "majeur" : "mineur");

// Valeur absolue
int x = -42;
int abs = (x < 0) ? -x : x;   // abs = 42
```

## 8. Opérateurs Binaires - Manipulation de Bits (Niveau Avancé)

### 8.1 Qu'est-ce qu'un Bit ?

Avant de manipuler des bits, comprenons ce qu'ils sont :

**BIT** = La plus petite unité d'information en informatique
- Peut être soit **0** soit **1** (comme un interrupteur : éteint/allumé)

**BYTE** = 8 bits
- Peut représenter 256 valeurs différentes (2^8 = 256)

```ascii
UN BYTE (8 bits) :

┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 0 │ 1 │ 1 │ 0 │ 1 │ 0 │ 1 │  ← 8 positions
└───┴───┴───┴───┴───┴───┴───┴───┘
  ↑                           ↑
Bit 7                       Bit 0
(MSB)                       (LSB)

MSB = Most Significant Bit (poids fort)
LSB = Least Significant Bit (poids faible)

Valeur : 1×128 + 0×64 + 1×32 + 1×16 + 0×8 + 1×4 + 0×2 + 1×1
       = 128 + 32 + 16 + 4 + 1
       = 181 (en décimal)
       = 0xB5 (en hexadécimal)
```

### 8.2 Opérateur AND (&) - Le Plus Strict

**Principe** : Le résultat est **1** seulement si LES DEUX bits sont **1**.

**Table de vérité** :
```ascii
A  &  B  =  Résultat
─────────────────────
0  &  0  =    0
0  &  1  =    0
1  &  0  =    0
1  &  1  =    1  ← Seulement quand TOUS DEUX sont 1
```

**Exemple Visuel Complet** :

```c
unsigned int a = 0b1100;  // 12 en décimal
unsigned int b = 0b1010;  // 10 en décimal
unsigned int resultat = a & b;
```

```ascii
OPÉRATION BIT PAR BIT :

Nombre a :  1  1  0  0   (12 en décimal)
            ↓  ↓  ↓  ↓
Nombre b :  1  0  1  0   (10 en décimal)
            │  │  │  │
         & (ET) pour chaque position
            ↓  ↓  ↓  ↓
Résultat :  1  0  0  0   (8 en décimal)
            │  │  │  │
            │  │  │  └─ 0 & 0 = 0
            │  │  └─ 0 & 1 = 0
            │  └─ 1 & 0 = 0
            └─ 1 & 1 = 1 ✅

┌────────────────────────────────────────┐
│  a     = 0b1100 = 12                   │
│  b     = 0b1010 = 10                   │
│  a & b = 0b1000 = 8                    │
└────────────────────────────────────────┘

VISUALISATION GRAPHIQUE :

Position: 3  2  1  0
         ┌──┬──┬──┬──┐
a :      │ 1│ 1│ 0│ 0│  12
         └──┴──┴──┴──┘
            &
         ┌──┬──┬──┬──┐
b :      │ 1│ 0│ 1│ 0│  10
         └──┴──┴──┴──┘
            =
         ┌──┬──┬──┬──┐
Résultat:│ 1│ 0│ 0│ 0│  8
         └──┴──┴──┴──┘
         ✅❌❌❌
```

**Usage pratique** : Masquer/Extraire des bits spécifiques

```ascii
EXEMPLE : Extraire les 4 bits de poids faible

Valeur :     1011 0110  (0xB6 = 182)
Masque :     0000 1111  (0x0F = 15)
            ──────────
Résultat:    0000 0110  (0x06 = 6)
             └──────┘
        Bits extraits !

Code :
int valeur = 0xB6;
int lower_nibble = valeur & 0x0F;  // 0x06
```

### 8.3 Opérateur OR (|) - Le Plus Permissif

**Principe** : Le résultat est **1** si AU MOINS UN des bits est **1**.

**Table de vérité** :
```ascii
A  |  B  =  Résultat
─────────────────────
0  |  0  =    0  ← Seulement quand TOUS DEUX sont 0
0  |  1  =    1
1  |  0  =    1
1  |  1  =    1
```

**Exemple Visuel** :

```ascii
a     : 1  1  0  0  (12)
        ↓  ↓  ↓  ↓
b     : 1  0  1  0  (10)
        │  │  │  │
     | (OU) pour chaque position
        ↓  ↓  ↓  ↓
Résultat: 1  1  1  0  (14)
        ✅✅✅❌

Position: 3  2  1  0
         ┌──┬──┬──┬──┐
a :      │ 1│ 1│ 0│ 0│  12
         └──┴──┴──┴──┘
            |
         ┌──┬──┬──┬──┐
b :      │ 1│ 0│ 1│ 0│  10
         └──┴──┴──┴──┘
            =
         ┌──┬──┬──┬──┐
Résultat:│ 1│ 1│ 1│ 0│  14
         └──┴──┴──┴──┘
```

**Usage pratique** : Activer des bits spécifiques

```ascii
EXEMPLE : Activer le bit 2

Flags :   0001 0000  (0x10)
Masque :  0000 0100  (0x04 = bit 2)
         ──────────
Résultat: 0001 0100  (0x14)
              ↑
         Bit 2 activé !

Code :
int flags = 0x10;
flags = flags | 0x04;  // Active bit 2
// ou : flags |= 0x04;
```

### 8.4 Opérateur XOR (^) - Le Plus Malin

**Principe** : Le résultat est **1** si les bits sont **DIFFÉRENTS**.

**Table de vérité** :
```ascii
A  ^  B  =  Résultat
─────────────────────
0  ^  0  =    0  ← Même valeur
0  ^  1  =    1  ← Différent
1  ^  0  =    1  ← Différent
1  ^  1  =    0  ← Même valeur
```

**Exemple Visuel** :

```ascii
a     : 1  1  0  0  (12)
        ↓  ↓  ↓  ↓
b     : 1  0  1  0  (10)
        │  │  │  │
     ^ (XOR) pour chaque position
        ↓  ↓  ↓  ↓
Résultat: 0  1  1  0  (6)
        ❌✅✅❌

Position: 3  2  1  0
         ┌──┬──┬──┬──┐
a :      │ 1│ 1│ 0│ 0│  12
         └──┴──┴──┴──┘
            ^
         ┌──┬──┬──┬──┐
b :      │ 1│ 0│ 1│ 0│  10
         └──┴──┴──┴──┘
            =
         ┌──┬──┬──┬──┐
Résultat:│ 0│ 1│ 1│ 0│  6
         └──┴──┴──┴──┘
```

**Propriété Magique de XOR** : `X ^ X = 0` et `X ^ 0 = X`

```ascii
SWAP SANS VARIABLE TEMPORAIRE :

int a = 5;   // 0101
int b = 10;  // 1010

┌─────────────────────────────────────┐
│ ÉTAPE 1 : a ^= b                    │
│                                     │
│  a = a ^ b                          │
│    = 0101 ^ 1010                    │
│    = 1111  (15)                     │
│                                     │
│  État : a=15, b=10                  │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ ÉTAPE 2 : b ^= a                    │
│                                     │
│  b = b ^ a                          │
│    = 1010 ^ 1111                    │
│    = 0101  (5)                      │
│                                     │
│  État : a=15, b=5                   │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ ÉTAPE 3 : a ^= b                    │
│                                     │
│  a = a ^ b                          │
│    = 1111 ^ 0101                    │
│    = 1010  (10)                     │
│                                     │
│  État : a=10, b=5                   │
└─────────────────────────────────────┘

RÉSULTAT : a et b ont échangé leurs valeurs !
           a était 5 → maintenant 10
           b était 10 → maintenant 5
```

### Décalages de Bits

```c
unsigned int x = 5;        // 0b0101

// Décalage à gauche (<<) : Multiplie par 2^n
unsigned int gauche = x << 1;  // 0b1010 = 10
unsigned int gauche2 = x << 2; // 0b10100 = 20

// Décalage à droite (>>) : Divise par 2^n
unsigned int droite = x >> 1;  // 0b0010 = 2
```

### Applications Pratiques

```c
// Vérifier si un bit est activé
int flags = 0b1010;
if (flags & 0b0010) {  // Bit 1 activé ?
    printf("Flag actif\n");
}

// Activer un bit
flags = flags | 0b0100;   // Active bit 2

// Désactiver un bit
flags = flags & ~0b0010;  // Désactive bit 1

// Inverser un bit
flags = flags ^ 0b1000;   // Toggle bit 3
```

## 9. Opérateur sizeof

Retourne la taille d'un type ou d'une variable en bytes.

```c
printf("%zu\n", sizeof(int));        // 4
printf("%zu\n", sizeof(char));       // 1
printf("%zu\n", sizeof(double));     // 8

int tableau[10];
printf("%zu\n", sizeof(tableau));    // 40 (10 * 4)

// Nombre d'éléments dans un tableau
int taille = sizeof(tableau) / sizeof(tableau[0]);  // 10
```

## 10. Précédence des Opérateurs

Ordre d'évaluation (de haut en bas) :

| Priorité | Opérateurs              | Associativité |
|----------|-------------------------|---------------|
| 1        | `()` `[]` `.` `->`      | Gauche→Droite |
| 2        | `!` `~` `++` `--` `*` `&` `sizeof` | Droite→Gauche |
| 3        | `*` `/` `%`             | Gauche→Droite |
| 4        | `+` `-`                 | Gauche→Droite |
| 5        | `<<` `>>`               | Gauche→Droite |
| 6        | `<` `<=` `>` `>=`       | Gauche→Droite |
| 7        | `==` `!=`               | Gauche→Droite |
| 8        | `&`                     | Gauche→Droite |
| 9        | `^`                     | Gauche→Droite |
| 10       | `|`                     | Gauche→Droite |
| 11       | `&&`                    | Gauche→Droite |
| 12       | `||`                    | Gauche→Droite |
| 13       | `?:`                    | Droite→Gauche |
| 14       | `=` `+=` `-=` etc.      | Droite→Gauche |

### Exemple

```c
int resultat = 5 + 3 * 2;    // 11 (pas 16)
// Parce que * a priorité sur +

int correct = (5 + 3) * 2;   // 16
```

## 11. Sécurité & Risques

### ⚠️ Overflow

```c
int max = 2147483647;  // INT_MAX
max = max + 1;         // Overflow → -2147483648 !
```

### ⚠️ Division par Zéro

```c
int x = 10 / 0;        // CRASH (exception)
```

### ⚠️ Effets de Bord avec ++

```c
int x = 5;
int y = x++ + x++;     // Comportement indéfini ! Ne JAMAIS faire ça
```

## 12. Bonnes Pratiques

1. **Utilisez des parenthèses** pour clarifier les expressions complexes
2. **Évitez les post/pré-incrémentations** dans des expressions complexes
3. **Vérifiez les divisions** par zéro avant d'opérer
4. **Utilisez unsigned** pour les opérations binaires
5. **Préférez les opérateurs composés** : `x += 5` plutôt que `x = x + 5`

## 13. Exercice Mental

Que vaut `x` à la fin ?
```c
int x = 10;
x += 5;
x *= 2;
x /= 3;
```

<details>
<summary>Réponse</summary>

**x = 10**

Étapes :
1. `x = 10`
2. `x += 5` → `x = 15`
3. `x *= 2` → `x = 30`
4. `x /= 3` → `x = 10` (division entière)
</details>

## 14. Ressources Complémentaires

- [Précédence des opérateurs C](https://en.cppreference.com/w/c/language/operator_precedence)
- [Opérations binaires](https://en.wikipedia.org/wiki/Bitwise_operation)
- [Short-circuit evaluation](https://en.wikipedia.org/wiki/Short-circuit_evaluation)


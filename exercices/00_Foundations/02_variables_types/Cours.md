# Cours 02 : Variables et Types de Données

## 1. Introduction - Qu'est-ce qu'une Variable ? (Explications Complètes)

### 1.1 Le Concept de Base - Pour Bien Comprendre

**Question Fondamentale** : Qu'est-ce qu'une variable ?

**Réponse Niveau 1 (Très Simple)** :

Une variable est comme une **boîte** avec une **étiquette** :
- L'**étiquette** = le nom de la variable (ex: `age`)
- Le **contenu** = la valeur stockée (ex: `25`)
- La **taille de la boîte** = le type (ex: `int` = boîte de 4 kg)

```ascii
┌─────────────────────────┐
│   Étiquette: "age"      │  ← Nom (pour vous, le programmeur)
├─────────────────────────┤
│   Type: int             │  ← Taille de la boîte (4 bytes)
├─────────────────────────┤
│   Contenu: 25           │  ← Valeur stockée
├─────────────────────────┤
│   Adresse: 0x1000       │  ← Où est la boîte (en mémoire)
└─────────────────────────┘
```

**Réponse Niveau 2 (Technique)** :

Une variable est un **emplacement nommé en mémoire** qui stocke une valeur d'un type spécifique.

**Réponse Niveau 3 (Expert)** :

Une variable est un **symbole** qui, pendant la compilation, est remplacé par une **adresse mémoire** où sont stockés N bytes (selon le type), accessibles via des instructions CPU (MOV, ADD, etc.).

### 1.2 Pourquoi Déclarer un Type ?

**En Python (typage dynamique)** :
```python
age = 25        # Python devine : "C'est un nombre"
age = "vingt"   # OK, Python change le type
```

**En C (typage statique)** :
```c
int age = 25;      // Vous DEVEZ dire : "C'est un int"
age = "vingt";     // ❌ ERREUR ! int ne peut pas contenir du texte
```

**Pourquoi cette différence ?**

```ascii
PYTHON (Haut Niveau) :

Variable Python = Objet complexe
┌──────────────────────────┐
│ Type : int               │  } 
│ Valeur : 25              │  } ~28 bytes
│ Compteur références      │  }
│ Métadonnées...           │  }
└──────────────────────────┘

Python gère tout automatiquement (pratique mais lent)

C (Bas Niveau) :

Variable C = Juste les bytes
┌──────────────────────────┐
│ 25                       │  } 4 bytes
└──────────────────────────┘

C travaille directement avec la mémoire (rapide mais strict)
Le compilateur DOIT savoir combien de bytes réserver !
```

### 1.3 Qu'est-ce qu'un "Type" ? (Définition Complète)

**Type** = Un **contrat** qui dit :
1. **Combien de bytes** la variable occupe
2. **Comment interpréter** ces bytes
3. **Quelles opérations** sont autorisées

```ascii
EXEMPLE : Même bytes, interprétations différentes

Mémoire à 0x1000 : [0x41] [0x00] [0x00] [0x00]
                    └────────────────────────┘

Interprété comme int :    65 (nombre)
Interprété comme char :   'A' (caractère)
Interprété comme float :  9.1e-44 (nombre très petit)

LE TYPE DIT AU CPU COMMENT LIRE CES BYTES !
```

**Table des Types et Leurs Significations** :

| Type | Taille | Signifie | Exemple Utilisation |
|------|--------|----------|---------------------|
| `char` | 1 byte | "Un seul caractère" | Lettre, symbole |
| `int` | 4 bytes | "Un nombre entier" | Âge, compteur |
| `float` | 4 bytes | "Nombre à virgule" | Prix, température |
| `double` | 8 bytes | "Virgule précise" | Calculs scientifiques |
| `char*` | 8 bytes | "Adresse d'un texte" | Nom, phrase |

### 1.4 La Déclaration - Que Se Passe-t-il Exactement ?

**Ligne de code** :
```c
int age = 25;
```

**Ce qui se passe en 5 étapes** :

```ascii
═══════════════════════════════════════════════════════════
ÉTAPE 1 : LE COMPILATEUR LIT "int"
═══════════════════════════════════════════════════════════

Compilateur : "Ah, un int ! Je dois réserver 4 bytes"

┌────────────────────────────────┐
│ Compilateur note :             │
│ - Type : int                   │
│ - Taille nécessaire : 4 bytes  │
└────────────────────────────────┘

═══════════════════════════════════════════════════════════
ÉTAPE 2 : LE COMPILATEUR LIT "age"
═══════════════════════════════════════════════════════════

Compilateur : "Le nom de la variable est 'age'"
             "Je vais créer un symbole 'age' dans ma table"

┌────────────────────────────────┐
│ Table des Symboles :           │
│ ┌──────┬──────┬──────────┐     │
│ │ Nom  │ Type │ Adresse  │     │
│ ├──────┼──────┼──────────┤     │
│ │ age  │ int  │ (à venir)│     │
│ └──────┴──────┴──────────┘     │
└────────────────────────────────┘

═══════════════════════════════════════════════════════════
ÉTAPE 3 : ALLOCATION MÉMOIRE (pendant l'exécution)
═══════════════════════════════════════════════════════════

Runtime : "Je réserve 4 bytes sur la Stack"

STACK (avant) :
┌──────────┐  0x1000
│  ...     │
└──────────┘

STACK (après) :
┌──────────┐  0x1000
│  age     │  ← 4 bytes réservés
│  [?][?]  │     (contenu indéfini)
│  [?][?]  │
└──────────┘  0x1003

Table mise à jour :
│ age  │ int  │ 0x1000   │  ✅

═══════════════════════════════════════════════════════════
ÉTAPE 4 : INITIALISATION (= 25)
═══════════════════════════════════════════════════════════

Runtime : "J'écris 25 dans ces 4 bytes"

25 = 0x00000019

STACK :
0x1000  ┌────┐
        │0x19│  ← LSB (Least Significant Byte)
0x1001  ├────┤
        │0x00│
0x1002  ├────┤
        │0x00│
0x1003  ├────┤
        │0x00│  ← MSB (Most Significant Byte)
        └────┘

═══════════════════════════════════════════════════════════
ÉTAPE 5 : LA VARIABLE EST PRÊTE
═══════════════════════════════════════════════════════════

Vous pouvez maintenant utiliser "age" :

printf("%d", age);  → Lit les 4 bytes à 0x1000
                    → Interprète comme int
                    → Affiche : 25

age = age + 10;     → Lit 25, ajoute 10, écrit 35
```

### 1.5 Pourquoi "25" Devient "0x19" ? (Explications Binaires)

**Question** : Pourquoi le nombre 25 est-il stocké comme 0x19 en mémoire ?

**Réponse Détaillée** :

Les ordinateurs ne comprennent que le **binaire** (0 et 1). Tout doit être converti.

```ascii
CONVERSION 25 (DÉCIMAL) → BINAIRE :

25 en base 10 (décimal)
│
├─ Division par 2 (méthode scolaire) :
│
│  25 ÷ 2 = 12  reste 1   ↓
│  12 ÷ 2 = 6   reste 0   ↓
│  6  ÷ 2 = 3   reste 0   ↓
│  3  ÷ 2 = 1   reste 1   ↓
│  1  ÷ 2 = 0   reste 1   ↓
│
│  Lire de BAS en HAUT : 11001
│
└─ 25₁₀ = 11001₂ (en binaire)

Compléter à 8 bits : 00011001

CONVERSION BINAIRE → HEXADÉCIMAL :

00011001 (binaire)
│  │
│  └─ Grouper par 4 bits
│
0001  1001
 │     │
 1     9    (en décimal)
 │     │
 1     9    (en hexadécimal)

25₁₀ = 00011001₂ = 0x19₁₆

POURQUOI L'HEXADÉCIMAL ?

Hexadécimal = Raccourci pour binaire
2 chiffres hexa = 1 byte exactement

00011001 (8 chiffres binaires, difficile à lire)
   ↓
  0x19  (2 chiffres hexa, plus lisible !)
```

## 2. Comprendre la Mémoire - Visualisations Détaillées

### 2.1 La Mémoire = Une Grande Rue de Boîtes aux Lettres

**Analogie** : Imaginez la mémoire RAM comme une **immense rue** avec des milliards de boîtes numérotées.

```ascii
RUE DE LA MÉMOIRE (RAM) :
         
         Adresse      Contenu
         -------      -------
         0x1000    ┌─────────┐
                   │    ?    │  ← Boîte vide (1 byte)
         0x1001    ├─────────┤
                   │    ?    │
         0x1002    ├─────────┤
                   │    ?    │
         0x1003    ├─────────┤
                   │    ?    │
         0x1004    ├─────────┤
                   │    ?    │
                   └─────────┘
                   
Chaque boîte peut contenir 1 BYTE (8 bits) de données
Chaque boîte a une ADRESSE unique (son numéro)
```

### 2.2 Une Variable = Un Ensemble de Boîtes

Quand vous déclarez une variable, vous **réservez plusieurs boîtes** côte à côte.

#### Exemple 1 : int age = 25

```ascii
DÉCLARATION : int age = 25;
              │   │    │
              │   │    └─ Valeur initiale : 25
              │   └─ Nom de variable : "age"
              └─ Type : int (entier sur 4 bytes)

ÉTAPE 1 - Réservation de 4 boîtes :

Adresse    Contenu    Explication
┌────────┬──────────┬────────────────────────┐
│0x1000  │    ?     │  ← Le système réserve
│0x1001  │    ?     │     4 boîtes côte à
│0x1002  │    ?     │     côte pour "age"
│0x1003  │    ?     │
└────────┴──────────┴────────────────────────┘
         └──────────┘
         "age" occupe
         les adresses
         0x1000 à 0x1003

ÉTAPE 2 - Stockage de la valeur 25 :

25 en décimal = 0x00000019 en hexadécimal
              = 00000000 00000000 00000000 00011001 en binaire

┌────────┬──────────┬────────────────────────┐
│0x1000  │   0x19   │  ← Byte de poids faible (Little Endian)
│0x1001  │   0x00   │
│0x1002  │   0x00   │
│0x1003  │   0x00   │  ← Byte de poids fort
└────────┴──────────┴────────────────────────┘

La variable "age" contient maintenant 25
```

**Question** : Pourquoi 4 boîtes pour un seul nombre ?

**Réponse** : Un `int` peut stocker des nombres de -2 milliards à +2 milliards. Pour représenter autant de valeurs différentes, il faut 4 bytes (32 bits), ce qui donne 2^32 = 4,294,967,296 combinaisons possibles.

#### Exemple 2 : char lettre = 'A'

```ascii
DÉCLARATION : char lettre = 'A';

ÉTAPE 1 - Réservation de 1 boîte :

┌────────┬──────────┬────────────────────────┐
│0x1004  │    ?     │  ← 1 seule boîte suffit
└────────┴──────────┴────────────────────────┘

ÉTAPE 2 - Stockage de 'A' :

'A' = 65 en ASCII = 0x41 en hexadécimal

┌────────┬──────────┬────────────────────────┐
│0x1004  │   0x41   │  ← Le caractère 'A'
└────────┴──────────┴────────────────────────┘

1 byte suffit car il y a seulement 256 caractères ASCII
```

#### Exemple 3 : double pi = 3.14

```ascii
DÉCLARATION : double pi = 3.14;

ÉTAPE 1 - Réservation de 8 boîtes :

┌────────┬──────────┐
│0x1008  │    ?     │  ← 8 bytes pour une
│0x1009  │    ?     │     haute précision
│0x100A  │    ?     │     (15 décimales)
│0x100B  │    ?     │
│0x100C  │    ?     │
│0x100D  │    ?     │
│0x100E  │    ?     │
│0x100F  │    ?     │
└────────┴──────────┘

ÉTAPE 2 - Stockage de 3.14 (format IEEE 754) :

┌────────┬──────────┬────────────────────────┐
│0x1008  │   0x1F   │  ← Représentation flottante
│0x1009  │   0x85   │     (format complexe IEEE 754)
│0x100A  │   0xEB   │
│0x100B  │   0x51   │
│0x100C  │   0xB8   │
│0x100D  │   0x1E   │
│0x100E  │   0x09   │
│0x100F  │   0x40   │
└────────┴──────────┴────────────────────────┘
```

### 2.3 Vue d'Ensemble - Toutes les Variables Ensemble

```ascii
MÉMOIRE RAM COMPLÈTE (Segment Data/Stack) :

Adresse    Type      Nom       Valeur    Bytes Utilisés
────────────────────────────────────────────────────────

0x1000  ┌──────────────────────────────────────┐
        │  int age = 25                        │
        │  [0x19] [0x00] [0x00] [0x00]        │  4 bytes
0x1003  └──────────────────────────────────────┘

0x1004  ┌──────────────────────────────────────┐
        │  char lettre = 'A'                   │
        │  [0x41]                              │  1 byte
0x1004  └──────────────────────────────────────┘

        ┌─ PADDING (3 bytes vides) ─┐  ← Alignement mémoire
0x1005  │  [0x00] [0x00] [0x00]      │  (optimisation CPU)
0x1007  └────────────────────────────┘

0x1008  ┌──────────────────────────────────────┐
        │  double pi = 3.14                    │
        │  [0x1F][0x85][0xEB][0x51]           │  8 bytes
        │  [0xB8][0x1E][0x09][0x40]           │
0x100F  └──────────────────────────────────────┘

0x1010  ┌──────────────────────────────────────┐
        │  float taille = 1.75                 │
        │  [0x00][0x00][0xE0][0x3F]           │  4 bytes
0x1013  └──────────────────────────────────────┘

TOTAL MÉMOIRE UTILISÉE : 20 bytes (+ 3 bytes padding = 23)
```

**Observations Importantes** :

1. **Adresses en hexadécimal** : `0x1000` = 4096 en décimal
2. **Alignement mémoire** : Le CPU préfère lire par blocs de 4 ou 8 bytes
3. **Padding** : Espaces vides ajoutés pour l'alignement
4. **Little Endian** : Byte de poids faible en premier (0x19 avant 0x00)

### 2.4 Comparaison des Tailles - Schéma Visuel

```ascii
TAILLES RELATIVES DES TYPES :

char (1 byte) :
┌───┐
│ 1 │
└───┘

short (2 bytes) :
┌───┬───┐
│ 1 │ 2 │
└───┴───┘

int (4 bytes) :
┌───┬───┬───┬───┐
│ 1 │ 2 │ 3 │ 4 │
└───┴───┴───┴───┘

long (8 bytes sur 64-bit) :
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │
└───┴───┴───┴───┴───┴───┴───┴───┘

double (8 bytes) :
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │
└───┴───┴───┴───┴───┴───┴───┴───┘

Plus c'est grand :
✅ Plus de valeurs possibles (plus grande plage)
✅ Plus de précision (pour float/double)
❌ Plus de mémoire consommée
```

### 2.5 Représentation Binaire Détaillée

Comprenons comment **25** est stocké en mémoire :

```ascii
NOMBRE : 25 (en décimal)

ÉTAPE 1 - Conversion en binaire :
25 ÷ 2 = 12 reste 1   ↓
12 ÷ 2 = 6  reste 0   ↓
6  ÷ 2 = 3  reste 0   ↓
3  ÷ 2 = 1  reste 1   ↓
1  ÷ 2 = 0  reste 1   ↓

Lire de BAS en HAUT : 11001

ÉTAPE 2 - Compléter à 32 bits (int) :
00000000 00000000 00000000 00011001
│      │ │      │ │      │ │      │
Byte 3   Byte 2   Byte 1   Byte 0
(MSB)                      (LSB)

MSB = Most Significant Byte (poids fort)
LSB = Least Significant Byte (poids faible)

ÉTAPE 3 - Stockage en Little Endian :
En mémoire, on stocke LSB en PREMIER :

Adresse    Binaire          Hexadécimal
0x1000  │ 00011001     │  0x19  ← LSB en premier
0x1001  │ 00000000     │  0x00
0x1002  │ 00000000     │  0x00
0x1003  │ 00000000     │  0x00  ← MSB en dernier

C'est l'ordre "Little Endian" (petit bout en premier)
```

**Pourquoi Little Endian ?**

- Historique : compatibilité x86
- Performance : CPU peut lire le byte de poids faible rapidement
- Standard sur Intel/AMD/ARM (macOS, Windows, Linux)

### 2.6 Anatomie Complète d'une Variable

```ascii
┌─────────────────────────────────────────────────────┐
│               VARIABLE : int age = 25;              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  NOM (Identifier) : "age"                           │
│  ↓                                                  │
│  Ce que le programmeur utilise dans le code        │
│                                                     │
│  TYPE : int                                         │
│  ↓                                                  │
│  Dit au compilateur : "Réserve 4 bytes"            │
│                                                     │
│  VALEUR : 25                                        │
│  ↓                                                  │
│  Ce qui est stocké en mémoire                      │
│                                                     │
│  ADRESSE : 0x1000                                   │
│  ↓                                                  │
│  Où la variable est stockée en RAM                 │
│                                                     │
│  TAILLE : 4 bytes (32 bits)                        │
│  ↓                                                  │
│  Espace occupé : 0x1000 à 0x1003                   │
│                                                     │
│  PORTÉE (Scope) : Locale ou Globale                │
│  ↓                                                  │
│  Où dans le code la variable est accessible        │
│                                                     │
│  DURÉE DE VIE : Automatique ou Statique            │
│  ↓                                                  │
│  Quand la variable est créée/détruite              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 3. Les Types Fondamentaux - Expliqués en Profondeur

### 3.1 Comprendre "Signé" vs "Non Signé" (Crucial !)

**Question** : Qu'est-ce que "signé" (signed) et "non signé" (unsigned) ?

**Analogie** : Pensez à un **thermomètre** :

```ascii
THERMOMÈTRE SIGNÉ (signed) :
Peut afficher positif ET négatif

    30°C  ┐
    20°C  │
    10°C  │  Positif
     0°C  ├─── Point zéro
   -10°C  │  Négatif
   -20°C  │
   -30°C  ┘

THERMOMÈTRE NON SIGNÉ (unsigned) :
Seulement positif (ou zéro)

    60°C  ┐
    40°C  │  
    20°C  │  Tout positif
     0°C  ┘  Pas de négatif possible
```

**En Programmation** :

```ascii
SIGNED INT (4 bytes = 32 bits) :

1 bit réservé pour le SIGNE (+ ou -)
31 bits pour la VALEUR

┌─┬──────────────────────────────────┐
│S│     Valeur (31 bits)             │
└─┴──────────────────────────────────┘
 │
 └─ Bit de signe : 0 = positif, 1 = négatif

Plage : -2,147,483,648 à +2,147,483,647

UNSIGNED INT (4 bytes = 32 bits) :

TOUS les 32 bits pour la VALEUR (pas de signe)

┌──────────────────────────────────────┐
│     Valeur (32 bits)                 │
└──────────────────────────────────────┘

Plage : 0 à 4,294,967,295

COMPARAISON :
Signed :   -2 milliards à +2 milliards
Unsigned :  0 à +4 milliards

Même taille, mais unsigned va DEUX FOIS plus loin dans le positif
(car pas besoin de stocker le signe)
```

### 3.2 Types Entiers - Chaque Type Expliqué

#### char - Le Plus Petit (1 byte)

```c
char lettre = 'A';
```

**Qu'est-ce que c'est ?**

```ascii
CHAR = 1 byte = 8 bits

┌──┬──┬──┬──┬──┬──┬──┬──┐
│ 0│ 1│ 0│ 0│ 0│ 0│ 0│ 1│  = 65 = 'A' en ASCII
└──┴──┴──┴──┴──┴──┴──┴──┘

Peut stocker :
- Un caractère ('A', 'b', '!', '\n')
- OU un petit nombre (-128 à 127)
```

**Table ASCII (pour comprendre)** :

| Déc | Hexa | Char | Description |
|-----|------|------|-------------|
| 0 | 0x00 | NUL | Caractère nul |
| 10 | 0x0A | \n | Nouvelle ligne |
| 32 | 0x20 | ' ' | Espace |
| 48 | 0x30 | '0' | Chiffre zéro |
| 65 | 0x41 | 'A' | Lettre A majuscule |
| 97 | 0x61 | 'a' | Lettre a minuscule |

**Pourquoi 'A' = 65 ?**

C'est la convention **ASCII** (American Standard Code for Information Interchange). Les créateurs ont décidé que 65 représente 'A', 66 = 'B', etc.

```ascii
ALPHABERT EN ASCII :

Majuscules :
'A'=65, 'B'=66, 'C'=67, ..., 'Z'=90

Minuscules :
'a'=97, 'b'=98, 'c'=99, ..., 'z'=122

Différence : 'a' - 'A' = 97 - 65 = 32
(pour convertir majuscule ↔ minuscule)
```

#### short - Le Moyen (2 bytes)

```c
short petit_nombre = 100;
```

```ascii
SHORT = 2 bytes = 16 bits

┌──────────┬──────────┐
│ Byte 0   │ Byte 1   │
└──────────┴──────────┘

Plage (signed) :
- Minimum : -32,768  (0x8000)
- Maximum : +32,767  (0x7FFF)

Plage (unsigned short) :
- Minimum : 0
- Maximum : 65,535

QUAND L'UTILISER ?

✅ Économiser mémoire (tableaux de milliers d'éléments)
✅ Nombres garantis petits (notes sur 20, âge, etc.)
❌ Pas pour calculs généraux (risque overflow)
```

#### int - Le Standard (4 bytes)

```c
int age = 25;
```

```ascii
INT = 4 bytes = 32 bits

┌──────┬──────┬──────┬──────┐
│Byte 0│Byte 1│Byte 2│Byte 3│
└──────┴──────┴──────┴──────┘

Plage (signed int) :
- Minimum : -2,147,483,648  (0x80000000)
- Maximum : +2,147,483,647  (0x7FFFFFFF)

POURQUOI 4 BYTES ?

Historique : Taille naturelle des processeurs 32-bit
Pratique : Assez grand pour la plupart des usages
Standard : Type par défaut en C

REPRÉSENTATION EN MÉMOIRE :

Exemple : int x = 305419896;

En hexadécimal : 0x12345678
En binaire : 00010010 00110100 01010110 01111000

Mémoire (Little Endian) :
0x1000 : 0x78  ← Byte de poids faible EN PREMIER
0x1001 : 0x56
0x1002 : 0x34
0x1003 : 0x12  ← Byte de poids fort EN DERNIER

Pourquoi à l'envers ? Convention Intel/AMD (Little Endian)
```

#### long long - Le Grand (8 bytes)

```c
long long tres_grand = 9223372036854775807LL;
```

```ascii
LONG LONG = 8 bytes = 64 bits

┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│Byte0│Byte1│Byte2│Byte3│Byte4│Byte5│Byte6│Byte7│
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘

Plage :
- Minimum : -9,223,372,036,854,775,808
- Maximum : +9,223,372,036,854,775,807
            (9 quintillions !)

QUAND L'UTILISER ?

✅ Timestamps (millisecondes depuis 1970)
✅ Calculs financiers (centimes sur gros montants)
✅ Astronomie, génétique (très grands nombres)
✅ Tailles de fichiers (> 2 GB)

VISUALISATION DE LA TAILLE :

int (4 bytes) :
┌────────────────┐
│  2 milliards   │
└────────────────┘

long long (8 bytes) :
┌────────────────────────────────────────────────┐
│  9 quintillions (4 milliards de fois plus !)  │
└────────────────────────────────────────────────┘
```

### Types à Virgule Flottante

```c
float taille = 1.75f;            // 4 bytes, précision ~7 décimales
double pi = 3.14159265359;       // 8 bytes, précision ~15 décimales
```

### Type Caractère

```c
char lettre = 'A';               // 1 byte, stocke un caractère ASCII
char nouvelle_ligne = '\n';      // Caractère spécial (saut de ligne)
```

### Type Booléen (C99+)

```c
#include <stdbool.h>
bool est_majeur = true;          // 1 byte, true ou false
```

## 4. Syntaxe et Déclaration

### Déclaration Simple
```c
int age;                   // Déclaration (valeur indéfinie !)
age = 25;                  // Affectation
```

### Déclaration avec Initialisation (Recommandé)
```c
int age = 25;              // Déclaration + initialisation
float pi = 3.14f;          // Le 'f' indique un float (sinon c'est un double)
```

### Déclarations Multiples
```c
int x = 10, y = 20, z = 30;        // Même type, même ligne
```

### Constantes (valeur non modifiable)
```c
const int MAX = 100;               // Constante avec const
#define PI 3.14159                 // Macro (ancienne méthode)
```

### Format Specifiers pour printf

| Type       | Specifier | Exemple               |
|------------|-----------|-----------------------|
| `int`      | `%d`      | `printf("%d", age);`  |
| `unsigned` | `%u`      | `printf("%u", val);`  |
| `float`    | `%f`      | `printf("%.2f", x);`  |
| `double`   | `%lf`     | `printf("%lf", pi);`  |
| `char`     | `%c`      | `printf("%c", 'A');`  |
| `string`   | `%s`      | `printf("%s", txt);`  |
| `pointeur` | `%p`      | `printf("%p", &age);` |

## 5. Sous le Capot

### Représentation en Mémoire

Un `int` de valeur `42` est stocké en binaire :
```
Décimal : 42
Binaire : 00000000 00000000 00000000 00101010
Hexa    : 0x0000002A
```

### Exemple en Assembleur (x86-64)

```asm
; int age = 25;
mov dword ptr [rbp-4], 25    ; Stocke 25 dans la stack

; age = age + 10;
mov eax, dword ptr [rbp-4]   ; Charge age dans EAX
add eax, 10                  ; Ajoute 10
mov dword ptr [rbp-4], eax   ; Stocke le résultat
```

### Taille des Types avec sizeof()

```c
printf("Tailles en bytes :\n");
printf("char   : %zu\n", sizeof(char));      // 1
printf("int    : %zu\n", sizeof(int));       // 4
printf("float  : %zu\n", sizeof(float));     // 4
printf("double : %zu\n", sizeof(double));    // 8
printf("long   : %zu\n", sizeof(long));      // 4 ou 8
```

## 6. Conversions de Types (Casting) - Explications Complètes

### 6.1 Qu'est-ce qu'une Conversion ? (Pour Bien Comprendre)

**Conversion** = Transformer une valeur d'un type vers un autre type.

**Analogie** : Comme **traduire** d'une langue à une autre :
- Français → Anglais : "Bonjour" → "Hello"
- int → float : 10 → 10.0

```ascii
AVANT Conversion :
┌──────────────┐
│ int a = 10   │  Type : int
│ [0x0A 0x00   │  Stockage : 4 bytes
│  0x00 0x00]  │  Format : entier
└──────────────┘

APRÈS Conversion en float :
┌──────────────┐
│ float b      │  Type : float
│ [0x00 0x00   │  Stockage : 4 bytes
│  0x20 0x41]  │  Format : IEEE 754 (virgule flottante)
└──────────────┘

Même nombre (10), mais REPRÉSENTATION différente !
```

### 6.2 Conversion Implicite (Automatique) - Détails

**Le compilateur convertit AUTOMATIQUEMENT** dans certains cas.

```c
int a = 10;
float b = a;        // Conversion auto : int → float
```

**Que se passe-t-il exactement ?**

```ascii
═══════════════════════════════════════════════════════════
ÉTAPE 1 : Lire "int a" depuis mémoire
═══════════════════════════════════════════════════════════

Adresse 0x1000 :
┌────┬────┬────┬────┐
│0x0A│0x00│0x00│0x00│  = 10 (format int)
└────┴────┴────┴────┘

CPU charge dans registre :
RAX = 0x000000000000000A (10 en entier)

═══════════════════════════════════════════════════════════
ÉTAPE 2 : Conversion int → float
═══════════════════════════════════════════════════════════

CPU utilise instruction spéciale : CVTSI2SS
(ConVert Signed Integer TO Single-precision floating-point)

Algorithme de conversion :
1. Prendre 10 (entier)
2. Le représenter en format IEEE 754
3. 10.0 en IEEE 754 = 0x41200000

═══════════════════════════════════════════════════════════
ÉTAPE 3 : Stocker dans "float b"
═══════════════════════════════════════════════════════════

Adresse 0x1010 :
┌────┬────┬────┬────┐
│0x00│0x00│0x20│0x41│  = 10.0 (format float)
└────┴────┴────┴────┘

MÊME VALEUR (10), mais REPRÉSENTATION complètement différente !
```

**Conversions Implicites Autorisées** :

```ascii
┌─────────────────────────────────────────────────────┐
│  DIRECTION DES CONVERSIONS AUTOMATIQUES             │
├─────────────────────────────────────────────────────┤
│                                                     │
│  char → short → int → long → long long             │
│    ↓      ↓      ↓      ↓        ↓                 │
│  float ───────────→ double                          │
│                                                     │
│  ✅ Vers la DROITE : Automatique (pas de perte)    │
│  ❌ Vers la GAUCHE : Nécessite cast explicite      │
│                                                     │
└─────────────────────────────────────────────────────┘

EXEMPLES :

char c = 65;
int i = c;      ✅ OK (char → int, élargissement)

int x = 1000;
char c2 = x;    ⚠️ Perte ! (int → char, compilateur warning)
                   1000 ne tient pas dans 1 byte !
```

### 6.3 Conversion Explicite (Cast) - En Profondeur

**Cast** = Forcer une conversion avec `(type)`.

```c
float x = 3.7f;
int y = (int)x;     // Cast forcé : float → int
```

**Que fait le (int) ?**

```ascii
═══════════════════════════════════════════════════════════
SANS CAST :
═══════════════════════════════════════════════════════════

int y = x;  // ❌ Compilateur proteste :
            //    "Warning: conversion from float to int"

═══════════════════════════════════════════════════════════
AVEC CAST :
═══════════════════════════════════════════════════════════

int y = (int)x;  // ✅ "Je sais ce que je fais"

ÉTAPE 1 : Lire float x = 3.7

Mémoire :
0x1000 : [float 3.7 en IEEE 754]

CPU charge dans registre flottant :
XMM0 = 3.7 (format virgule flottante)

ÉTAPE 2 : Cast (int)

CPU utilise instruction : CVTTSS2SI
(ConVerT with Truncation Single to Signed Integer)

Algorithme :
1. Prendre 3.7
2. TRONQUER (enlever .7, pas arrondir)
3. Garder seulement 3

ÉTAPE 3 : Stocker dans int y

y = 3 (partie entière seulement)

┌────────────────────────────────────────┐
│  3.7 (float) ──CAST──→ 3 (int)        │
│                  ↓                    │
│          Partie décimale             │
│          PERDUE : .7 ❌              │
└────────────────────────────────────────┘
```

**Cast = Perte de Précision** :

```ascii
DIRECTION        RÉSULTAT
────────────────────────────────────────
float → int      Perd les décimales
double → float   Perd la précision
int → char       Perd si nombre > 255
long → int       Perd si nombre > 2 milliards

VISUALISATION :

Original (double) : 3.14159265359  (15 décimales)
         ↓ cast
Cast (float) :      3.1415927      (7 décimales)
         ↓ cast
Cast (int) :        3              (0 décimales)

Chaque conversion perd de l'information !
```

### 6.4 Piège Mortel : La Division Entière (Explications Complètes)

**Problème Classique** :

```c
int a = 10, b = 3;
float resultat = a / b;
printf("%.2f\n", resultat);  // Affiche : 3.00 ❌ (pas 3.33)
```

**Pourquoi 3.00 et pas 3.33 ?**

```ascii
═══════════════════════════════════════════════════════════
EXPLICATION PAS-À-PAS :
═══════════════════════════════════════════════════════════

Code : float resultat = a / b;
                        └─┬─┘
                          │
                    Cette partie d'abord !

ÉTAPE 1 : Calculer "a / b"

a = 10 (int)
b = 3  (int)

Règle du C : int / int = int (division ENTIÈRE)

10 / 3 en division entière :
  10 ÷ 3 = 3 reste 1
           ↓
  Résultat : 3 (on ignore le reste)

┌──────────────────────────────────┐
│  a / b = 3 (int)                 │
│          └─ Pas 3.333...         │
│             Reste jeté !          │
└──────────────────────────────────┘

ÉTAPE 2 : Assigner à float

resultat = 3;  // 3 (int) converti en 3.0 (float)

┌──────────────────────────────────┐
│  TROP TARD !                     │
│  La division entière a déjà       │
│  perdu la partie décimale         │
│  3.0 ≠ 3.333...                  │
└──────────────────────────────────┘

═══════════════════════════════════════════════════════════
SOLUTION : Caster AVANT la division
═══════════════════════════════════════════════════════════

float correct = (float)a / b;
                └────┬────┘
                     │
              a devient float d'abord

ÉTAPE 1 : Caster a en float

a = 10 (int) → 10.0 (float)

ÉTAPE 2 : Division

10.0 (float) / 3 (int)
│              │
│              └─ Converti auto en 3.0 (float)
│
Règle : float / float = float

10.0 / 3.0 = 3.333... ✅

VISUALISATION :

MAUVAIS :
int/int → int → float
10 / 3  →  3  → 3.0   ❌ Perte !

BON :
float/int → float
10.0 / 3  → 3.333...  ✅ Correct !
```

### 6.5 Table Complète des Conversions et Leurs Effets

```ascii
┌──────────┬──────────┬────────────┬──────────────────┐
│  De      │  Vers    │  Résultat  │  Exemple         │
├──────────┼──────────┼────────────┼──────────────────┤
│  int     │  float   │  ✅ OK     │  10 → 10.0       │
│  int     │  double  │  ✅ OK     │  10 → 10.0       │
│  float   │  double  │  ✅ OK     │  3.14 → 3.14     │
├──────────┼──────────┼────────────┼──────────────────┤
│  float   │  int     │  ⚠️ Perte  │  3.7 → 3         │
│  double  │  float   │  ⚠️ Perte  │  Précision ↓     │
│  int     │  char    │  ⚠️ Perte  │  300 → 44 (bug!) │
│  long    │  int     │  ⚠️ Perte  │  Si > 2^31       │
└──────────┴──────────┴────────────┴──────────────────┘
```

## 7. Sécurité & Risques

### ⚠️ Dépassement de Capacité (Overflow)

```c
unsigned char compteur = 255;
compteur = compteur + 1;     // Overflow : 255 + 1 = 0 !
printf("%d\n", compteur);    // Affiche : 0
```

### ⚠️ Variables Non Initialisées

```c
int age;                     // Valeur indéfinie (garbage)
printf("%d\n", age);         // Comportement imprévisible !

// TOUJOURS initialiser :
int age = 0;                 // Sûr
```

### ⚠️ Perte de Précision

```c
double precis = 3.14159265359;
float imprecis = precis;     // Perte de précision
printf("%.10f\n", imprecis); // Moins de décimales correctes
```

### ⚠️ Signed vs Unsigned

```c
int signe = -10;
unsigned int non_signe = signe;  // Comportement dangereux !
printf("%u\n", non_signe);       // Affiche un grand nombre positif !
```

## 8. Bonnes Pratiques

1. **Toujours initialiser** vos variables à la déclaration
2. **Utiliser des noms descriptifs** : `age` plutôt que `a`
3. **Choisir le bon type** : pas besoin d'un `long` pour une note sur 20
4. **Utiliser `const`** pour les valeurs qui ne changent pas
5. **Attention aux conversions** : toujours vérifier les casts

## 9. Exercice Mental

Que se passe-t-il ici ?
```c
unsigned char max = 255;
max = max + 1;
printf("%d\n", max);  // ?
```

<details>
<summary>Réponse</summary>

**Affiche : 0**

Explication : Un `unsigned char` peut stocker des valeurs de 0 à 255 (8 bits). Quand on dépasse 255, il y a un **overflow** et la valeur revient à 0 (comme un compteur qui tourne).

Binaire :
- 255 = `11111111`
- 255 + 1 = `100000000` (9 bits)
- Mais un char fait 8 bits → on garde `00000000` = 0
</details>

## 10. Ressources Complémentaires

- [Documentation C - Types de base](https://en.cppreference.com/w/c/language/arithmetic_types)
- [Tailles des types selon l'architecture](https://en.cppreference.com/w/c/types/limits)
- [Format specifiers complets](https://en.cppreference.com/w/c/io/fprintf)


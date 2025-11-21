# Cours 03 : Printf et Scanf - Entrées/Sorties

## 1. Introduction

`printf()` et `scanf()` sont les **portes d'entrée et de sortie** de vos programmes. Ils permettent de communiquer avec l'utilisateur :
- **printf** : Afficher des données (**sortie** vers l'écran)
- **scanf** : Lire des données (**entrée** depuis le clavier)

Ces fonctions font partie de la bibliothèque standard `stdio.h` (Standard Input/Output).

## 2. Visualisation : Comprendre les Flux de Données

### 2.1 Les Trois Acteurs

```ascii
┌─────────────────────────────────────────────────────────┐
│                    UTILISATEUR (Vous)                   │
│                                                         │
│  👤 Tape au clavier    👁️ Voit à l'écran               │
└───────────────┬───────────────────────┬─────────────────┘
                │ Entrée                │ Sortie
                │ (Input)               │ (Output)
                ↓                       ↑
┌───────────────────────────────────────────────────────┐
│               BUFFERS DU SYSTÈME                      │
│                                                       │
│  ┌──────────────┐         ┌──────────────┐           │
│  │ stdin        │         │ stdout       │           │
│  │ (Buffer      │         │ (Buffer      │           │
│  │  d'entrée)   │         │  de sortie)  │           │
│  └──────┬───────┘         └───────┬──────┘           │
└─────────┼───────────────────────── ┼──────────────────┘
          │                          │
          │ scanf()                  │ printf()
          ↓                          ↑
┌─────────────────────────────────────────────────────────┐
│               VOTRE PROGRAMME C                         │
│                                                         │
│  int age;                                               │
│  scanf("%d", &age);  ← Lit depuis stdin                │
│  printf("Age: %d", age);  ← Écrit vers stdout          │
│                                                         │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ↓
┌─────────────────────────────────────────────────────────┐
│                   MÉMOIRE RAM                           │
│                                                         │
│  Adresse 0x1000 : [age] = 25                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Flux Détaillé - scanf() Étape par Étape

Voyons **exactement** ce qui se passe quand l'utilisateur tape un nombre :

```ascii
PROGRAMME :
scanf("%d", &age);  // Programme attend une entrée

ÉTAPE 1 - Utilisateur tape "25" et appuie sur Entrée :

CLAVIER :    [2] [5] [Enter]
              ↓   ↓     ↓

ÉTAPE 2 - Caractères vont dans le buffer stdin :

┌────────────────────────────────────┐
│  BUFFER stdin (Système)            │
│  ┌────┬────┬────┬────┐             │
│  │'2' │'5' │'\n'│    │             │
│  └────┴────┴────┴────┘             │
│   0x32 0x35 0x0A                   │
│   ↑    ↑    ↑                      │
│   │    │    └─ Newline (Enter)     │
│   │    └─ Caractère '5'            │
│   └─ Caractère '2'                 │
└────────────────────────────────────┘

ÉTAPE 3 - scanf() lit et convertit :

┌────────────────────────────────────┐
│  scanf("%d", &age)                 │
│                                    │
│  1. Lit "25\n" depuis stdin        │
│  2. Reconnaît %d (entier)          │
│  3. Convertit "25" (texte)         │
│     → 25 (nombre binaire)          │
│  4. Stocke à l'adresse &age        │
└────────────────────────────────────┘

ÉTAPE 4 - Stockage en mémoire :

┌────────────────────────────────────┐
│  MÉMOIRE RAM                       │
│                                    │
│  &age = 0x1000                     │
│  ┌────┬────┬────┬────┐             │
│  │0x19│0x00│0x00│0x00│             │  
│  └────┴────┴────┴────┘             │
│       = 25 en int                  │
└────────────────────────────────────┘

RÉSULTAT : age contient maintenant 25 (nombre utilisable)
```

### 2.3 Flux Détaillé - printf() Étape par Étape

```ascii
PROGRAMME :
printf("Age : %d ans\n", age);  // age = 25

ÉTAPE 1 - printf analyse la chaîne de format :

Format String : "Age : %d ans\n"
                       ↑
                       └─ Placeholder (sera remplacé)

ÉTAPE 2 - Construction du message :

┌────────────────────────────────────┐
│  printf() interne :                │
│                                    │
│  "Age : " + age + " ans\n"         │
│  "Age : " + 25  + " ans\n"         │
│                                    │
│  Conversion 25 (binaire)           │
│  → "25" (texte ASCII)              │
│                                    │
│  Résultat : "Age : 25 ans\n"       │
└────────────────────────────────────┘

ÉTAPE 3 - Écriture dans buffer stdout :

┌────────────────────────────────────┐
│  BUFFER stdout                     │
│  ┌────────────────────────┐        │
│  │'A''g''e'' '':'' ''2''5'│        │
│  │' ''a''n''s''\n'        │        │
│  └────────────────────────┘        │
└────────────────────────────────────┘

ÉTAPE 4 - Flush vers l'écran :

Le buffer est vidé (flushed) quand :
- Il y a un '\n' (newline)
- Le buffer est plein
- Vous appelez fflush()
- Le programme se termine

ÉCRAN :
┌────────────────────────────────────┐
│  Terminal                          │
│  $ ./programme                     │
│  Age : 25 ans                      │
│  $                                 │
└────────────────────────────────────┘
```

### 2.4 Le Rôle Crucial du '&' dans scanf

**Question** : Pourquoi `scanf("%d", &age)` et pas `scanf("%d", age)` ?

**Réponse Détaillée** :

```ascii
scanf() doit MODIFIER la variable age.

PROBLÈME avec scanf("%d", age) :
┌────────────────────────────────────┐
│  age = 0 (valeur initiale)         │
│                                    │
│  scanf() reçoit 0 (la VALEUR)      │
│  scanf() ne sait PAS où est        │
│  stocké age en mémoire             │
│  → Impossible de modifier age !    │
└────────────────────────────────────┘

SOLUTION avec scanf("%d", &age) :
┌────────────────────────────────────┐
│  &age = 0x1000 (ADRESSE)           │
│                                    │
│  scanf() reçoit 0x1000             │
│  scanf() sait maintenant OÙ        │
│  est stocké age                    │
│  → Peut écrire directement à       │
│     l'adresse 0x1000               │
└────────────────────────────────────┘

VISUALISATION :

Sans & (ERREUR) :
scanf("%d", age)
       ↓
scanf reçoit → [25] (valeur, inutile)
                     Ne peut rien faire

Avec & (CORRECT) :
scanf("%d", &age)
       ↓
scanf reçoit → [0x1000] (adresse)
                   ↓
         Va à cette adresse
                   ↓
         ┌──────────────┐
0x1000   │  ÉCRIT 25    │  ✅
         └──────────────┘
```

## 3. Printf - Affichage Formaté

### Syntaxe de Base

```c
printf("format string", argument1, argument2, ...);
```

### Format Specifiers Essentiels

| Specifier | Type          | Exemple                          | Sortie          |
|-----------|---------------|----------------------------------|-----------------|
| `%d`      | int           | `printf("%d", 42);`              | `42`            |
| `%u`      | unsigned int  | `printf("%u", 300);`             | `300`           |
| `%f`      | float/double  | `printf("%f", 3.14);`            | `3.140000`      |
| `%.2f`    | 2 décimales   | `printf("%.2f", 3.14159);`       | `3.14`          |
| `%c`      | char          | `printf("%c", 'A');`             | `A`             |
| `%s`      | string        | `printf("%s", "Bonjour");`       | `Bonjour`       |
| `%x`      | hexadécimal   | `printf("%x", 255);`             | `ff`            |
| `%p`      | pointeur      | `printf("%p", &age);`            | `0x7fff5...`    |
| `%%`      | % littéral    | `printf("100%%");`               | `100%`          |

### Modificateurs de Largeur

```c
// Largeur fixe (alignement à droite par défaut)
printf("[%5d]\n", 42);        // [   42]
printf("[%5d]\n", 12345);     // [12345]

// Alignement à gauche avec '-'
printf("[%-5d]\n", 42);       // [42   ]

// Zéros à gauche avec '0'
printf("[%05d]\n", 42);       // [00042]

// Précision pour les floats
printf("[%8.2f]\n", 3.14);    // [    3.14]
```

### Caractères Spéciaux (Escape Sequences)

```c
printf("Bonjour\n");          // \n : Nouvelle ligne
printf("Nom:\tJohn\n");       // \t : Tabulation
printf("Chemin: C:\\Users\n");// \\ : Backslash littéral
printf("Il dit \"Hi!\"\n");   // \" : Guillemets
```

### Exemples Pratiques

```c
int age = 25;
float taille = 1.75f;
char grade = 'A';

// Affichage simple
printf("Age : %d ans\n", age);
printf("Taille : %.2f m\n", taille);
printf("Grade : %c\n", grade);

// Affichage multiple
printf("Profil : %s, %d ans, %.2f m\n", "John", age, taille);

// Formatage aligné (tableau)
printf("%-10s | %5s | %10s\n", "Nom", "Age", "Taille");
printf("%-10s | %5d | %10.2f\n", "Alice", 25, 1.65);
printf("%-10s | %5d | %10.2f\n", "Bob", 30, 1.82);
```

## 4. Scanf - Lecture au Clavier

### Syntaxe Critique

```c
scanf("format", &variable);  // ATTENTION AU & (adresse) !
```

### Pourquoi le `&` ?

`scanf()` doit **modifier** la variable. En C, pour modifier une variable dans une fonction, on lui passe son **adresse mémoire** (pointeur). Le `&` signifie "adresse de".

```ascii
MÉMOIRE
+------------------+
| age = ???        | ← Adresse : 0x7fff5...
+------------------+

scanf("%d", &age);   // Donne l'adresse à scanf
                     // scanf écrit directement dans la mémoire
```

### Lecture de Différents Types

```c
int age;
printf("Entrez votre âge : ");
scanf("%d", &age);  // Lit un entier

float taille;
printf("Entrez votre taille (m) : ");
scanf("%f", &taille);  // Lit un float

char lettre;
printf("Entrez une lettre : ");
scanf(" %c", &lettre);  // ← ESPACE avant %c important !

// Lire plusieurs valeurs
int jour, mois, annee;
printf("Date (JJ MM AAAA) : ");
scanf("%d %d %d", &jour, &mois, &annee);
```

### ⚠️ Piège : Le Buffer et le `\n`

```c
// PROBLÈME
int nombre;
char lettre;

printf("Entrez un nombre : ");
scanf("%d", &nombre);        // Laisse '\n' dans le buffer !

printf("Entrez une lettre : ");
scanf("%c", &lettre);        // Lit le '\n' restant !

// SOLUTION 1 : Espace avant %c
scanf(" %c", &lettre);       // L'espace consomme les blancs

// SOLUTION 2 : Vider le buffer
while(getchar() != '\n');    // Consomme tout jusqu'au '\n'
```

### Vérification de la Saisie

```c
int age;
int resultat;

printf("Entrez votre âge : ");
resultat = scanf("%d", &age);

if (resultat == 1) {
    printf("OK : %d ans\n", age);
} else {
    printf("Erreur de saisie !\n");
}
```

## 5. Sous le Capot

### Comment printf Fonctionne

1. **Parsing** : Analyse la format string
2. **Conversion** : Convertit les arguments en texte
3. **Buffer** : Stocke dans un buffer temporaire
4. **Flush** : Envoie au terminal (stdout)

```c
printf("Age : %d\n", 25);
```

Devient en assembleur (simplifié) :
```asm
; Préparer les arguments (convention d'appel)
mov rdi, format_string    ; "Age : %d\n"
mov rsi, 25               ; Le nombre
call printf               ; Appel système
```

### Comment scanf Fonctionne

1. **Attente** : Bloque jusqu'à ce que l'utilisateur tape Enter
2. **Parsing** : Lit depuis le buffer stdin
3. **Conversion** : Convertit le texte en type voulu
4. **Écriture** : Stocke à l'adresse fournie

```c
scanf("%d", &age);
```

Assembleur (simplifié) :
```asm
lea rdi, format           ; "%d"
lea rsi, [rbp-4]          ; Adresse de 'age'
call scanf
```

## 6. Sécurité & Risques

### ⚠️ Buffer Overflow avec scanf

```c
char nom[10];
scanf("%s", nom);         // DANGEREUX ! Pas de limite
// Si l'utilisateur tape 50 caractères → CRASH

// SÉCURISÉ :
scanf("%9s", nom);        // Limite à 9 caractères (+ '\0')
```

### ⚠️ Format String Vulnerability

```c
char buffer[100];
fgets(buffer, 100, stdin);

// DANGEREUX :
printf(buffer);           // Si buffer contient "%x%x%x" → fuite mémoire

// SÉCURISÉ :
printf("%s", buffer);     // Toujours spécifier le format
```

### ⚠️ Oublier le `&` avec scanf

```c
int age;
scanf("%d", age);         // ERREUR ! Segmentation Fault
scanf("%d", &age);        // CORRECT
```

### ⚠️ Type Mismatch

```c
int age;
scanf("%f", &age);        // ERREUR ! %f attend un float*, pas un int*
```

## 7. Alternatives Sécurisées

### fgets() au lieu de scanf("%s")

```c
char nom[50];

// Au lieu de :
scanf("%s", nom);  // Dangereux

// Utiliser :
fgets(nom, 50, stdin);
nom[strcspn(nom, "\n")] = 0;  // Enlever le '\n' final
```

### sscanf() pour Parsing Avancé

```c
char input[100] = "John 25 1.75";
char nom[50];
int age;
float taille;

sscanf(input, "%s %d %f", nom, &age, &taille);
printf("%s : %d ans, %.2f m\n", nom, age, taille);
```

## 8. Bonnes Pratiques

1. **Toujours** mettre `&` devant les variables dans `scanf()` (sauf pour les strings)
2. **Toujours** spécifier le format dans `printf()` (pas `printf(user_input)`)
3. **Limiter** la taille des entrées avec `scanf("%49s", buffer)`
4. **Vérifier** la valeur de retour de `scanf()` pour détecter les erreurs
5. **Vider** le buffer après `scanf()` si nécessaire
6. **Préférer** `fgets()` pour lire des strings

## 9. Exercice Mental

Que se passe-t-il ici ?
```c
int x = 10, y = 20;
printf("%d + %d = %d\n", x, y);
```

<details>
<summary>Réponse</summary>

**Erreur de compilation ou comportement indéfini !**

Il y a **3 format specifiers** (`%d`) mais seulement **2 arguments** (x et y). Le 3ème `%d` va lire une valeur aléatoire sur la stack.

**Correction** :
```c
printf("%d + %d = %d\n", x, y, x + y);
```
</details>

## 10. Ressources Complémentaires

- [Documentation printf](https://en.cppreference.com/w/c/io/fprintf)
- [Documentation scanf](https://en.cppreference.com/w/c/io/fscanf)
- [Format specifiers complets](https://www.cplusplus.com/reference/cstdio/printf/)
- [Sécurité : Format String Attacks](https://owasp.org/www-community/attacks/Format_string_attack)


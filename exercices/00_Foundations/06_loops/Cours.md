# Cours 06 : Boucles (Loops)

## 1. Introduction

Les boucles permettent de **répéter du code** sans le réécrire. C'est l'un des concepts les plus puissants de la programmation. En C, il existe trois types de boucles :
- **for** : Quand on connaît le nombre d'itérations
- **while** : Tant qu'une condition est vraie
- **do-while** : Exécute au moins une fois, puis continue si condition vraie

## 2. Visualisation : Flux de Contrôle

```ascii
BOUCLE FOR                  BOUCLE WHILE              DO-WHILE
┌────────────┐              ┌─────────┐              ┌─────────┐
│ Init: i=0  │              │ Condition?            │  Code   │
└─────┬──────┘              │  (i < 5)│              └────┬────┘
      │                     └────┬────┘                   │
      v                          │                        v
┌─────────┐                   OUI│NON               ┌─────────┐
│Condition│                      │                  │Condition│
│ (i < 5)?│                      v                  │ (i < 5)?│
└───┬─┬───┘                 ┌────────┐              └──┬───┬──┘
 OUI│ │NON                  │  Code  │              OUI│   │NON
    │ └──→FIN               └────┬───┘                 │   └→FIN
    v                            │                     │
┌────────┐                       v                     │
│  Code  │                  [Incrémente]               │
└────┬───┘                       │                     │
     │                           └──────→ Loop         └→Loop
     v
[i++ (Incrémente)]
     │
     └──────→ Loop
```

## 3. Boucle FOR - La Plus Utilisée

### 3.1 Comprendre le Concept avec une Analogie

**Imaginez** : Vous devez monter un escalier de 5 marches et compter chaque marche.

```ascii
ESCALIER :
         ┌───┐ 5
      ┌──┤   │
   ┌──┤  └───┘ 4
┌──┤  └───┘ 3
│  └───┘ 2
└───┘ 1

Vous : 
1. Commencer à la marche 1 (initialisation)
2. Tant que marche ≤ 5 (condition)
3. Monter à la marche suivante (incrémentation)
```

C'est **exactement** ce que fait une boucle `for` !

### 3.2 Anatomie Complète d'une Boucle FOR

```c
for (int i = 0; i < 5; i++) {
    printf("%d\n", i);
}
```

**Décortiquons CHAQUE partie** :

```ascii
for  (  int i = 0  ;  i < 5  ;  i++  )  {  code  }
│       │          │  │       │  │      │  │
│       │          │  │       │  │      │  └─ Code à répéter
│       │          │  │       │  │      │
│       │          │  │       │  │      └─ Accolades (bloc)
│       │          │  │       │  │
│       │          │  │       │  └─ INCRÉMENTATION
│       │          │  │       │     (après chaque tour)
│       │          │  │       │
│       │          │  │       └─ Point-virgule
│       │          │  │
│       │          │  └─ CONDITION
│       │          │     (testée avant chaque tour)
│       │          │
│       │          └─ Point-virgule
│       │
│       └─ INITIALISATION
│          (exécutée UNE FOIS au début)
│
└─ Mot-clé "for"
```

### 3.3 Exécution Étape par Étape - Animation Visuelle

Regardons **exactement** ce qui se passe, tour par tour :

```ascii
CODE : for (int i = 0; i < 5; i++) { printf("%d ", i); }

═══════════════════════════════════════════════════════════
AVANT LA BOUCLE :
═══════════════════════════════════════════════════════════

Mémoire :
┌──────┐
│  i   │  (n'existe pas encore)
└──────┘

═══════════════════════════════════════════════════════════
INITIALISATION : int i = 0
═══════════════════════════════════════════════════════════

Créer variable i et lui donner 0

┌──────┐
│ i: 0 │  ← Variable créée
└──────┘

═══════════════════════════════════════════════════════════
TOUR 1 :
═══════════════════════════════════════════════════════════

1️⃣ TESTER condition : i < 5 ?
   i = 0, 0 < 5 ? → OUI ✅

2️⃣ EXÉCUTER code :
   printf("%d ", i);  → Affiche : 0
   
3️⃣ INCRÉMENTER :
   i++
   
   ┌──────┐      ┌──────┐
   │ i: 0 │  →   │ i: 1 │
   └──────┘      └──────┘

Sortie jusqu'ici : "0 "

═══════════════════════════════════════════════════════════
TOUR 2 :
═══════════════════════════════════════════════════════════

1️⃣ TESTER : i < 5 ?
   i = 1, 1 < 5 ? → OUI ✅

2️⃣ EXÉCUTER :
   printf("%d ", i);  → Affiche : 1

3️⃣ INCRÉMENTER :
   ┌──────┐      ┌──────┐
   │ i: 1 │  →   │ i: 2 │
   └──────┘      └──────┘

Sortie jusqu'ici : "0 1 "

═══════════════════════════════════════════════════════════
TOUR 3 :
═══════════════════════════════════════════════════════════

1️⃣ TESTER : i < 5 ?
   i = 2, 2 < 5 ? → OUI ✅

2️⃣ EXÉCUTER :
   printf("%d ", i);  → Affiche : 2

3️⃣ INCRÉMENTER :
   ┌──────┐      ┌──────┐
   │ i: 2 │  →   │ i: 3 │
   └──────┘      └──────┘

Sortie jusqu'ici : "0 1 2 "

═══════════════════════════════════════════════════════════
TOUR 4 :
═══════════════════════════════════════════════════════════

1️⃣ TESTER : i < 5 ?
   i = 3, 3 < 5 ? → OUI ✅

2️⃣ EXÉCUTER :
   printf("%d ", i);  → Affiche : 3

3️⃣ INCRÉMENTER :
   ┌──────┐      ┌──────┐
   │ i: 3 │  →   │ i: 4 │
   └──────┘      └──────┘

Sortie jusqu'ici : "0 1 2 3 "

═══════════════════════════════════════════════════════════
TOUR 5 :
═══════════════════════════════════════════════════════════

1️⃣ TESTER : i < 5 ?
   i = 4, 4 < 5 ? → OUI ✅

2️⃣ EXÉCUTER :
   printf("%d ", i);  → Affiche : 4

3️⃣ INCRÉMENTER :
   ┌──────┐      ┌──────┐
   │ i: 4 │  →   │ i: 5 │
   └──────┘      └──────┘

Sortie jusqu'ici : "0 1 2 3 4 "

═══════════════════════════════════════════════════════════
TOUR 6 (Tentative) :
═══════════════════════════════════════════════════════════

1️⃣ TESTER : i < 5 ?
   i = 5, 5 < 5 ? → NON ❌
   
   SORTIE DE LA BOUCLE !

═══════════════════════════════════════════════════════════
APRÈS LA BOUCLE :
═══════════════════════════════════════════════════════════

┌──────┐
│ i: 5 │  ← i existe toujours (dans certains compilateurs)
└──────┘

Sortie finale : "0 1 2 3 4 "

Le code continue après la boucle...
```

### 3.4 Diagramme de Flux de Contrôle

```ascii
               ┌─────────────────┐
               │  Début FOR      │
               └────────┬────────┘
                        │
                        ↓
               ┌─────────────────┐
               │ INITIALISATION  │
               │   int i = 0     │
               └────────┬────────┘
                        │
                        ↓
            ┌───────────────────────┐
            │   TESTER CONDITION    │
            │      i < 5 ?          │
            └───┬───────────────┬───┘
                │ OUI           │ NON
                ↓               ↓
        ┌───────────────┐   ┌──────────┐
        │  EXÉCUTER     │   │  SORTIR  │
        │  CODE         │   └────┬─────┘
        │  printf(...)  │        │
        └───────┬───────┘        │
                │                │
                ↓                │
        ┌───────────────┐        │
        │ INCRÉMENTER   │        │
        │    i++        │        │
        └───────┬───────┘        │
                │                │
                │                │
                └────────┐       │
                         │       │
                         ↓       ↓
                    ┌─────────────────┐
                    │  Suite du code  │
                    └─────────────────┘

CYCLE : Test → Exécute → Incrémente → Test → ...
        └────────── BOUCLE ──────────┘
```

### Exemples Classiques

```c
// Compter de 1 à 10
for (int i = 1; i <= 10; i++) {
    printf("%d ", i);  // 1 2 3 4 5 6 7 8 9 10
}

// Compter à l'envers
for (int i = 10; i > 0; i--) {
    printf("%d ", i);  // 10 9 8 7 6 5 4 3 2 1
}

// Pas de 2
for (int i = 0; i < 10; i += 2) {
    printf("%d ", i);  // 0 2 4 6 8
}

// Parcourir un tableau
int notes[5] = {15, 18, 12, 16, 14};
for (int i = 0; i < 5; i++) {
    printf("Note %d : %d\n", i+1, notes[i]);
}
```

### For Vide (Boucle Infinie)

```c
for (;;) {
    printf("Infini\n");
    // Nécessite un break pour sortir
}
```

## 4. Boucle WHILE

### Syntaxe

```c
while (condition) {
    // Code à répéter
}
```

### Quand l'Utiliser ?

Quand le **nombre d'itérations est inconnu** à l'avance.

### Exemples

```c
// Compte à rebours
int compte = 5;
while (compte > 0) {
    printf("%d...\n", compte);
    compte--;
}
printf("Décollage!\n");

// Lire jusqu'à entrée valide
int age = -1;
while (age < 0 || age > 120) {
    printf("Entrez votre âge (0-120) : ");
    scanf("%d", &age);
}

// Parcourir une chaîne
char texte[] = "Bonjour";
int i = 0;
while (texte[i] != '\0') {  // Jusqu'au caractère nul
    printf("%c\n", texte[i]);
    i++;
}
```

### ⚠️ Piège : Boucle Infinie

```c
int x = 0;
while (x < 10) {
    printf("x = %d\n", x);
    // OUBLI DE x++ !  → Boucle infinie
}
```

## 5. Boucle DO-WHILE

### Syntaxe

```c
do {
    // Code à répéter
} while (condition);
```

### Différence Clé

Le code est **toujours exécuté au moins une fois**, même si la condition est fausse dès le départ.

```c
// WHILE : Peut ne jamais s'exécuter
int x = 10;
while (x < 5) {
    printf("Jamais affiché\n");
}

// DO-WHILE : S'exécute au moins une fois
do {
    printf("Affiché une fois\n");
} while (x < 5);
```

### Cas d'Usage : Menu Interactif

```c
int choix;
do {
    printf("\n=== MENU ===\n");
    printf("1. Option 1\n");
    printf("2. Option 2\n");
    printf("3. Quitter\n");
    printf("Votre choix : ");
    scanf("%d", &choix);

    switch (choix) {
        case 1:
            printf("Option 1 sélectionnée\n");
            break;
        case 2:
            printf("Option 2 sélectionnée\n");
            break;
        case 3:
            printf("Au revoir!\n");
            break;
        default:
            printf("Choix invalide\n");
    }
} while (choix != 3);
```

## 6. Contrôle de Flux : break et continue

### break : Sortir de la Boucle

```c
// Sortir dès qu'on trouve un nombre négatif
for (int i = 0; i < 10; i++) {
    int nombre;
    printf("Entrez un nombre : ");
    scanf("%d", &nombre);

    if (nombre < 0) {
        printf("Nombre négatif détecté, arrêt.\n");
        break;  // Sort immédiatement de la boucle
    }

    printf("Vous avez entré : %d\n", nombre);
}
```

### continue : Sauter une Itération

```c
// Afficher seulement les nombres impairs
for (int i = 1; i <= 10; i++) {
    if (i % 2 == 0) {
        continue;  // Saute le reste et passe à i++
    }
    printf("%d ", i);  // 1 3 5 7 9
}
```

### Différence break vs continue

```c
for (int i = 0; i < 5; i++) {
    if (i == 2) break;      // Sort de la boucle
    printf("%d ", i);       // Affiche : 0 1
}

for (int i = 0; i < 5; i++) {
    if (i == 2) continue;   // Saute seulement i=2
    printf("%d ", i);       // Affiche : 0 1 3 4
}
```

## 7. Boucles Imbriquées

Des boucles à l'intérieur d'autres boucles.

### Table de Multiplication

```c
for (int i = 1; i <= 5; i++) {
    for (int j = 1; j <= 5; j++) {
        printf("%d x %d = %2d   ", i, j, i*j);
    }
    printf("\n");
}
```

Sortie :
```
1 x 1 =  1   1 x 2 =  2   1 x 3 =  3   1 x 4 =  4   1 x 5 =  5   
2 x 1 =  2   2 x 2 =  4   2 x 3 =  6   2 x 4 =  8   2 x 5 = 10   
...
```

### Motif Triangle

```c
for (int i = 1; i <= 5; i++) {
    for (int j = 1; j <= i; j++) {
        printf("* ");
    }
    printf("\n");
}
```

Sortie :
```
* 
* * 
* * * 
* * * * 
* * * * * 
```

### ⚠️ Complexité : O(n²)

```c
// Cette boucle fait n * n itérations
for (int i = 0; i < n; i++) {
    for (int j = 0; j < n; j++) {
        // Code exécuté n² fois
    }
}
```

## 8. Sous le Capot

### Compilation d'une Boucle for

```c
for (int i = 0; i < 5; i++) {
    printf("%d\n", i);
}
```

Assembleur (x86-64) :
```asm
; int i = 0
mov dword ptr [rbp-4], 0

loop_start:
; Vérifier i < 5
mov eax, [rbp-4]
cmp eax, 5
jge loop_end           ; Si i >= 5, sortir

; printf("%d\n", i)
mov edi, format        ; "%d\n"
mov esi, [rbp-4]       ; i
call printf

; i++
inc dword ptr [rbp-4]
jmp loop_start

loop_end:
```

### Optimisations du Compilateur

Le compilateur peut **dérouler** (unroll) les boucles courtes :

```c
// Code original
for (int i = 0; i < 4; i++) {
    tableau[i] = 0;
}

// Optimisé par le compilateur (loop unrolling)
tableau[0] = 0;
tableau[1] = 0;
tableau[2] = 0;
tableau[3] = 0;
```

## 9. Patterns Courants

### Calcul de Somme

```c
int somme = 0;
for (int i = 1; i <= 10; i++) {
    somme += i;  // somme = somme + i
}
printf("Somme : %d\n", somme);  // 55
```

### Recherche dans un Tableau

```c
int nombres[] = {10, 25, 3, 42, 7};
int cherche = 42;
int trouve = 0;

for (int i = 0; i < 5; i++) {
    if (nombres[i] == cherche) {
        printf("Trouvé à l'index %d\n", i);
        trouve = 1;
        break;
    }
}

if (!trouve) {
    printf("Non trouvé\n");
}
```

### Compteur avec Flag

```c
int compteur = 0;
for (int i = 1; i <= 100; i++) {
    if (i % 3 == 0 || i % 5 == 0) {
        compteur++;
    }
}
printf("Nombres divisibles par 3 ou 5 : %d\n", compteur);
```

## 10. Sécurité & Risques

### ⚠️ Boucle Infinie

```c
// Oubli d'incrémentation
int i = 0;
while (i < 10) {
    printf("%d\n", i);
    // MANQUE i++ !
}

// Condition toujours vraie
while (1) {  // Boucle infinie volontaire
    // ...
}
```

### ⚠️ Off-by-One Error

```c
int tab[5] = {1, 2, 3, 4, 5};

// ERREUR : i <= 5 au lieu de i < 5
for (int i = 0; i <= 5; i++) {  // Accès à tab[5] !
    printf("%d\n", tab[i]);     // Buffer overflow
}

// CORRECT
for (int i = 0; i < 5; i++) {
    printf("%d\n", tab[i]);
}
```

### ⚠️ Modification du Compteur

```c
// DANGEREUX
for (int i = 0; i < 10; i++) {
    if (condition) {
        i += 5;  // Modification du compteur dans la boucle
    }
}
// Comportement difficile à prédire
```

## 11. Bonnes Pratiques

1. **Toujours initialiser** les compteurs
2. **Vérifier** les conditions de sortie pour éviter les boucles infinies
3. **Utiliser for** quand le nombre d'itérations est connu
4. **Utiliser while** quand on attend une condition externe
5. **Utiliser do-while** pour les menus interactifs
6. **Limiter** la profondeur d'imbrication (max 2-3 niveaux)
7. **Extraire** les boucles complexes dans des fonctions

## 12. Choix de la Boucle

| Situation                          | Boucle Recommandée |
|------------------------------------|--------------------|
| Nombre d'itérations connu          | `for`              |
| Parcourir un tableau/liste         | `for`              |
| Attendre une condition             | `while`            |
| Valider une entrée utilisateur     | `while` ou `do-while` |
| Menu interactif                    | `do-while`         |
| Boucle infinie (serveur, jeu...)   | `while(1)` ou `for(;;)` |

## 13. Exercice Mental

Combien de fois "Hello" est affiché ?
```c
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 2; j++) {
        printf("Hello\n");
    }
}
```

<details>
<summary>Réponse</summary>

**6 fois**

- Boucle externe : 3 itérations (i = 0, 1, 2)
- Boucle interne : 2 itérations (j = 0, 1) **pour chaque i**
- Total : 3 × 2 = 6
</details>

## 14. Ressources Complémentaires

- [Documentation for](https://en.cppreference.com/w/c/language/for)
- [Documentation while](https://en.cppreference.com/w/c/language/while)
- [Loop unrolling](https://en.wikipedia.org/wiki/Loop_unrolling)
- [Big-O notation](https://en.wikipedia.org/wiki/Big_O_notation)


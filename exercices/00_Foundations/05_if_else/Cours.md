# Cours 05 : Structures Conditionnelles (if/else)

## 1. Introduction

Les structures conditionnelles permettent à votre programme de **prendre des décisions**. C'est ce qui transforme un programme linéaire en programme intelligent qui s'adapte aux situations.

En C, une condition est **vraie** si elle vaut `1` (ou toute valeur non-zéro), et **fausse** si elle vaut `0`.

## 2. Visualisation : Flux de Contrôle

```ascii
DÉBUT
  |
  v
┌──────────┐
│ if (age  │
│  >= 18)? │
└─┬────┬───┘
  │    │
OUI   NON
  │    │
  v    v
[Majeur] [Mineur]
  │    │
  └────┴──→ FIN
```

## 3. Structure if Simple

### Syntaxe

```c
if (condition) {
    // Code exécuté si condition vraie
}
```

### Exemples

```c
int age = 20;

if (age >= 18) {
    printf("Vous êtes majeur\n");
}

// Sans accolades (1 seule instruction)
if (age >= 18)
    printf("Majeur\n");  // Fonctionne, mais déconseillé
```

### ⚠️ Piège : Affectation vs Comparaison

```c
int x = 10;

// ERREUR FRÉQUENTE
if (x = 5) {              // Affectation ! x devient 5
    printf("Toujours vrai\n");  // Toujours exécuté
}

// CORRECT
if (x == 5) {             // Comparaison
    printf("x vaut 5\n");
}
```

## 4. Structure if-else

### Syntaxe

```c
if (condition) {
    // Si vrai
} else {
    // Sinon
}
```

### Exemple

```c
int temperature = 15;

if (temperature > 20) {
    printf("Il fait chaud\n");
} else {
    printf("Il fait froid\n");
}
```

## 5. Structure if-else if-else

Pour tester plusieurs conditions séquentielles.

### Syntaxe

```c
if (condition1) {
    // Si condition1 vraie
} else if (condition2) {
    // Sinon si condition2 vraie
} else if (condition3) {
    // Sinon si condition3 vraie
} else {
    // Si aucune condition vraie
}
```

### Exemple : Système de Notes

```c
int note = 75;

if (note >= 90) {
    printf("Grade : A (Excellent)\n");
} else if (note >= 80) {
    printf("Grade : B (Très bien)\n");
} else if (note >= 70) {
    printf("Grade : C (Bien)\n");
} else if (note >= 60) {
    printf("Grade : D (Passable)\n");
} else {
    printf("Grade : F (Échec)\n");
}
```

### ⚠️ Important : Ordre des Conditions

```c
// MAUVAIS
if (age >= 0) {               // Toujours vrai en premier
    printf("Vous existez\n");
} else if (age >= 18) {       // Jamais atteint !
    printf("Majeur\n");
}

// CORRECT
if (age >= 18) {
    printf("Majeur\n");
} else if (age >= 0) {
    printf("Mineur\n");
}
```

## 6. Conditions Imbriquées

Des `if` à l'intérieur d'autres `if`.

```c
int age = 25;
int permis = 1;
int voiture = 1;

if (age >= 18) {
    if (permis) {
        if (voiture) {
            printf("Peut conduire!\n");
        } else {
            printf("Pas de voiture\n");
        }
    } else {
        printf("Pas de permis\n");
    }
} else {
    printf("Trop jeune\n");
}
```

### Simplification avec Opérateurs Logiques

```c
// Plus lisible
if (age >= 18 && permis && voiture) {
    printf("Peut conduire!\n");
} else if (age < 18) {
    printf("Trop jeune\n");
} else if (!permis) {
    printf("Pas de permis\n");
} else {
    printf("Pas de voiture\n");
}
```

## 7. Opérateur Ternaire (Alternative Compacte)

### Syntaxe

```c
variable = (condition) ? valeur_si_vrai : valeur_si_faux;
```

### Exemples

```c
int age = 20;
char *statut = (age >= 18) ? "majeur" : "mineur";
printf("Vous êtes %s\n", statut);

// Équivalent à :
char *statut;
if (age >= 18) {
    statut = "majeur";
} else {
    statut = "mineur";
}
```

### Cas d'Usage

```c
// Maximum de deux nombres
int a = 10, b = 20;
int max = (a > b) ? a : b;

// Affichage conditionnel
printf("Nombre : %d (%s)\n", x, (x % 2 == 0) ? "pair" : "impair");

// Valeur absolue
int abs = (x < 0) ? -x : x;
```

## 8. Switch-Case

Alternative à `if-else if` pour tester une **valeur exacte** (pas de comparaisons `<`, `>`, etc.).

### Syntaxe

```c
switch (expression) {
    case valeur1:
        // Code
        break;
    case valeur2:
        // Code
        break;
    default:
        // Code si aucun case ne correspond
}
```

### Exemple : Menu

```c
int choix = 2;

switch (choix) {
    case 1:
        printf("Nouveau fichier\n");
        break;
    case 2:
        printf("Ouvrir fichier\n");
        break;
    case 3:
        printf("Sauvegarder\n");
        break;
    default:
        printf("Option invalide\n");
}
```

### ⚠️ Piège : Oublier `break`

```c
int jour = 2;

switch (jour) {
    case 1:
        printf("Lundi\n");
        // OUBLI DE break !
    case 2:
        printf("Mardi\n");
        break;
    case 3:
        printf("Mercredi\n");
        break;
}
// Affiche "Mardi" même si jour = 1 !
```

### Fall-Through Intentionnel

```c
char grade = 'B';

switch (grade) {
    case 'A':
    case 'B':
    case 'C':
        printf("Admis\n");  // Pour A, B ou C
        break;
    case 'D':
    case 'F':
        printf("Recalé\n");
        break;
}
```

## 9. Sous le Capot

### Compilation d'un if-else

```c
if (x > 10) {
    y = 1;
} else {
    y = 2;
}
```

Assembleur (x86-64) :
```asm
mov eax, [x]           ; Charge x
cmp eax, 10            ; Compare x avec 10
jle else_branch        ; Saute à else si x <= 10

; if branch
mov dword ptr [y], 1   ; y = 1
jmp end                ; Saute à la fin

else_branch:
mov dword ptr [y], 2   ; y = 2

end:
; Suite du programme
```

### Compilation d'un switch

Le compilateur peut optimiser un `switch` avec une **jump table** (tableau de pointeurs) pour O(1) au lieu de O(n).

```c
switch (x) {
    case 0: printf("Zero\n"); break;
    case 1: printf("Un\n"); break;
    case 2: printf("Deux\n"); break;
}
```

Jump table :
```asm
; Table des adresses
jump_table:
    .quad case_0
    .quad case_1
    .quad case_2

; Calcul de l'adresse
mov rax, [x]
jmp [jump_table + rax*8]
```

## 10. Vérité en C

En C, **tout nombre non-zéro** est considéré comme vrai.

```c
if (1) printf("Vrai\n");          // Exécuté
if (42) printf("Vrai\n");         // Exécuté
if (-1) printf("Vrai\n");         // Exécuté
if (0) printf("Jamais\n");        // Jamais exécuté

// Pointeur NULL = 0 = faux
int *ptr = NULL;
if (ptr) {
    printf("Pointeur valide\n");
} else {
    printf("Pointeur NULL\n");    // Exécuté
}

// Piège classique
int x = 5;
if (x = 0) {                      // Affectation, x devient 0
    printf("Jamais affiché\n");
}
```

## 11. Bonnes Pratiques

### 1. Toujours Utiliser des Accolades

```c
// MAUVAIS (dangereux lors de modifications)
if (x > 10)
    printf("Grand\n");
    printf("Très grand\n");  // Toujours exécuté !

// BON
if (x > 10) {
    printf("Grand\n");
    printf("Très grand\n");
}
```

### 2. Inverser les Conditions pour Gérer les Erreurs d'Abord

```c
// MAUVAIS
if (fichier_ouvert) {
    // 50 lignes de code
} else {
    printf("Erreur\n");
    return;
}

// BON (early return)
if (!fichier_ouvert) {
    printf("Erreur\n");
    return;
}
// 50 lignes de code (moins d'indentation)
```

### 3. Éviter les Conditions Trop Complexes

```c
// MAUVAIS
if ((age >= 18 && age <= 65 && permis && voiture) || (age > 65 && special)) {
    // ...
}

// BON
int peut_conduire = (age >= 18 && age <= 65 && permis && voiture);
int senior_special = (age > 65 && special);

if (peut_conduire || senior_special) {
    // ...
}
```

### 4. Utiliser switch pour 3+ Valeurs Exactes

```c
// Si 3 cas ou plus avec égalité exacte, préférer switch
if (x == 1) { ... }
else if (x == 2) { ... }
else if (x == 3) { ... }

// MIEUX
switch (x) {
    case 1: ... break;
    case 2: ... break;
    case 3: ... break;
}
```

## 12. Sécurité & Risques

### ⚠️ Confusion `=` et `==`

```c
if (x = 10) {  // ERREUR ! Toujours vrai
    // ...
}
```

### ⚠️ Comparaisons Flottantes

```c
float x = 0.1 + 0.2;
if (x == 0.3) {  // Peut être faux (imprécision flottante)
    printf("Égal\n");
}

// MIEUX
if (fabs(x - 0.3) < 0.0001) {  // Tolérance
    printf("Égal\n");
}
```

### ⚠️ Oubli de break dans switch

Toujours mettre `break` sauf si fall-through intentionnel (et commenté).

## 13. Exercice Mental

Que se passe-t-il ?
```c
int x = 10;
if (x > 5)
    if (x < 15)
        printf("Entre 5 et 15\n");
else
    printf("Pas entre 5 et 15\n");
```

<details>
<summary>Réponse</summary>

**Affiche : "Entre 5 et 15"**

Le `else` est associé au `if` le **plus proche** (ici `if (x < 15)`), pas au premier `if`.

Pour éviter la confusion :
```c
if (x > 5) {
    if (x < 15) {
        printf("Entre 5 et 15\n");
    } else {
        printf("Pas entre 5 et 15\n");
    }
}
```
</details>

## 14. Ressources Complémentaires

- [Documentation if](https://en.cppreference.com/w/c/language/if)
- [Documentation switch](https://en.cppreference.com/w/c/language/switch)
- [Jump tables](https://en.wikipedia.org/wiki/Branch_table)


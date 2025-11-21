# Cours 07 : Fonctions en C

## 1. Introduction

Les fonctions sont les **blocs de construction** de tout programme structuré. Elles permettent de :
- **Réutiliser** du code (DRY : Don't Repeat Yourself)
- **Organiser** le programme en modules logiques
- **Abstraire** la complexité (masquer les détails d'implémentation)
- **Tester** chaque partie indépendamment

Une fonction est une **boîte noire** : on lui donne des entrées (paramètres), elle fait un traitement, et renvoie un résultat (valeur de retour).

## 2. Visualisation : Anatomie d'une Fonction

```ascii
┌─────────────────────────────────────┐
│  FONCTION : calculer_moyenne        │
├─────────────────────────────────────┤
│  ENTRÉES (Paramètres)               │
│  ↓ int notes[] = {15, 18, 12}      │
│  ↓ int taille = 3                   │
├─────────────────────────────────────┤
│  TRAITEMENT                          │
│  somme = 15 + 18 + 12 = 45          │
│  moyenne = 45 / 3 = 15.0            │
├─────────────────────────────────────┤
│  SORTIE (Retour)                     │
│  ↑ float = 15.0                     │
└─────────────────────────────────────┘
```

## 3. Syntaxe de Base

### Structure Complète

```c
type_retour nom_fonction(type1 param1, type2 param2) {
    // Corps de la fonction
    return valeur;  // Optionnel si void
}
```

### Exemple Simple

```c
int additionner(int a, int b) {
    int resultat = a + b;
    return resultat;
}

// Utilisation
int main() {
    int somme = additionner(10, 20);
    printf("Somme : %d\n", somme);  // 30
    return 0;
}
```

## 4. Types de Fonctions

### 4.1. Fonction void (sans retour)

```c
void afficher_message() {
    printf("Bonjour!\n");
    // Pas de return (ou "return;" sans valeur)
}

void afficher_nombre(int n) {
    printf("Nombre : %d\n", n);
}
```

### 4.2. Fonction avec Retour

```c
int carre(int x) {
    return x * x;
}

float moyenne(int a, int b) {
    return (float)(a + b) / 2;
}

// Retour booléen (0 ou 1)
int est_pair(int n) {
    return (n % 2 == 0);
}
```

### 4.3. Fonction sans Paramètres

```c
int obtenir_nombre_aleatoire() {
    return rand() % 100;  // Entre 0 et 99
}
```

## 5. Prototypes (Déclarations Forward)

Le compilateur C lit le fichier **de haut en bas**. Si vous appelez une fonction avant de la définir, vous devez la **déclarer** en haut.

### Problème

```c
int main() {
    int resultat = multiplier(5, 6);  // ERREUR : multiplier non déclaré
    printf("%d\n", resultat);
    return 0;
}

int multiplier(int a, int b) {
    return a * b;
}
```

### Solution 1 : Prototype en Haut

```c
// PROTOTYPE (déclaration)
int multiplier(int a, int b);

int main() {
    int resultat = multiplier(5, 6);  // OK
    printf("%d\n", resultat);
    return 0;
}

// DÉFINITION
int multiplier(int a, int b) {
    return a * b;
}
```

### Solution 2 : Définir Avant main

```c
int multiplier(int a, int b) {
    return a * b;
}

int main() {
    int resultat = multiplier(5, 6);  // OK
    printf("%d\n", resultat);
    return 0;
}
```

## 6. Passage de Paramètres

### Par Valeur (Copie)

En C, **tout est passé par valeur** par défaut. La fonction reçoit une **copie** du paramètre.

```c
void modifier(int x) {
    x = 100;  // Modifie la copie locale
    printf("Dans fonction : %d\n", x);  // 100
}

int main() {
    int nombre = 50;
    modifier(nombre);
    printf("Dans main : %d\n", nombre);  // 50 (inchangé !)
    return 0;
}
```

### Par Référence (Pointeur)

Pour **modifier** la variable originale, on passe son **adresse**.

```c
void modifier(int *x) {
    *x = 100;  // Modifie la valeur à l'adresse x
}

int main() {
    int nombre = 50;
    modifier(&nombre);  // Passe l'adresse
    printf("Dans main : %d\n", nombre);  // 100 (modifié !)
    return 0;
}
```

### Tableaux : Toujours Passés par Référence

```c
void doubler_valeurs(int tab[], int taille) {
    for (int i = 0; i < taille; i++) {
        tab[i] *= 2;  // Modifie le tableau original
    }
}

int main() {
    int nombres[] = {1, 2, 3, 4, 5};
    doubler_valeurs(nombres, 5);
    
    for (int i = 0; i < 5; i++) {
        printf("%d ", nombres[i]);  // 2 4 6 8 10
    }
    return 0;
}
```

## 7. Fonctions avec Tableaux

### Passer un Tableau

```c
float calculer_moyenne(int tab[], int taille) {
    int somme = 0;
    for (int i = 0; i < taille; i++) {
        somme += tab[i];
    }
    return (float)somme / taille;
}

int main() {
    int notes[] = {15, 18, 12, 16, 14};
    float moy = calculer_moyenne(notes, 5);
    printf("Moyenne : %.2f\n", moy);  // 15.00
    return 0;
}
```

### Retourner un Tableau (Attention !)

```c
// ERREUR : Retourne un pointeur vers un tableau local
int* creer_tableau() {
    int tab[5] = {1, 2, 3, 4, 5};
    return tab;  // DANGER : tab est détruit après le return
}

// CORRECT : Allocation dynamique
int* creer_tableau() {
    int *tab = malloc(5 * sizeof(int));
    for (int i = 0; i < 5; i++) {
        tab[i] = i + 1;
    }
    return tab;  // OK : le tableau survit
}
```

## 8. Retours Multiples (Avec Pointeurs)

Une fonction ne peut retourner qu'**une seule valeur**. Pour retourner plusieurs valeurs, on utilise des **pointeurs**.

```c
void diviser_avec_reste(int dividende, int diviseur, int *quotient, int *reste) {
    *quotient = dividende / diviseur;
    *reste = dividende % diviseur;
}

int main() {
    int q, r;
    diviser_avec_reste(17, 5, &q, &r);
    printf("17 / 5 = %d reste %d\n", q, r);  // 17 / 5 = 3 reste 2
    return 0;
}
```

## 9. Récursivité

Une fonction qui **s'appelle elle-même**.

### Exemple : Factorielle

```c
int factorielle(int n) {
    if (n <= 1) {
        return 1;  // Cas de base (condition d'arrêt)
    }
    return n * factorielle(n - 1);  // Appel récursif
}

// factorielle(5) = 5 * factorielle(4)
//                = 5 * 4 * factorielle(3)
//                = 5 * 4 * 3 * factorielle(2)
//                = 5 * 4 * 3 * 2 * factorielle(1)
//                = 5 * 4 * 3 * 2 * 1
//                = 120
```

### ⚠️ Danger : Stack Overflow

```c
// ERREUR : Pas de condition d'arrêt
int boucle_infinie(int n) {
    return boucle_infinie(n - 1);  // Crash après ~10000 appels
}
```

### Récursivité vs Itération

```c
// Récursif
int somme_recursive(int n) {
    if (n <= 0) return 0;
    return n + somme_recursive(n - 1);
}

// Itératif (plus efficace)
int somme_iterative(int n) {
    int somme = 0;
    for (int i = 1; i <= n; i++) {
        somme += i;
    }
    return somme;
}
```

## 10. Sous le Capot

### La Stack (Pile d'Appels)

```c
int fonction_a() {
    return fonction_b() + 10;
}

int fonction_b() {
    return fonction_c() * 2;
}

int fonction_c() {
    return 5;
}
```

Stack pendant l'exécution :
```ascii
┌───────────────────┐
│ fonction_a()      │ ← Attend fonction_b()
├───────────────────┤
│ fonction_b()      │ ← Attend fonction_c()
├───────────────────┤
│ fonction_c()      │ ← Retourne 5
└───────────────────┘

Dépile :
fonction_c() → 5
fonction_b() → 5 * 2 = 10
fonction_a() → 10 + 10 = 20
```

### Convention d'Appel (x86-64)

```c
int additionner(int a, int b) {
    return a + b;
}
```

Assembleur :
```asm
additionner:
    ; Paramètres dans EDI (a) et ESI (b)
    mov eax, edi        ; a dans EAX
    add eax, esi        ; EAX = a + b
    ret                 ; Retourne (EAX contient le résultat)
```

Appel :
```asm
mov edi, 10            ; Premier paramètre
mov esi, 20            ; Second paramètre
call additionner       ; Appel
; EAX contient maintenant 30
```

## 11. Fonctions dans des Headers

### Structure Typique

**math_utils.h** (Header)
```c
#ifndef MATH_UTILS_H
#define MATH_UTILS_H

int additionner(int a, int b);
int multiplier(int a, int b);
float moyenne(int tab[], int taille);

#endif
```

**math_utils.c** (Implémentation)
```c
#include "math_utils.h"

int additionner(int a, int b) {
    return a + b;
}

int multiplier(int a, int b) {
    return a * b;
}

float moyenne(int tab[], int taille) {
    int somme = 0;
    for (int i = 0; i < taille; i++) {
        somme += tab[i];
    }
    return (float)somme / taille;
}
```

**main.c**
```c
#include <stdio.h>
#include "math_utils.h"

int main() {
    int resultat = additionner(10, 20);
    printf("Résultat : %d\n", resultat);
    return 0;
}
```

Compilation :
```bash
gcc main.c math_utils.c -o program
```

## 12. Fonctions Inline (Optimisation)

```c
// Suggère au compilateur de remplacer l'appel par le code directement
inline int carre(int x) {
    return x * x;
}

// Au lieu de :
// call carre
// Le compilateur génère :
// mov eax, [x]
// imul eax, eax
```

## 13. Sécurité & Risques

### ⚠️ Retourner un Pointeur vers Variable Locale

```c
int* fonction_dangereuse() {
    int x = 42;
    return &x;  // ERREUR ! x est détruit après le return
}
```

### ⚠️ Ne Pas Vérifier les Paramètres

```c
float diviser(float a, float b) {
    return a / b;  // DANGER si b = 0 !
}

// MIEUX
float diviser_safe(float a, float b) {
    if (b == 0) {
        fprintf(stderr, "Erreur : division par zéro\n");
        return 0;
    }
    return a / b;
}
```

### ⚠️ Buffer Overflow avec Tableaux

```c
void copier(char dest[], char src[]) {
    int i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i];  // DANGER : dest peut être trop petit
        i++;
    }
    dest[i] = '\0';
}

// MIEUX
void copier_safe(char dest[], char src[], int max) {
    int i = 0;
    while (src[i] != '\0' && i < max - 1) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}
```

## 14. Bonnes Pratiques

1. **Une fonction = Une tâche** (principe de responsabilité unique)
2. **Nom descriptif** : `calculer_moyenne()` plutôt que `calc()`
3. **Fonctions courtes** : ~20 lignes max (si possible)
4. **Vérifier les paramètres** : NULL, division par zéro, limites
5. **Commenter** les prototypes (ce que fait la fonction, pas comment)
6. **Utiliser const** pour les paramètres non modifiés
```c
float moyenne(const int tab[], int taille);
```
7. **Éviter les effets de bord** : une fonction doit faire ce que son nom indique

## 15. Exercice Mental

Quelle est la sortie ?
```c
int x = 10;

void fonction(int x) {
    x = 20;
}

int main() {
    fonction(x);
    printf("%d\n", x);
    return 0;
}
```

<details>
<summary>Réponse</summary>

**Affiche : 10**

La fonction reçoit une **copie** de `x` (passage par valeur). La modification dans la fonction n'affecte pas la variable originale.

Pour modifier `x`, il faudrait :
```c
void fonction(int *x) {
    *x = 20;
}

fonction(&x);  // Passe l'adresse
```
</details>

## 16. Ressources Complémentaires

- [Documentation fonctions](https://en.cppreference.com/w/c/language/functions)
- [Convention d'appel x86-64](https://en.wikipedia.org/wiki/X86_calling_conventions)
- [Inline functions](https://en.cppreference.com/w/c/language/inline)
- [Function pointers (avancé)](https://www.geeksforgeeks.org/function-pointer-in-c/)


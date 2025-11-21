# Cours : Les Tableaux (Arrays)

## 🎯 Objectif du Module
Comprendre comment les tableaux sont stockés en mémoire, leur relation avec les pointeurs, et pourquoi ils sont à la base de nombreuses vulnérabilités.

---

## 1. Qu'est-ce qu'un Tableau ?

Un **tableau** est une collection de **variables du même type** stockées **consécutivement** en mémoire.

**Analogie :** Une rue avec des maisons numérotées.
- Chaque maison (case du tableau) contient une valeur.
- Toutes les maisons sont alignées, sans espace entre elles.

```c
int ages[5] = {10, 20, 30, 40, 50};
```

### 1.1 Visualisation Mémoire

```
Adresse      Contenu     Variable
--------     -------     --------
0x7ffe00     [ 10 ]      ages[0]
0x7ffe04     [ 20 ]      ages[1]
0x7ffe08     [ 30 ]      ages[2]
0x7ffe0c     [ 40 ]      ages[3]
0x7ffe10     [ 50 ]      ages[4]
```

**Observations :**
- Chaque `int` occupe **4 octets** (sur la plupart des systèmes).
- Les adresses augmentent de 4 en 4 (`0x04` en hexa = 4 en décimal).
- Il n'y a **aucun espace** entre les éléments.

---

## 2. Déclaration et Initialisation

### 2.1 Déclaration Simple
```c
int numbers[5];  // Tableau de 5 entiers (non initialisé, contient du garbage)
```

### 2.2 Initialisation à la Déclaration
```c
int numbers[5] = {1, 2, 3, 4, 5};
```

### 2.3 Initialisation Partielle
```c
int numbers[5] = {1, 2};  // {1, 2, 0, 0, 0} (le reste est mis à 0)
```

### 2.4 Taille Implicite
```c
int numbers[] = {1, 2, 3};  // Le compilateur déduit la taille (3)
```

---

## 3. Accès aux Éléments

### 3.1 Indexation (Notation avec Crochets)
```c
int ages[5] = {10, 20, 30, 40, 50};
printf("%d\n", ages[0]);  // 10
printf("%d\n", ages[2]);  // 30
```

**Note :** Les indices commencent à **0**, pas à 1.
- Premier élément : `ages[0]`
- Dernier élément : `ages[4]` (pour un tableau de taille 5)

### 3.2 Modification
```c
ages[2] = 99;  // Modifie le 3ème élément
```

---

## 4. Relation Tableau ↔ Pointeur (CRUCIAL)

**Règle d'or :** Un tableau n'est **pas** un pointeur, mais son nom **se comporte comme un pointeur** vers le premier élément.

```c
int ages[5] = {10, 20, 30, 40, 50};
printf("%p\n", ages);    // Adresse du premier élément (0x7ffe00)
printf("%p\n", &ages[0]); // Même chose
```

### 4.1 Équivalences
```c
ages[i]  ≡  *(ages + i)
&ages[i] ≡  (ages + i)
```

**Explication :**
- `ages` est un pointeur vers `ages[0]`.
- `ages + 1` pointe vers `ages[1]`.
- `*(ages + 2)` accède à `ages[2]`.

### 4.2 Arithmétique de Pointeurs
Quand on fait `ages + 1`, le compilateur **ne** ajoute **pas** 1 octet, mais **1 fois la taille du type**.

```c
int ages[5];
printf("%p\n", ages);      // ex: 0x7ffe00
printf("%p\n", ages + 1);  // 0x7ffe04 (+ 4 octets, car sizeof(int) = 4)
```

---

## 5. Visualisation Complète : Tableau vs Pointeur

```c
int ages[5] = {10, 20, 30, 40, 50};
int *ptr = ages;  // ptr pointe vers ages[0]
```

**Mémoire :**
```
┌──────────────────────────────────────────┐
│ Tableau 'ages' (stocké sur la Stack)     │
├──────────────────────────────────────────┤
│ 0x7ffe00  [ 10 ]  ages[0]                │
│ 0x7ffe04  [ 20 ]  ages[1]                │
│ 0x7ffe08  [ 30 ]  ages[2]                │
│ 0x7ffe0c  [ 40 ]  ages[3]                │
│ 0x7ffe10  [ 50 ]  ages[4]                │
└──────────────────────────────────────────┘
           ▲
           │
┌──────────┴───────────────────────────────┐
│ Pointeur 'ptr' (stocké ailleurs)         │
├──────────────────────────────────────────┤
│ 0x7ffe20  [ 0x7ffe00 ]  (adresse)        │
└──────────────────────────────────────────┘
```

**Différence clé :**
- `ages` est un tableau (les 5 valeurs sont stockées directement).
- `ptr` est un pointeur (il contient l'adresse de `ages[0]`).

---

## 6. Les Chaînes de Caractères (Strings)

En C, une chaîne de caractères est un **tableau de `char`** terminé par `\0` (caractère nul).

### 6.1 Déclaration
```c
char name[6] = "Alice";  // {'A', 'l', 'i', 'c', 'e', '\0'}
```

**Mémoire :**
```
0x7ffe00  [ 'A' ]  name[0]
0x7ffe01  [ 'l' ]  name[1]
0x7ffe02  [ 'i' ]  name[2]
0x7ffe03  [ 'c' ]  name[3]
0x7ffe04  [ 'e' ]  name[4]
0x7ffe05  [ '\0' ] name[5]  ← Terminateur obligatoire
```

### 6.2 Pourquoi `\0` est Crucial ?
Les fonctions comme `printf`, `strlen`, `strcpy` **ne connaissent pas la taille du tableau**. Elles lisent jusqu'à trouver `\0`.

**Sans `\0` :**
```c
char name[5] = {'A', 'l', 'i', 'c', 'e'};  // Pas de \0
printf("%s\n", name);  // Affiche "Alice" + GARBAGE jusqu'à trouver un \0 par hasard
```

---

## 7. Danger : Accès Hors Limites

### 7.1 Out-of-Bounds Access
```c
int ages[5] = {10, 20, 30, 40, 50};
printf("%d\n", ages[10]);  // ERREUR : Accès hors limites
```

**Problème :** Le C **ne vérifie pas les limites**. Le programme lit une zone mémoire qui ne lui appartient pas.

**Résultat :**
- Lecture d'une valeur aléatoire (garbage).
- Ou plantage (Segmentation Fault) si l'adresse est invalide.

### 7.2 Buffer Overflow (Débordement)
```c
char buffer[4];
strcpy(buffer, "Hello");  // "Hello" fait 6 caractères ('\0' inclus)
                          // On déborde de 2 octets !
```

**Conséquences :**
- Écrasement de variables adjacentes.
- Corruption de l'adresse de retour (exploit possible).

---

## 8. Tableaux Multidimensionnels (2D)

### 8.1 Déclaration
```c
int matrix[3][4] = {
    {1, 2, 3, 4},
    {5, 6, 7, 8},
    {9, 10, 11, 12}
};
```

### 8.2 Visualisation Mémoire
**Attention :** En mémoire, c'est **linéaire** (pas vraiment une grille).

```
0x7ffe00  [ 1 ]   matrix[0][0]
0x7ffe04  [ 2 ]   matrix[0][1]
0x7ffe08  [ 3 ]   matrix[0][2]
0x7ffe0c  [ 4 ]   matrix[0][3]
0x7ffe10  [ 5 ]   matrix[1][0]
0x7ffe14  [ 6 ]   matrix[1][1]
...
```

### 8.3 Accès
```c
matrix[1][2]  // Ligne 1, Colonne 2 → Valeur 7
```

**Formule de calcul d'adresse :**
```
Adresse(matrix[i][j]) = base + (i * nombre_colonnes + j) * sizeof(type)
```

---

## 9. Tableaux et Fonctions

### 9.1 Passage par Référence (Implicite)
```c
void modify(int arr[], int size) {
    arr[0] = 99;
}

int main() {
    int numbers[5] = {1, 2, 3, 4, 5};
    modify(numbers, 5);
    printf("%d\n", numbers[0]);  // Affiche 99 (modifié)
}
```

**Pourquoi ?** Quand on passe un tableau, on passe **l'adresse du premier élément**, pas une copie.

### 9.2 Équivalence
```c
void modify(int arr[], int size)  ≡  void modify(int *arr, int size)
```

---

## 10. Application Red Team

### 10.1 Buffer Overflow Classique
Les tableaux mal gérés sont la cause #1 des vulnérabilités historiques.

**Exemple :**
```c
void vulnerable() {
    char buffer[64];
    gets(buffer);  // DANGEREUX : Pas de limite
}
```

Si l'attaquant envoie 100 octets, il déborde et écrase l'adresse de retour.

### 10.2 Format String Attack
```c
char buffer[128];
scanf("%s", buffer);
printf(buffer);  // DANGEREUX : buffer contrôlé par l'utilisateur
```

Si `buffer` contient `%x %x %x`, l'attaquant peut lire la pile.

---

## 11. Checklist de Compréhension

- [ ] Quelle est la différence entre un tableau et un pointeur ?
- [ ] Pourquoi `arr[i]` est équivalent à `*(arr + i)` ?
- [ ] Combien d'octets occupe `int arr[10]` ?
- [ ] Qu'est-ce que `\0` et pourquoi est-il obligatoire dans une chaîne ?
- [ ] Que se passe-t-il si on accède à `arr[100]` pour un tableau de taille 10 ?
- [ ] Comment un tableau 2D est-il stocké en mémoire ?

---

## 12. Exercices Pratiques

Consultez `exercice.txt` pour :
1. Manipuler des tableaux d'entiers.
2. Créer des chaînes de caractères manuellement.
3. Parcourir un tableau avec des pointeurs.
4. Identifier des buffer overflows.

---

**Prochaine étape :** Module `02_strings` (Manipulation avancée de chaînes, `string.h`).


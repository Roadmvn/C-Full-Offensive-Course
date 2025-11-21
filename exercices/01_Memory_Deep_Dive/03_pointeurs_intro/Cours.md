# Cours : Les Pointeurs - La Clé de la Mémoire

## 🎯 Objectif du Module
Comprendre **intimement** ce qu'est un pointeur, comment la mémoire est adressée, et pourquoi c'est le concept fondamental de toute manipulation système et offensive.

---

## 1. Rappel Fondamental : Qu'est-ce que la Mémoire ?

La **mémoire RAM** est comme une gigantesque rue avec des milliards de "maisons" alignées.
Chaque maison peut contenir **1 octet** (8 bits) de données.
Chaque maison a une **adresse unique** (un numéro).

```
Adresse     Contenu (1 octet par case)
-------     -------------------------
0x1000      [ 0x41 ]  ← Lettre 'A' en ASCII
0x1001      [ 0x42 ]  ← Lettre 'B'
0x1002      [ 0x19 ]  ← Le nombre 25
0x1003      [ 0x00 ]  ← Rien (NULL)
...
```

**Concepts de base :**
- Une **variable** est un nom qu'on donne à une ou plusieurs cases mémoire.
- Une **adresse** est le numéro de la première case occupée par la variable.
- Un **pointeur** est une variable qui stocke une adresse (au lieu de stocker une valeur normale).

---

## 2. La Notation Hexadécimale (0x...)

Pourquoi voit-on toujours des adresses comme `0x7ffe00` ?

### 2.1 Les Bases de l'Hexadécimal
En **décimal** (base 10), on compte : 0, 1, 2, ..., 9, puis 10.
En **hexadécimal** (base 16), on compte : 0, 1, 2, ..., 9, A, B, C, D, E, F, puis 10.

| Décimal | Hexadécimal | Binaire    |
|---------|-------------|------------|
| 0       | 0           | 0000       |
| 10      | A           | 1010       |
| 15      | F           | 1111       |
| 16      | 10          | 0001 0000  |
| 255     | FF          | 1111 1111  |

### 2.2 Pourquoi l'Hexa en Programmation ?
- **Compact** : `0xFF` est plus lisible que `11111111` (binaire) ou `255` (décimal).
- **Alignement** : 2 chiffres hexa = 1 octet exactement (pratique pour la mémoire).
- Le préfixe `0x` signifie : "Ce qui suit est en hexadécimal".

**Exemple pratique :**
```
0x00   = 0 en décimal
0x08   = 8 en décimal
0x10   = 16 en décimal
0xFF   = 255 en décimal
```

**Calcul d'adresse :**
```
0x1008 - 0x1000 = 0x08 = 8 octets de différence
```

---

## 3. Les Pointeurs : Concept et Syntaxe

### 3.1 Variable vs Pointeur

**Variable normale :**
```c
int age = 25;
```
- `age` est une "boîte" qui contient la valeur `25`.
- Cette boîte est quelque part en mémoire (disons à l'adresse `0x7ffe00`).

**Pointeur :**
```c
int *ptr = &age;
```
- `ptr` est une "boîte" qui contient **l'adresse** de `age` (pas sa valeur).
- `ptr` contient `0x7ffe00` (l'adresse où se trouve `age`).

### 3.2 Visualisation Mémoire

```
┌─────────────────────────┐
│ Variable : age          │
│ Adresse  : 0x7ffe00     │  ← Ici vit la variable 'age'
│ Valeur   : 25 (0x19)    │
└─────────────────────────┘
           ▲
           │
           │ Le pointeur "pointe" vers cette adresse
           │
┌─────────────────────────┐
│ Pointeur : ptr          │
│ Adresse  : 0x7ffe08     │  ← Ici vit le pointeur 'ptr'
│ Valeur   : 0x7ffe00     │  ← Il contient l'adresse de 'age'
└─────────────────────────┘
```

**Pourquoi `0x7ffe08` (et pas `0x7ffe01`) ?**
- Sur un système **64 bits**, un pointeur occupe **8 octets** (car une adresse fait 64 bits / 8 = 8 octets).
- Si `age` (un `int`, 4 octets) commence à `0x7ffe00`, il occupe de `0x7ffe00` à `0x7ffe03`.
- Mais pour l'**alignement mémoire** (optimisation CPU), le compilateur réserve souvent des blocs de 8 octets.
- Donc `ptr` commence à `0x7ffe00 + 8 = 0x7ffe08`.

---

## 4. Les Opérateurs Magiques : `&` et `*`

### 4.1 L'opérateur `&` (Adresse de...)

```c
int age = 25;
int *ptr = &age;  // &age signifie "l'adresse de age"
```

`&age` retourne l'adresse mémoire où `age` est stocké.

**Analogie :** Si `age` est une maison, `&age` est son adresse postale.

### 4.2 L'opérateur `*` (Déréférencement)

Le symbole `*` a **deux usages différents** :

**1) Déclaration d'un pointeur :**
```c
int *ptr;  // "ptr est un pointeur vers un int"
```

**2) Déréférencement (accès à la valeur pointée) :**
```c
int value = *ptr;  // "Va à l'adresse stockée dans ptr et lis la valeur"
```

**Exemple complet :**
```c
int age = 25;
int *ptr = &age;

printf("%d\n", age);    // Affiche : 25
printf("%p\n", &age);   // Affiche : 0x7ffe00 (adresse de age)
printf("%p\n", ptr);    // Affiche : 0x7ffe00 (ptr contient l'adresse de age)
printf("%d\n", *ptr);   // Affiche : 25 (on déréférence ptr pour lire age)

*ptr = 30;  // Modifier la valeur pointée
printf("%d\n", age);    // Affiche : 30 (age a été modifié via le pointeur)
```

---

## 5. Schéma d'Exécution Pas-à-Pas

```c
int age = 25;
int *ptr = &age;
*ptr = 30;
```

**Étape 1 : `int age = 25;`**
```
Adresse    Contenu
0x7ffe00   [ 25 ]  ← Variable 'age'
```

**Étape 2 : `int *ptr = &age;`**
```
Adresse    Contenu
0x7ffe00   [ 25 ]          ← Variable 'age'
0x7ffe08   [ 0x7ffe00 ]    ← Pointeur 'ptr' (contient l'adresse de age)
```

**Étape 3 : `*ptr = 30;`**
- On lit la valeur dans `ptr` → `0x7ffe00`.
- On va à cette adresse et on modifie la valeur → `30`.

```
Adresse    Contenu
0x7ffe00   [ 30 ]          ← 'age' a été modifié via le pointeur
0x7ffe08   [ 0x7ffe00 ]    ← 'ptr' n'a pas changé (toujours la même adresse)
```

---

## 6. Pourquoi C'est Dangereux (Sécurité)

### 6.1 Pointeurs Non-Initialisés (Wild Pointers)
```c
int *ptr;  // Attention ! ptr contient n'importe quoi (adresse aléatoire)
*ptr = 42; // CRASH : On écrit à une adresse random
```

**Règle d'or :** Toujours initialiser un pointeur.
```c
int *ptr = NULL;  // Pointeur "vide" (adresse 0x0)
```

### 6.2 Segmentation Fault
Si vous déréférencez une adresse invalide (comme `NULL`), le système tue le programme.
```c
int *ptr = NULL;
printf("%d\n", *ptr);  // CRASH : Segmentation Fault
```

### 6.3 Application Red Team : Arbitrary Read/Write
Si un attaquant peut **contrôler la valeur d'un pointeur**, il peut lire ou écrire **n'importe où** en mémoire.

**Exemple d'exploit conceptuel :**
```c
int *ptr = (int *)0x12345678;  // Adresse contrôlée par l'attaquant
*ptr = 0x41414141;  // Écriture arbitraire
```

C'est le fondement de presque toutes les exploitations mémoire (Buffer Overflow, Use-After-Free, etc.).

---

## 7. Types de Pointeurs

### 7.1 Pointeur vers `int`
```c
int age = 25;
int *ptr = &age;
```

### 7.2 Pointeur vers `char` (Chaînes de caractères)
```c
char letter = 'A';
char *ptr = &letter;
```

### 7.3 Pointeur Générique (`void*`)
Un pointeur qui peut pointer vers n'importe quel type (utilisé par `malloc`).
```c
void *ptr = malloc(100);  // Alloue 100 octets, retourne void*
int *int_ptr = (int*)ptr; // On "cast" pour l'utiliser
```

### 7.4 Pointeur vers Pointeur (`**`)
Un pointeur qui contient l'adresse d'un autre pointeur (nous verrons ça dans le module suivant).

---

## 8. Application Red Team

### 8.1 Pourquoi les Pointeurs sont Cruciaux ?
En développement de malware et exploitation, vous devez :
- **Manipuler la mémoire d'un autre processus** (Process Injection).
- **Trouver l'adresse de fonctions** (API Hooking).
- **Écrire du shellcode en mémoire** (VirtualAllocEx).

Tout cela repose sur des pointeurs.

### 8.2 Exemple : Injection Windows
```c
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
LPVOID addr = VirtualAllocEx(hProcess, NULL, shellcode_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, addr, shellcode, shellcode_size, NULL);
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
```

- `addr` est un **pointeur** vers la mémoire du processus distant.
- `WriteProcessMemory` écrit à l'adresse pointée par `addr`.
- Sans comprendre les pointeurs, impossible de faire de l'injection.

---

## 9. Checklist de Compréhension

Avant de passer au module suivant, vous devez pouvoir répondre à ces questions :

- [ ] Quelle est la différence entre `&` et `*` ?
- [ ] Pourquoi `0x10 - 0x08 = 8` en hexadécimal ?
- [ ] Qu'est-ce qu'un Segmentation Fault et pourquoi arrive-t-il ?
- [ ] Que contient un pointeur ? (Une valeur ou une adresse ?)
- [ ] Combien d'octets occupe un pointeur sur un système 64-bits ?
- [ ] Pourquoi initialiser un pointeur à `NULL` est important ?

---

## 10. Exercices Pratiques

Consultez le fichier `exercice.txt` pour mettre en pratique ces concepts.

**Conseil :** Compilez avec `-g` et utilisez `gdb` pour visualiser les adresses réelles.
```bash
gcc example.c -g -o program
gdb ./program
(gdb) break main
(gdb) run
(gdb) print &age
(gdb) print ptr
```

---

**Prochaine étape :** Module `04_pointeurs_avances` (Arithmétique de pointeurs, Tableaux, Pointeurs de pointeurs).


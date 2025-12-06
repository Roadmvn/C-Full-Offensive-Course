# Cours : Les Pointeurs - Introduction Fondamentale

## Objectif du Module

Maîtriser le concept de pointeur depuis zéro : comprendre ce qu'est une adresse mémoire, pourquoi les pointeurs existent, comment utiliser les opérateurs & et *, gérer les pointeurs NULL, et utiliser l'arithmétique de pointeurs. C'est le concept CENTRAL de toute programmation système et Red Team.

---

## 1. C'est quoi une adresse mémoire ?

### 1.1 La RAM : Un Immense Tableau

Imagine la mémoire RAM comme une gigantesque rue avec des milliards de cases numérotées. Chaque case peut contenir 1 octet (8 bits).

```
        MÉMOIRE RAM (vue simplifiée)

Adresse      Contenu (1 octet)
┌────────┬──────────────────────┐
│0x1000  │     0x41  ('A')      │
├────────┼──────────────────────┤
│0x1001  │     0x42  ('B')      │
├────────┼──────────────────────┤
│0x1002  │     0x19  (25)       │
├────────┼──────────────────────┤
│0x1003  │     0x00  (NULL)     │
├────────┼──────────────────────┤
│0x1004  │     0xFF             │
├────────┼──────────────────────┤
│  ...   │      ...             │
└────────┴──────────────────────┘

Chaque case a un NUMÉRO UNIQUE = son ADRESSE
```

### 1.2 Les 3 Concepts Clés

**Variable** : Un nom donné à une ou plusieurs cases mémoire
```c
int age = 25;
// "age" est un nom pour 4 cases mémoire contenant le nombre 25
```

**Adresse** : Le numéro de la première case occupée
```c
// Si "age" est stocké à partir de la case 0x1000
// Alors l'adresse de "age" est 0x1000
```

**Pointeur** : Une variable qui contient une ADRESSE (pas une valeur normale)
```c
int *ptr = &age;
// "ptr" contient l'adresse de "age" (0x1000)
// C'est un pointeur !
```

---

## 2. Pourquoi les pointeurs existent ?

### 2.1 Problème : Passage par Valeur

En C, quand tu passes une variable à une fonction, elle est COPIÉE.

```c
void modifier(int x) {
    x = 100;  // Modifie la COPIE, pas l'original
}

int main() {
    int age = 25;
    modifier(age);
    printf("%d\n", age);  // Affiche 25 (inchangé !)
    return 0;
}
```

**Schéma du problème :**
```
main() :
┌──────────┐
│ age = 25 │  Adresse: 0x1000
└──────────┘
     │
     │ Appel modifier(age) → Copie la valeur
     ↓
modifier() :
┌──────────┐
│ x = 25   │  Adresse: 0x2000 (NOUVELLE case !)
└──────────┘
     │
     ↓ x = 100
┌──────────┐
│ x = 100  │  Modifie la copie
└──────────┘

Retour à main() :
┌──────────┐
│ age = 25 │  INCHANGÉ !
└──────────┘
```

### 2.2 Solution : Passage par Référence (Pointeurs !)

Si on passe l'ADRESSE de la variable, on peut modifier l'original.

```c
void modifier(int *ptr) {  // Reçoit une ADRESSE
    *ptr = 100;  // Modifie la valeur À cette adresse
}

int main() {
    int age = 25;
    modifier(&age);  // Passe l'ADRESSE de age
    printf("%d\n", age);  // Affiche 100 (modifié !)
    return 0;
}
```

**Schéma de la solution :**
```
main() :
┌──────────┐
│ age = 25 │  Adresse: 0x1000
└──────────┘
     ↑
     │ Appel modifier(&age) → Passe l'adresse 0x1000
     │
modifier() :
┌─────────────┐
│ ptr = 0x1000│  Contient l'adresse de age
└─────────────┘
     │
     ↓ *ptr = 100 (va à l'adresse 0x1000 et modifie)
     │
┌──────────┐
│ age = 100│  MODIFIÉ directement !
└──────────┘
```

### 2.3 Autres Cas d'Usage

**1. Structures de données dynamiques**
```c
// Liste chaînée : chaque élément pointe vers le suivant
struct Node {
    int data;
    struct Node *next;  // Pointeur vers le prochain nœud
};
```

**2. Allocation dynamique (malloc)**
```c
int *tableau = malloc(100 * sizeof(int));
// malloc retourne un POINTEUR vers la mémoire allouée
```

**3. Red Team : Manipulation mémoire**
```c
// Lire/écrire à une adresse spécifique
int *ptr = (int *)0x12345678;
*ptr = 0xDEADBEEF;  // Écriture arbitraire !
```

---

## 3. Opérateur & (Adresse de...)

### 3.1 Obtenir l'Adresse d'une Variable

L'opérateur `&` permet d'obtenir l'adresse mémoire d'une variable.

```c
int age = 25;
printf("Adresse de age : %p\n", &age);
// Affiche quelque chose comme : 0x7ffe00
```

**Schéma visuel :**
```
int age = 25;

┌─────────────────────────┐
│ Variable : age          │
│ Adresse  : 0x7ffe00  ← &age retourne CECI
│ Valeur   : 25           │
└─────────────────────────┘

&age = 0x7ffe00
```

### 3.2 Analogie : L'Adresse Postale

Tu peux voir `&` comme le panneau "Adresse postale" devant une maison.

```
Maison (variable) :     age = 25
Adresse postale :       &age = 0x7ffe00

Si quelqu'un demande "où habite age ?"
Tu réponds : "à l'adresse 0x7ffe00"
```

### 3.3 Stocker une Adresse : Créer un Pointeur

Pour stocker une adresse, on utilise un **pointeur**.

```c
int age = 25;
int *ptr = &age;  // ptr contient l'adresse de age
```

**Décortiquons la syntaxe :**
```
int *ptr = &age;
│   │ │    │
│   │ │    └─ Adresse de age (0x7ffe00)
│   │ └─ Nom du pointeur
│   └─ * = c'est un POINTEUR
└─ Type de la valeur pointée (int)
```

**Schéma complet :**
```
┌─────────────────────────┐
│ Variable : age          │
│ Adresse  : 0x7ffe00     │
│ Valeur   : 25           │
└─────────────────────────┘
           ▲
           │
           │ ptr "pointe" vers age
           │
┌─────────────────────────┐
│ Pointeur : ptr          │
│ Adresse  : 0x7ffe08     │ (adresse de ptr lui-même)
│ Valeur   : 0x7ffe00     │ (contient l'adresse de age)
└─────────────────────────┘
```

---

## 4. Opérateur * (Déréférencement)

### 4.1 Deux Usages du Symbole *

Le symbole `*` a **DEUX significations différentes** selon le contexte.

**Usage 1 : Déclaration de pointeur**
```c
int *ptr;  // "ptr est un pointeur vers un int"
```

**Usage 2 : Déréférencement (accès à la valeur)**
```c
int value = *ptr;  // "Va à l'adresse contenue dans ptr et lis la valeur"
```

### 4.2 Déréférencement Expliqué

Déréférencer un pointeur signifie : "Aller à l'adresse stockée dans le pointeur et accéder à la valeur qui s'y trouve".

```c
int age = 25;
int *ptr = &age;  // ptr contient 0x7ffe00

printf("%d\n", *ptr);  // Affiche 25
```

**Schéma étape par étape :**
```
Étape 1 : ptr contient 0x7ffe00
┌─────────────┐
│ ptr = 0x7ffe00
└─────────────┘

Étape 2 : *ptr signifie "va à l'adresse 0x7ffe00"
           ↓
┌─────────────────────────┐
│ Adresse : 0x7ffe00      │
│ Valeur  : 25         ← *ptr accède ici
└─────────────────────────┘

Résultat : *ptr = 25
```

### 4.3 Modifier via un Pointeur

Tu peux aussi MODIFIER la valeur pointée avec `*`.

```c
int age = 25;
int *ptr = &age;

*ptr = 30;  // Modifie la valeur À l'adresse stockée dans ptr

printf("%d\n", age);  // Affiche 30 (age a changé !)
```

**Schéma de modification :**
```
AVANT : *ptr = 30;

┌─────────────┐         ┌─────────────────────┐
│ ptr = 0x7ffe00 │─────→│ Adresse : 0x7ffe00  │
└─────────────┘         │ Valeur  : 25        │
                        └─────────────────────┘

APRÈS : *ptr = 30;

┌─────────────┐         ┌─────────────────────┐
│ ptr = 0x7ffe00 │─────→│ Adresse : 0x7ffe00  │
└─────────────┘         │ Valeur  : 30     ← Modifié !
                        └─────────────────────┘

age a changé de 25 à 30
```

### 4.4 Exemple Complet

```c
#include <stdio.h>

int main() {
    int age = 25;
    int *ptr = &age;

    printf("age = %d\n", age);        // 25
    printf("&age = %p\n", &age);      // 0x7ffe00 (adresse de age)
    printf("ptr = %p\n", ptr);        // 0x7ffe00 (ptr contient l'adresse)
    printf("*ptr = %d\n", *ptr);      // 25 (déréférence : lit la valeur)

    *ptr = 30;  // Modification via pointeur

    printf("age = %d\n", age);        // 30 (modifié !)

    return 0;
}
```

---

## 5. Pointeur NULL et Segfault

### 5.1 Qu'est-ce que NULL ?

`NULL` est une adresse spéciale qui signifie "pointeur vide" ou "ne pointe nulle part".

```c
int *ptr = NULL;  // ptr ne pointe vers rien
```

En réalité, `NULL` est l'adresse `0x0` (zéro).

**Schéma :**
```
┌─────────────┐
│ ptr = NULL  │ = ptr = 0x00000000
└─────────────┘
      │
      └─ Ne pointe vers RIEN
```

### 5.2 Pourquoi NULL est Important ?

Un pointeur non-initialisé contient une adresse ALÉATOIRE (garbage).

```c
int *ptr;  // ptr contient n'importe quoi (ex: 0x8F3A2B10)
*ptr = 42; // CRASH ! Tente d'écrire à une adresse random
```

**Schéma du problème :**
```
int *ptr;  (non-initialisé)

┌──────────────────┐
│ ptr = 0x8F3A2B10 │ ← Adresse aléatoire (DANGEREUSE)
└──────────────────┘
         │
         ↓ *ptr = 42
    CRASH ! Segmentation Fault
```

**Solution : Initialiser à NULL**
```c
int *ptr = NULL;  // Explicitement vide
if (ptr != NULL) {
    *ptr = 42;  // Seulement si ptr pointe quelque part
}
```

### 5.3 Segmentation Fault Expliqué

Un **Segmentation Fault** (segfault) arrive quand tu essaies d'accéder à une adresse invalide.

```c
int *ptr = NULL;
printf("%d\n", *ptr);  // CRASH : Segmentation Fault
```

**Pourquoi ça crash ?**
```
Le système d'exploitation protège la mémoire.
L'adresse 0x0 (NULL) est VOLONTAIREMENT invalide.

Tentative d'accès :
┌──────────┐
│ ptr = NULL│ = 0x00000000
└──────────┘
     │
     ↓ *ptr (tentative de lecture à 0x0)
     │
  ┌──┴──┐
  │ OS  │ "STOP ! Adresse invalide !"
  └─────┘
     │
  CRASH (signal SIGSEGV)
```

**Cas courants de segfault :**
```c
// 1. Déréférencement de NULL
int *ptr = NULL;
*ptr = 10;  // CRASH

// 2. Pointeur non-initialisé
int *ptr;
*ptr = 10;  // CRASH

// 3. Double free (on verra plus tard)
free(ptr);
free(ptr);  // CRASH

// 4. Use-after-free
free(ptr);
*ptr = 10;  // CRASH
```

---

## 6. Arithmétique de Pointeurs

### 6.1 Les Pointeurs et les Tableaux

Un tableau en C est juste un pointeur vers le premier élément.

```c
int ages[5] = {10, 20, 30, 40, 50};
int *ptr = ages;  // ages "se dégrade" en pointeur
```

**Schéma mémoire :**
```
Adresse      Valeur      Variable
┌─────────┬──────────┬────────────┐
│ 0x1000  │   10     │  ages[0]   │ ← ptr pointe ici
├─────────┼──────────┼────────────┤
│ 0x1004  │   20     │  ages[1]   │
├─────────┼──────────┼────────────┤
│ 0x1008  │   30     │  ages[2]   │
├─────────┼──────────┼────────────┤
│ 0x100C  │   40     │  ages[3]   │
├─────────┼──────────┼────────────┤
│ 0x1010  │   50     │  ages[4]   │
└─────────┴──────────┴────────────┘

ages = 0x1000 (adresse du premier élément)
ptr  = 0x1000
```

### 6.2 Addition et Soustraction

Quand tu fais `ptr + 1`, le compilateur avance de `sizeof(type)` octets automatiquement.

```c
int *ptr = ages;  // ptr = 0x1000

ptr + 0  → 0x1000 (ages[0])
ptr + 1  → 0x1004 (ages[1])  ← Avance de 4 bytes (sizeof(int))
ptr + 2  → 0x1008 (ages[2])
ptr + 3  → 0x100C (ages[3])
ptr + 4  → 0x1010 (ages[4])
```

**Schéma visuel :**
```
ptr = 0x1000
│
↓
┌────┐  +1  ┌────┐  +1  ┌────┐  +1  ┌────┐  +1  ┌────┐
│ 10 │ ───→ │ 20 │ ───→ │ 30 │ ───→ │ 40 │ ───→ │ 50 │
└────┘      └────┘      └────┘      └────┘      └────┘
0x1000      0x1004      0x1008      0x100C      0x1010

Chaque +1 avance de sizeof(int) = 4 bytes
```

### 6.3 Équivalence Tableau/Pointeur

Ces deux notations sont IDENTIQUES :

```c
ages[2]  ≡  *(ages + 2)
&ages[2] ≡  (ages + 2)
```

**Exemple concret :**
```c
int ages[5] = {10, 20, 30, 40, 50};

printf("%d\n", ages[2]);      // 30
printf("%d\n", *(ages + 2));  // 30 (identique !)

printf("%p\n", &ages[2]);     // 0x1008
printf("%p\n", ages + 2);     // 0x1008 (identique !)
```

### 6.4 Incrémenter/Décrémenter un Pointeur

```c
int ages[5] = {10, 20, 30, 40, 50};
int *ptr = ages;

printf("%d\n", *ptr);  // 10

ptr++;  // Avance au prochain élément
printf("%d\n", *ptr);  // 20

ptr += 2;  // Avance de 2 éléments
printf("%d\n", *ptr);  // 40

ptr--;  // Recule d'un élément
printf("%d\n", *ptr);  // 30
```

**Schéma d'avancement :**
```
DÉBUT : ptr = 0x1000
┌────┐
│ 10 │ ← ptr
└────┘

ptr++ :
┌────┐  ┌────┐
│ 10 │  │ 20 │ ← ptr (avancé de 4 bytes)
└────┘  └────┘

ptr += 2 :
┌────┐  ┌────┐  ┌────┐  ┌────┐
│ 10 │  │ 20 │  │ 30 │  │ 40 │ ← ptr
└────┘  └────┘  └────┘  └────┘

ptr-- :
┌────┐  ┌────┐  ┌────┐  ┌────┐
│ 10 │  │ 20 │  │ 30 │  │ 40 │
└────┘  └────┘  └────┘  └────┘
                   ↑
                  ptr (reculé de 4 bytes)
```

---

## 7. Application Red Team

### 7.1 Pourquoi les Pointeurs Sont le Coeur du Red Team ?

Les pointeurs permettent de manipuler la mémoire directement. C'est LA compétence fondamentale pour :

**1. Process Injection** : Injecter du code dans un autre processus
```c
// Allouer de la mémoire dans un processus distant
LPVOID addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
// addr est un POINTEUR vers la mémoire du processus cible

// Écrire notre shellcode à cette adresse
WriteProcessMemory(hProcess, addr, shellcode, size, NULL);
```

**2. Buffer Overflow** : Écraser la mémoire pour contrôler le flux d'exécution
```c
char buffer[10];
char *ptr = buffer;

// Écriture au-delà des limites
strcpy(ptr, "AAAAAAAAAAAAAAAAAAAAAAAA");  // Dépasse 10 bytes
// Peut écraser la return address sur la stack !
```

**3. Lecture/Écriture Arbitraire**
```c
// Lire une adresse mémoire spécifique
int *ptr = (int *)0x12345678;
int valeur = *ptr;  // Lit la valeur à cette adresse

// Écrire à une adresse spécifique
*ptr = 0xDEADBEEF;  // Écrit notre valeur
```

### 7.2 Exemple Concret : API Hooking Basique

```c
#include <stdio.h>

// Fonction originale
int verifier_licence() {
    return 0;  // 0 = licence invalide
}

int main() {
    // Créer un pointeur vers la fonction
    int (*func_ptr)() = verifier_licence;

    printf("Licence valide : %d\n", func_ptr());  // Affiche 0

    // RED TEAM : Remplacer le pointeur par une autre fonction
    int toujours_valide() { return 1; }
    func_ptr = toujours_valide;

    printf("Licence valide : %d\n", func_ptr());  // Affiche 1 (bypass !)

    return 0;
}
```

**Schéma de l'exploit :**
```
AVANT :
func_ptr ─────→ verifier_licence() { return 0; }

APRÈS (hook) :
func_ptr ─────→ toujours_valide() { return 1; }

Le programme appelle func_ptr() qui exécute maintenant notre fonction !
```

### 7.3 Format String Vulnerability (Aperçu)

```c
// Code vulnérable
void vulnerable(char *input) {
    printf(input);  // DANGER ! input contrôlé par l'attaquant
}

// Exploitation
char exploit[] = "%p %p %p %p";  // Lit la stack
vulnerable(exploit);
// Affiche les adresses mémoire de la stack !

char exploit2[] = "%n";  // Écrit dans la mémoire (!)
```

Le `%p` lit des POINTEURS sur la stack. Le `%n` écrit à une adresse pointée.

### 7.4 Pourquoi C'est Possible ?

En C, les pointeurs donnent un **contrôle total** sur la mémoire. C'est puissant mais dangereux.

```
Langages de haut niveau (Python, Java) :
┌────────────────┐
│  Gestionnaire  │  ← Protège la mémoire
│   Mémoire      │
└────────────────┘
       ↓
   [Mémoire]


Langage C :
┌────────────────┐
│  Ton code      │  ← Accès DIRECT à la mémoire
└────────────────┘
       ↓
   [Mémoire]  ← Tu peux lire/écrire n'importe où !
```

Cette liberté est ce qui rend le C parfait pour le Red Team, mais aussi source de vulnérabilités.

---

## 8. Checklist de Compréhension

Avant de passer au module suivant, assure-toi de pouvoir répondre :

- [ ] C'est quoi une adresse mémoire ?
- [ ] Quelle différence entre `&age` et `*ptr` ?
- [ ] Pourquoi `int *ptr; *ptr = 10;` crash ?
- [ ] Comment fonctionne `ptr + 1` sur un tableau ?
- [ ] Que contient exactement un pointeur ?
- [ ] Pourquoi NULL est important ?
- [ ] Qu'est-ce qu'un segmentation fault ?

Si tu hésites sur une question, relis la section correspondante.

---

## 9. Exercices Pratiques

Va dans le fichier `exercice.txt` pour pratiquer :
- Manipulation basique de pointeurs
- Arithmétique de pointeurs sur tableaux
- Passage par référence
- Debug avec gdb

**Astuce Debug :**
```bash
gcc example.c -g -o program
gdb ./program
(gdb) break main
(gdb) run
(gdb) print &age       # Voir l'adresse
(gdb) print ptr        # Voir le contenu du pointeur
(gdb) print *ptr       # Déréférencer
(gdb) x/4wx ptr        # Examiner la mémoire (4 words en hexa)
```

---

**Prochaine étape :** Module 12 - Pointeurs Avancés (pointeur de pointeur, pointeurs de fonctions, void*, const).


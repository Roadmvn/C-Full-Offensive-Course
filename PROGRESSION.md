# 📊 Progression détaillée - Apprentissage C pour Red Teaming

## 🎯 Vue d'ensemble

**Durée totale estimée** : 4-6 semaines (40-60 heures)
**Niveau de départ** : Débutant absolu
**Niveau final** : Bases solides en exploitation

---

## 📅 PHASE 1 : Bases Absolues (1-2 semaines)

### Semaine 1 : Les fondamentaux

#### ✅ Exercice 01 : Hello World
**Durée** : 30-45 minutes
**Concepts** :
- Structure d'un programme C
- `#include` et bibliothèques
- La fonction `main()`
- `printf()` pour l'affichage
- Compilation avec gcc
- Exécution d'un programme

**Tu sauras** : Écrire, compiler et exécuter ton premier programme C

---

#### ✅ Exercice 02 : Variables et Types
**Durée** : 45-60 minutes
**Concepts** :
- Déclaration de variables
- Types de données : `int`, `char`, `float`, `double`
- Initialisation
- `sizeof()` pour connaître la taille en mémoire
- Affichage avec `printf()`

**Tu sauras** : Manipuler différents types de données et comprendre leur stockage

---

#### ✅ Exercice 03 : Printf et Scanf
**Durée** : 1 heure
**Concepts** :
- Format specifiers (`%d`, `%c`, `%f`, `%s`, `%p`)
- `printf()` avancé
- `scanf()` pour la saisie utilisateur
- L'opérateur `&` (adresse)
- Lire différents types de données

**Tu sauras** : Interagir avec l'utilisateur et formater l'affichage

---

#### ✅ Exercice 04 : Opérateurs
**Durée** : 1 heure
**Concepts** :
- Opérateurs arithmétiques (`+`, `-`, `*`, `/`, `%`)
- Opérateurs de comparaison (`==`, `!=`, `<`, `>`, `<=`, `>=`)
- Opérateurs logiques (`&&`, `||`, `!`)
- Incrémentation (`++`, `--`)
- Priorité des opérateurs

**Tu sauras** : Effectuer des calculs et des comparaisons

---

#### ✅ Exercice 05 : If, Else, Switch
**Durée** : 1-1.5 heures
**Concepts** :
- Structure conditionnelle `if`
- `else if` et `else`
- Opérateur ternaire `? :`
- `switch case`
- Programme de décision

**Tu sauras** : Créer des programmes qui prennent des décisions

---

### Semaine 2 : Structures de contrôle et données

#### ✅ Exercice 06 : Loops (Boucles)
**Durée** : 1.5-2 heures
**Concepts** :
- Boucle `for`
- Boucle `while`
- Boucle `do-while`
- `break` et `continue`
- Boucles imbriquées

**Tu sauras** : Répéter des actions et parcourir des données

---

#### ✅ Exercice 07 : Arrays (Tableaux)
**Durée** : 1.5-2 heures
**Concepts** :
- Déclaration d'arrays
- Initialisation
- Accès aux éléments `array[index]`
- Parcourir avec des boucles
- Arrays 2D (matrices)
- Limites et dépassements

**Tu sauras** : Stocker et manipuler des collections de données

---

#### ✅ Exercice 08 : Strings (Chaînes)
**Durée** : 2 heures
**Concepts** :
- String = array de `char`
- Terminaison `\0` (null terminator)
- `<string.h>` : `strlen()`, `strcpy()`, `strcmp()`, `strcat()`
- Manipulation de strings
- Lecture sécurisée

**Tu sauras** : Travailler avec du texte en C

---

#### ✅ Exercice 09 : Functions (Fonctions)
**Durée** : 2 heures
**Concepts** :
- Déclaration et définition de fonctions
- Paramètres et arguments
- Valeurs de retour
- Prototypes
- Scope des variables (locale vs globale)
- Modularité du code

**Tu sauras** : Organiser ton code en fonctions réutilisables

---

## 📅 PHASE 2 : Niveau Intermédiaire (1 semaine)

### Semaine 3 : Mémoire et structures

#### ✅ Exercice 10 : Introduction aux Pointeurs
**Durée** : 2-3 heures
**⚠️ CRUCIAL** - Les pointeurs sont la base de tout ce qui suit

**Concepts** :
- Qu'est-ce qu'un pointeur ?
- Opérateur `&` (adresse de)
- Opérateur `*` (déréférence)
- Relation pointeur-variable
- Affichage d'adresses mémoire
- `NULL` pointer

**Tu sauras** : Comprendre comment les variables sont stockées en mémoire

---

#### ✅ Exercice 11 : Pointeurs Avancés
**Durée** : 2-3 heures
**Concepts** :
- Arithmétique de pointeurs (`ptr++`, `ptr+n`)
- Relation pointeurs-arrays
- Passer des pointeurs aux fonctions
- Pointeurs de pointeurs (`**ptr`)
- `void*` (pointeur générique)

**Tu sauras** : Manipuler la mémoire de manière avancée

---

#### ✅ Exercice 12 : Malloc et Free
**Durée** : 2-3 heures
**Concepts** :
- Stack vs Heap
- Allocation dynamique : `malloc()`, `calloc()`, `realloc()`
- Libération : `free()`
- Memory leaks (fuites mémoire)
- Valgrind pour détecter les fuites

**Tu sauras** : Gérer la mémoire dynamiquement

---

#### ✅ Exercice 13 : Structures
**Durée** : 2 heures
**Concepts** :
- Définir une `struct`
- Accès aux membres (`.` et `->`)
- Structures et pointeurs
- Arrays de structures
- `typedef` pour simplifier

**Tu sauras** : Créer des types de données personnalisés

---

#### ✅ Exercice 14 : Fichiers
**Durée** : 2 heures
**Concepts** :
- `fopen()`, `fclose()`
- Modes : `"r"`, `"w"`, `"a"`, `"rb"`, `"wb"`
- `fwrite()`, `fread()`
- `fprintf()`, `fscanf()`
- `fgets()`, `fputs()`
- Manipulation de fichiers binaires

**Tu sauras** : Lire et écrire des données dans des fichiers

---

## 📅 PHASE 3 : Exploitation et Sécurité (1-2 semaines)

### Semaine 4-5 : Introduction à l'exploitation

#### ⚠️ Exercice 15 : Concept de Buffer
**Durée** : 2-3 heures
**⚠️ Début de la partie sécurité**

**Concepts** :
- Qu'est-ce qu'un buffer ?
- Buffer fixe vs dynamique
- Écrire dans un buffer
- Introduction au concept d'overflow
- Visualiser avec `printf()` et addresses

**Tu sauras** : Comprendre les bases des buffers et leurs limites

---

#### 🔴 Exercice 16 : Stack Overflow
**Durée** : 3-4 heures
**⚠️ IMPORTANT** - Premier exploit réel

**Concepts** :
- Organisation de la stack
- Stack frame (frame pointer, return address)
- Buffer overflow simple
- Écraser une variable adjacente
- Écraser la return address
- Compilation sans protections (`-fno-stack-protector`)
- GDB pour visualiser la stack

**Tu sauras** : Comprendre et exploiter un buffer overflow basique

---

#### 🔴 Exercice 17 : Shellcode
**Durée** : 3-4 heures
**Concepts** :
- Qu'est-ce qu'un shellcode ?
- Function pointers
- Exécuter du code depuis un buffer
- Shellcode simple (`execve("/bin/sh")`)
- NOP sled (0x90)
- Flags de compilation : `-z execstack`

**Tu sauras** : Injecter et exécuter du code arbitraire

---

#### 🔴 Exercice 18 : Format String
**Durée** : 3-4 heures
**Concepts** :
- Vulnérabilité `printf(user_input)`
- Lire la stack avec `%x`, `%p`
- `%s` pour leak des strings
- `%n` pour écrire en mémoire
- Exploitation basique

**Tu sauras** : Exploiter les format strings pour leak et écrire en mémoire

---

#### 🔴 Exercice 19 : Heap Exploitation
**Durée** : 4 heures
**Concepts** :
- Organisation du heap
- Heap overflow
- Use-after-free (UAF)
- Double-free
- Heap spray
- Exploitation simple du heap

**Tu sauras** : Comprendre les vulnérabilités du heap

---

#### 🔴 Exercice 20 : Reverse Shell
**Durée** : 4 heures
**🎓 PROJET FINAL**

**Concepts** :
- Socket programming (`socket()`, `bind()`, `listen()`, `accept()`)
- Client/server TCP
- `dup2()` pour rediriger stdin/stdout/stderr
- Envoyer des commandes
- Recevoir l'output
- Shell over network

**Tu sauras** : Créer un reverse shell fonctionnel

---

## 🎯 Checklist de progression

Coche au fur et à mesure :

### Phase 1 : Bases
- [ ] 01 - Hello World
- [ ] 02 - Variables et Types
- [ ] 03 - Printf et Scanf
- [ ] 04 - Opérateurs
- [ ] 05 - If/Else/Switch
- [ ] 06 - Loops
- [ ] 07 - Arrays
- [ ] 08 - Strings
- [ ] 09 - Functions

### Phase 2 : Intermédiaire
- [ ] 10 - Pointeurs (intro)
- [ ] 11 - Pointeurs (avancé)
- [ ] 12 - Malloc/Free
- [ ] 13 - Structures
- [ ] 14 - Fichiers

### Phase 3 : Exploitation
- [ ] 15 - Buffer concept
- [ ] 16 - Stack Overflow
- [ ] 17 - Shellcode
- [ ] 18 - Format String
- [ ] 19 - Heap Exploitation
- [ ] 20 - Reverse Shell

---

## 🏆 Après avoir tout complété

Tu auras acquis :
- ✅ Maîtrise du langage C
- ✅ Compréhension profonde de la gestion mémoire
- ✅ Bases de l'exploitation de binaires
- ✅ Capacité à lire et analyser du code C
- ✅ Fondations pour des CTFs et le bug bounty

## 🚀 Prochaines étapes

1. **Pratiquer sur des CTFs** : HackTheBox, TryHackMe, PicoCTF
2. **Apprendre l'assembleur x86/x64** : Pour comprendre plus en profondeur
3. **Étudier les protections modernes** : ASLR, DEP, Stack Canaries, PIE
4. **Reverse engineering** : IDA, Ghidra, Binary Ninja
5. **Exploitation avancée** : ROP chains, ret2libc, heap feng shui

---

**Bon courage dans ton apprentissage ! 🔥**

*N'oublie pas : Chaque expert a été un débutant. La clé est la persistance.*

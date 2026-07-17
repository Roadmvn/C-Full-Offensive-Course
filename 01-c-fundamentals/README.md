# Semaine 1 : C Absolute Basics

## Objectif de la semaine

A la fin de cette semaine, tu sauras :
- Ecrire et compiler un programme C
- Utiliser des variables (int, float, char)
- Prendre des decisions avec if/else
- Repeter des actions avec des boucles
- Creer tes propres fonctions

## Prerequis

- Un editeur de texte (VS Code recommande)
- Une chaine d'outils C installee avec le guide correspondant :
  [Windows avec MSVC](../fr/setup/windows.md),
  [Linux avec GCC ou Clang](../fr/setup/linux.md) ou
  [macOS avec Clang](../fr/setup/macos.md)
- Savoir ouvrir un terminal

## Comment travailler

1. Ouvre [`lessons/01-hello-world.c`](lessons/01-hello-world.c).
2. Compile-le avec la commande MSVC, GCC ou Clang ci-dessous.
3. Execute le programme genere et compare sa sortie aux commentaires du fichier.
4. Recommence avec chacune des quatre lessons suivantes, dans l'ordre.
5. Quand les cinq lessons compilent, fais les trois exercices.
6. Termine avec l'[auto-evaluation `CHECKPOINT.md`](CHECKPOINT.md).

## Contenu

### Lessons (a lire dans l'ordre)

| Fichier | Sujet | Duree estimee |
|---------|-------|---------------|
| `01-hello-world.c` | Structure d'un programme C, printf | 15 min |
| `02-variables.c` | Types int, float, char, operations | 20 min |
| `03-if-else.c` | Conditions, comparaisons | 25 min |
| `04-loops.c` | Boucles for, while, do-while | 30 min |
| `05-functions.c` | Creer et utiliser des fonctions | 25 min |

### Exercices (a faire apres les lessons)

| Fichier | Difficulte | Description |
|---------|------------|-------------|
| `ex01-calculator.c` | ⭐ | Calculatrice + - * / |
| `ex02-fizzbuzz.c` | ⭐⭐ | Le classique FizzBuzz |
| `ex03-string-reverse.c` | ⭐⭐⭐ | Inverser une chaine |

### Solutions

Dans le dossier `solutions/` - ne regarde qu'apres avoir essaye !

## Compilation rapide

Depuis la racine du depot, entre d'abord dans le module :

```bash
cd 01-c-fundamentals
```

Compile un fichier avec **une seule** des trois commandes suivantes.

**MSVC**, dans le Developer Command Prompt for Visual Studio :

```batch
cl /nologo /std:c11 /W4 lessons\01-hello-world.c /Fe:01-hello-world.exe
01-hello-world.exe
```

**GCC**, dans un shell Linux ou macOS :

```bash
gcc -std=c11 -Wall -Wextra lessons/01-hello-world.c -o 01-hello-world
./01-hello-world
```

**Clang**, dans un shell Linux ou macOS :

```bash
clang -std=c11 -Wall -Wextra lessons/01-hello-world.c -o 01-hello-world
./01-hello-world
```

Pour compiler les cinq lessons, execute uniquement la boucle de ton compilateur.

**MSVC / Developer Command Prompt :**

```batch
for %f in (lessons\01-hello-world.c lessons\02-variables.c lessons\03-if-else.c lessons\04-loops.c lessons\05-functions.c) do cl /nologo /std:c11 /W4 "%f"
```

**GCC / shell POSIX :**

```bash
for source in lessons/01-hello-world.c lessons/02-variables.c lessons/03-if-else.c lessons/04-loops.c lessons/05-functions.c; do
  gcc -std=c11 -Wall -Wextra "$source" -o "$(basename "${source%.c}")" || break
done
```

**Clang / shell POSIX :**

```bash
for source in lessons/01-hello-world.c lessons/02-variables.c lessons/03-if-else.c lessons/04-loops.c lessons/05-functions.c; do
  clang -std=c11 -Wall -Wextra "$source" -o "$(basename "${source%.c}")" || break
done
```

## Auto-evaluation de validation

Quand tu as fini les lessons et les exercices, ouvre
[`CHECKPOINT.md`](CHECKPOINT.md). La validation repose sur la compilation des
cinq lessons et la reussite des trois exercices presents dans ce depot.

## Checklist de validation

- [ ] J'ai lu et compile les 5 lessons
- [ ] J'ai fait l'exercice calculatrice
- [ ] J'ai fait l'exercice FizzBuzz
- [ ] J'ai fait l'exercice string reverse
- [ ] J'ai complete l'auto-evaluation de `CHECKPOINT.md`
- [ ] Je comprends la difference entre int, float, char
- [ ] Je sais utiliser if/else et les boucles
- [ ] Je sais creer une fonction

## Problemes courants

### "cl n'est pas reconnu"
-> Ouvre "Developer Command Prompt for VS" au lieu du terminal normal

### "undefined reference to printf"
-> Tu as oublie `#include <stdio.h>` en haut du fichier

### Le programme affiche n'importe quoi
-> Verifie que tu utilises le bon format (%d pour int, %f pour float, %c pour char)

## Lien avec le maldev

Pourquoi ces bases sont importantes ?

| Concept | Usage en maldev |
|---------|-----------------|
| Variables | Stocker shellcode, configs, cles |
| Conditions | Detecter l'environnement, anti-debug |
| Boucles | Decoder, XOR, parcourir memoire |
| Fonctions | Organiser le code, reutiliser |

**Semaine prochaine** : Pointeurs et memoire - les vrais outils du maldev !

---

Temps estime : **4-6 heures**

Quand tu as valide le checkpoint, passe a la **Semaine 2** !

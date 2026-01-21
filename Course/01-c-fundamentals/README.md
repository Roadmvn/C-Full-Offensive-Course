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
- Visual Studio Build Tools installe (voir setup.ps1)
- Savoir ouvrir un terminal

## Comment travailler

```
1. Lis le fichier Lessons/01-hello-world.c
2. Compile-le : cl 01-hello-world.c
3. Execute-le : 01-hello-world.exe
4. Passe au fichier suivant
5. Quand tu as fini les lessons, fais les exercices
6. Termine par le quiz !
```

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

Dans le dossier `Solutions/` - ne regarde qu'apres avoir essaye !

## Compilation rapide

```batch
REM Compiler un seul fichier
cl nom_du_fichier.c

REM Compiler tout
build.bat
```

## Quiz de validation

Quand tu as fini lessons + exercices :

```bash
python ../../scripts/quiz-runner.py quiz.json
```

Score minimum : **8/10** pour valider la semaine.

## Checklist de validation

- [ ] J'ai lu et compile les 5 lessons
- [ ] J'ai fait l'exercice calculatrice
- [ ] J'ai fait l'exercice FizzBuzz
- [ ] J'ai fait l'exercice string reverse
- [ ] J'ai obtenu 8/10 ou plus au quiz
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

Quand tu as valide le quiz, passe a la **Semaine 2** !

# CHECKPOINT - Semaine 1

## Criteres de validation

Pour considerer cette semaine comme VALIDEE, tu dois :

### 1. Compilation (Obligatoire)
- [ ] Tous les fichiers Lessons/*.c compilent sans erreur
- [ ] Tous les fichiers Exercises/*.c compilent sans erreur (apres completion)

### 2. Exercices (Obligatoire)
- [ ] ex01-calculator.c : Gere +, -, *, / et division par zero
- [ ] ex02-fizzbuzz.c : Affiche correctement 1-20 avec Fizz/Buzz/FizzBuzz
- [ ] ex03-string-reverse.c : Inverse correctement "HELLO" en "OLLEH"

### 3. Quiz (Obligatoire)
- [ ] Score >= 8/10 au quiz.json

### 4. Comprehension (Auto-evaluation)
- [ ] Je peux expliquer ce que fait `#include <stdio.h>`
- [ ] Je connais la difference entre `=` et `==`
- [ ] Je sais quand utiliser `for` vs `while`
- [ ] Je peux creer une fonction qui retourne une valeur

## Livrable

A la fin de cette semaine, tu dois avoir :

```
Un programme "calculatrice" qui fonctionne
= preuve que tu maitrises variables, conditions, et fonctions
```

## Verification automatique

Execute ce script pour verifier :

```batch
build.bat
```

Si tout affiche [OK], tu es pret pour la Semaine 2 !

## En cas de blocage

1. Relis la lesson concernee
2. Regarde les indices dans le fichier exercice
3. Compare avec la solution (en dernier recours)
4. Pose ta question avec le code exact et l'erreur

## Pret pour la suite ?

Si tu as coche toutes les cases ci-dessus :

```
git add .
git commit -m "feat: semaine 1 completee"
git tag week-01-complete
```

➡️ Passe a `../02-memory-pointers/` !

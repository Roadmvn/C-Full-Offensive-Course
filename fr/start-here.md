**Français** · [English](../en/start-here.md)

# Bien démarrer : vérifier votre première compilation C

Ce guide accompagne votre première session. Vous allez choisir le bon point d'entrée, installer une chaîne d'outils C, compiler la première leçon partagée, puis supprimer le fichier généré.

> Avant tout laboratoire de sécurité, validez les [règles de sécurité du labo](safety/lab-safety.md). La première leçon C ci-dessous est un exercice normal de programmation locale et ne nécessite pas de labo de sécurité.

## 1. Choisir votre point de départ

- **Les notions de binaire, CPU, mémoire ou système d'exploitation sont nouvelles pour vous :** lisez d'abord [`00-prerequisites`](../00-prerequisites/README.md) et faites ses exercices écrits.
- **Vous maîtrisez déjà ces notions :** commencez directement par les fondamentaux C ci-dessous.

`00-prerequisites` est réservé à la lecture : il contient des explications et des exercices écrits, mais pas `01-hello-world.c`. La compilation commence dans `01-c-fundamentals`.

## 2. Vérifier Git et cloner le dépôt

Git est requis pour télécharger et mettre à jour le cours. Vérifiez-le avant le clonage :

```bash
git --version
```

Si la commande est introuvable, installez Git pour votre système depuis les [téléchargements Git officiels](https://git-scm.com/downloads/), rouvrez le terminal, puis exécutez à nouveau `git --version`.

Clonez ensuite le dépôt :

```bash
git clone https://github.com/Roadmvn/C-Full-Offensive-Course.git
cd C-Full-Offensive-Course
```

Si vous avez déjà cloné le dépôt, ouvrez plutôt un terminal à sa racine.

## 3. Sélectionner une chaîne d'outils

Suivez le guide correspondant à votre système d'exploitation :

- [Windows avec MSVC](setup/windows.md)
- [Linux avec GCC ou Clang](setup/linux.md)
- [macOS avec Clang](setup/macos.md)

Un seul compilateur suffit. N'installez pas toutes les chaînes d'outils sauf si un autre projet les exige.

## 4. Vérifier le compilateur

Exécutez la commande correspondant à la chaîne d'outils choisie.

**MSVC, dans un Developer Command Prompt for Visual Studio :**

```batch
cl
```

**GCC :**

```bash
gcc --version
```

**Clang :**

```bash
clang --version
```

Le nom et la version du compilateur doivent s'afficher. Si la commande est introuvable, revenez au guide d'installation correspondant avant de continuer.

## 5. Entrer dans le module des fondamentaux C

Depuis la racine du dépôt, exécutez exactement :

```bash
cd 01-c-fundamentals
```

La source reste dans un emplacement partagé unique : [`../01-c-fundamentals/lessons/01-hello-world.c`](../01-c-fundamentals/lessons/01-hello-world.c). Les portails français et anglais ne la copient pas.

## 6. Compiler et exécuter la leçon

Choisissez les commandes de votre compilateur.

**MSVC :**

```batch
cl lessons\01-hello-world.c /Fe:hello-world.exe
hello-world.exe
```

**GCC :**

```bash
gcc lessons/01-hello-world.c -o hello-world
./hello-world
```

**Clang :**

```bash
clang lessons/01-hello-world.c -o hello-world
./hello-world
```

Sortie attendue :

```text
Hello, World!
```

Si la compilation échoue, lisez la première ligne d'erreur, confirmez que le terminal se trouve encore dans `01-c-fundamentals`, puis vérifiez à nouveau le compilateur.

## 7. Faire le premier exercice

Ouvrez [`exercises/ex01-calculator.c`](../01-c-fundamentals/exercises/ex01-calculator.c), lisez ses consignes et travaillez dans ce fichier partagé ou dans votre propre branche Git locale. Réutilisez le cycle de compilation et d'exécution que vous venez de vérifier. Ne créez pas de copie sous `en/` ou `fr/`.

## 8. Supprimer les fichiers de compilation générés

Depuis `01-c-fundamentals`, utilisez la commande correspondant à votre compilation.

**MSVC :**

```batch
del hello-world.exe 01-hello-world.obj
```

**GCC ou Clang :**

```bash
rm hello-world
```

Ces commandes suppriment uniquement les fichiers générés, pas la source de la leçon.

## Suite

[Choisissez l'un des quatre parcours](paths.md). Avant tout contenu pratique de sécurité, relisez les [règles de sécurité du labo](safety/lab-safety.md).

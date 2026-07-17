**Français** · [English](../../en/setup/windows.md)

# Installation Windows : MSVC

Ce guide installe le compilateur C Microsoft utilisé par la première leçon. Utilisez un système Windows 10 ou Windows 11 pris en charge pour préparer le cours ; utilisez une VM jetable pour les futurs laboratoires de sécurité.

## Prérequis Git

Git est requis pour cloner le dépôt du cours. Installez la version Windows depuis les [téléchargements Git officiels](https://git-scm.com/downloads/), rouvrez votre terminal, puis vérifiez-la :

```batch
git --version
```

La commande doit afficher une version de Git avant de continuer.

## 1. Installer Visual Studio Build Tools 2022

1. Téléchargez [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).
2. Lancez l'installateur et sélectionnez la charge de travail **Desktop development with C++**.
3. Gardez sélectionnés le compilateur MSVC et les composants Windows SDK recommandés par cette charge de travail.
4. Terminez l'installation et ne redémarrez Windows que si l'installateur le demande.

Une approbation administrateur peut être nécessaire pour l'installation. La compilation courante ne devrait pas nécessiter de terminal administrateur.

## 2. Ouvrir le terminal configuré

Dans le menu Démarrer de Windows, ouvrez **Developer Command Prompt for VS 2022**. Ce raccourci configure les chemins utilisés par `cl` ; une invite de commandes ordinaire peut ne pas trouver le compilateur.

Vérifiez l'emplacement et la version du compilateur :

```batch
where cl
cl
```

`where cl` doit afficher un chemin dans l'installation de Visual Studio Build Tools. `cl` doit afficher la bannière de version du compilateur Microsoft. Si Windows indique que `cl` est inconnu, confirmez la charge de travail choisie et rouvrez le Developer Command Prompt.

## 3. Vérifier la première compilation

Ouvrez la racine du dépôt dans le Developer Command Prompt, puis exécutez :

```batch
cd 01-c-fundamentals
cl lessons\01-hello-world.c /Fe:hello-world.exe
hello-world.exe
```

La sortie attendue du programme est `Hello, World!`. Revenez au [guide de première session](../start-here.md) pour l'exercice et la suite.

## Nettoyage ou désinstallation

Supprimez uniquement les fichiers de compilation générés :

```batch
del hello-world.exe 01-hello-world.obj
```

Pour retirer la chaîne d'outils, ouvrez **Visual Studio Installer**, choisissez **Modify** pour retirer **Desktop development with C++**, ou **More > Uninstall** pour Build Tools 2022. Ne le faites que si aucun autre projet n'utilise ces outils ou SDK partagés.

[Accueil du cours](../README.md) · [Sécurité du labo](../safety/lab-safety.md)

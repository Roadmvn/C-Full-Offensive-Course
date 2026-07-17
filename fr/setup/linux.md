**Français** · [English](../../en/setup/linux.md)

# Installation Linux : GCC ou Clang

Git est requis pour cloner le dépôt du cours. Installez Git, un compilateur C, `make` et `gdb`. Les commandes de paquets ci-dessous sont regroupées par distribution ; exécutez uniquement le bloc correspondant à votre système. Les [téléchargements Git officiels](https://git-scm.com/downloads/) fournissent une autre méthode si votre distribution ne propose pas Git.

## 1. Installer les outils

**Ubuntu ou Debian :**

```bash
sudo apt update
sudo apt install git build-essential clang gdb
```

**Fedora :**

```bash
sudo dnf install git gcc clang make gdb
```

**Arch Linux :**

```bash
sudo pacman -Syu --needed git base-devel clang gdb
```

Ces commandes modifient les paquets système et peuvent demander votre mot de passe administrateur. Ne combinez pas les commandes de distributions différentes.

## 2. Vérifier les outils

Les exemples ci-dessus installent GCC et Clang afin de pouvoir les comparer. Un seul des deux suffit pour compiler la première leçon.

```bash
git --version
gcc --version
clang --version
make --version
gdb --version
```

Chaque commande doit afficher le nom et la version de l'outil. S'il en manque un, utilisez le gestionnaire de paquets de votre distribution pour confirmer que son installation s'est terminée.

## 3. Vérifier la première compilation

Depuis la racine du dépôt, compilez avec GCC :

```bash
cd 01-c-fundamentals
gcc lessons/01-hello-world.c -o hello-world
./hello-world
```

ou avec Clang :

```bash
cd 01-c-fundamentals
clang lessons/01-hello-world.c -o hello-world
./hello-world
```

La sortie attendue du programme est `Hello, World!`. Revenez au [guide de première session](../start-here.md) pour l'exercice et la suite.

## Nettoyage ou désinstallation

Supprimez le programme généré dans `01-c-fundamentals` :

```bash
rm hello-world
```

Si vous désinstallez ensuite des paquets, utilisez le même gestionnaire de paquets et ne retirez que ceux installés exclusivement pour ce cours. Des groupes de développement comme `build-essential` ou `base-devel` peuvent être partagés par d'autres projets ; consultez donc l'historique et les dépendances du gestionnaire avant de les retirer.

[Accueil du cours](../README.md) · [Sécurité du labo](../safety/lab-safety.md)

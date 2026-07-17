**Français** · [English](../../en/setup/macos.md)

# Installation macOS : Clang

Les Xcode Command Line Tools d'Apple fournissent `clang`, `make` et les utilitaires de développement associés sans exiger l'application Xcode complète.

Git est requis pour cloner le dépôt du cours. Les Command Line Tools installés ci-dessous fournissent normalement Git eux aussi ; si Git reste indisponible ensuite, utilisez les [téléchargements Git officiels](https://git-scm.com/downloads/).

## 1. Installer Xcode Command Line Tools

Ouvrez Terminal et exécutez :

```bash
xcode-select --install
```

Suivez la boîte de dialogue macOS et acceptez les conditions de licence Apple. Si macOS indique que les outils sont déjà installés, passez à la vérification.

## 2. Vérifier les outils et l'architecture

```bash
git --version
xcode-select -p
clang --version
make --version
uname -m
```

`xcode-select -p` doit afficher le répertoire de développement actif, et `clang --version` la version du compilateur. `uname -m` renvoie normalement `arm64` sur Apple Silicon ou `x86_64` sur un Mac Intel. Notez cette valeur, car certains contenus ultérieurs sur l'assembleur ou la plateforme dépendent de l'architecture.

Pour les apprenants sur Apple Silicon, les exercices d'assembleur de `03-asm-x64` nécessitent une VM `x86-64`. Rosetta seule ne garantit pas que le compilateur, l'assembleur, le débogueur et l'environnement x86-64 attendus par le module soient disponibles ; utilisez une VM x86-64 jetable pour ces exercices.

## 3. Vérifier la première compilation

Depuis la racine du dépôt, exécutez :

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

Les Command Line Tools sont partagés par de nombreux outils de développement. Conservez-les sauf raison particulière de les retirer ; si une désinstallation est nécessaire, suivez la procédure actuelle prise en charge par Apple pour les outils de développement au lieu de supprimer des répertoires sans vérification.

[Accueil du cours](../README.md) · [Sécurité du labo](../safety/lab-safety.md)

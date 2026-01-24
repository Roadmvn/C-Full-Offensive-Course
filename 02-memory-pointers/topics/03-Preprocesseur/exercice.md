# Module 13 : Préprocesseur et Macros - Exercices

## Exercice 1 : Macros de base
[ ] Créer une macro CUBE(x) qui calcule le cube d'un nombre
[ ] Créer une macro ABS(x) qui retourne la valeur absolue
[ ] Créer une macro IS_EVEN(x) qui teste si un nombre est pair
[ ] Tester avec différentes valeurs et expressions (ex: CUBE(2+1))

## Exercice 2 : Compilation conditionnelle multi-plateforme
[ ] Créer un programme qui compile différemment selon l'OS
[ ] Définir des chemins différents pour Windows/Linux/macOS
[ ] Ajouter des fonctions spécifiques à chaque plateforme
[ ] Tester la compilation avec -D flags personnalisés

## Exercice 3 : Obfuscation de strings
[ ] Créer une macro qui XOR tous les caractères d'une string
[ ] Implémenter un système de clé de chiffrement
[ ] Obfusquer plusieurs strings sensibles
[ ] Créer une fonction de déobfuscation à l'exécution

## Exercice 4 : Logging conditionnel
[ ] Créer 3 niveaux de log: DEBUG, INFO, ERROR
[ ] Implémenter avec macros variadiques
[ ] Ajouter timestamp et nom de fichier automatiquement
[ ] Compiler avec différents niveaux de verbosité

## Exercice 5 : Token pasting avancé
[ ] Créer une macro qui génère automatiquement des getters/setters
[ ] Utiliser ## pour créer des noms de fonctions
[ ] Générer une structure et ses fonctions d'accès
[ ] Tester avec plusieurs types de données

## Exercice 6 : Anti-debugging avec macros
[ ] Créer une macro CHECK_DEBUGGER qui détecte ptrace
[ ] Implémenter différemment selon l'OS (Linux vs macOS)
[ ] Ajouter un mode "stealth" qui ne fait rien
[ ] Tester en mode normal et sous debugger

## Exercice 7 : Macros pour payload multiplateforme
[ ] Définir des payloads différents selon l'architecture (x64/ARM64)
[ ] Créer des macros pour shellcode adaptatif
[ ] Implémenter un système de fallback
[ ] Compiler pour différentes architectures

## Exercice 8 : Optimisation et inline
[ ] Comparer macro vs fonction inline vs fonction normale
[ ] Mesurer la performance avec un benchmark
[ ] Analyser le code assembleur généré (gcc -S)
[ ] Identifier quand utiliser chaque approche

BONUS:
[ ] Créer un système de macros pour encoder/décoder Base64
[ ] Implémenter un obfuscateur de noms de fonctions
[ ] Générer automatiquement des anti-analysis checks
[ ] Créer un header avec toutes vos macros offensives

TIPS:
- Toujours parenthéser les arguments de macros
- Utiliser gcc -E pour voir l'expansion des macros
- Attention aux side-effects (i++, fonction calls)
- Préférer inline pour le code complexe
- Documenter les macros complexes

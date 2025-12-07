# MODULE 17 : COMPILATION ET LINKING - EXERCICES

## Exercice 1 : Étapes de compilation
[ ] Créer un programme simple (main.c)
[ ] Générer le fichier préprocessé (.i)
[ ] Générer le fichier assembleur (.s)
[ ] Générer le fichier objet (.o)
[ ] Créer l'exécutable final
[ ] Comparer les contenus de chaque étape
[ ] Identifier les différences entre chaque fichier

## Exercice 2 : Optimisations
[ ] Compiler le même code avec -O0, -O1, -O2, -O3, -Os
[ ] Comparer les tailles des binaires (size command)
[ ] Désassembler chaque version (objdump -d)
[ ] Mesurer les performances avec un benchmark
[ ] Identifier quel niveau d'optimisation choisir selon le contexte

## Exercice 3 : Bibliothèque statique
[ ] Créer un fichier mylib.c avec 3 fonctions utilitaires
[ ] Compiler en fichier objet (.o)
[ ] Créer une bibliothèque statique (.a) avec ar
[ ] Créer un main.c qui utilise cette bibliothèque
[ ] Compiler et lier le programme final
[ ] Vérifier que le binaire contient le code de la lib (nm)

## Exercice 4 : Bibliothèque dynamique
[ ] Créer une bibliothèque partagée (.so ou .dylib)
[ ] Compiler avec -fPIC -shared
[ ] Créer un programme qui l'utilise
[ ] Configurer LD_LIBRARY_PATH (Linux) ou DYLD_LIBRARY_PATH (macOS)
[ ] Vérifier les dépendances avec ldd/otool -L
[ ] Comparer la taille avec la version statique

## Exercice 5 : Analyse de symboles
[ ] Créer un programme avec symboles globaux, static, extern
[ ] Compiler sans strip
[ ] Lister tous les symboles avec nm
[ ] Identifier les types de symboles (T, D, B, U)
[ ] Compiler avec -s (strip) et comparer
[ ] Utiliser readelf -s (Linux) ou nm -m (macOS)

## Exercice 6 : Protections de sécurité
[ ] Compiler un programme vulnérable (buffer overflow)
[ ] Version avec toutes les protections activées
[ ] Version sans aucune protection
[ ] Utiliser checksec pour vérifier
[ ] Tester l'exploitation dans les deux cas
[ ] Comparer les différences en assembleur

## Exercice 7 : Analyse de format binaire
[ ] Compiler un programme
[ ] Analyser le header ELF/Mach-O (readelf -h / otool -h)
[ ] Lister les sections (readelf -S / otool -l)
[ ] Identifier .text, .data, .bss, .rodata
[ ] Trouver le point d'entrée (entry point)
[ ] Dumper le contenu de chaque section

## Exercice 8 : Injection de bibliothèque
[ ] Créer une bibliothèque malveillante qui hook printf
[ ] Compiler en .so/.dylib
[ ] Utiliser LD_PRELOAD (Linux) ou DYLD_INSERT_LIBRARIES (macOS)
[ ] Tester l'injection sur des programmes système (/bin/ls)
[ ] Observer le comportement modifié
[ ] Créer un hook plus sophistiqué

BONUS:
[ ] Créer un programme qui se compile différemment selon l'OS
[ ] Implémenter un système de vérification d'intégrité
[ ] Créer un binaire polymorphe (change à chaque compilation)
[ ] Analyser un malware réel avec les outils du module
[ ] Créer un script pour automatiser l'analyse binaire

TIPS:
- Utiliser file pour identifier le type de fichier
- objdump est l'outil universel pour analyser
- strings révèle beaucoup d'informations
- nm pour les symboles, ldd pour les dépendances
- checksec pour vérifier les protections
- Comparer toujours les versions debug et release

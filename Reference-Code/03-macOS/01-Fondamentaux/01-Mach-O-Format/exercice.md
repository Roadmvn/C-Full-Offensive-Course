# EXERCICE : MACH-O FORMAT


### OBJECTIF :
Analyser et manipuler des binaires Mach-O.

1. Créer un parser Mach-O qui affiche :
   - Magic number
   - CPU type
   - File type
   - Tous les load commands
   - Tous les segments et sections

2. Extraire toutes les strings du binaire

3. Trouver le point d'entrée (_main)

4. Lister toutes les dylibs chargées

5. Créer un patcher qui modifie une instruction


### COMPILATION :
clang -o parser example.c


### USAGE :
./parser /bin/ls



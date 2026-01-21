# MODULE 18 : DEBUGGING GDB/LLDB - EXERCICES

## Exercice 1 : Breakpoints de base
[ ] Compiler example.c avec symboles de debug (-g)
[ ] Lancer GDB/LLDB et mettre breakpoint sur main
[ ] Mettre breakpoint sur factorial
[ ] Lancer le programme et observer l'arrêt
[ ] Continuer jusqu'au prochain breakpoint
[ ] Lister tous les breakpoints actifs

## Exercice 2 : Step et navigation
[ ] Breakpoint sur main
[ ] Utiliser next pour avancer ligne par ligne
[ ] Utiliser step pour entrer dans factorial
[ ] Observer la différence entre step et next
[ ] Utiliser finish pour sortir de la fonction
[ ] Utiliser until pour aller à la ligne suivante

## Exercice 3 : Examination de variables
[ ] Breakpoint dans factorial
[ ] Afficher la valeur de n avec print
[ ] Afficher n en hexadécimal (print/x)
[ ] Afficher toutes les variables locales (info locals)
[ ] Afficher les arguments de la fonction (info args)
[ ] Modifier la valeur de n avec set

## Exercice 4 : Backtrace et frames
[ ] Mettre breakpoint dans factorial avec n=1
[ ] Lancer et examiner le backtrace complet
[ ] Compter combien de frames
[ ] Naviguer entre les frames (frame 0, frame 1, etc.)
[ ] Afficher les variables de chaque frame
[ ] Observer la stack qui grandit

## Exercice 5 : Watchpoints
[ ] Mettre watchpoint sur watch_me
[ ] Lancer le programme
[ ] Observer quand le watchpoint se déclenche
[ ] Examiner l'ancienne et nouvelle valeur
[ ] Tester rwatch (read) et awatch (access)
[ ] Supprimer le watchpoint

## Exercice 6 : Examination mémoire
[ ] Breakpoint dans memory_operations
[ ] Examiner stack_var avec x/s
[ ] Examiner heap_var avec x/s
[ ] Afficher 20 bytes en hex: x/20x
[ ] Comparer les adresses stack vs heap
[ ] Dumper une région mémoire en fichier

## Exercice 7 : Registres et assembleur
[ ] Afficher tous les registres (info registers / register read)
[ ] Examiner RIP/PC (pointeur instruction)
[ ] Désassembler main
[ ] Désassembler factorial
[ ] Mettre breakpoint sur une adresse spécifique
[ ] Examiner le code autour de RIP: x/10i $rip

## Exercice 8 : Debugging de crash
[ ] Compiler vuln_function sans buffer protector
[ ] Lancer avec input long: run $(python3 -c 'print("A"*100)')
[ ] Observer le crash (SIGSEGV)
[ ] Examiner les registres au crash
[ ] Examiner la stack: x/40x $rsp
[ ] Identifier l'overflow dans la mémoire

BONUS:
[ ] Installer pwndbg ou GEF pour GDB
[ ] Créer un .gdbinit avec vos commandes favorites
[ ] Écrire un script Python pour GDB
[ ] Utiliser GDB pour bypass un anti-debug
[ ] Patcher du code en live avec set {int}addr=value
[ ] Automatiser une session de debug avec -x script.gdb

TIPS:
- Toujours compiler avec -g pour les symboles
- -O0 désactive optimisations (meilleur pour debug)
- Utiliser TUI mode: gdb -tui ou Ctrl+X A
- help <commande> pour l'aide
- Tab completion fonctionne partout
- Historique avec flèches haut/bas

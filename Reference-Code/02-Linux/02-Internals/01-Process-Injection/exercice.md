# MODULE L09 : PROCESS INJECTION - EXERCICES

## Exercice 1 : ptrace ATTACH/DETACH
[ ] Attacher à un processus avec PTRACE_ATTACH
[ ] Attendre avec waitpid()
[ ] Détacher avec PTRACE_DETACH
[ ] Tester sur `sleep 60`

## Exercice 2 : Lire registres
[ ] Attacher à un processus
[ ] Lire registres avec PTRACE_GETREGS
[ ] Afficher RIP, RSP, RBP, RAX
[ ] Détacher

## Exercice 3 : Lire mémoire
[ ] Attacher à un processus
[ ] Lire 8 bytes avec PTRACE_PEEKDATA
[ ] Afficher valeur hexadécimale
[ ] Détacher

## Exercice 4 : Écrire mémoire
[ ] Attacher à un processus
[ ] Écrire "HACKED" avec PTRACE_POKEDATA
[ ] Vérifier avec PTRACE_PEEKDATA
[ ] Détacher

## Exercice 5 : Injection shellcode
[ ] Attacher à un processus
[ ] Sauvegarder registres
[ ] Écrire shellcode (0xc3 = ret)
[ ] Modifier RIP vers shellcode
[ ] Détacher

## Exercice 6 : process_vm_writev
[ ] Utiliser process_vm_writev pour écrire
[ ] Comparer performance vs PTRACE_POKEDATA
[ ] Écrire bloc de 1KB

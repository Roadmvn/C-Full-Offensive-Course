# MODULE 37 : LINUX SYSCALLS - EXERCICES

## Exercice 1 : syscall() wrapper
[ ] Utiliser syscall(SYS_write, ...)
[ ] Utiliser syscall(SYS_read, ...)
[ ] Utiliser syscall(SYS_getpid)

## Exercice 2 : Inline assembly
[ ] Implémenter my_write avec inline asm
[ ] Implémenter my_read
[ ] Implémenter my_open

## Exercice 3 : Syscall table
[ ] Lister tous numéros syscall x64
[ ] Tester chaque syscall important
[ ] Comparer avec /usr/include/asm/unistd_64.h

## Exercice 4 : Bypass hooks
[ ] Créer LD_PRELOAD hook sur write
[ ] Appeler write() normal (hooké)
[ ] Appeler syscall direct (non hooké)
[ ] Observer différence

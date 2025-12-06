# MODULE 42 : macOS SYSCALLS - EXERCICES

## Exercice 1 : BSD syscalls
[ ] Implémenter write avec syscall direct
[ ] Implémenter read
[ ] Implémenter getpid (0x2000014)

## Exercice 2 : Mach traps
[ ] Utiliser task_self_trap (-28)
[ ] Utiliser thread_self_trap (-27)
[ ] Utiliser mach_reply_port (-26)

## Exercice 3 : Syscall table
[ ] Lister syscalls BSD (/usr/include/sys/syscall.h)
[ ] Tester différents syscalls
[ ] Comparer avec Linux

## Exercice 4 : Bypass hooks
[ ] Créer DYLD_INSERT_LIBRARIES hook sur write
[ ] Tester write() normal (hooké)
[ ] Tester syscall direct (non hooké)

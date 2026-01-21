# EXERCICE : SHELLCODE ARM64

1. Créer un shellcode exit(0)

2. Créer un shellcode write("PWN\n", 4)

3. Créer un shellcode execve("/bin/sh", NULL, NULL)

4. Encoder le shellcode avec XOR

5. Tester dans un loader C


### SYSCALLS :
- exit: 0x2000001
- write: 0x2000004
- execve: 0x200003B


### COMPILATION :
clang -o loader example.c
./loader
echo $?  # Voir exit code



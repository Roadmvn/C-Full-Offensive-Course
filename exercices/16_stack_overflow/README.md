# Stack Overflow

Le stack overflow permet de contrôler le flux d'exécution en écrasant l'adresse de retour stockée sur la pile. Cela permet de rediriger l'exécution vers du code arbitraire ou des fonctions existantes.

⚠️ AVERTISSEMENT : Code éducatif. Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.

```c
// Stack frame typique
void vulnerable() {
    char buffer[64];        // Buffer vulnérable
    // ... saved RBP ...
    // ... return address ... <- CIBLE : écraser ceci
    gets(buffer);           // Overflow vers return address
}

// Lors du 'ret', CPU saute vers l'adresse écrasée
```

## Compilation

```bash
gcc -fno-stack-protector -z execstack -no-pie example.c -o example
./example
```

## Concepts clés

- La stack stocke variables locales, saved RBP, et return address
- Un overflow du buffer peut écraser la return address
- Au moment du 'ret', l'exécution saute vers l'adresse écrasée
- Offset typique : taille_buffer + 8 (saved RBP sur x64)
- Les protections modernes (canaries, ASLR, DEP) compliquent l'exploitation

## Exploitation

Pour exploiter un stack overflow, il faut calculer l'offset entre le buffer et la return address. Sur x86-64, l'offset typique est : taille_buffer + 8 bytes (saved RBP).

Le payload se compose de : padding (pour remplir le buffer) + saved RBP (8 bytes) + return address (8 bytes). Par exemple, pour un buffer[64], le payload fait 64 + 8 + 8 = 80 bytes.

L'adresse cible peut être une fonction existante (comme win()), un shellcode placé dans le buffer, ou une libc function (return-to-libc). Avec -no-pie, les adresses sont fixes et prévisibles.

Les protections modernes rendent l'exploitation plus complexe : stack canaries détectent les corruptions, ASLR randomise les adresses, DEP/NX empêche l'exécution sur la stack, et PIE randomise le code.

## Outils

- GDB : debugger pour examiner la stack et calculer les offsets
- pwntools : framework Python pour générer des exploits
- checksec : vérifier les protections d'un binaire
- objdump -d : désassembler pour trouver les adresses

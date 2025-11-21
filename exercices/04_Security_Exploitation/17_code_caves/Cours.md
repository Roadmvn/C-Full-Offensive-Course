# Cours : Code Caves - Espaces Vides dans les Binaires

## 1. Introduction

**Code Cave** = Zone de bytes nuls (\x00) dans un exécutable où on peut injecter du code.

```ascii
BINAIRE ORIGINAL :

0x401000: Code section
0x401234: mov rax, rbx
0x401236: ...
0x401500: \x00\x00\x00...\x00  ← CODE CAVE ! (100 bytes vides)
0x401564: ...
```

## 2. Utilisation

1. Trouver une cave (zone de \x00)
2. Y écrire notre shellcode
3. Modifier un JMP pour sauter dans la cave
4. Exécuter, puis retourner au code original

## Ressources

- [Code Caves](https://www.codeproject.com/Articles/20240/The-Beginners-Guide-to-Codecaves)


# Cours : Obfuscation - Rendre le Code Illisible

## 1. Introduction

**Obfuscation** = Rendre le code difficile à analyser et reverse engineer.

## 2. Techniques

### 2.1 String Encryption

```c
// Au lieu de :
char cmd[] = "cmd.exe";  // Détectable

// Chiffrer :
char cmd[] = {0xC1, 0xC9, 0xCA, 0xD6, 0xC9, 0xD8, 0xC9};
decrypt_xor(cmd, 7, 0xAA);  // Runtime
```

### 2.2 Control Flow Obfuscation

```ascii
AVANT (clair) :
if (x > 10) {
    func_a();
} else {
    func_b();
}

APRÈS (obfusqué) :
switch ((x > 10) + rand() % 2) {
    case 0: func_b(); break;
    case 1: func_a(); break;
    case 2: func_a(); break;
}
```

### 2.3 Dead Code Insertion

Ajouter du code inutile pour confondre l'analyse.

## Ressources

- [Code Obfuscation](https://en.wikipedia.org/wiki/Obfuscation_(software))


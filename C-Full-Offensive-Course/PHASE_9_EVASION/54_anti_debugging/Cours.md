# Cours : Anti-Debugging - Détecter les Débogueurs

## 1. Introduction

**Anti-debugging** = Techniques pour détecter si le programme est analysé dans un débogueur (gdb, WinDbg, x64dbg).

## 2. Techniques Windows

### 2.1 IsDebuggerPresent()

```c
if (IsDebuggerPresent()) {
    exit(1);  // Débogueur détecté
}
```

### 2.2 PEB (Process Environment Block)

```c
// Vérifier flag BeingDebugged dans PEB
BOOL check_peb() {
    PPEB peb = (PPEB)__readgsqword(0x60);  // x64
    return peb->BeingDebugged;
}
```

### 2.3 Timing Attacks

```ascii
Code sans débogueur : rapide
Code avec débogueur : lent (breakpoints, step-by-step)

clock_t start = clock();
// Code rapide
clock_t end = clock();

if ((end - start) > THRESHOLD) {
    // Trop lent = débogueur !
}
```

## Ressources

- [Anti-Debugging Techniques](https://anti-debug.checkpoint.com/)


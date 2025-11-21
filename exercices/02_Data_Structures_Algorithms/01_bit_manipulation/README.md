# Manipulation de Bits

Maîtriser les opérations binaires pour optimiser le code et comprendre le bas niveau.

## Concepts Clés

- **Opérateurs binaires** : `&`, `|`, `^`, `~`
- **Décalages** : `<<`, `>>`
- **Masques** : Isoler/modifier des bits spécifiques
- **Flags** : Stocker plusieurs booléens dans un seul entier

## Opérations Essentielles

```c
// Vérifier un bit
if (x & (1 << n))

// Activer un bit
x |= (1 << n);

// Désactiver un bit
x &= ~(1 << n);

// Toggle un bit
x ^= (1 << n);
```

## Compilation

```bash
gcc example.c -o bitman
./bitman
```

## Applications

- Permissions Unix (rwx)
- Flags de compilation
- Réseaux (masques IP)
- Cryptographie
- Exploitation (shellcode, ROP)
- Optimisation (opérations rapides)

## Pourquoi C'est Important ?

Les opérations binaires sont :
- **Rapides** : 1 cycle CPU
- **Compactes** : Stocker 32 flags dans un int
- **Puissantes** : Contrôle total sur la mémoire
- **Essentielles** : Pour la sécurité et l'exploitation


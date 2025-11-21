# Binaire, Hexadécimal et Calculs IP

Comprendre les systèmes de numération et les calculs réseau.

## Concepts Clés

- **Binaire** (base 2) : 0, 1
- **Décimal** (base 10) : 0-9
- **Hexadécimal** (base 16) : 0-9, A-F

## Conversions

### Binaire ↔ Décimal

```
42₁₀ = 00101010₂
     = 32 + 8 + 2
```

### Binaire ↔ Hexadécimal

```
4 bits = 1 chiffre hexa
1010₂ = A₁₆
```

## Opérations

- **AND (&)** : Masquer des bits
- **OR (|)** : Activer des bits
- **XOR (^)** : Inverser des bits
- **<< / >>** : Décalages (× ou ÷ par 2)

## Calculs IP

```
IP : 192.168.1.10/24
Masque : 255.255.255.0
Réseau : 192.168.1.0
Machines : 254 (2^8 - 2)
```

## Compilation

```bash
gcc example.c -o binary_demo
./binary_demo
```

## Applications

- Adresses mémoire
- Adresses IP
- Permissions Unix (rwx)
- Flags et options
- Cryptographie
- Compression


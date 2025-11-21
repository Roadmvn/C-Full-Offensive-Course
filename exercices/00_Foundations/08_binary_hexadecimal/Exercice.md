# Exercices : Binaire, Hexadécimal et IP

## PARTIE 1 : Conversions de Base

### Exercice 1 : Décimal → Binaire

Convertir les nombres suivants en binaire (8 bits) :

1. 7
2. 15
3. 64
4. 127
5. 200

**Méthode** : Divisions successives par 2

---

### Exercice 2 : Binaire → Décimal

Convertir en décimal :

1. 00001111
2. 10101010
3. 11110000
4. 01010101
5. 11111111

**Méthode** : Additionner les puissances de 2

---

### Exercice 3 : Hexadécimal → Décimal

Convertir :

1. 0x10
2. 0xFF
3. 0xAB
4. 0x100
5. 0xDEAD

---

### Exercice 4 : Décimal → Hexadécimal

Convertir :

1. 16
2. 255
3. 256
4. 4096
5. 65535

---

## PARTIE 2 : Opérations Binaires

### Exercice 5 : Opérations AND, OR, XOR

Calculer (montrer les étapes en binaire) :

1. 0b1100 & 0b1010
2. 0b1100 | 0b1010
3. 0b1100 ^ 0b1010
4. ~0b1010
5. 0xFF & 0x0F

---

### Exercice 6 : Décalages

Calculer :

1. 8 << 1
2. 8 << 3
3. 64 >> 2
4. 100 >> 1
5. 1 << 7

---

## PARTIE 3 : Masques et Extraction

### Exercice 7 : Extraire des Bits

Pour la valeur 0xA5 (10100101) :

1. Extraire les 4 bits de poids fort
2. Extraire les 4 bits de poids faible
3. Extraire le bit 5
4. Vérifier si le bit 3 est activé
5. Activer le bit 2

---

### Exercice 8 : Manipulation de Bits

Créer des fonctions pour :

1. Activer un bit à la position N
2. Désactiver un bit à la position N
3. Inverser un bit à la position N
4. Vérifier si un bit est activé
5. Compter le nombre de bits à 1

---

## PARTIE 4 : Adresses IP

### Exercice 9 : Conversions IP

Convertir les IP suivantes en binaire :

1. 192.168.1.1
2. 10.0.0.1
3. 172.16.0.1
4. 255.255.255.255
5. 127.0.0.1

---

### Exercice 10 : Calculs de Sous-Réseau

Pour chaque réseau, calculer :
- Adresse réseau
- Première IP utilisable
- Dernière IP utilisable
- Adresse broadcast
- Nombre de machines

Réseaux :

1. 192.168.1.50/24
2. 10.0.0.100/8
3. 172.16.5.200/16
4. 192.168.10.50/26
5. 10.1.1.1/30

---

### Exercice 11 : Vérification Réseau

Vérifier si les IP suivantes sont dans le même réseau :

1. 192.168.1.10 et 192.168.1.200 (/24)
2. 10.0.5.10 et 10.1.5.10 (/8)
3. 172.16.1.1 et 172.16.2.1 (/16)
4. 192.168.1.65 et 192.168.1.130 (/26)

---

## PARTIE 5 : Programmation

### Exercice 12 : Calculateur en C

Créer un programme qui :

1. Affiche un nombre en binaire, décimal et hexa
2. Convertit binaire → décimal
3. Convertit hexa → binaire
4. Effectue des opérations AND, OR, XOR
5. Calcule le réseau d'une IP donnée

---

### Exercice 13 : Subnet Calculator

Créer un calculateur de sous-réseau qui :

1. Prend une IP et un masque CIDR (ex: /24)
2. Affiche l'adresse réseau
3. Affiche la plage d'IP utilisables
4. Affiche le broadcast
5. Affiche le nombre total de machines

---

## BONUS

### Exercice 14 : Compression

Stocker 4 valeurs (0-15) dans un seul byte en utilisant :
- Bits 0-1 : valeur 1
- Bits 2-3 : valeur 2
- Bits 4-5 : valeur 3
- Bits 6-7 : valeur 4

### Exercice 15 : Classes d'IP

Identifier la classe (A, B, C) des IP suivantes :

1. 10.0.0.1
2. 172.16.0.1
3. 192.168.1.1
4. 8.8.8.8
5. 224.0.0.1

---

## Compilation

```bash
gcc main.c -o calculator
./calculator
```


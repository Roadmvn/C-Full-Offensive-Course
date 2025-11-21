# Solutions : Binaire, Hexadécimal et IP

## PARTIE 1 : Conversions de Base

### Exercice 1 : Décimal → Binaire

```
1. 7   = 00000111
   (4 + 2 + 1)

2. 15  = 00001111
   (8 + 4 + 2 + 1)

3. 64  = 01000000
   (2^6)

4. 127 = 01111111
   (tous bits à 1 sauf MSB)

5. 200 = 11001000
   (128 + 64 + 8)
```

---

### Exercice 2 : Binaire → Décimal

```
1. 00001111 = 8+4+2+1 = 15
2. 10101010 = 128+32+8+2 = 170
3. 11110000 = 128+64+32+16 = 240
4. 01010101 = 64+16+4+1 = 85
5. 11111111 = 255
```

---

### Exercice 3 : Hexadécimal → Décimal

```
1. 0x10 = 16
2. 0xFF = 255
3. 0xAB = 10×16 + 11 = 171
4. 0x100 = 256
5. 0xDEAD = 13×4096 + 14×256 + 10×16 + 13 = 57005
```

---

## PARTIE 2 : Opérations

### Exercice 5 : AND, OR, XOR

```
1. 1100 & 1010 = 1000 (8)
2. 1100 | 1010 = 1110 (14)
3. 1100 ^ 1010 = 0110 (6)
4. ~1010 = 0101 (complément)
5. 0xFF & 0x0F = 0x0F (15)
```

---

### Exercice 6 : Décalages

```
1. 8 << 1 = 16 (8 × 2)
2. 8 << 3 = 64 (8 × 8)
3. 64 >> 2 = 16 (64 ÷ 4)
4. 100 >> 1 = 50 (100 ÷ 2)
5. 1 << 7 = 128 (bit 7 activé)
```

---

## PARTIE 4 : Adresses IP

### Exercice 10 : Sous-Réseaux

#### 1. 192.168.1.50/24

```
Masque : 255.255.255.0
Réseau : 192.168.1.0
Première : 192.168.1.1
Dernière : 192.168.1.254
Broadcast : 192.168.1.255
Machines : 254
```

#### 2. 10.0.0.100/8

```
Masque : 255.0.0.0
Réseau : 10.0.0.0
Première : 10.0.0.1
Dernière : 10.255.255.254
Broadcast : 10.255.255.255
Machines : 16,777,214
```

#### 4. 192.168.10.50/26

```
Masque : 255.255.255.192
Réseau : 192.168.10.0
Première : 192.168.10.1
Dernière : 192.168.10.62
Broadcast : 192.168.10.63
Machines : 62
```

---

## Code Complet - Subnet Calculator

```c
#include <stdio.h>

void calculer_subnet(unsigned char ip[4], int cidr) {
    // Créer masque
    unsigned int masque_int = 0xFFFFFFFF << (32 - cidr);
    unsigned char masque[4];
    masque[0] = (masque_int >> 24) & 0xFF;
    masque[1] = (masque_int >> 16) & 0xFF;
    masque[2] = (masque_int >> 8) & 0xFF;
    masque[3] = masque_int & 0xFF;
    
    // Adresse réseau
    unsigned char reseau[4];
    for (int i = 0; i < 4; i++) {
        reseau[i] = ip[i] & masque[i];
    }
    
    // Broadcast
    unsigned char broadcast[4];
    for (int i = 0; i < 4; i++) {
        broadcast[i] = reseau[i] | (~masque[i]);
    }
    
    // Affichage
    printf("IP        : %d.%d.%d.%d/%d\n", 
           ip[0], ip[1], ip[2], ip[3], cidr);
    printf("Masque    : %d.%d.%d.%d\n", 
           masque[0], masque[1], masque[2], masque[3]);
    printf("Réseau    : %d.%d.%d.%d\n", 
           reseau[0], reseau[1], reseau[2], reseau[3]);
    printf("Broadcast : %d.%d.%d.%d\n", 
           broadcast[0], broadcast[1], broadcast[2], broadcast[3]);
    
    int hotes = (1 << (32 - cidr)) - 2;
    printf("Machines  : %d\n", hotes);
}

int main() {
    unsigned char ip[] = {192, 168, 1, 50};
    calculer_subnet(ip, 24);
    
    return 0;
}
```

---

## Compilation

```bash
gcc solution.c -o subnet
./subnet
```


# SOLUTION : MANIPULATION DE BITS

Voici une implémentation complète du système de permissions avec manipulation de bits.


---
FICHIER : main.c

---


```c
#include <stdio.h>
```


```c
// Définition des permissions (bits)
#define READ    (1 << 0)  // 0b00000001 = 1
#define WRITE   (1 << 1)  // 0b00000010 = 2
#define EXECUTE (1 << 2)  // 0b00000100 = 4
#define DELETE  (1 << 3)  // 0b00001000 = 8
#define ADMIN   (1 << 4)  // 0b00010000 = 16
#define DEBUG   (1 << 5)  // 0b00100000 = 32
#define AUDIT   (1 << 6)  // 0b01000000 = 64
#define SUPER   (1 << 7)  // 0b10000000 = 128
```


```c
// 1. Ajouter une permission
```
unsigned char grant_permission(unsigned char perms, unsigned char flag) {
    return perms | flag;
}


```c
// 2. Retirer une permission
```
unsigned char revoke_permission(unsigned char perms, unsigned char flag) {
    return perms & ~flag;
}


```c
// 3. Vérifier une permission
int has_permission(unsigned char perms, unsigned char flag) {
    return (perms & flag) != 0;
}
```


```c
// 4. Toggle une permission
```
unsigned char toggle_permission(unsigned char perms, unsigned char flag) {
    return perms ^ flag;
}


```c
// 5. Afficher les permissions
void print_permissions(unsigned char perms) {
```
    printf("Permissions : ");
    
    if (perms & READ)    printf("READ ");
    if (perms & WRITE)   printf("WRITE ");
    if (perms & EXECUTE) printf("EXECUTE ");
    if (perms & DELETE)  printf("DELETE ");
    if (perms & ADMIN)   printf("ADMIN ");
    if (perms & DEBUG)   printf("DEBUG ");
    if (perms & AUDIT)   printf("AUDIT ");
    if (perms & SUPER)   printf("SUPER ");
    
    if (perms == 0) printf("AUCUNE");
    
    printf("\n");
}


```c
// 6. Compter les permissions actives
int count_permissions(unsigned char perms) {
    int count = 0;
```
    while (perms) {
        count += perms & 1;  // Ajoute le bit de poids faible
        perms >>= 1;         // Décale à droite
    }
    return count;
}


```c
// Alternative rapide (Brian Kernighan's Algorithm)
int count_permissions_fast(unsigned char perms) {
    int count = 0;
```
    while (perms) {
        perms &= (perms - 1);  // Retire le bit le plus à droite
        count++;
    }
    return count;
}


```c
// 7. Extraire les nibbles
void extract_nibbles(unsigned char byte) {
```
    unsigned char lower = byte & 0x0F;        // 4 bits de poids faible
    unsigned char upper = (byte >> 4) & 0x0F; // 4 bits de poids fort
    
    printf("Byte : 0x%02X\n", byte);
    printf("  Lower nibble : 0x%X (%d)\n", lower, lower);
    printf("  Upper nibble : 0x%X (%d)\n", upper, upper);
}


```c
// 8. Inverser tous les bits
```
unsigned char invert_bits(unsigned char byte) {
    return ~byte;
}


```c
// 9. Vérifier parité des bits
int has_even_parity(unsigned char byte) {
    int count = count_permissions(byte);
    return (count % 2) == 0;  // Pair = 1, Impair = 0
}
```


```c
// 10. Compresser 4 valeurs (0-15) dans un byte
```
unsigned char compress_values(unsigned char v1, unsigned char v2, 
                               unsigned char v3, unsigned char v4) {

```c
    // Chaque valeur sur 2 bits
    return ((v1 & 0x03) << 6) | 
```
           ((v2 & 0x03) << 4) | 
           ((v3 & 0x03) << 2) | 
           (v4 & 0x03);
}


```c
void decompress_values(unsigned char byte) {
```
    unsigned char v1 = (byte >> 6) & 0x03;
    unsigned char v2 = (byte >> 4) & 0x03;
    unsigned char v3 = (byte >> 2) & 0x03;
    unsigned char v4 = byte & 0x03;
    
    printf("Valeurs : %d %d %d %d\n", v1, v2, v3, v4);
}


```c
// Fonction utilitaire : Afficher en binaire
void print_binary(unsigned char byte) {
```
    printf("0b");
    for (int i = 7; i >= 0; i--) {
        printf("%d", (byte >> i) & 1);
    }
    printf(" (0x%02X = %d)\n", byte, byte);
}


```c
// ==============================================
// FONCTION MAIN - DÉMONSTRATION
// ==============================================
```


```c
int main() {
```
    printf("╔═══════════════════════════════════════╗\n");
    printf("║  SYSTÈME DE GESTION DE PERMISSIONS   ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");


```c
    // Initialisation
```
    unsigned char user_perms = 0;
    
    printf("1. AJOUT DE PERMISSIONS\n");
    printf("   Initial : ");
    print_binary(user_perms);
    
    user_perms = grant_permission(user_perms, READ);
    printf("   + READ : ");
    print_binary(user_perms);
    
    user_perms = grant_permission(user_perms, WRITE);
    printf("   + WRITE : ");
    print_binary(user_perms);
    
    user_perms = grant_permission(user_perms, EXECUTE);
    printf("   + EXECUTE : ");
    print_binary(user_perms);
    print_permissions(user_perms);
    
    printf("\n2. VÉRIFICATION\n");
    printf("   Has READ?    %s\n", has_permission(user_perms, READ) ? "OUI" : "NON");
    printf("   Has DELETE?  %s\n", has_permission(user_perms, DELETE) ? "OUI" : "NON");
    printf("   Count : %d permissions\n", count_permissions(user_perms));
    
    printf("\n3. RETRAIT DE PERMISSION\n");
    user_perms = revoke_permission(user_perms, WRITE);
    printf("   - WRITE : ");
    print_binary(user_perms);
    print_permissions(user_perms);
    
    printf("\n4. TOGGLE\n");
    user_perms = toggle_permission(user_perms, ADMIN);
    printf("   Toggle ADMIN : ");
    print_binary(user_perms);
    print_permissions(user_perms);
    
    user_perms = toggle_permission(user_perms, ADMIN);
    printf("   Toggle ADMIN again : ");
    print_binary(user_perms);
    print_permissions(user_perms);
    
    printf("\n5. PROFIL ADMIN COMPLET\n");
    unsigned char admin_perms = READ | WRITE | EXECUTE | DELETE | ADMIN;
    print_binary(admin_perms);
    print_permissions(admin_perms);
    printf("   Total : %d permissions\n", count_permissions(admin_perms));
    
    printf("\n6. EXTRACTION DE NIBBLES\n");
    extract_nibbles(0xAB);
    
    printf("\n7. INVERSION DE BITS\n");
    unsigned char original = 0b10110010;
    unsigned char inverted = invert_bits(original);
    printf("   Original : ");
    print_binary(original);
    printf("   Inverted : ");
    print_binary(inverted);
    
    printf("\n8. PARITÉ\n");
    unsigned char test1 = 0b1010;  // 2 bits (pair)
    unsigned char test2 = 0b1011;  // 3 bits (impair)
    printf("   0b1010 : %s\n", has_even_parity(test1) ? "Pair" : "Impair");
    printf("   0b1011 : %s\n", has_even_parity(test2) ? "Pair" : "Impair");
    
    printf("\n9. COMPRESSION\n");
    unsigned char compressed = compress_values(3, 2, 1, 0);
    printf("   Compressé : ");
    print_binary(compressed);
    printf("   Décompressé : ");
    decompress_values(compressed);
    
    printf("\n10. EXEMPLES PRATIQUES\n");
    

```c
    // Masque IP
```
    unsigned int ip = 0xC0A80101;  // 192.168.1.1
    printf("   IP : %d.%d.%d.%d\n",
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
    

```c
    // Swap sans variable temporaire
    int a = 42, b = 17;
```
    printf("   Avant swap : a=%d, b=%d\n", a, b);
    a ^= b;
    b ^= a;
    a ^= b;
    printf("   Après swap : a=%d, b=%d\n", a, b);
    

```c
    // Puissance de 2
```
    printf("   64 est puissance de 2 ? %s\n", 
           (64 && !(64 & (64-1))) ? "OUI" : "NON");
    printf("   63 est puissance de 2 ? %s\n", 
           (63 && !(63 & (63-1))) ? "OUI" : "NON");
    
    printf("\n═══════════════════════════════════════\n");
    printf("Programme terminé avec succès.\n");
    
    return 0;
}


---
EXPLICATIONS DÉTAILLÉES

---

1. GRANT (Ajouter) : perms | flag
   - Utilise OR pour activer le bit correspondant
   - 0b0001 | 0b0010 = 0b0011

2. REVOKE (Retirer) : perms & ~flag
   - Utilise AND avec le complément pour désactiver
   - 0b0111 & ~0b0010 = 0b0111 & 0b1101 = 0b0101

3. HAS (Vérifier) : (perms & flag) != 0
   - Utilise AND pour tester le bit
   - Si le résultat != 0, le bit est actif

4. TOGGLE (Inverser) : perms ^ flag
   - Utilise XOR pour inverser le bit
   - 0 ^ 1 = 1, 1 ^ 1 = 0

5. COUNT (Compter) :
   - Méthode 1 : Décaler et accumuler
   - Méthode 2 : Brian Kernighan (plus rapide)
     n & (n-1) retire le bit le plus à droite

6. NIBBLES :
   - Lower : byte & 0x0F (garde les 4 bits de droite)
   - Upper : (byte >> 4) & 0x0F (décale puis garde 4 bits)

7. COMPRESSION :
   - Place chaque valeur (2 bits) dans une position
   - v1 aux bits 6-7, v2 aux bits 4-5, etc.


---
COMPILATION ET EXÉCUTION

---

gcc main.c -o bitflags -Wall -Wextra
./bitflags


---
COMPLEXITÉ

---

Toutes les opérations : O(1) - Temps constant
Opérations binaires : 1 cycle CPU (extrêmement rapide)


---
FIN DE LA SOLUTION

---



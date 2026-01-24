# Module 20 - Opérations Bitwise : XOR et Masques

## Pourquoi tu dois maîtriser ça

```c
// XOR encoding (contourne les signatures AV)
unsigned char sc[] = {0x48, 0x31, 0xC0};
for (int i = 0; i < sizeof(sc); i++) sc[i] ^= 0xAA;

// Parser un header réseau
unsigned char ip_version = (header[0] >> 4) & 0x0F;

// Flags et permissions
if (perms & EXECUTE) exec_shellcode();
```

**Bitwise = encoding, parsing binaire, manipulation de flags.**

---

## Opérateurs en 30 secondes

| Opérateur | Action | Usage offensif |
|-----------|--------|----------------|
| `&` (AND) | 1 si les DEUX sont 1 | Masquer/extraire bits |
| `\|` (OR) | 1 si AU MOINS UN est 1 | Activer bits/flags |
| `^` (XOR) | 1 si DIFFÉRENTS | **Encoding réversible** |
| `~` (NOT) | Inverse tous les bits | Clear bits |
| `<<` | Décale à gauche | × 2^n |
| `>>` | Décale à droite | ÷ 2^n |

---

## XOR : L'arme secrète

> **Propriété magique** : `x ^ key ^ key = x` → même opération pour encoder ET décoder.

### Single-byte XOR

```c
void xor_encode(unsigned char* data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Encoder
unsigned char shellcode[] = {0x48, 0x31, 0xC0, 0x50};
xor_encode(shellcode, sizeof(shellcode), 0xAA);

// Décoder (même fonction!)
xor_encode(shellcode, sizeof(shellcode), 0xAA);
```

### Multi-byte XOR (plus résistant)

```c
void xor_multi(unsigned char* data, int len, unsigned char* key, int key_len) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];  // Rotation de clé
    }
}

unsigned char key[] = {0xDE, 0xAD, 0xBE, 0xEF};
xor_multi(shellcode, sizeof(shellcode), key, 4);
```

---

## Manipulation de bits

### Macros essentielles

```c
#define BIT_SET(val, bit)    ((val) |=  (1 << (bit)))   // Activer
#define BIT_CLEAR(val, bit)  ((val) &= ~(1 << (bit)))   // Désactiver
#define BIT_TOGGLE(val, bit) ((val) ^=  (1 << (bit)))   // Inverser
#define BIT_CHECK(val, bit)  ((val) &   (1 << (bit)))   // Tester
```

### Extraire des nibbles (4 bits)

```c
unsigned char byte = 0xAB;
unsigned char high = (byte >> 4) & 0x0F;  // 0x0A
unsigned char low  = byte & 0x0F;          // 0x0B
```

---

## Applications offensives

### 1. Parser header IP

```c
unsigned char ip_version = (header[0] >> 4) & 0x0F;  // Bits 4-7
unsigned char ihl        = header[0] & 0x0F;          // Bits 0-3
```

### 2. Flags TCP

```c
unsigned char flags = tcp_header[13];
int syn = (flags >> 1) & 0x01;
int ack = (flags >> 4) & 0x01;
int rst = (flags >> 2) & 0x01;
```

### 3. Permissions Unix

```c
#define READ    0b100
#define WRITE   0b010
#define EXECUTE 0b001

unsigned char perms = READ | WRITE;  // rw-
if (perms & EXECUTE) { /* ... */ }
perms |= EXECUTE;   // Ajouter
perms &= ~WRITE;    // Retirer
```

### 4. Obfuscation de constantes

```c
// Éviter les strings en clair
int port = (0x1000 | 0x15C);  // 4444
int cmd  = ('c' ^ 0x20) << 16 | ('m' ^ 0x20) << 8 | ('d' ^ 0x20);
```

---

## Checklist

```
□ Je comprends XOR et sa réversibilité
□ Je sais encoder avec single-byte et multi-byte XOR
□ Je sais extraire des bits avec masques (&)
□ Je sais manipuler des flags (|, &~)
□ Je sais utiliser les shifts pour parser des headers
```

---

## Glossaire express

| Terme | Définition |
|-------|------------|
| **XOR** | OU exclusif, réversible avec la même clé |
| **Masque** | Valeur pour isoler certains bits |
| **Nibble** | 4 bits (half-byte) |
| **Shift** | Décalage de bits (×2 ou ÷2 par position) |

---

**Temps lecture :** 3 min | **Pratique :** 15 min

# Cours : Cryptographie pour Malware

## 1. Introduction

La cryptographie dans les malwares sert à :
- Chiffrer les communications C2
- Obfusquer les strings sensibles
- Protéger le payload
- Éviter les signatures antivirus

## 2. XOR - Le Plus Simple

```ascii
Chiffrement ET déchiffrement avec la même opération !

Message : "SECRET"
Clé : 0xAA

'S' (0x53) ^ 0xAA = 0xF9  (chiffré)
0xF9 ^ 0xAA = 0x53 = 'S'  (déchiffré)
```

**Code** :
```c
void xor_encrypt(char *data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
```

## 3. AES - Standard Moderne

AES (Advanced Encryption Standard) : Chiffrement par blocs robuste.

```ascii
CHIFFREMENT AES :

Plaintext (16 bytes)
    ↓ + Clé (128/192/256 bits)
10-14 Rounds de transformations
    ↓
Ciphertext (16 bytes)
```

## Ressources

- [Cryptography Basics](https://en.wikipedia.org/wiki/Cryptography)
- [OpenSSL Library](https://www.openssl.org/)


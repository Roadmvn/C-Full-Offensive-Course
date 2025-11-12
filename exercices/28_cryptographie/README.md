# Module 28 : Cryptographie

## Objectifs d'apprentissage

Ce module explore les techniques cryptographiques utilisées en offensive security. Vous apprendrez :

- **XOR Cipher** : Chiffrement simple pour obfuscation
- **AES Encryption** : Chiffrement symétrique moderne
- **RSA Concepts** : Chiffrement asymétrique
- **String Obfuscation** : Cacher des strings sensibles
- **Hashing** : MD5, SHA-256 pour intégrité

## Concepts clés

### XOR Cipher
Opération bit à bit simple :
- Rapide et efficace
- Utilisé pour obfuscation basique
- Réversible (A XOR B XOR B = A)
- Vulnérable à l'analyse fréquentielle

### AES (Advanced Encryption Standard)
Chiffrement symétrique robuste :
- Clé de 128, 192 ou 256 bits
- Block cipher (blocs de 128 bits)
- Modes : ECB, CBC, CTR, GCM
- Standard industriel

### RSA
Chiffrement asymétrique :
- Paire de clés (publique/privée)
- Utilisé pour échange de clés
- Signature numérique
- Lent, utilisé avec AES (hybrid)

### String Obfuscation
Cacher les strings du binaire :
- Éviter détection par strings
- XOR ou AES au compile-time
- Déchiffrement runtime
- Complique l'analyse statique

## Architecture Cryptographique

```
┌─────────────────────────────────────────────────┐
│         Encryption/Decryption Flow              │
├─────────────────────────────────────────────────┤
│                                                 │
│  [Plaintext]                                    │
│       │                                         │
│       ├─→ XOR with key ──→ [Ciphertext]         │
│       │                                         │
│       ├─→ AES-256-CBC ──→ [Encrypted Data]      │
│       │      ↑                                  │
│       │      └── Key + IV                       │
│       │                                         │
│       └─→ Base64 Encode ──→ [Obfuscated]        │
│                                                 │
│  Hybrid (RSA + AES):                            │
│  1. Generate random AES key                     │
│  2. Encrypt data with AES                       │
│  3. Encrypt AES key with RSA public key         │
│  4. Send encrypted key + encrypted data         │
│                                                 │
└─────────────────────────────────────────────────┘
```

## Compilation

```bash
# Sans bibliothèque externe (XOR, Base64)
gcc -o crypto main.c

# Avec OpenSSL (AES, RSA, SHA)
gcc -o crypto main.c -lcrypto -lssl

# Windows
gcc -o crypto.exe main.c -lcrypto -lssl -lws2_32
```

## ⚠️ AVERTISSEMENT

**NE PAS RÉINVENTER LA CRYPTOGRAPHIE**

### Bonnes pratiques :
- Utiliser des bibliothèques éprouvées (OpenSSL, libsodium)
- Ne JAMAIS créer son propre algorithme
- Clés aléatoires et suffisamment longues
- IV (Initialization Vector) unique par chiffrement
- Authentification (HMAC, GCM) pour intégrité

### Erreurs communes :
- Clés hardcodées dans le binaire
- Réutilisation d'IV
- ECB mode (vulnérable)
- Mauvaise génération de nombres aléatoires

### Usage en Red Team :
- Chiffrement de payload pour évasion AV
- C2 communication chiffrée
- Exfiltration de credentials chiffrés
- Ransomware (⚠️ ILLÉGAL sans autorisation)

**USAGE ÉDUCATIF UNIQUEMENT**

## Exercices

Consultez `exercice.txt` pour 8 défis progressifs.

## Prérequis

- Bases de la cryptographie
- Compréhension des opérations binaires
- OpenSSL installé (optionnel)

---

**RAPPEL** : Cryptographie robuste = bibliothèques éprouvées, pas de custom crypto!

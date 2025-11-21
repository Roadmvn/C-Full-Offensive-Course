# Cryptographie - Chiffrement de Payload et String Obfuscation

XOR, AES-256, RSA, string obfuscation compile-time - techniques pour chiffrer payloads shellcode, évader signatures AV/EDR, protéger C2 traffic. Base de tous les crypters et polymorphic malware modernes.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// XOR encoding compile-time pour strings
#define XOR_KEY 0xAA
#define OBFUSCATE(s) {s[0]^XOR_KEY, s[1]^XOR_KEY, ...}

// Runtime decryption
unsigned char encrypted[] = OBFUSCATE("cmd.exe");
for(int i=0; i<sizeof(encrypted); i++) encrypted[i] ^= XOR_KEY;
CreateProcessA(encrypted, ...);  // "cmd.exe" jamais en plaintext dans binary
```

## Compilation

### Linux
```bash
gcc example.c -o crypter -lcrypto
```

### Windows
```bash
gcc example.c -o crypter.exe -lcrypto -lssl
```

## Concepts clés

- **XOR Cipher** : Obfuscation simple, rapide, réversible (shellcode encryption)
- **AES-256-CBC** : Chiffrement robuste payload (avec PKCS7 padding)
- **RC4** : Stream cipher rapide (utilisé WannaCry, Emotet)
- **String Obfuscation** : Compiler strings chiffrées (éviter "strings" command)
- **Key Derivation** : PBKDF2 pour générer clé depuis password
- **Crypters** : Chiffrer PE complet, déchiffrer en mémoire
- **Polymorphic Malware** : Rechiffrer avec clé différente à chaque exécution

## Techniques utilisées par

- **WannaCry** : AES-128 pour chiffrer fichiers, RSA-2048 pour clé AES
- **Emotet** : RC4 pour chiffrer strings et C2 traffic
- **Cobalt Strike** : AES-256 pour beacon encryption
- **APT29 (Cozy Bear)** : Custom XOR pour string obfuscation
- **Lazarus Group** : Multi-layer encryption (XOR + AES + RC4)

## Détection et Mitigation

**Indicateurs** :
- High entropy sections dans PE (.text avec entropy > 7.0)
- Imports crypto APIs (CryptEncrypt, BCrypt*)
- Strings chiffrées détectées par YARA entropy rules
- Decryption loops dans code (XOR pattern detection)

**Mitigations AV/EDR** :
- Entropy analysis des sections PE
- YARA rules pour crypto patterns
- Memory scanning post-decryption
- Behavioral detection (allocation RWX + write + execute)

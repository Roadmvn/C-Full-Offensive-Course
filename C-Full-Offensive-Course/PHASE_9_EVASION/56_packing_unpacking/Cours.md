# Cours : Packing - Compression et Chiffrement de Malware

## 1. Introduction

**Packer** = Compresse/chiffre un exécutable pour éviter la détection.

```ascii
MALWARE ORIGINAL :
┌──────────────┐
│ Code clair   │  → Signature détectée par AV
└──────────────┘

MALWARE PACKÉ :
┌──────────────────────────┐
│ Stub Unpacker            │  ← Code de décompression
├──────────────────────────┤
│ Payload Compressé/Chiffré│  → Signature cachée
└──────────────────────────┘

EXÉCUTION :
1. Stub décompresse/déchiffre
2. Charge en mémoire
3. Saute dessus
4. Malware original s'exécute
```

## 2. Packers Courants

- **UPX** : Open-source, simple
- **Themida** : Commercial, anti-debug
- **VMProtect** : Virtualisation de code

## Ressources

- [UPX](https://upx.github.io/)
- [Packing Techniques](https://www.sentinelone.com/blog/malware-packing-state-art/)


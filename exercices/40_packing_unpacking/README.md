# Module 40 - Packing & Unpacking

AVERTISSEMENT : Ce module est strictement educatif. Le packing de malware est une technique d'evasion utilisee par 90% des malwares modernes. Ne jamais utiliser sur systemes non autorises.

## Concepts

Le packing consiste a compresser et/ou chiffrer un executable pour masquer son contenu reel. L'unpacking est l'operation inverse (decompression/dechiffrement runtime).

### Objectifs Packing Malware

**Evasion AV**: Masquer signatures malveillantes connues
**Anti-Reverse Engineering**: Compliquer analyse statique
**Reduction Taille**: Compression binaire (effet secondaire)
**Polymorphisme**: Chaque generation = hash different

### Architecture Packer

```
Packed Executable Structure:
[Unpacker Stub] -> Code decompression/dechiffrement
[Packed Data]   -> Payload original compresse/chiffre
[Import Table]  -> Imports necessaires au stub
[Resources]     -> Eventuelles resources compressees
```

### Types de Packers

**Compression Packers**: UPX, ASPack, PECompact (legitimes)
**Cryptographic Packers**: Themida, VMProtect, Enigma
**Custom Packers**: Packers proprietaires malware-specific

### Processus Unpacking Runtime

1. Stub unpacker demarre execution
2. Allocate memoire pour payload original
3. Decompress/decrypt payload en memoire
4. Resoud imports du payload original
5. Transfert execution vers Original Entry Point (OEP)
6. (Optionnel) Efface stub unpacker de memoire

### Techniques Detection Packing

**Entropy Analysis**: Packed sections ont entropie elevee (>7.0)
**Section Anomalies**: Noms suspects (.UPX, .MPRESS), permissions RWX
**Import Table**: Tres peu imports (seuls ceux du stub)
**Behavioral**: Automodification code, allocation memoire suspecte

### Real-World Packers

**UPX (Ultimate Packer for eXecutables)**: Open source, tres utilise
**Themida**: Commercial, anti-debugging sophistique
**VMProtect**: Virtualization-based obfuscation
**Custom**: APT groups developpent packers proprietaires

### Unpacking Techniques

**Static Unpacking**: Extraction payload sans execution
**Dynamic Unpacking**: Execution + dump memoire a l'OEP
**Automated Tools**: PE-sieve, Scylla, UnpacMe service

## Detection & Mitigation

**Entropy Scanning**: Detecter sections haute entropie
**Behavioral Analysis**: Monitorer allocations memoire executables
**Yara Rules**: Signatures packers connus
**Memory Scanning**: Dumper process memory pour analyse

## Compilation

```bash
# Packer simple
gcc packer.c -o packer -lz

# Unpacker
gcc unpacker.c -o unpacker

# Test avec UPX
upx --best target.exe
upx -d target.exe  # Decompress
```

## Entropy Analysis

```bash
# Python entropy calculation
python -c "import math; from collections import Counter; data = open('file.exe','rb').read(); freq = Counter(data); ent = -sum(float(c)/len(data) * math.log2(float(c)/len(data)) for c in freq.values()); print(f'Entropy: {ent:.2f}')"
```

## References

- UPX: https://upx.github.io/
- Research: Practical Malware Analysis (Chapter 18)
- Tools: Detect It Easy, PE Studio, PEiD
- Service: UnpacMe.com (automated unpacking)

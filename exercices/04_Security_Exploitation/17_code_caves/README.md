# Module 39 - Code Caves

AVERTISSEMENT : Ce module est strictement educatif. L'injection dans code caves et le backdooring de binaires sont des techniques de malware avancees. Ne jamais utiliser sur des systemes non autorises.

## Concepts

Les code caves sont des regions de memoire inutilisees dans les executables (sections padding, alignment, etc.). Les attaquants les utilisent pour injecter du code malveillant sans augmenter visiblement la taille du fichier.

### Anatomie PE

```
PE Structure:
DOS Header (64 bytes)
DOS Stub
PE Signature (4 bytes)
COFF File Header (20 bytes)
Optional Header (224/240 bytes)
Section Headers (40 bytes each)
Sections (.text, .data, .rdata, etc.)
```

### Detection Code Caves

1. Identifier sections avec slack space (padding entre sections)
2. Rechercher sequences de null bytes (0x00) ou NOP (0x90)
3. Verifier taille cave >= taille shellcode
4. S'assurer permissions executables (RWX ou RX)

### Injection Process

1. Ouvrir fichier PE en lecture/ecriture
2. Parser headers pour localiser caves
3. Calculer RVA (Relative Virtual Address) cave
4. Ecrire shellcode dans cave
5. Modifier entry point ou hooker fonction existante
6. Recalculer checksum PE (optionnel)

### Techniques Backdooring

**Entry Point Modification**: Rediriger execution vers code cave au demarrage
**Import Table Hooking**: Remplacer adresse fonction importee
**Code Flow Hijacking**: Inserter JMP vers cave dans code legitime
**TLS Callbacks**: Ajouter callback executee avant entry point

### Real-World Examples

**APT29 (Cozy Bear)**: Modification PE pour persistence
**Turla**: Code cave injection dans drivers systeme
**Equation Group**: Binary patching sophistique

## Detection & Mitigation

**Entropy Analysis**: Code caves legitimes ont entropie basse
**PE Integrity Checking**: Verifier hash sections critiques
**Code Signing**: Invalidation signature apres modification
**Memory Scanning**: Detecter code executable dans regions inattendues

## Compilation

```bash
# Windows
cl example.c /Fe:pe_patcher.exe

# Linux (MinGW)
x86_64-w64-mingw32-gcc example.c -o pe_patcher.exe

# Analyse binaire
dumpbin /headers target.exe
objdump -x target.exe
```

## Limitations Techniques

- Code caves limites en taille (quelques centaines bytes max)
- Invalidation signatures code signing
- Detection par outils entropy analysis
- Complexite maintenir compatibilite PE

## References

- PE Format: Microsoft PE/COFF Specification
- Malware: Practical Malware Analysis (Sikorski & Honig)
- Tools: PE-bear, CFF Explorer, HxD

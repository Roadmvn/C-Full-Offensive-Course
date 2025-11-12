# Code Obfuscation - Evasion Analyse Statique

String encryption, control flow flattening, opaque predicates, junk code - techniques pour rendre le code illisible aux analystes et outils AV/EDR. Complique reverse engineering et signature-based detection.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Control flow flattening (state machine)
int state = 0;
while(state != -1) {
    switch(state) {
        case 0: shellcode_decrypt(); state = 1; break;
        case 1: check_debugger(); state = 2; break;
        case 2: execute_payload(); state = -1; break;
    }
}
```

## Compilation

### Linux/Windows
```bash
gcc example.c -o obfuscated -O0
objdump -d obfuscated  # Voir code assembleur obfusqué
```

## Concepts clés

- **String Encryption** : XOR compile-time pour cacher strings du binaire
- **Control Flow Flattening** : Transformer code linéaire en state machine
- **Opaque Predicates** : Conditions toujours vraies/fausses (complique CFG)
- **Junk Code** : Instructions inutiles mais valides (noyer le vrai code)
- **Dead Code** : Code jamais exécuté (fausses pistes)
- **Instruction Substitution** : Remplacer instr simples par équivalents complexes
- **Virtualization Obfuscation** : VM custom pour exécuter code

## Techniques utilisées par

- **VMProtect/Themida** : Virtualization + mutation pour protéger PE
- **Confuser/ConfuserEx** : Obfuscation .NET (control flow, renaming)
- **APT malwares** : String encryption + junk code pour éviter signatures
- **Packers (UPX, Themida)** : Compression + obfuscation + anti-debug
- **Obfuscator-LLVM** : LLVM passes pour obfuscation compile-time

## Détection et Mitigation

**Indicateurs** :
- Code assembleur anormal (junk instructions, dead code)
- Control flow complexe non-naturel (state machines flat)
- Strings absentes ou chiffrées (détecté par entropy)
- Taille binaire anormalement élevée

**Mitigations Reverse Engineering** :
- Analyse dynamique (exécution en sandbox)
- Deobfuscation automatique (IDA plugins, Binary Ninja)
- Symbolic execution (angr, Triton)
- Pattern matching pour junk code removal

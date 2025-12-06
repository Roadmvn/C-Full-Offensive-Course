# Modules Complétés - C Full Offensive Course

## Statut de complétion

### PHASE 2 : CONCEPTS AVANCÉS ✓
- ✓ **Module 16** : Préprocesseur et Macros
  - `#define`, `#include`, `#ifdef`, macros avancées pour obfuscation
- ✓ **Module 17** : Compilation et Linking
  - GCC flags, static/dynamic linking, PE/ELF basics, symbols, strip

### PHASE 3 : TOOLING ✓
- ✓ **Module 18** : Debugging GDB/LLDB
  - GDB Linux, LLDB macOS, breakpoints, memory, backtrace, registres
- ✓ **Module 19** : Debugging Windows
  - x64dbg, WinDbg basics, debugging malware, API monitoring

### PHASE 4 : EXPLOITATION BINAIRE ✓
- ✓ **Module 20** : Integer Overflow
  - Signed/unsigned, truncation, wraparound, exploitation
- ✓ **Module 27** : Race Conditions
  - TOCTOU, threading vulnerabilities, exploitation
- ✓ **Module 31** : ROP Chains ARM64
  - ROP sur ARM64, PAC bypass Apple Silicon

### PHASE 6 : LINUX INTERNALS ✓
- ✓ **Module 37** : Linux Syscalls
  - Syscalls directs x64, syscall table, inline assembly
- ✓ **Module 38** : ELF Parsing
  - Structure ELF, headers, sections, parsing binaire

### PHASE 7 : MACOS INTERNALS ✓
- ✓ **Module 42** : macOS Syscalls
  - Mach traps, BSD syscalls, XNU, syscall directs
- ✓ **Module 44** : macOS Persistence
  - LaunchAgents, LaunchDaemons, Login Items
- ✓ **Module 45** : macOS Evasion
  - TCC bypass, entitlements exploitation, SIP evasion

## Structure de chaque module

Chaque module contient 4 fichiers :

1. **README.md** : Théorie complète avec section "Pertinence Red Team"
2. **example.c** : Code fonctionnel commenté en français
3. **exercice.txt** : 8 exercices progressifs avec cases à cocher [ ]
4. **solution.txt** : Solutions complètes avec code et explications

## Comment utiliser

```bash
cd /Users/tudygbaguidi/Desktop/Learning-C/C-Full-Offensive-Course

# Exemple : Module 16
cd PHASE_2_CONCEPTS_AVANCES/16_preprocesseur_macros
cat README.md          # Lire la théorie
gcc example.c -o example && ./example  # Compiler et tester
cat exercice.txt       # Voir les exercices
cat solution.txt       # Consulter les solutions
```

## Progression recommandée

1. Lire le README.md du module
2. Compiler et exécuter example.c
3. Faire les exercices de exercice.txt
4. Comparer avec solution.txt
5. Expérimenter et modifier le code

## Notes

- Tous les exemples sont fonctionnels et compilables
- Code commenté en français pour faciliter la compréhension
- Focus offensive security et Red Team
- Style Bro Code : concis, pratique, efficace

---

**Créé le** : 2025-12-05  
**Total modules** : 12  
**Total fichiers** : 48  
**Statut** : ✓ COMPLET

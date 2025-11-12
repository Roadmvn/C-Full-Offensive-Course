# Learning C - Red Team Development

Formation progressive en C du niveau débutant absolu au malware development avancé.

## Objectif

Apprendre le C avec une **progression naturelle** vers le red teaming :
- **Modules 01-09** : Bases du C (style Bro Code)
- **Modules 10-14** : Concepts avancés + premières notes red team
- **Modules 15-20** : Exploitation (buffer overflow, shellcode, etc.)
- **Modules 21-45** : Malware development complet (OSWA prep)

## Prérequis

**AUCUN** - Ce cours part de zéro.

Tu dois juste savoir :
- Utiliser un terminal
- Naviguer dans les dossiers (cd, ls)

## Installation

```bash
chmod +x setup.sh
./setup.sh
```

Ou manuellement :
```bash
# macOS
brew install gcc

# Linux
sudo apt install build-essential gcc

# Windows
# Utilise WSL ou MinGW
```

## Structure

Chaque module contient **4 fichiers** :
```
XX_nom_module/
├── README.md       # Cours concis + exemples
├── example.c       # Code d'exemple commenté
├── exercice.txt    # 8 défis pratiques avec [ ] auto-évaluation
└── solution.txt    # Solutions complètes
```

**Plus de Makefile** - Compilation simple : `gcc example.c -o program`

## Progression

### Phase 1 : Bases C (01-09) - 1-2 semaines
Style **Bro Code** : ultra-concis, exemples neutres

- 01 : Hello World
- 02 : Variables et types
- 03 : Printf et scanf
- 04 : Opérateurs
- 05 : If/else/switch
- 06 : Loops (for, while, do-while)
- 07 : Arrays
- 08 : Strings
- 09 : Functions

### Phase 2 : Transition (10-14) - 1 semaine
Bases avancées + **section Red Team** à la fin de chaque README

- 10 : Pointeurs intro
- 11 : Pointeurs avancés
- 12 : Malloc et free
- 13 : Structures
- 14 : Fichiers

### Phase 3 : Exploitation (15-20) - 1-2 semaines
Code **vulnérable intentionnel**, avertissements légaux

- 15 : Buffer concept
- 16 : Stack overflow
- 17 : Shellcode
- 18 : Format string
- 19 : Heap exploitation
- 20 : Reverse shell

### Phase 4 : Malware Dev (21-45) - 3-4 semaines
Techniques **réelles** utilisées par APT groups

- 21 : Process & threads
- 22 : Syscalls directs (Hell's Gate, Halo's Gate)
- 23 : Windows APIs
- 24 : Process injection
- 25 : DLL injection
- 26 : API hooking
- 27 : Networking sockets & C2
- 28 : Cryptographie
- 29 : Obfuscation
- 30 : Anti-debugging
- 31 : Anti-VM/sandbox
- 32 : Persistence Windows
- 33 : Persistence Linux
- 34 : Token manipulation
- 35 : Registry manipulation
- 36 : Memory mapping
- 37 : Reflective loading
- 38 : ROP chains
- 39 : Code caves
- 40 : Packing/unpacking
- 41 : ETW patching
- 42 : AMSI bypass
- 43 : Credential dumping
- 44 : Lateral movement
- 45 : C2 development

## Comment utiliser

### Pour chaque module :

```bash
cd exercices/01_hello_world/

# 1. Lire le cours
cat README.md

# 2. Étudier le code
cat example.c

# 3. Compiler et tester
gcc example.c -o program
./program

# 4. Faire les exercices
cat exercice.txt

# 5. Vérifier les solutions
cat solution.txt
```

### Règles d'apprentissage :

✅ Faire les modules dans l'ordre (01 → 02 → 03 → ...)
✅ Lire TOUS les commentaires dans le code
✅ Faire les exercices avant de regarder les solutions
✅ Réé crire le code sans regarder pour mémoriser

❌ Ne pas sauter de modules
❌ Ne pas copier-coller sans comprendre
❌ Ne pas ignorer les warnings du compilateur

## Temps estimé

| Modules | Durée par module |
|---------|------------------|
| 01-09 | 30-60 min |
| 10-14 | 1-2h |
| 15-20 | 2-4h |
| 21-33 | 3-5h |
| 34-45 | 4-6h |

**Total** : 120-200 heures (~3-6 mois à temps partiel)

## Après ce cours

Tu sauras :
- ✓ Coder en C de manière professionnelle
- ✓ Comprendre l'architecture mémoire et système
- ✓ Exploiter des vulnérabilités binaires
- ✓ Développer des outils de red teaming
- ✓ Passer la certification **OSWA**
- ✓ Préparer des entretiens **FAANG Red Team**

## Prochaines étapes

- **CTF** : HackTheBox, TryHackMe, PicoCTF
- **Certifications** : OSWA, OSCP, OSCE
- **Assembleur** : x86/x64 pour reverse engineering
- **Outils** : IDA, Ghidra, Binary Ninja
- **Advanced** : ROP, ret2libc, heap feng shui

## Ressources

- [GCC Docs](https://gcc.gnu.org/onlinedocs/)
- [GDB Tutorial](https://www.gdbtutorial.com/)
- [C Reference](https://en.cppreference.com/w/c)
- **Bro Code** : [YouTube C Tutorial](https://www.youtube.com/watch?v=87SH2Cn0s9A)

## ⚠️ AVERTISSEMENT LÉGAL

**Les techniques enseignées sont à des fins ÉDUCATIVES UNIQUEMENT.**

**Usage autorisé sur** :
- Tes propres systèmes
- VM de test isolées
- CTF légaux
- Bug bounty avec autorisation
- Red team contractuel

**INTERDIT** :
- Systèmes sans autorisation
- Usage malveillant
- Attaques réelles

**Usage illégal = PRISON**. Nous déclinons toute responsabilité.

## Démarrage rapide

```bash
cd exercices/01_hello_world/
cat README.md
gcc example.c -o program
./program
```

**Bonne chance ! 🔥**

---

*"Le C est la clé pour comprendre comment les systèmes fonctionnent réellement."*

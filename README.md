# Learning C - Système & Sécurité Offensive (Red Team)

[![Stars](https://img.shields.io/github/stars/yourusername/Learning-C?style=social)](https://github.com/yourusername/Learning-C/stargazers)
[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![French](https://img.shields.io/badge/Lang-Fran%C3%A7ais-blue.svg)](README.md)
[![Level](https://img.shields.io/badge/Level-Zero%20to%20Malware%20Dev-red.svg)](PROGRESSION.md)

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║          Arbre d'Apprentissage : Maîtrise du C "Système" & Offensif       ║
║          De la Syntaxe de Base aux Techniques Red Team Avancées           ║
║          (Windows Internals, macOS ARM, Evasion, Post-Exploitation)       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

Ce parcours est conçu pour bâtir une expertise technique profonde, en partant de zéro. L'objectif est la **compréhension intime des mécanismes**, prérequis indispensable pour l'exploitation et le développement d'outils offensifs.

---

## 🌳 Arbre d'Apprentissage

### 1. Le Socle Fondamental (Les Racines)
*L'objectif est d'écrire du code qui fonctionne et de comprendre la syntaxe de base.*

*   **Environnement** : GCC/Clang, VS Code/Vim, Compilation (`gcc main.c`).
*   **Syntaxe de Base** : Variables, Types (`int`, `char`), Opérateurs.
*   **Contrôle de Flux** : `if`, `else`, `switch`, Boucles (`for`, `while`).
*   **Fonctions** : Déclaration, Définition, Portée (Scope).

### 2. Le Cœur du C : Mémoire et Pointeurs (Le Tronc)
*C'est l'étape critique. 90% de la sécurité repose sur la maîtrise de la mémoire.*

*   **Pointeurs** : Adresse (`&`), Déréférencement (`*`), `NULL`.
*   **Tableaux & Strings** : Relation Tableau/Pointeur, `string.h`.
*   **Gestion Mémoire** :
    *   **Stack** (Pile) : Variables locales, frames de fonction.
    *   **Heap** (Tas) : `malloc`, `free`, `calloc`, `realloc`.
    *   **Dangers** : Memory Leaks, Double Free, Use-After-Free.

### 3. Techniques Avancées et Structuration (Les Branches)
*Organisation des données et techniques idiomatiques.*

*   **Types Composites** : `struct`, `union` (très important pour le parsing), `enum`.
*   **Fichiers** : `fopen`, `fread`, `fwrite` (Manipulation binaire).
*   **Préprocesseur** : Macros `#define`, inclusion conditionnelle.
*   **Avancé** : Pointeurs de fonction (Callbacks), `void*`, Arguments CLI (`argc`/`argv`).

### 4. Structures de Données (L'Écosystème)
*Implémentation manuelle pour comprendre l'allocation mémoire complexe.*

*   **Linéaires** : Listes chaînées, Piles, Files.
*   **Non-Linéaires** : Arbres Binaires, Hashmaps.
*   **Algorithmes** : Tri, Recherche, Récursivité.

### 5. Interaction Bas-Niveau et Système (Le Sol)
*Sortir du C pur pour parler à l'OS (Linux/POSIX).*

*   **Bitwise** : Masques, XOR (chiffrement simple), Décalages.
*   **Toolchain** : Compilation, Linking, Makefile, Bibliothèques (`.a`, `.so`).
*   **Appels Système (Linux)** : `open`, `read`, `fork`, `exec`, `socket`.
*   **Réseau** : Sockets TCP/UDP, Client/Serveur.

### 6. Fondamentaux de la Sécurité (L'Analyse)
*Comprendre la vulnérabilité pour mieux l'exploiter.*

*   **Mémoire Processus** : Segments `.text`, `.data`, Stack layout.
*   **Assembleur (x86_64)** : Registres, Instructions de base, Stack Frames.
*   **Exploitation** : Buffer Overflow (Stack/Heap), Format String.
*   **Protections** : ASLR, DEP/NX, Canaries (et comment les contourner en théorie).

---

### 🛡️ 7. Malware Dev & Windows Internals (L'Armement)
*Le C est le langage natif de Windows. Indispensable pour l'offensif.*

*   **Format PE** : Headers, Sections, Import Address Table (IAT).
*   **Win32 API** : `windows.h`, Types (`HANDLE`, `LPVOID`, `DWORD`).
*   **Manipulation Processus** : `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`.
*   **Techniques d'Injection** :
    *   DLL Injection (Classique).
    *   Process Hollowing.
    *   Reflective DLL Loading (Chargement sans disque).

### 🍎 8. Spécificités macOS ARM & Apple Silicon (La Pomme)
*L'offensif moderne sur Mac (M1/M2/M3).*

*   **Architecture ARM64 (AArch64)** :
    *   Registres (`x0`-`x30`, `sp`, `pc`, `lr`).
    *   Instructions (`mov`, `ldr`, `str`, `svc`).
    *   Calling Convention ARM64.
*   **Format Mach-O** : Headers, Load Commands (`LC_SEGMENT_64`), FAT binaries.
*   **Sécurité Apple** :
    *   **PAC** (Pointer Authentication Codes) : Signature de pointeurs.
    *   **Codesigning** : Contraintes strictes (Entitlements, CS_FLAGS).
    *   **SIP** (System Integrity Protection) & Gatekeeper.
*   **Techniques Offensives** : Shellcode ARM64, Dylib Injection (`DYLD_INSERT_LIBRARIES`).

### 👻 9. Evasion & Discrétion (Le Camouflage)
*Ne pas se faire détecter par les EDR/AV.*

*   **Obfuscation** :
    *   Chiffrement de chaînes (Stack Strings, XOR).
    *   API Hashing (Masquer l'IAT).
*   **Direct Syscalls** :
    *   Windows : Hell's Gate, Halo's Gate (Contourner les hooks User-mode).
    *   macOS : Instructions `svc` directes.
*   **Anti-Analysis** : Détection de Debugger (`IsDebuggerPresent`, `ptrace`), Détection de VM/Sandbox.

### 🏴‍☠️ 10. Post-Exploitation (La Persistance)
*S'installer durablement.*

*   **Persistance** :
    *   Windows : Registre (Run Keys), Services, Tâches Planifiées.
    *   Linux/macOS : `cron`, `LaunchDaemons`, `.zshrc`.
*   **Credential Dumping** : Accès mémoire LSASS, Parsing SAM/SECURITY.
*   **C2 Development** : Architecture Client/Serveur robuste, protocoles furtifs.

---

## 📂 Structure du Projet

Chaque module contient désormais un fichier **`Cours.md`** essentiel :

```text
XX_Module_Name/
├── Cours.md        # 📘 THÉORIE COMPLÈTE + SCHÉMAS ASCII
├── example.c       # 💻 Code de démonstration commenté
├── exercice.txt    # 🎯 Énoncé du défi
└── solution.txt    # ✅ Correction expliquée
```

## 🚀 Comment Démarrer

1.  **Cloner le repo** : `git clone ...`
2.  **Installer GCC/Clang** (via `setup.sh`).
3.  **Suivre l'ordre** : Ne sautez pas les bases (Niveaux 1 & 2) !
4.  **Pratiquer** : Codez *toujours* les exemples à la main.

---

⚠️ **AVERTISSEMENT LÉGAL** : Ce contenu est strictement éducatif. L'utilisation de ces techniques sur des systèmes sans autorisation explicite est illégale et passible de sanctions pénales lourdes.

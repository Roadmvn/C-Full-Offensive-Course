# Module 26 : API Hooking

## Objectifs d'apprentissage

Ce module explore les techniques de hooking (détournement) d'API Windows pour intercepter et modifier le comportement des fonctions. Vous apprendrez :

- **IAT Hooking** : Modification de l'Import Address Table
- **Inline Hooking** : Patching direct du code d'une fonction (hot patching)
- **Microsoft Detours** : Framework professionnel de hooking
- **API Unhooking** : Bypass des hooks EDR pour évasion

## Concepts clés

### IAT Hooking
Modification de la table d'imports :
- Localiser l'IAT du processus/module cible
- Trouver l'entrée de la fonction à hooker
- Remplacer l'adresse par celle de la fonction hook
- Simple mais limité aux imports

### Inline Hooking (Hot Patching)
Modification directe du code machine :
- Écrire un JMP au début de la fonction cible
- Sauvegarder les bytes originaux (trampoline)
- Rediriger vers la fonction hook
- Permet d'appeler la fonction originale

### Microsoft Detours
Framework professionnel :
- Gestion automatique des trampolines
- Support multi-architecture (x86/x64/ARM)
- API simple et robuste
- Utilisé en production

### API Unhooking
Bypass des hooks EDR :
- EDR hookent les API pour monitoring
- Unhook en restaurant les bytes originaux
- Lecture depuis ntdll.dll sur disque
- Permet d'éviter la détection

## Architecture d'un Hook

```
┌─────────────────────────────────────────────────┐
│           Inline Hook Architecture              │
├─────────────────────────────────────────────────┤
│                                                 │
│  [Original Function]                            │
│  0x00: E9 XX XX XX XX    ← JMP to hook         │
│  0x05: [bytes sauvegardés]                      │
│                                                 │
│         │                                       │
│         └──────────────┐                        │
│                        ▼                        │
│              [Hook Function]                    │
│                   │                             │
│                   ├─→ Log/Monitor/Modify        │
│                   │                             │
│                   └─→ Call trampoline           │
│                            │                    │
│                            ▼                    │
│                   [Trampoline]                  │
│                   [Bytes originaux]             │
│                   JMP suite de la fonction      │
│                                                 │
└─────────────────────────────────────────────────┘
```

## Compilation

```bash
# Avec MinGW-w64
gcc -o api_hooking main.c

# Avec MSVC
cl /Fe:api_hooking.exe main.c

# Avec Microsoft Detours
cl /Fe:hook.exe main.c /I"C:\Detours\include" /link "C:\Detours\lib\detours.lib"
```

## ⚠️ AVERTISSEMENT LÉGAL CRITIQUE ⚠️

**LE HOOKING D'API EST UNE TECHNIQUE EXTRÊMEMENT SENSIBLE**

### Utilisation autorisée :
- Environnements de test isolés uniquement
- Développement d'outils de sécurité légitimes
- Debugging et reverse engineering autorisé
- Red teaming avec autorisation écrite

### INTERDIT :
- Contournement d'anti-cheat (violations de ToS)
- Bypass d'EDR sans autorisation
- Vol de credentials
- Keylogging malveillant
- Toute activité illégale

### Détection
- EDR détectent les modifications de code
- Kernel Patch Protection (PatchGuard) en kernel mode
- Signature scanning des patterns de hook
- Behavioral analysis

**USAGE ÉDUCATIF UNIQUEMENT**

## Exercices pratiques

Consultez `exercice.txt` pour 8 défis progressifs.

## Prérequis

- Connaissance de l'assembleur x86/x64
- Compréhension du format PE
- Modules 24-25 complétés

---

**RAPPEL** : Utilisation strictement éducative dans des environnements contrôlés.

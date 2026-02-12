# Module 09 : macOS Offensive

```
+-------------------------------------------------------------------+
|                                                                     |
|   "macOS a la reputation d'etre sur. C'est surtout qu'il          |
|    est moins attaque. Pas moins attaquable."                       |
|                                                                     |
|   Mach-O, TCC, Dylib injection, ARM64, XPC...                     |
|   Ce module t'apprend a operer sur l'ecosysteme Apple.            |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Comprendre le format Mach-O et les syscalls macOS
- Manipuler les mecanismes de securite (TCC, SIP, Gatekeeper, AMFI)
- Injecter des dylibs et ecrire du shellcode ARM64
- Developper un beacon adapte a macOS
- Evader les protections Apple (sandbox, anti-debug, code signing)

## Prerequis

- Modules 01-03 (C, Pointeurs, ASM) valides
- Module 08 (Linux) recommande (concepts Unix partages)
- Un Mac ou une VM macOS pour tester
- Connaissance basique de l'ecosysteme Apple

## Contenu du module

Ce module est organise en **5 sections** dans `topics/`.

---

### Section 1 : Fondamentaux (`topics/01-Fondamentaux/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Mach-O-Format | Structure des binaires Mach-O, headers, load commands |
| 02 | macOS-Syscalls | Appels systeme macOS (Mach traps, BSD syscalls) |
| 03 | Dylib-Loading | Chargement dynamique de dylibs (dlopen, dlsym) |
| 04 | Mach-Ports | Communication inter-processus via Mach ports |
| 05 | Code-Signing | Signature de code, entitlements |
| 06 | XPC-Services | Services XPC et communication |
| 07 | ARM64-Architecture | Specificites ARM64 (Apple Silicon) |

### Section 2 : Internals & Securite (`topics/02-Internals/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | TCC | Transparency, Consent & Control (acces camera, micro...) |
| 02 | SIP | System Integrity Protection |
| 03 | Gatekeeper | Verification des applications |
| 04 | Endpoint-Security | Framework Endpoint Security (EDR Apple) |
| 05 | KEXT-Basics | Kernel extensions (deprecees mais encore presentes) |
| 06 | AMFI | Apple Mobile File Integrity |

### Section 3 : Injection & Tooling (`topics/03-Injection/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | HTTP-Client-macOS | Client HTTP natif macOS |
| 02 | Beacon-macOS | Beacon adapte a macOS |
| 03 | Persistence-macOS | LaunchAgents, LaunchDaemons, login items |
| 04 | Dylib-Injection | Injection de dylib via DYLD_INSERT_LIBRARIES |
| 05 | Keychain-Access | Acces au trousseau de cles |
| 06 | Screenshot-macOS | Capture d'ecran (CGWindowListCreateImage) |
| 07 | Keylogger-macOS | Keylogger via CGEventTap |
| 08 | Evasion-macOS | Techniques d'evasion specifiques macOS |
| 09 | Shellcode-ARM64 | Shellcode pour Apple Silicon |

### Section 4 : Evasion (`topics/04-Evasion/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Sandbox-Detection | Detecter si on est dans une sandbox Apple |
| 02 | Anti-Debug-macOS | Techniques anti-debugging (ptrace, sysctl) |
| 03 | Process-Injection-macOS | Injection de processus via task_for_pid |
| 04 | Fileless-macOS | Execution sans fichier sur macOS |
| 05 | Lateral-macOS | Mouvement lateral (SSH, Apple Remote Desktop) |

### Section 5 : Privilege Escalation (`topics/06-Privilege-Escalation/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | ROP-ARM64 | Return-Oriented Programming sur ARM64 |

## Comment travailler

```
1. Commence par les Fondamentaux (section 1)
2. Etudie les mecanismes de securite (section 2) - c'est crucial sur macOS
3. Passe a l'Injection et au Tooling (section 3)
4. Termine par l'Evasion (section 4)
5. Teste sur un Mac ou une VM macOS
6. Attention : macOS detecte beaucoup de choses, travaille dans un env controle
```

## Compilation

```bash
# Compilation standard
clang -o example example.c

# Avec frameworks Apple
clang -o example example.c -framework CoreFoundation -framework Security

# Pour le keylogger (CGEventTap)
clang -o example example.c -framework ApplicationServices

# Pour les screenshots
clang -o example example.c -framework CoreGraphics

# Cross-compilation ARM64 (si sur Intel)
clang -arch arm64 -o example example.c
```

## Checklist

- [ ] Je comprends le format Mach-O
- [ ] Je connais les mecanismes de securite macOS (TCC, SIP, Gatekeeper)
- [ ] J'ai charge une dylib dynamiquement
- [ ] J'ai un beacon macOS fonctionnel
- [ ] J'ai mis en place de la persistence (LaunchAgent)
- [ ] J'ai ecrit du shellcode ARM64
- [ ] J'ai evade la sandbox

---

Temps estime : **15-20 heures**

Prochain module : [10 - Advanced](../10-advanced/)

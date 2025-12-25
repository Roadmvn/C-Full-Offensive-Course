# Phase 1 : Fondations C & Windows API

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         PHASE 1                                     │   │
│   │                    FONDATIONS C & WINAPI                            │   │
│   │                                                                     │   │
│   │    Semaines 1-4 : Du premier printf() a l'API Windows              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   "Le C est le langage de ceux qui veulent comprendre la machine."         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Vue d'Ensemble

Cette phase pose les **bases solides** necessaires pour tout le reste du parcours. Vous apprendrez le langage C depuis le debut et ferez vos premiers pas avec l'API Windows.

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROGRESSION PHASE 1                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   SEMAINE 1         SEMAINE 2         SEMAINE 3      SEMAINE 4 │
│   C Basics          Memoire           Structures     Windows   │
│      │                 │                  │             │      │
│      ▼                 ▼                  ▼             ▼      │
│   ┌───────┐        ┌───────┐         ┌───────┐     ┌───────┐  │
│   │printf │   →    │Pointeurs│   →   │struct │  →  │WinAPI │  │
│   │if/for │        │malloc  │        │union  │     │Handles│  │
│   │fonc.  │        │free    │        │enum   │     │Errors │  │
│   └───────┘        └───────┘         └───────┘     └───────┘  │
│      │                 │                  │             │      │
│      ▼                 ▼                  ▼             ▼      │
│  Calculatrice    XOR Buffer       Parser Binaire  Hello WinAPI │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Objectifs d'Apprentissage

A la fin de cette phase, vous serez capable de :

- [ ] Ecrire et compiler des programmes C complets
- [ ] Manipuler la memoire avec les pointeurs
- [ ] Utiliser l'allocation dynamique (malloc/free)
- [ ] Creer des structures de donnees personnalisees
- [ ] Lire et ecrire des fichiers binaires
- [ ] Comprendre les bases de l'API Windows
- [ ] Gerer les handles et les erreurs Windows

## Prerequis

- **Phase 0 completee** (ou connaissances equivalentes en binaire/memoire)
- Visual Studio Build Tools installe
- Environnement Windows 10/11

## Contenu Detaille

### Semaine 1 : C Absolute Basics
| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | Variables, types, printf | Hello World |
| 3-4 | Conditions if/else | Decision tree |
| 5-6 | Boucles for/while | Iterations |
| 7 | Fonctions | **Calculatrice** |

### Semaine 2 : Memory & Pointers
| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | Adresses et pointeurs | Swap function |
| 3-4 | Arithmetique pointeurs | Array sum |
| 5-6 | malloc/free | Buffer allocation |
| 7 | Strings et buffers | **XOR Buffer** |

### Semaine 3 : Structures & Files
| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | struct et typedef | Person struct |
| 3-4 | union et enum | Data packing |
| 5-6 | Fichiers texte | Config parser |
| 7 | Fichiers binaires | **Binary Parser** |

### Semaine 4 : First WinAPI
| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | Types Windows | DWORD, HANDLE, etc. |
| 3-4 | MessageBox | User interaction |
| 5-6 | Error handling | GetLastError |
| 7 | File handles | **Hello WinAPI** |

## Schema Conceptuel

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ARCHITECTURE MEMOIRE C                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   STACK (Pile)                     HEAP (Tas)                               │
│   ┌─────────────────┐              ┌─────────────────┐                      │
│   │ Variables locales│             │ malloc/free     │                      │
│   │ Parametres func  │             │ Allocation      │                      │
│   │ Adresses retour  │             │ dynamique       │                      │
│   │       ↓          │             │       ↑         │                      │
│   │  Croissance      │             │  Croissance     │                      │
│   └─────────────────┘              └─────────────────┘                      │
│                                                                             │
│   int x = 42;        ←───── Stack                                           │
│   int *p = malloc(4);─────→ Heap                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         POINTEURS : LE COEUR DU C                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   int x = 42;                                                               │
│   int *ptr = &x;        // ptr contient l'adresse de x                     │
│                                                                             │
│   ┌─────────┐           ┌─────────┐                                         │
│   │  ptr    │──────────→│    x    │                                         │
│   │ 0x1000  │           │   42    │                                         │
│   └─────────┘           └─────────┘                                         │
│   Adresse: 0x2000       Adresse: 0x1000                                     │
│                                                                             │
│   *ptr = 100;           // Modifie x via le pointeur                       │
│   printf("%d", x);      // Affiche 100                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Lien avec le Maldev

Pourquoi ces concepts sont fondamentaux pour la securite offensive :

| Concept | Application Maldev |
|---------|-------------------|
| Pointeurs | Manipulation memoire, shellcode |
| malloc/free | Allocation de buffers pour payloads |
| Structures | Headers PE, structures Windows |
| Fichiers binaires | Lecture/ecriture d'executables |
| API Windows | Toutes les techniques offensives |
| Handles | Interaction avec processus, threads |

## Validation de Phase

Avant de passer a la Phase 2, verifiez que vous pouvez :

- [ ] Ecrire un programme C qui utilise des pointeurs
- [ ] Allouer et liberer de la memoire dynamiquement
- [ ] Creer une structure et la manipuler
- [ ] Lire un fichier binaire octet par octet
- [ ] Appeler une fonction WinAPI (MessageBox)
- [ ] Recuperer et afficher une erreur Windows

## Navigation

| Precedent | Suivant |
|-----------|---------|
| [Phase 0 : Prerequisites](../Phase-0-Prerequisites/) | [Phase 2 : Windows Fundamentals](../Phase-2-Windows-Fundamentals/) |

---

**Pret a commencer ?**

```bash
cd Week-01-C-Absolute-Basics
```

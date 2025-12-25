# Phase 0 : Prerequis Fondamentaux

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   "Avant de programmer, il faut comprendre la machine."                     │
│                                                                             │
│   Ce module pose les bases absolues. Sans ces connaissances,                │
│   vous ne ferez que repeter des incantations magiques.                      │
│   Avec elles, vous comprendrez reellement ce qui se passe.                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Vue d'ensemble

Cette phase est le **point de depart absolu** du parcours. Elle couvre les concepts fondamentaux de l'informatique que tout developpeur d'outils offensifs doit maitriser.

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATIONS DIRECTES                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  BINAIRE/HEXA        →   Lecture de shellcode, patches         │
│  CPU & REGISTRES     →   Reverse engineering, ROP chains       │
│  MEMOIRE             →   Buffer overflow, injection            │
│  SYSTEME D'EXPLOIT.  →   Elevation de privileges               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Objectifs d'apprentissage

A la fin de cette phase, vous serez capable de :

- [ ] Convertir entre binaire, decimal et hexadecimal
- [ ] Expliquer comment un processeur execute des instructions
- [ ] Decrire l'organisation de la memoire (stack, heap, etc.)
- [ ] Comprendre le role du systeme d'exploitation
- [ ] Lire et interpreter des dumps memoire en hexadecimal

## Contenu du Module

### Cours Theoriques

| # | Cours | Duree | Description |
|---|-------|-------|-------------|
| 01 | [Systemes de Numeration](cours/01-systemes-numeration.md) | 45 min | Binaire, decimal, hexadecimal |
| 02 | [Le Processeur (CPU)](cours/02-processeur.md) | 60 min | Architecture, registres, cycle d'execution |
| 03 | [La Memoire](cours/03-memoire.md) | 60 min | RAM, stack, heap, segments |
| 04 | [Le Systeme d'Exploitation](cours/04-systeme-exploitation.md) | 45 min | Role, processus, appels systeme |
| 05 | [Du Code Source a l'Execution](cours/05-code-a-execution.md) | 30 min | Compilation, chargement, execution |

### Exercices Pratiques

| # | Exercice | Difficulte | Concepts |
|---|----------|------------|----------|
| 01 | [Conversions Numeriques](exercices/exercice-01.md) | * | Binaire, hexa, decimal |
| 02 | [Lecture Hexadecimale](exercices/exercice-02.md) | ** | Interpretation de dumps |
| 03 | [Analyse de Stack](exercices/exercice-03.md) | ** | Comprendre la pile |
| 04 | [Quiz Complet](exercices/exercice-04.md) | *** | Tous les concepts |

## Prerequis

**Aucun.** Ce module est le point de depart absolu.

## Temps Estime

- Cours : ~4 heures
- Exercices : ~2 heures
- **Total : ~6 heures**

## Schema Conceptuel

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ARCHITECTURE SIMPLIFIEE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                              CPU                                     │   │
│   │   ┌─────────────────────────────────────────────────────────────┐   │   │
│   │   │  Registres: EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP, EIP    │   │   │
│   │   └─────────────────────────────────────────────────────────────┘   │   │
│   │                              │                                       │   │
│   │                     Execute les instructions                        │   │
│   └──────────────────────────────┼──────────────────────────────────────┘   │
│                                  │                                          │
│                            ┌─────┴─────┐                                    │
│                            │    BUS    │                                    │
│                            └─────┬─────┘                                    │
│                                  │                                          │
│   ┌──────────────────────────────┼──────────────────────────────────────┐   │
│   │                           MEMOIRE                                    │   │
│   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐   │   │
│   │   │    STACK    │  │    HEAP     │  │    DATA     │  │   TEXT   │   │   │
│   │   │  Variables  │  │  Allocation │  │  Variables  │  │   Code   │   │   │
│   │   │   locales   │  │  dynamique  │  │  globales   │  │ compile  │   │   │
│   │   └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Conseils

1. **Prenez des notes manuscrites** - Ecrire aide a memoriser
2. **Faites les conversions a la main** - Pas de calculatrice au debut
3. **Dessinez les schemas vous-meme** - La visualisation est cle
4. **Relisez si necessaire** - Ces concepts sont fondamentaux

## Navigation

| Precedent | Suivant |
|-----------|---------|
| - | [Phase 1 : Foundations](../Phase-1-Foundations/) |

---

```
   ┌────────────────────────────────────────────┐
   │  Pret ? Commencez par les nombres...       │
   │  → cours/01-systemes-numeration.md         │
   └────────────────────────────────────────────┘
```

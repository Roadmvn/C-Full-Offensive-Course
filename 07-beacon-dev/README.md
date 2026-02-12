# Module 07 : Beacon Development

```
+-------------------------------------------------------------------+
|                                                                     |
|   "Un beacon, c'est un agent autonome qui vit sur la cible.       |
|    Il dort, se reveille, execute, rapporte, et recommence."        |
|                                                                     |
|   Ce module rassemble tout ce que tu as appris pour                |
|   construire un beacon fonctionnel de A a Z.                       |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Concevoir l'architecture d'un beacon (config, sleep loop, dispatcher)
- Implementer des commandes (whoami, ls, cat, capture output)
- Appliquer l'obfuscation et le hiding d'API
- Gerer le check-in et la communication avec le serveur
- Assembler un beacon complet et fonctionnel

## Prerequis

- Module 04 (Windows Fundamentals) valide
- Module 05 (Windows Advanced) - au moins les sections Shellcoding + Evasion
- Module 06 (Network) valide
- Bonne maitrise du C, des sockets et des API Windows

## Contenu du module

### Lessons (dans `lessons/`)

Trois axes de progression en parallele :

**Axe 1 : Architecture du beacon**

| Fichier | Sujet |
|---------|-------|
| `01-beacon-concept.c` | Architecture globale, structure d'un beacon |
| `02-config-struct.c` | Structure de configuration (URL, sleep, jitter...) |
| `03-sleep-loop.c` | Boucle sleep avec jitter et check-in |
| `04-check-in.c` | Premier contact avec le serveur C2 |

**Axe 2 : Commandes**

| Fichier | Sujet |
|---------|-------|
| `01-cmd-whoami.c` | Commande whoami (info systeme) |
| `02-cmd-filesystem.c` | Commandes filesystem (ls, pwd, cd) |
| `03-cmd-cat.c` | Lire le contenu d'un fichier |
| `04-dispatcher.c` | Dispatcher de commandes central |

**Axe 3 : Stealth**

| Fichier | Sujet |
|---------|-------|
| `01-string-obfuscation.c` | Obfusquer les strings du beacon |
| `02-api-hiding.c` | Cacher les appels API |
| `03-compilation.c` | Techniques de compilation pour reduire la detection |

### Exercices (dans `exercises/`)

**Exercices Architecture**

| Fichier | Description |
|---------|-------------|
| `ex01-config-init.c` | Initialiser la config du beacon |
| `ex02-jitter-sleep.c` | Implementer un sleep avec jitter |
| `ex03-beacon-skeleton.c` | Squelette complet du beacon |

**Exercices Commandes**

| Fichier | Description |
|---------|-------------|
| `ex01-capture-output.c` | Capturer la sortie d'une commande |
| `ex02-implement-ls.c` | Implementer la commande ls |
| `ex03-full-dispatcher.c` | Dispatcher complet avec toutes les commandes |

**Exercices Stealth**

| Fichier | Description |
|---------|-------------|
| `ex01-obfuscate-strings.c` | Obfusquer toutes les strings |
| `ex02-test-beacon.c` | Tester le beacon dans un environnement controle |

### Solutions (dans `solutions/`)

Ne regarde qu'apres avoir essaye !

### Projet final

Le fichier `final-beacon.c` a la racine du module est le **beacon complet assemble**. C'est le resultat final de tout le module.

## Comment travailler

```
1. Lis les lessons de l'axe 1 (architecture) en premier
2. Enchaine avec l'axe 2 (commandes)
3. Termine par l'axe 3 (stealth)
4. Fais les exercices de chaque axe
5. Assemble le tout dans ton propre beacon
6. Compare avec final-beacon.c
```

## Compilation

```batch
REM Compiler une lesson/exercice
cl fichier.c /link ws2_32.lib winhttp.lib kernel32.lib user32.lib

REM Compiler le beacon final
cl final-beacon.c /link ws2_32.lib winhttp.lib kernel32.lib user32.lib advapi32.lib
```

## Lien avec le maldev

| Concept | Usage offensif |
|---------|---------------|
| Config struct | Parametrage flexible de l'agent |
| Sleep loop + jitter | Eviter la detection par patterns reseau |
| Dispatcher | Executer des commandes a la demande |
| String obfuscation | Eviter la detection statique |
| API hiding | Eviter l'analyse d'imports |
| Check-in | Communication fiable avec le C2 |

## Checklist

- [ ] J'ai compris l'architecture d'un beacon
- [ ] J'ai implemente la structure de configuration
- [ ] J'ai un sleep loop avec jitter fonctionnel
- [ ] J'ai implemente les commandes whoami, ls, cat
- [ ] J'ai un dispatcher qui route les commandes
- [ ] J'ai applique l'obfuscation de strings et d'API
- [ ] J'ai assemble un beacon complet
- [ ] J'ai compare mon beacon avec final-beacon.c

---

Temps estime : **12-15 heures**

Prochain module : [08 - Linux](../08-linux/)

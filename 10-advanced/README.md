# Module 10 : Advanced Topics

```
+-------------------------------------------------------------------+
|                                                                     |
|   "Au-dela du userland, au-dela du kernel.                         |
|    Firmware, hyperviseurs, hardware, supply chain, IA."            |
|                                                                     |
|   Ce module final explore les frontieres de la securite            |
|   offensive. Du metal nu jusqu'a l'intelligence artificielle.      |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Comprendre les hyperviseurs et les techniques d'evasion/detection de VM
- Analyser le firmware (UEFI, Secure Boot, SPI Flash, SMM)
- Connaitre les attaques hardware (side-channel, Spectre, Rowhammer)
- Comprendre les vecteurs d'attaque supply chain
- Explorer les surfaces d'attaque de l'IA/LLM

## Prerequis

- Modules 01-09 completes (ou au moins 01-07)
- Solide comprehension du kernel (modules 05 et 08)
- Curiosite pour les sujets bas-niveau et emergents

## Contenu du module

Ce module est organise en **5 sections** dans `topics/`.

---

### Section 1 : Hyperviseur (`topics/01-Hypervisor/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Virtualization-Basics | Fondamentaux de la virtualisation (VT-x, EPT) |
| 02 | VM-Detection | Detecter si on tourne dans une VM |
| 03 | VM-Escape-Concepts | Concepts d'evasion de VM |
| 04 | Hyperjacking-Theory | Theorie du hyperjacking (Blue Pill) |
| 05 | Cloud-Hypervisors | Hyperviseurs cloud (AWS, Azure, GCP) |

### Section 2 : Firmware (`topics/02-Firmware/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | UEFI-Basics | Fondamentaux UEFI, DXE drivers |
| 02 | Secure-Boot | Mecanisme Secure Boot et ses faiblesses |
| 03 | SPI-Flash | Lecture/ecriture du SPI Flash |
| 04 | Bootkit-Concepts | Concepts de bootkits (MBR, VBR, UEFI) |
| 05 | SMM-Basics | System Management Mode et ses privileges |

### Section 3 : Hardware (`topics/03-Hardware/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Side-Channel-Intro | Introduction aux attaques par canaux auxiliaires |
| 02 | Spectre-Meltdown | Etude de Spectre et Meltdown |
| 03 | Rowhammer | Exploitation de Rowhammer |
| 04 | Hardware-Implants | Implants hardware (concepts et detection) |

### Section 4 : Supply Chain (`topics/04-Supply-Chain/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Dependency-Confusion | Attaque par confusion de dependances |
| 02 | Typosquatting | Typosquatting de paquets |
| 03 | Build-Compromise | Compromission de la chaine de build |
| 04 | Signed-Malware | Malware signe avec des certificats voles |

### Section 5 : AI Security (`topics/05-AI-Security/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | LLM-Attack-Surface | Surface d'attaque des LLM |
| 02 | Prompt-Injection | Injection de prompts |
| 03 | Model-Extraction | Extraction de modeles |
| 04 | AI-Red-Team-Prep | Preparation au red team sur des systemes IA |

## Comment travailler

```
1. Les 5 sections sont independantes - commence par ce qui t'interesse
2. Chaque topic a un example.c et souvent un solution.c
3. Ces sujets sont plus theoriques que les modules precedents
4. Lis les commentaires dans le code - ils contiennent beaucoup d'explications
5. Certains topics necessitent du materiel specifique (hardware, firmware)
6. Pour les topics IA, pas besoin de GPU - c'est de l'analyse de surface d'attaque
```

## Compilation

```bash
# La plupart des examples sont cross-platform
gcc -o example example.c

# Sur Windows
cl example.c

# Certains topics hardware necessitent des libs specifiques
gcc -o example example.c -lm

# Les topics firmware necessitent le SDK EDK2 pour compiler des DXE drivers
```

## Lien avec le maldev

| Concept | Usage offensif |
|---------|---------------|
| VM Detection | Eviter l'analyse en sandbox |
| Bootkits | Persistence maximale (survit au reinstall) |
| Side-channel | Extraction de cles cryptographiques |
| Supply chain | Compromission a grande echelle |
| AI attacks | Nouvelle surface d'attaque emergente |

## Checklist

- [ ] Je comprends les bases de la virtualisation et la detection de VM
- [ ] Je connais le processus de boot UEFI
- [ ] Je comprends Spectre/Meltdown conceptuellement
- [ ] Je connais les vecteurs d'attaque supply chain
- [ ] J'ai explore la surface d'attaque des LLM

---

Temps estime : **15-20 heures**

```
+-------------------------------------------------------------------+
|                                                                     |
|   Felicitations. Si tu es arrive ici, tu as couvert l'ensemble    |
|   du parcours offensif en C. De "Hello World" jusqu'aux           |
|   hyperviseurs et au firmware.                                     |
|                                                                     |
|   Continue a pratiquer, a explorer, et a construire.              |
|                                                                     |
+-------------------------------------------------------------------+
```

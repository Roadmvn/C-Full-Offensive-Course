# Module A14 : Hardware Implants - Backdoors matériels

## Objectifs pédagogiques

- Comprendre les implants hardware (supply chain)
- Analyser des cas réels (KeyGrabber, NSA ANT)
- Détecter les implants hardware
- Se protéger de la supply chain compromise

## Introduction

Les **hardware implants** sont des modifications physiques du matériel pour installer des backdoors. Ils peuvent être ajoutés pendant la fabrication, le transport, ou par accès physique.

```
┌────────────────────────────────────────────┐
│     Types d'implants hardware              │
└────────────────────────────────────────────┘

1. Keylogger USB/PS2
   └─> Capture les frappes clavier

2. PCIe implant
   └─> DMA attack, accès mémoire

3. Chip malveillant sur PCB
   └─> Backdoor dans firmware/BIOS

4. Câble réseau modifié
   └─> Sniffer/injection trafic
```

## Cas réels

### NSA ANT Catalog (2013)

Documents leakés montrant des implants NSA :
- **COTTONMOUTH** : Câble USB avec backdoor RF
- **IRONCHEF** : Implant dans BIOS
- **RAGEMASTER** : Implant VGA pour exfiltrer l'écran via RF

### BadUSB (2014)

Firmware USB modifié pour :
- Se faire passer pour un clavier
- Exécuter des commandes
- Non détectable par antivirus (hardware-level)

## Détection

**Méthodes :**
```bash
# Lister les devices PCIe
lspci -vvv

# Analyser le firmware
flashrom -p internal -r bios.bin
binwalk bios.bin

# X-ray du PCB (pour inspection physique)
# → Comparer avec un PCB de référence
```

## Résumé

- Implants hardware = backdoors physiques
- Supply chain attack = modification pendant fabrication/transport
- Détection difficile (nécessite inspection physique ou firmware analysis)
- Protection : chaîne d'approvisionnement sécurisée, inspection matérielle

## Ressources

- **NSA ANT Catalog** : https://www.spiegel.de/media/media-35671.pdf
- **BadUSB** : https://github.com/adamcaudill/Psychson

---

**Module suivant** : [A15 - Dependency Confusion](../../PHASE_A04_SUPPLY_CHAIN/A15_dependency_confusion/)

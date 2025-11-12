# Module 31 : Anti-VM et Anti-Sandbox

## Vue d'ensemble

Ce module explore les techniques de détection de machines virtuelles (VM) et de sandboxes utilisées pour l'analyse de logiciels. Ces techniques permettent à un programme de détecter s'il s'exécute dans un environnement d'analyse.

## Concepts abordés

### 1. Détection de VM

**Hyperviseurs détectables** :
- VMware (Workstation, Player, ESXi)
- VirtualBox (Oracle)
- QEMU/KVM
- Hyper-V (Microsoft)
- Parallels Desktop

**Méthodes de détection** :
- Vérification de fichiers spécifiques
- Clés de registre (Windows)
- Instructions CPUID
- Périphériques virtuels
- Artefacts système

### 2. Détection de Sandbox

**Sandboxes courantes** :
- Cuckoo Sandbox
- Any.run
- Joe Sandbox
- VirusTotal
- Hybrid Analysis

**Indicateurs** :
- Noms de machine spécifiques
- Utilisateurs par défaut
- Faible uptime système
- Ressources limitées
- Absence d'interaction utilisateur

### 3. Sleep Acceleration

Détection basée sur la manipulation du temps par les sandboxes.

```c
time_t start = time(NULL);
Sleep(10000);  // 10 secondes
time_t end = time(NULL);

if ((end - start) < 9) {
    // Sandbox détectée (temps accéléré)
}
```

### 4. User Interaction Check

Vérification de l'interaction réelle d'un utilisateur.

```c
// Vérifier les mouvements de souris
// Compter les clics
// Détecter l'activité clavier
```

### 5. CPUID Checks

Utilisation de l'instruction CPUID pour détecter la virtualisation.

```c
// CPUID leaf 0x1, bit 31 de ECX = hypervisor bit
int cpuid_hypervisor(void) {
    unsigned int ecx;
    __asm__ volatile("cpuid"
        : "=c"(ecx)
        : "a"(1)
        : "ebx", "edx");
    return (ecx >> 31) & 1;
}
```

## Avertissements et considérations

### AVERTISSEMENT LÉGAL

**IMPORTANT** : Ces techniques sont présentées UNIQUEMENT à des fins éducatives.

**Utilisations légitimes** :
- Protection contre l'analyse automatisée de malware
- Détection d'environnements d'émulation
- Recherche en sécurité informatique
- Tests de robustesse

**Utilisations ILLÉGALES** :
- Évasion de détection de malware
- Contournement d'analyses de sécurité
- Distribution de logiciels malveillants

**L'utilisateur est SEUL RESPONSABLE** de l'usage qu'il fait de ces techniques.

## Ressources complémentaires

- "Evasive Malware" - Paranoid Fish
- VMware Detection Techniques
- Pafish (Paranoid Fish) - Outil de détection

## Exercices pratiques

Consultez `exercice.txt` et `solution.txt` pour les implémentations détaillées.

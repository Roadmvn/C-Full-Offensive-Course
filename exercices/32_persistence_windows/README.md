# Module 32 : Persistence Windows

## Vue d'ensemble

Ce module explore les techniques de persistence sur Windows permettant à un programme de s'exécuter automatiquement au démarrage ou lors d'événements système spécifiques.

## Concepts abordés

### 1. Registry Run Keys
Clés de registre pour l'exécution automatique au démarrage.

**Clés principales** :
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### 2. Scheduled Tasks
Création de tâches planifiées via Task Scheduler.

### 3. Windows Services
Installation d'un service Windows pour exécution en arrière-plan.

### 4. WMI Event Subscriptions
Utilisation de WMI pour déclencher l'exécution sur événements.

### 5. DLL Hijacking
Exploitation de l'ordre de chargement des DLL.

### 6. COM Hijacking
Détournement d'objets COM pour persistence.

## AVERTISSEMENT LÉGAL STRICT

**DANGER** : Ces techniques sont EXTRÊMEMENT sensibles et utilisées par les malwares.

**Utilisations légitimes UNIQUEMENT** :
- Développement d'applications légitimes nécessitant démarrage automatique
- Recherche en sécurité informatique dans environnement contrôlé
- Apprentissage de la sécurité défensive

**STRICTEMENT INTERDIT** :
- Installation non autorisée sur systèmes tiers
- Création de malware ou backdoors
- Toute activité malveillante

**RESPONSABILITÉ** : L'utilisateur est SEUL et ENTIÈREMENT responsable.
L'utilisation malveillante peut entraîner des poursuites pénales.

## Ressources

- Microsoft Documentation - Services
- MITRE ATT&CK - Persistence Techniques
- Windows Sysinternals - Autoruns

## Exercices

Consultez `exercice.txt` et `solution.txt`.

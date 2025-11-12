# Module 33 : Persistence Linux

## Vue d'ensemble

Ce module explore les techniques de persistence sur systèmes Linux/Unix permettant à un programme de s'exécuter automatiquement au démarrage ou lors d'événements système.

## Concepts abordés

### 1. Cron Jobs
Tâches planifiées via crontab pour exécution périodique ou au démarrage.

```bash
# Exécution au démarrage
@reboot /path/to/script

# Toutes les heures
0 * * * * /path/to/script
```

### 2. Systemd Services
Services systemd pour démarrage automatique et gestion.

```ini
[Unit]
Description=My Service

[Service]
ExecStart=/path/to/executable

[Install]
WantedBy=multi-user.target
```

### 3. Shell RC Files
Modification des fichiers de configuration shell (.bashrc, .profile).

**Fichiers principaux** :
- ~/.bashrc (Bash)
- ~/.profile (shell de connexion)
- ~/.zshrc (Zsh)
- /etc/profile (global)

### 4. LD_PRELOAD Hijacking
Préchargement de bibliothèques partagées.

```bash
export LD_PRELOAD=/path/to/malicious.so
```

### 5. Init Scripts
Scripts d'initialisation dans /etc/init.d/ ou /etc/rc.local.

## AVERTISSEMENT LÉGAL

**IMPORTANT** : Ces techniques sont sensibles et utilisées par les malwares.

**Utilisations légitimes** :
- Applications légitimes nécessitant démarrage automatique
- Administration système
- Recherche en sécurité

**STRICTEMENT INTERDIT** :
- Installation non autorisée
- Création de backdoors
- Activités malveillantes

**L'utilisateur est SEUL RESPONSABLE** de l'usage de ces techniques.

## Détection

Outils :
- chkrootkit : Détection de rootkits
- rkhunter : Scanner de rootkits
- auditd : Surveillance système
- systemctl list-units : Liste des services

## Ressources

- Linux Documentation - systemd
- crontab man pages
- MITRE ATT&CK - Linux Persistence

## Exercices

Consultez `exercice.txt` et `solution.txt`.

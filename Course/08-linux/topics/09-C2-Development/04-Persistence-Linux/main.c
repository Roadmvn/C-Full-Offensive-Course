/*
 * ═══════════════════════════════════════════════════════════════════════
 * MODULE 33 : PERSISTENCE LINUX
 * ═══════════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT LÉGAL :
 *   Ces techniques sont sensibles et utilisées par les malwares.
 *   Usage ÉDUCATIF UNIQUEMENT dans un environnement contrôlé.
 *   L'utilisateur est SEUL et ENTIÈREMENT RESPONSABLE.
 *
 * ═══════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 1 : CRON JOBS
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_cron_persistence(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("1. CRON JOBS\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Tâches planifiées via crontab\n");
    printf("  - Exécution au démarrage avec @reboot\n");
    printf("  - Exécution périodique (horaire, quotidien, etc.)\n\n");

    printf("Syntaxe crontab:\n");
    printf("  * * * * * commande\n");
    printf("  │ │ │ │ │\n");
    printf("  │ │ │ │ └─ Jour de la semaine (0-7, 0 et 7 = dimanche)\n");
    printf("  │ │ │ └─── Mois (1-12)\n");
    printf("  │ │ └───── Jour du mois (1-31)\n");
    printf("  │ └─────── Heure (0-23)\n");
    printf("  └───────── Minute (0-59)\n\n");

    printf("Exemples:\n");
    printf("  @reboot /path/to/script           # Au démarrage\n");
    printf("  0 * * * * /path/to/script         # Toutes les heures\n");
    printf("  0 0 * * * /path/to/script         # Tous les jours à minuit\n\n");

    printf("Commandes:\n");
    printf("  crontab -l                        # Lister les cron jobs\n");
    printf("  crontab -e                        # Éditer les cron jobs\n");
    printf("  crontab -r                        # Supprimer tous les cron jobs\n\n");

    printf("[!] Modification désactivée pour sécurité\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 2 : SYSTEMD SERVICES
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_systemd_service(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("2. SYSTEMD SERVICES\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Services systemd pour démarrage automatique\n");
    printf("  - Fichiers .service dans /etc/systemd/system/\n");
    printf("  - Gestion via systemctl\n\n");

    printf("Exemple de fichier service (/etc/systemd/system/myapp.service):\n\n");
    printf("  [Unit]\n");
    printf("  Description=My Application\n");
    printf("  After=network.target\n\n");
    printf("  [Service]\n");
    printf("  Type=simple\n");
    printf("  ExecStart=/usr/local/bin/myapp\n");
    printf("  Restart=on-failure\n");
    printf("  User=myuser\n\n");
    printf("  [Install]\n");
    printf("  WantedBy=multi-user.target\n\n");

    printf("Commandes systemctl:\n");
    printf("  systemctl enable myapp.service    # Activer au démarrage\n");
    printf("  systemctl start myapp.service     # Démarrer maintenant\n");
    printf("  systemctl status myapp.service    # Vérifier le statut\n");
    printf("  systemctl disable myapp.service   # Désactiver\n\n");

    printf("[!] Installation de service désactivée (nécessite root)\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 3 : BASHRC / PROFILE
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_bashrc_persistence(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("3. BASHRC / PROFILE PERSISTENCE\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Modification des fichiers RC du shell\n");
    printf("  - Exécution à chaque ouverture de session\n");
    printf("  - Discret mais détectable\n\n");

    printf("Fichiers utilisateur:\n");
    printf("  ~/.bashrc                         # Bash (shells interactifs)\n");
    printf("  ~/.profile                        # Shell de connexion\n");
    printf("  ~/.bash_profile                   # Bash (connexion)\n");
    printf("  ~/.zshrc                          # Zsh\n\n");

    printf("Fichiers système (nécessite root):\n");
    printf("  /etc/profile                      # Global pour tous users\n");
    printf("  /etc/bash.bashrc                  # Bash global\n\n");

    printf("Exemple d'ajout:\n");
    printf("  echo '/path/to/malicious' >> ~/.bashrc\n\n");

    char* home = getenv("HOME");
    if (home) {
        char bashrc_path[512];
        snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", home);
        printf("Votre .bashrc: %s\n\n", bashrc_path);
    }

    printf("[!] Modification désactivée pour sécurité\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 4 : LD_PRELOAD
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_ld_preload(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("4. LD_PRELOAD HIJACKING\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Préchargement de bibliothèques partagées\n");
    printf("  - Interception de fonctions système\n");
    printf("  - Technique de rootkit courante\n\n");

    printf("Méthodes:\n");
    printf("  1. Variable d'environnement:\n");
    printf("     export LD_PRELOAD=/path/to/malicious.so\n\n");
    printf("  2. Fichier /etc/ld.so.preload (nécessite root):\n");
    printf("     echo '/path/to/malicious.so' >> /etc/ld.so.preload\n\n");

    printf("Exemple de bibliothèque malveillante:\n");
    printf("  // malicious.c\n");
    printf("  int getuid(void) {\n");
    printf("      return 0;  // Toujours retourner root\n");
    printf("  }\n\n");
    printf("  Compilation:\n");
    printf("  gcc -shared -fPIC -o malicious.so malicious.c\n\n");

    printf("Détection:\n");
    printf("  - Vérifier $LD_PRELOAD\n");
    printf("  - Vérifier /etc/ld.so.preload\n");
    printf("  - Utiliser ldd pour voir les bibliothèques chargées\n\n");

    char* ld_preload = getenv("LD_PRELOAD");
    if (ld_preload) {
        printf("[!] ATTENTION: LD_PRELOAD est défini: %s\n\n", ld_preload);
    } else {
        printf("[✓] LD_PRELOAD n'est pas défini\n\n");
    }

    printf("[!] Démonstration uniquement - pas de modification\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 5 : INIT SCRIPTS
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_init_scripts(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("5. INIT SCRIPTS (RC.LOCAL)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Scripts exécutés au démarrage du système\n");
    printf("  - /etc/rc.local (système SysV)\n");
    printf("  - Nécessite privilèges root\n\n");

    printf("Fichiers d'initialisation:\n");
    printf("  /etc/rc.local                     # Exécuté au boot\n");
    printf("  /etc/init.d/                      # Scripts init SysV\n");
    printf("  /etc/rc*.d/                       # Liens symboliques runlevels\n\n");

    printf("Exemple /etc/rc.local:\n");
    printf("  #!/bin/sh\n");
    printf("  /path/to/malicious &\n");
    printf("  exit 0\n\n");

    printf("Note:\n");
    printf("  - Sur systèmes systemd modernes, rc.local est obsolète\n");
    printf("  - Utiliser systemd services à la place\n\n");

    printf("[!] Modification désactivée (nécessite root)\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║             MODULE 33 : PERSISTENCE LINUX                     ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                   AVERTISSEMENT LÉGAL                         ║\n");
    printf("║                                                               ║\n");
    printf("║  Ces techniques sont sensibles et utilisées par malwares.    ║\n");
    printf("║  Usage ÉDUCATIF UNIQUEMENT dans environnement CONTRÔLÉ.      ║\n");
    printf("║  L'utilisateur est SEUL et ENTIÈREMENT RESPONSABLE.          ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n[!] MODE DÉMONSTRATION - Aucune modification système\n");

    demo_cron_persistence();
    demo_systemd_service();
    demo_bashrc_persistence();
    demo_ld_preload();
    demo_init_scripts();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("DÉTECTION ET SUPPRESSION\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Détection:\n");
    printf("  crontab -l                        # Lister cron jobs\n");
    printf("  systemctl list-units              # Lister services\n");
    printf("  cat ~/.bashrc                     # Vérifier .bashrc\n");
    printf("  cat /etc/ld.so.preload            # Vérifier LD_PRELOAD\n");
    printf("  chkrootkit                        # Scanner rootkits\n");
    printf("  rkhunter --check                  # Scanner rootkits\n\n");

    printf("Suppression:\n");
    printf("  crontab -r                        # Supprimer cron jobs\n");
    printf("  systemctl disable service         # Désactiver service\n");
    printf("  # Éditer manuellement les fichiers RC pour suppression\n");

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Programme terminé.\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    return 0;
}

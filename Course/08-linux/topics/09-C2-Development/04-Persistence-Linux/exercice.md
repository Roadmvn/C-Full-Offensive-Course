⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.


### EXERCICES - MODULE 33 : LINUX PERSISTENCE

[ ] 1. CRON PERSISTENCE MULTI-TRIGGERS
Implémenter multiple cron triggers :
- @reboot pour démarrage
- @daily pour exécution quotidienne
- Toutes les heures (0 * * * *)
- Backup crontab si détecté/supprimé
- Vérifier existence avec crontab -l

Référence : man 5 crontab

[ ] 2. SYSTEMD SERVICE COMPLET
Service systemd malveillant fonctionnel :
- ServiceType=forking (daemon)
- Restart=always (auto-restart si crash)
- StandardOutput=null (pas de logs)
- User=root si disponible
- WantedBy=multi-user.target
- systemctl enable pour autostart

Référence : systemd.service man page

[ ] 3. BASHRC/PROFILE STEALTHY
Persistence dans shell RC files :
- ~/.bashrc, ~/.bash_profile, ~/.profile
- ~/.zshrc si Zsh détecté
- /etc/profile si root (global)
- Commentaires légitimes pour masquer
- Background execution (&) silencieuse
- Vérifier si ligne déjà présente (éviter duplications)

Référence : Bash startup files

[ ] 4. LD_PRELOAD ROOTKIT
Créer bibliothèque LD_PRELOAD malveillante :
- Intercepter getuid() retourner 0 (fake root)
- Intercepter readdir() cacher fichiers/processus
- Intercepter fopen() rediriger /etc/passwd
- Ajouter à /etc/ld.so.preload
- Compiler : gcc -shared -fPIC -o hook.so hook.c

Référence : ld.so man page, LD_PRELOAD tricks

[ ] 5. XDG AUTOSTART DESKTOP
Persistence via XDG autostart (GNOME/KDE) :
- ~/.config/autostart/app.desktop
- [Desktop Entry] avec Exec=
- Hidden=false ou true selon furtivité
- X-GNOME-Autostart-enabled=true
- Icon et Name légitimes (masquerade)
- NoDisplay=true pour cacher

Référence : XDG Autostart spec

[ ] 6. INIT SCRIPTS (LEGACY)
Init scripts pour SysV (systèmes legacy) :
- /etc/rc.local (exécuté au boot)
- /etc/init.d/script avec start/stop
- update-rc.d pour activer
- Runlevels 2-5 pour multi-user
- LSB header (### BEGIN INIT INFO)

Référence : SysV init scripts

[ ] 7. MULTI-METHOD REDUNDANCY
Implémenter 5+ méthodes simultanées :
- Cron + .bashrc + systemd + XDG
- Watchdog vérifiant présence chaque méthode
- Auto-repair si une supprimée
- Logging vers C2 si détection
- Sleep aléatoire entre vérifications

Référence : APT persistence redundancy

[ ] 8. KERNEL MODULE PERSISTENCE (AVANCÉ)
Rootkit kernel module (nécessite root) :
- insmod malicious.ko
- Cacher module avec list_del(&__this_module.list)
- /etc/modules-load.d/ pour autoload
- Hook sys_call_table
- Cacher fichiers/processus au niveau kernel

Référence : Linux kernel module programming


### NOTES :
- Cron = facile détecter (crontab -l)
- .bashrc = exécution login, visible .bash_history
- Systemd = systemctl list-units detect
- LD_PRELOAD = chkrootkit détecte
- XDG = desktop uniquement, facile scan
- Init scripts = rkhunter scan
- Kernel modules = lsmod, mais peut se cacher
- Combiner multiples pour redondance


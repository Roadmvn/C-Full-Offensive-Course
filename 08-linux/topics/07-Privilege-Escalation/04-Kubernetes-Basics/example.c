/*
 * OBJECTIF  : Comprendre les bases de Kubernetes pour la securite offensive
 * PREREQUIS : Bases C, containers, notions reseau, API REST
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les concepts fondamentaux de Kubernetes :
 * architecture, pods, services, RBAC, service accounts, et comment
 * detecter et enumerer un environnement Kubernetes depuis un pod.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * Etape 1 : Architecture Kubernetes
 */
static void explain_architecture(void) {
    printf("[*] Etape 1 : Architecture Kubernetes\n\n");

    printf("    ┌──────────────────────────────────────────────────┐\n");
    printf("    │              CONTROL PLANE (Master)               │\n");
    printf("    │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │\n");
    printf("    │  │ API      │ │ etcd     │ │ Controller       │ │\n");
    printf("    │  │ Server   │ │ (store)  │ │ Manager          │ │\n");
    printf("    │  └────┬─────┘ └──────────┘ └──────────────────┘ │\n");
    printf("    │       │       ┌──────────────────┐              │\n");
    printf("    │       │       │ Scheduler         │              │\n");
    printf("    │       │       └──────────────────┘              │\n");
    printf("    ├───────┼──────────────────────────────────────────┤\n");
    printf("    │       v                                          │\n");
    printf("    │  ┌─── NODE 1 ──────┐  ┌─── NODE 2 ──────┐      │\n");
    printf("    │  │ kubelet         │  │ kubelet         │      │\n");
    printf("    │  │ kube-proxy      │  │ kube-proxy      │      │\n");
    printf("    │  │ ┌─Pod──┐┌─Pod──┐│  │ ┌─Pod──┐┌─Pod──┐│      │\n");
    printf("    │  │ │ C1   ││ C2   ││  │ │ C3   ││ C4   ││      │\n");
    printf("    │  │ └──────┘└──────┘│  │ └──────┘└──────┘│      │\n");
    printf("    │  └─────────────────┘  └─────────────────┘      │\n");
    printf("    └──────────────────────────────────────────────────┘\n\n");

    printf("    Composants cles :\n");
    printf("    - API Server    : Point d'entree de toutes les commandes\n");
    printf("    - etcd          : Base de donnees cle-valeur (secrets, config)\n");
    printf("    - kubelet       : Agent sur chaque node, gere les pods\n");
    printf("    - kube-proxy    : Gestion reseau des services\n");
    printf("    - Pod           : Unite d'execution (1+ containers)\n\n");
}

/*
 * Etape 2 : Detecter si on est dans un pod Kubernetes
 */
static void detect_kubernetes(void) {
    printf("[*] Etape 2 : Detection d'environnement Kubernetes\n\n");

    int in_k8s = 0;

    /* Methode 1 : Variables d'environnement Kubernetes */
    const char *k8s_env_vars[] = {
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_SERVICE_PORT",
        "KUBERNETES_PORT",
        NULL
    };

    for (int i = 0; k8s_env_vars[i]; i++) {
        const char *val = getenv(k8s_env_vars[i]);
        if (val) {
            printf("    [+] %s = %s\n", k8s_env_vars[i], val);
            in_k8s = 1;
        }
    }
    if (!in_k8s)
        printf("    [-] Variables KUBERNETES_* non trouvees\n");
    printf("\n");

    /* Methode 2 : Service Account Token */
    const char *token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    if (access(token_path, R_OK) == 0) {
        printf("    [+] Service Account Token trouve : %s\n", token_path);
        in_k8s = 1;

        /* Lire les premiers caracteres du token */
        FILE *fp = fopen(token_path, "r");
        if (fp) {
            char token[64] = {0};
            size_t n = fread(token, 1, 40, fp);
            fclose(fp);
            if (n > 0)
                printf("        Token (debut) : %.40s...\n", token);
        }
    } else {
        printf("    [-] Pas de service account token\n");
    }

    /* Methode 3 : CA certificate */
    const char *ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    if (access(ca_path, R_OK) == 0) {
        printf("    [+] CA certificate trouve : %s\n", ca_path);
        in_k8s = 1;
    }

    /* Methode 4 : Namespace */
    const char *ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
    FILE *fp = fopen(ns_path, "r");
    if (fp) {
        char ns[64] = {0};
        if (fgets(ns, sizeof(ns), fp)) {
            ns[strcspn(ns, "\n")] = '\0';
            printf("    [+] Namespace : %s\n", ns);
        }
        fclose(fp);
        in_k8s = 1;
    }

    printf("\n    Verdict : %s\n\n",
           in_k8s ? "[+] Dans un pod Kubernetes"
                  : "[-] Probablement pas dans Kubernetes");
}

/*
 * Etape 3 : Enumeration depuis un pod
 */
static void explain_enumeration(void) {
    printf("[*] Etape 3 : Enumeration depuis un pod\n\n");

    printf("    1. Recuperer le token du service account :\n");
    printf("       TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n\n");

    printf("    2. Trouver l'API server :\n");
    printf("       echo $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT\n\n");

    printf("    3. Lister les permissions (RBAC) :\n");
    printf("       curl -sk https://$KUBE_HOST:$KUBE_PORT/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \\\n");
    printf("         -H \"Authorization: Bearer $TOKEN\" \\\n");
    printf("         -H 'Content-Type: application/json' \\\n");
    printf("         -d '{\"apiVersion\":\"authorization.k8s.io/v1\",\n");
    printf("              \"kind\":\"SelfSubjectRulesReview\",\n");
    printf("              \"spec\":{\"namespace\":\"default\"}}'\n\n");

    printf("    4. Lister les pods :\n");
    printf("       curl -sk https://$KUBE_HOST:$KUBE_PORT/api/v1/namespaces/default/pods \\\n");
    printf("         -H \"Authorization: Bearer $TOKEN\"\n\n");

    printf("    5. Lister les secrets :\n");
    printf("       curl -sk https://$KUBE_HOST:$KUBE_PORT/api/v1/namespaces/default/secrets \\\n");
    printf("         -H \"Authorization: Bearer $TOKEN\"\n\n");
}

/*
 * Etape 4 : RBAC et Service Accounts
 */
static void explain_rbac(void) {
    printf("[*] Etape 4 : RBAC (Role-Based Access Control)\n\n");

    printf("    ┌─────────────────────────────────────────────────┐\n");
    printf("    │  ServiceAccount  --bind-->  Role/ClusterRole    │\n");
    printf("    │       │                         │               │\n");
    printf("    │       │                    rules:               │\n");
    printf("    │  (identite du pod)         - resources: [pods]  │\n");
    printf("    │                            - verbs: [get, list] │\n");
    printf("    └─────────────────────────────────────────────────┘\n\n");

    printf("    Types de roles :\n");
    printf("    - Role            : permissions dans un namespace\n");
    printf("    - ClusterRole     : permissions cluster-wide\n");
    printf("    - RoleBinding     : lie un ServiceAccount a un Role\n");
    printf("    - ClusterRoleBinding : lie au niveau cluster\n\n");

    printf("    Permissions dangereuses :\n");
    printf("    - pods/exec              : executer des commandes dans des pods\n");
    printf("    - secrets (get/list)     : lire les secrets (tokens, mots de passe)\n");
    printf("    - pods (create)          : creer des pods (avec montages)\n");
    printf("    - * (wildcard)           : toutes les permissions\n");
    printf("    - nodes/proxy            : acceder directement au kubelet\n\n");
}

/*
 * Etape 5 : Scanner les variables d'environnement pour des services
 */
static void scan_service_env(void) {
    printf("[*] Etape 5 : Decouverte de services via variables d'environnement\n\n");

    printf("    Kubernetes injecte des variables pour chaque service :\n");
    printf("    <SERVICE>_SERVICE_HOST et <SERVICE>_SERVICE_PORT\n\n");

    /* Lire /proc/self/environ */
    FILE *fp = fopen("/proc/self/environ", "r");
    if (!fp) {
        printf("    (impossible de lire /proc/self/environ)\n\n");
        return;
    }

    char buf[8192] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);

    printf("    Variables de service detectees :\n");
    int found = 0;
    char *ptr = buf;
    while (ptr < buf + n) {
        size_t len = strlen(ptr);
        if (len == 0) {
            ptr++;
            continue;
        }
        if (strstr(ptr, "_SERVICE_HOST") || strstr(ptr, "_SERVICE_PORT") ||
            strstr(ptr, "_PORT_")) {
            printf("      %s\n", ptr);
            found++;
        }
        ptr += len + 1;
    }

    if (found == 0)
        printf("      (aucune variable de service trouvee)\n");
    printf("\n");
}

/*
 * Etape 6 : Reseau Kubernetes
 */
static void explain_network(void) {
    printf("[*] Etape 6 : Reseau Kubernetes\n\n");

    printf("    Plages reseau typiques :\n");
    printf("    - Pod CIDR      : 10.244.0.0/16 (flannel) ou 10.0.0.0/8\n");
    printf("    - Service CIDR  : 10.96.0.0/12\n");
    printf("    - Node network  : reseau physique\n\n");

    printf("    DNS interne :\n");
    printf("    - <service>.<namespace>.svc.cluster.local\n");
    printf("    - kubernetes.default.svc.cluster.local (API server)\n\n");

    /* Lire /etc/resolv.conf pour le DNS */
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (fp) {
        printf("    DNS configuration (/etc/resolv.conf) :\n");
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        fclose(fp);
        printf("\n");
    }

    printf("    Cibles interessantes a scanner :\n");
    printf("    - 10.96.0.1:443     : API server (kubernetes service)\n");
    printf("    - 10.96.0.10:53     : CoreDNS\n");
    printf("    - <node-ip>:10250   : kubelet API\n");
    printf("    - <node-ip>:10255   : kubelet read-only (si active)\n");
    printf("    - 169.254.169.254   : metadata service (cloud)\n\n");
}

/*
 * Etape 7 : Outils et protections
 */
static void explain_tools_and_protections(void) {
    printf("[*] Etape 7 : Outils et protections\n\n");

    printf("    Outils offensifs :\n");
    printf("    - kubectl         : client Kubernetes officiel\n");
    printf("    - kube-hunter     : scanner de vulnerabilites K8s\n");
    printf("    - peirates        : outil de pentest Kubernetes\n");
    printf("    - kubeletctl      : interaction directe avec kubelet\n\n");

    printf("    Protections :\n");
    printf("    Protection          | Description\n");
    printf("    ────────────────────|──────────────────────────────\n");
    printf("    RBAC strict         | Principe du moindre privilege\n");
    printf("    Network Policies    | Segmentation reseau entre pods\n");
    printf("    Pod Security        | Pas de root, pas de privileged\n");
    printf("    Secrets encryption  | Chiffrement etcd at-rest\n");
    printf("    Audit logging       | Journaliser les appels API\n");
    printf("    Admission control   | OPA/Gatekeeper, Kyverno\n");
    printf("    Service mesh        | mTLS entre pods (Istio/Linkerd)\n\n");
}

int main(void) {
    printf("[*] Demo : Kubernetes Basics\n\n");

    explain_architecture();
    detect_kubernetes();
    explain_enumeration();
    explain_rbac();
    scan_service_env();
    explain_network();
    explain_tools_and_protections();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

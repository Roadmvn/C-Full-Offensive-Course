/*
 * OBJECTIF  : Comprendre les hyperviseurs cloud
 * PREREQUIS : Bases C, virtualisation, cloud computing
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les specificites des hyperviseurs cloud :
 * AWS Nitro, Azure, GCP, isolation, surface d'attaque,
 * et securite.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/stat.h>
#endif

/*
 * Etape 1 : Hyperviseurs cloud
 */
static void explain_cloud_hypervisors(void) {
    printf("[*] Etape 1 : Hyperviseurs cloud\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Cloud Provider                           │\n");
    printf("    │  ┌────────┐ ┌────────┐ ┌────────┐       │\n");
    printf("    │  │Client A│ │Client B│ │Client C│       │\n");
    printf("    │  │  VM    │ │  VM    │ │  VM    │       │\n");
    printf("    │  └───┬────┘ └───┬────┘ └───┬────┘       │\n");
    printf("    │  ┌───┴──────────┴──────────┴────┐       │\n");
    printf("    │  │  Hyperviseur Cloud            │       │\n");
    printf("    │  │  + Control Plane               │       │\n");
    printf("    │  └──────────────┬───────────────┘       │\n");
    printf("    │  ┌──────────────v───────────────┐       │\n");
    printf("    │  │  Hardware (serveur physique)  │       │\n");
    printf("    │  └──────────────────────────────┘       │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Provider | Hyperviseur     | Base\n");
    printf("    ─────────|─────────────────|──────────────\n");
    printf("    AWS      | Nitro           | KVM custom\n");
    printf("    Azure    | Hyper-V         | Proprietaire\n");
    printf("    GCP      | KVM custom      | KVM\n");
    printf("    Oracle   | KVM/Xen         | KVM/Xen\n");
    printf("    Alibaba  | KVM custom      | KVM\n\n");
}

/*
 * Etape 2 : AWS Nitro
 */
static void explain_aws_nitro(void) {
    printf("[*] Etape 2 : AWS Nitro System\n\n");

    printf("    Architecture Nitro :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ┌──────────────────────────────────┐\n");
    printf("    │  Instance EC2                     │\n");
    printf("    │  ┌─────────────────────────┐     │\n");
    printf("    │  │ Guest OS                  │     │\n");
    printf("    │  └───────────┬──────────────┘     │\n");
    printf("    │              │                     │\n");
    printf("    │  ┌───────────v──────────────┐     │\n");
    printf("    │  │ Nitro Hypervisor          │     │\n");
    printf("    │  │ (KVM minimal, ~25K LOC)   │     │\n");
    printf("    │  └───────────┬──────────────┘     │\n");
    printf("    │              │                     │\n");
    printf("    │  ┌───────────v──────────────┐     │\n");
    printf("    │  │ Nitro Cards (hardware)    │     │\n");
    printf("    │  │ - Nitro Card (VPC, EBS)   │     │\n");
    printf("    │  │ - Nitro Security Chip      │     │\n");
    printf("    │  │ - Nitro Enclaves           │     │\n");
    printf("    │  └──────────────────────────┘     │\n");
    printf("    └──────────────────────────────────┘\n\n");

    printf("    Points cles :\n");
    printf("    - L'hyperviseur est minimal (~25K lignes)\n");
    printf("    - Le reseau et le stockage sont sur des cartes dediees\n");
    printf("    - Pas d'acces SSH a l'hote pour AWS\n");
    printf("    - Nitro Enclaves : TEE pour les donnees sensibles\n\n");
}

/*
 * Etape 3 : Detection de l'environnement cloud
 */
static void demo_cloud_detection(void) {
    printf("[*] Etape 3 : Detection de l'environnement cloud\n\n");

    printf("    Techniques de detection :\n");
    printf("    ───────────────────────────────────\n");

#ifdef __linux__
    /* DMI */
    printf("    DMI system vendor :\n");
    FILE *fp = fopen("/sys/class/dmi/id/sys_vendor", "r");
    if (fp) {
        char val[128] = {0};
        fgets(val, sizeof(val), fp);
        val[strcspn(val, "\n")] = '\0';
        fclose(fp);
        printf("      %s\n", val);
        if (strstr(val, "Amazon")) printf("      -> AWS detecte\n");
        else if (strstr(val, "Microsoft")) printf("      -> Azure detecte\n");
        else if (strstr(val, "Google")) printf("      -> GCP detecte\n");
    }
    printf("\n");

    /* Hyperviseur */
    fp = fopen("/sys/hypervisor/type", "r");
    if (fp) {
        char val[64] = {0};
        fgets(val, sizeof(val), fp);
        val[strcspn(val, "\n")] = '\0';
        fclose(fp);
        printf("    Hyperviseur : %s\n", val);
    }
    printf("\n");
#endif

    printf("    Metadata services :\n");
    printf("    ───────────────────────────────────\n");
    printf("    AWS   : curl http://169.254.169.254/latest/meta-data/\n");
    printf("    Azure : curl -H 'Metadata:true' \\\n");
    printf("            http://169.254.169.254/metadata/instance\n");
    printf("    GCP   : curl -H 'Metadata-Flavor: Google' \\\n");
    printf("            http://metadata.google.internal/\n\n");

    printf("    SSRF vers metadata = credentials leak !\n");
    printf("    -> IMDSv2 (AWS) : necessite un token\n");
    printf("    -> Azure : header Metadata:true requis\n\n");
}

/*
 * Etape 4 : Surface d'attaque cloud
 */
static void explain_cloud_attacks(void) {
    printf("[*] Etape 4 : Surface d'attaque cloud\n\n");

    printf("    1. SSRF vers metadata service :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Voler les credentials IAM de l'instance\n");
    printf("    -> Pivoter vers d'autres services AWS/Azure/GCP\n");
    printf("    -> Capital One breach (2019) via SSRF\n\n");

    printf("    2. Container escape :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> ECS, EKS, AKS, GKE\n");
    printf("    -> Escape vers le noeud worker\n");
    printf("    -> Puis vers d'autres containers\n\n");

    printf("    3. Shared tenancy attacks :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Side-channels entre VMs co-localisees\n");
    printf("    -> Cache attacks (Flush+Reload, Prime+Probe)\n");
    printf("    -> Spectre entre VMs\n\n");

    printf("    4. IAM misconfiguration :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Roles IAM trop permissifs\n");
    printf("    -> AssumeRole vers d'autres comptes\n");
    printf("    -> Service accounts GCP mal configures\n\n");
}

/*
 * Etape 5 : Confidential computing
 */
static void explain_confidential_computing(void) {
    printf("[*] Etape 5 : Confidential Computing\n\n");

    printf("    Technologies :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Technologie     | Fournisseur | Protection\n");
    printf("    ────────────────|─────────────|──────────────\n");
    printf("    Intel SGX       | Intel       | Enclaves\n");
    printf("    Intel TDX       | Intel       | VM entiere\n");
    printf("    AMD SEV/SNP     | AMD         | VM chiffree\n");
    printf("    ARM CCA         | ARM         | Realms\n");
    printf("    Nitro Enclaves  | AWS         | Enclaves\n\n");

    printf("    AMD SEV (Secure Encrypted Virtualization) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Chaque VM a une cle AES unique\n");
    printf("    - La memoire est chiffree en hardware\n");
    printf("    - L'hyperviseur ne peut PAS lire la memoire\n");
    printf("    - SNP ajoute l'integrite (anti-tampering)\n\n");

    printf("    Attaques connues contre SEV :\n");
    printf("    - SEVered : manipulation des page tables\n");
    printf("    - CipherLeaks : side-channel sur le chiffrement\n");
    printf("    - SNP corrige la plupart de ces attaques\n\n");
}

/*
 * Etape 6 : Defense et monitoring
 */
static void explain_defense(void) {
    printf("[*] Etape 6 : Defense et monitoring cloud\n\n");

    printf("    Bonnes pratiques :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - IMDSv2 (AWS) : toujours activer\n");
    printf("    - Principe du moindre privilege (IAM)\n");
    printf("    - Network segmentation (VPC, Security Groups)\n");
    printf("    - Chiffrement des disques (EBS, managed disks)\n");
    printf("    - CloudTrail / Azure Monitor / GCP Audit Logs\n\n");

    printf("    Detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - GuardDuty (AWS) : detection d'anomalies\n");
    printf("    - Microsoft Defender for Cloud\n");
    printf("    - GCP Security Command Center\n");
    printf("    - Monitorer les appels API inhabituels\n");
    printf("    - Alerter sur les acces metadata service\n\n");
}

int main(void) {
    printf("[*] Demo : Cloud Hypervisors\n\n");

    explain_cloud_hypervisors();
    explain_aws_nitro();
    demo_cloud_detection();
    explain_cloud_attacks();
    explain_confidential_computing();
    explain_defense();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

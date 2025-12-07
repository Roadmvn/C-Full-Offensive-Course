# Exercices - Cloud Hypervisors

## Objectifs des exercices

Ces exercices vous permettront de pratiquer la détection et l'exploitation des hyperviseurs cloud.
Commencez par l'exercice 1 (très facile) et progressez vers les plus difficiles.

---

## Exercice 1 : Détection basique (Très facile)

**Objectif** : Détecter si vous êtes dans un environnement cloud

**Instructions** :
1. Créez un fichier `detect_cloud.c` avec le code de détection multi-cloud du cours
2. Compilez avec `gcc -o detect_cloud detect_cloud.c -lcurl`
3. Exécutez le programme sur différents environnements :
   - Machine locale (bare metal)
   - VM VirtualBox
   - Instance AWS EC2 (si disponible)
   - VM Azure (si disponible)
4. Observez les différences de détection

**Résultat attendu** :
```
[*] Test AWS...
[-] Pas de réponse
[*] Test Azure...
[-] Pas de réponse
[*] Test GCP...
[-] Pas de réponse
[-] Aucun cloud détecté
```

**Indice** : Si vous n'avez pas accès à un cloud, utilisez une VM locale et modifiez /etc/hosts pour simuler le metadata service.

---

## Exercice 2 : Simulation IMDS (Facile)

**Objectif** : Créer un serveur IMDS local pour tester

**Instructions** :
1. Créez un script Python pour simuler IMDS AWS :
```python
from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/latest/meta-data/instance-id')
def instance_id():
    return "i-1234567890abcdef0"

@app.route('/latest/meta-data/iam/security-credentials/')
def list_roles():
    return "MyTestRole"

@app.route('/latest/meta-data/iam/security-credentials/MyTestRole')
def get_creds():
    return jsonify({
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "EXAMPLE_TOKEN"
    })

if __name__ == '__main__':
    app.run(host='169.254.169.254', port=80)
```

2. Lancez le serveur (avec sudo pour port 80)
3. Testez votre programme de détection
4. Modifiez pour récupérer les credentials

**Résultat attendu** :
```
[+] AWS détecté!
[+] Instance ID: i-1234567890abcdef0
[+] Credentials IAM récupérés:
{"AccessKeyId": "AKIA...", ...}
```

---

## Exercice 3 : Détection avancée (Moyen)

**Objectif** : Créer un détecteur cloud multi-méthodes

**Instructions** :
1. Créez un programme qui détecte le cloud via:
   - CPUID (hypervisor vendor)
   - IMDS (metadata service)
   - DMI/SMBIOS (`dmidecode -s system-manufacturer`)
   - MAC addresses spécifiques (AWS: 02:*, Azure: 00:0d:3a:*)
   - Timing d'instructions (VMs sont plus lentes)

2. Implémentez un système de scoring :
   - Chaque méthode positive = +1 point
   - Affichez le niveau de confiance

3. Testez sur différents environnements

**Critères de réussite** :
- [ ] Détecte AWS Nitro avec score > 3
- [ ] Détecte Azure Hyper-V avec score > 3
- [ ] Détecte GCP KVM avec score > 3
- [ ] Bare metal détecte score = 0

**Code de démarrage** :
```c
#include <stdio.h>

typedef struct {
    int cpuid_score;
    int imds_score;
    int dmi_score;
    int mac_score;
    int timing_score;
} cloud_score_t;

cloud_score_t detect_with_scoring(void) {
    cloud_score_t score = {0};

    // TODO: Implémenter chaque méthode

    return score;
}

int main(void) {
    cloud_score_t score = detect_with_scoring();
    int total = score.cpuid_score + score.imds_score +
                score.dmi_score + score.mac_score + score.timing_score;

    printf("Score de confiance: %d/5\n", total);

    if (total >= 3) {
        printf("Environnement cloud détecté avec haute confiance\n");
    } else if (total > 0) {
        printf("Possible VM/Cloud (confiance faible)\n");
    } else {
        printf("Bare metal probable\n");
    }

    return 0;
}
```

---

## Exercice 4 : Exploitation SSRF (Difficile)

**Objectif** : Exploiter une SSRF pour accéder à IMDS

**Contexte** :
Vous avez trouvé une application web vulnérable à SSRF qui accepte un paramètre `url` :
```
http://vulnerable-app.com/fetch?url=http://example.com
```

L'application tourne sur une instance EC2 AWS.

**Instructions** :
1. Créez un serveur web vulnérable en Python :
```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # Vulnérable SSRF !
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    app.run(port=8080)
```

2. Créez un exploit en C qui :
   - Détecte la vuln SSRF
   - Exploite pour accéder à IMDS
   - Récupère les credentials IAM
   - Exfiltre vers un C2

3. Testez contre votre serveur de simulation IMDS (exercice 2)

**Bonus** :
- Contourner une protection qui bloque `169.254.169.254`
  - Hint: http://425.510.425.510/ = 169.254.169.254 (decimal encoding)
  - Hint: http://0xA9.0xFE.0xA9.0xFE/ (hex encoding)
- Implémenter un bypass pour IMDSv2 (récupérer le token d'abord)

**Code de démarrage** :
```c
#include <stdio.h>
#include <curl/curl.h>

void exploit_ssrf(const char *target_app, const char *imds_endpoint) {
    CURL *curl;
    char exploit_url[1024];
    char response[8192] = {0};

    // Construire l'URL d'exploitation
    snprintf(exploit_url, sizeof(exploit_url),
        "%s/fetch?url=%s", target_app, imds_endpoint);

    printf("[*] Exploitation SSRF: %s\n", exploit_url);

    // TODO: Implémenter l'exploitation
}

int main(void) {
    const char *target = "http://localhost:8080";
    const char *imds = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";

    exploit_ssrf(target, imds);

    return 0;
}
```

---

## Exercice 5 : IMDSv2 Bypass Research (Très difficile)

**Objectif** : Comprendre les limites de IMDSv2

**Contexte** :
IMDSv2 requiert un token PUT pour protéger contre SSRF.
Mais certaines SSRF permettent des requêtes PUT !

**Instructions** :
1. Modifiez le serveur vulnérable pour supporter PUT :
```python
@app.route('/fetch', methods=['GET', 'POST'])
def fetch_url():
    url = request.args.get('url')
    method = request.args.get('method', 'GET')
    headers = {}

    if request.args.get('header'):
        # Format: "Header-Name: value"
        h = request.args.get('header').split(': ')
        headers[h[0]] = h[1]

    if method == 'PUT':
        response = requests.put(url, headers=headers)
    else:
        response = requests.get(url, headers=headers)

    return response.text
```

2. Créez un exploit qui :
   - Utilise SSRF pour obtenir un token IMDSv2 (PUT request)
   - Réutilise ce token pour accéder aux credentials (GET request)

3. Analysez les logs et traces laissées

**Questions de réflexion** :
- Quelle est la différence de détection entre IMDSv1 et IMDSv2 ?
- Comment un WAF/IDS pourrait détecter cette exploitation ?
- Quelles mitigations supplémentaires AWS pourrait implémenter ?

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer la différence entre AWS Nitro, Azure Hyper-V et GCP KVM
- [ ] Détecter un cloud provider via multiples méthodes
- [ ] Récupérer des credentials depuis IMDS
- [ ] Exploiter une SSRF pour accéder à IMDS
- [ ] Comprendre les protections IMDSv2 et leurs limites
- [ ] Identifier les traces laissées par une exploitation IMDS

---

## Solutions

Les solutions détaillées sont disponibles dans `solution.md`.

**Note OPSEC** : Ces techniques sont pour l'apprentissage et le Red Teaming autorisé uniquement.
L'accès non autorisé aux metadata services cloud est illégal.

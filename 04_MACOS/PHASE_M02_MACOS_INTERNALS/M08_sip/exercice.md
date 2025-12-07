# Exercices - System Integrity Protection (SIP)

## Objectifs des exercices

Ces exercices vous permettront de comprendre le fonctionnement de SIP et ses implications en Red Team.

---

## Exercice 1 : Vérifier l'État de SIP (Très facile)

**Objectif** : Déterminer si SIP est activé sur le système

**Instructions** :
1. Utilisez la commande `csrutil status` dans le Terminal
2. Créez un programme C qui utilise `csr_check()` pour vérifier l'état de SIP
3. Compilez et exécutez le programme

**Code de départ** :

```c
#include <stdio.h>
#include <sys/csr.h>

int main() {
    // TODO: Vérifier CSR_ALLOW_UNRESTRICTED_FS
    // TODO: Afficher si SIP est activé ou désactivé

    return 0;
}
```

**Résultat attendu** :
```
System Integrity Protection: ENABLED
Filesystem Protection: ENABLED
```

**Indice** : `csr_check()` retourne 0 si le flag est DÉSACTIVÉ

---

## Exercice 2 : Test des Chemins Protégés (Facile)

**Objectif** : Identifier quels chemins sont protégés par SIP

**Instructions** :
1. Créez un programme qui tente d'écrire dans différents chemins
2. Testez les chemins suivants :
   - `/System/test.txt`
   - `/usr/bin/test.txt`
   - `/usr/local/test.txt`
   - `/tmp/test.txt`
   - `~/test.txt`
3. Affichez un message pour chaque chemin (protégé ou accessible)

**Code de départ** :

```c
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

void test_path(const char *path) {
    // TODO: Ouvrir le fichier en écriture
    // TODO: Vérifier errno si échec
    // TODO: Afficher résultat
}

int main() {
    test_path("/System/test.txt");
    test_path("/usr/bin/test.txt");
    test_path("/usr/local/test.txt");
    test_path("/tmp/test.txt");

    return 0;
}
```

**Résultat attendu** :
```
/System/test.txt          : PROTECTED
/usr/bin/test.txt         : PROTECTED
/usr/local/test.txt       : WRITABLE
/tmp/test.txt             : WRITABLE
```

---

## Exercice 3 : SIP Scanner Complet (Moyen)

**Objectif** : Créer un outil de reconnaissance SIP

**Instructions** :
1. Créez un programme qui vérifie tous les flags SIP importants
2. Testez plusieurs chemins protégés
3. Générez un rapport formaté
4. Ajoutez des couleurs (optionnel)

**Fonctionnalités à implémenter** :
- Vérifier tous les flags CSR (KEXT, FS, task_for_pid, etc.)
- Tester au moins 10 chemins différents
- Afficher un rapport structuré
- Calculer un "score de sécurité" (combien de protections actives)

**Critères de réussite** :
- [ ] Vérifie au moins 5 flags SIP différents
- [ ] Teste au moins 10 chemins
- [ ] Affiche un rapport clair et organisé
- [ ] Gère les erreurs correctement

---

## Exercice 4 : Simulation d'Attaque (Difficile)

**Objectif** : Simuler une reconnaissance Red Team avec contournement

**Contexte** :
Vous avez obtenu un accès shell sur un Mac. Votre objectif est d'établir une persistence sans déclencher d'alertes SIP.

**Instructions** :
1. Créez un programme qui :
   - Vérifie l'état de SIP
   - Identifie les chemins accessibles pour persistence
   - Crée un LaunchAgent dans `~/Library/LaunchAgents/`
   - Teste l'injection de dylib dans une app tierce
2. Le programme doit être discret (pas de messages bruyants)
3. Générez un rapport JSON des findings

**Scénario** :

```ascii
PHASE 1: Reconnaissance
├─ Vérifier SIP status
├─ Identifier chemins writables
└─ Lister processus non-SIP protected

PHASE 2: Persistence
├─ Créer LaunchAgent dans ~/Library/
├─ Copier payload dans /usr/local/bin/
└─ Vérifier permissions

PHASE 3: Validation
├─ Tester si LaunchAgent se charge
└─ Confirmer exécution du payload
```

**Bonus** :
- Ajoutez une fonction pour nettoyer les traces (supprimer fichiers créés)
- Implémentez une vérification TCC en plus de SIP
- Créez un mode "stealth" qui n'écrit aucun fichier sur disque

**Code de départ** :

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/csr.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    int sip_enabled;
    int filesystem_protected;
    int kext_protected;
    char writable_paths[10][256];
    int num_writable;
} ReconReport;

ReconReport perform_reconnaissance() {
    ReconReport report = {0};

    // TODO: Implémenter reconnaissance

    return report;
}

int create_persistence(const char *payload_path) {
    // TODO: Créer LaunchAgent
    // TODO: Copier payload

    return 0;
}

void print_json_report(ReconReport *report) {
    // TODO: Formater en JSON
}

int main() {
    printf("[*] Starting macOS Red Team Recon...\n");

    ReconReport report = perform_reconnaissance();

    if (!report.sip_enabled) {
        printf("[!] SIP DISABLED - Full system access possible!\n");
    } else {
        printf("[+] SIP ENABLED - Using alternative persistence...\n");
        create_persistence("/usr/local/bin/payload");
    }

    print_json_report(&report);

    return 0;
}
```

**Format JSON attendu** :

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "hostname": "target-mac.local",
  "sip": {
    "enabled": true,
    "flags": {
      "filesystem": true,
      "kext": true,
      "task_for_pid": true,
      "dtrace": true
    }
  },
  "writable_paths": [
    "/usr/local/bin",
    "/tmp",
    "/Users/victim/Library/LaunchAgents"
  ],
  "persistence": {
    "method": "LaunchAgent",
    "path": "/Users/victim/Library/LaunchAgents/com.apple.update.plist",
    "payload": "/usr/local/bin/payload",
    "status": "success"
  },
  "recommendations": [
    "Use user-level LaunchAgent for persistence",
    "Avoid /System/ and /usr/bin/",
    "Target third-party applications for injection"
  ]
}
```

---

## Exercice 5 : Analyse d'Entitlements (Challenge)

**Objectif** : Identifier les processus qui peuvent bypass SIP

**Instructions** :
1. Créez un programme qui scanne les processus en cours
2. Pour chaque processus, extrayez ses entitlements
3. Identifiez ceux qui ont `com.apple.rootless.install` ou similaires
4. Générez un rapport des cibles potentielles pour exploitation

**Indice** : Utilisez `codesign -d --entitlements -` ou accédez directement au Mach-O.

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer ce qu'est SIP et comment il fonctionne
- [ ] Utiliser `csr_check()` pour vérifier l'état de SIP
- [ ] Identifier les chemins protégés et non-protégés
- [ ] Créer une persistence sans violer SIP
- [ ] Lister les techniques de bypass de SIP
- [ ] Comprendre les implications OPSEC de SIP

---

## Ressources complémentaires

- [Apple SIP Documentation](https://support.apple.com/en-us/HT204899)
- [Objective-See: SIP Bypass Research](https://objective-see.com)
- [XNU Source Code - csr.h](https://opensource.apple.com/source/xnu/)

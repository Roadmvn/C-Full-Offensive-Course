# Exercices : SMB Communication pour C2

## Avertissement Legal

**ATTENTION** : L'utilisation de SMB Named Pipes pour C2 non autorise est **ILLEGALE**.
- Peines de prison : 5-20 ans selon juridiction
- Amendes massives
- Interdiction professionnelle

**Usage autorise uniquement** :
- Lab isole personnel (VMs disconnectees d'Internet)
- Red Team avec contrat ecrit
- Penetration testing avec autorisation formelle

**NE JAMAIS** :
- Deployer sur reseau d'entreprise sans autorisation
- Tester sur infrastructure tierce
- Utiliser en production

---

## Exercice 1 : Named Pipe Basique (Tres facile)

**Objectif** : Creer un Named Pipe server et client fonctionnel.

**Difficulte** : ★☆☆☆☆

**Instructions** :
1. Creer un serveur Named Pipe `\\.\\pipe\\ex1`
2. Implementer un client qui se connecte au serveur
3. Echanger un message "Hello from client"
4. Serveur repond "Hello from server"
5. Tester en local (deux processus)

**Criteres de validation** :
- [ ] Serveur demarre et attend connexion
- [ ] Client se connecte avec succes
- [ ] Messages echanges correctement
- [ ] Cleanup propre (CloseHandle)

**Indice** :
```c
// Server side
HANDLE hPipe = CreateNamedPipe(
    "\\\\.\\pipe\\ex1",
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    1,      // 1 instance
    4096,   // Buffer sizes
    4096,
    0,
    NULL
);
ConnectNamedPipe(hPipe, NULL);
```

---

## Exercice 2 : Communication Bidirectionnelle (Facile)

**Objectif** : Implementer un shell interactif via Named Pipe.

**Difficulte** : ★★☆☆☆

**Instructions** :
1. Serveur cree pipe `\\.\\pipe\\shell`
2. Client envoie commandes shell (ex: "whoami", "ipconfig")
3. Serveur execute commandes avec `CreateProcess`
4. Serveur retourne output au client
5. Loop jusqu'a commande "exit"

**Criteres de validation** :
- [ ] Commandes executees correctement
- [ ] Output complet retourne au client
- [ ] Gestion erreurs (commande invalide)
- [ ] Exit propre

**Indice** :
```c
// Execute command
STARTUPINFO si = {0};
si.cb = sizeof(si);
si.dwFlags = STARTF_USESTDHANDLES;
si.hStdOutput = hOutputWrite;  // Pipe output
si.hStdError = hOutputWrite;

CreateProcess(NULL, command, NULL, NULL, TRUE,
              CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
```

---

## Exercice 3 : SMB Lateral Movement (Moyen)

**Objectif** : Connexion Named Pipe reseau (entre deux VMs).

**Difficulte** : ★★★☆☆

**Setup** :
- VM1 (192.168.1.10) : Serveur Named Pipe
- VM2 (192.168.1.20) : Client

**Instructions** :
1. VM1 : Creer pipe accessible reseau
2. VM2 : Se connecter via `\\192.168.1.10\pipe\lateral`
3. Echanger messages entre VMs
4. Tester authentification SMB
5. Analyser trafic avec Wireshark

**Criteres de reussite** :
- [ ] Connexion reseau reussie
- [ ] Trafic SMB visible (port 445)
- [ ] Messages transmis sans corruption
- [ ] Logs Windows Event generes (Event ID 5145)

**Indice** :
```c
// Client reseau
#define PIPE_NAME "\\\\192.168.1.10\\pipe\\lateral"

WaitNamedPipe(PIPE_NAME, 5000);
HANDLE hPipe = CreateFile(PIPE_NAME,
                          GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);
```

---

## Exercice 4 : Parent/Child Beacon Architecture (Difficile)

**Objectif** : Implementer architecture C2 parent (HTTP) / child (SMB).

**Difficulte** : ★★★★☆

**Contexte** :
Architecture C2 avec agent parent connecte a Internet et agent child isole communiquant via SMB.

```ascii
C2 Server (HTTP) ◄─► Agent Parent ◄─SMB─► Agent Child
```

**Instructions** :
1. Agent Parent : HTTP beacon vers C2 (simule)
2. Agent Parent : Cree Named Pipe server
3. Agent Child : Connecte au Parent via SMB
4. Parent relaie commandes C2 vers Child
5. Child execute et retourne resultats
6. Parent renvoie resultats au C2

**Criteres de reussite** :
- [ ] Architecture parent/child fonctionnelle
- [ ] Commandes relayees correctement
- [ ] Resultats remontes au C2
- [ ] Gestion deconnexion child (reconnexion)

**Bonus** :
- Implementer heartbeat pour detecter child mort
- Multi-child (plusieurs agents enfants)
- Chiffrement AES sur canal SMB

---

## Exercice 5 : OPSEC - Detection Analysis (Blue Team)

**Objectif** : Identifier IOCs SMB C2 avec outils Blue Team.

**Difficulte** : ★★★☆☆

**Instructions** :
1. Configurer Sysmon pour monitorer Named Pipes (Event ID 17/18)
2. Executer exercices precedents
3. Analyser logs Windows Event (5145, 5140)
4. Identifier anomalies (pipes non-standard, timing)
5. Proposer regles detection

**Criteres de validation** :
- [ ] Sysmon capture creations pipes
- [ ] Event Logs montrent connexions SMB
- [ ] Anomalies identifiees correctement
- [ ] Regles detection documentees

**Indice** :
```xml
<!-- Sysmon config -->
<PipeEvent onmatch="include">
  <PipeName condition="contains any">suspicious;malware;c2</PipeName>
</PipeEvent>
```

---

## Auto-evaluation

Avant de passer au module suivant, verifiez que vous pouvez :
- [ ] Expliquer Named Pipes et leur fonctionnement
- [ ] Creer server/client Named Pipe sans reference
- [ ] Implementer communication reseau via SMB
- [ ] Identifier risques OPSEC et IOCs
- [ ] Proposer mitigations detection

---

## Ressources Additionnelles

- [Named Pipes MSDN](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
- [Cobalt Strike SMB Beacon](https://www.cobaltstrike.com/help-smb-beacon)
- [MITRE ATT&CK: T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

---

**RAPPEL LEGAL** : Exercices strictement pour lab isole ou engagement autorise. Violation = consequences penales graves.

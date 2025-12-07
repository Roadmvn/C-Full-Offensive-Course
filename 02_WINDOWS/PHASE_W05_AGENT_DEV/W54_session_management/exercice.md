# Exercices : Session Management

## Avertissement

Code educatif uniquement. Usage illegal = poursuites penales.

---

## Exercice 1 : Generation Session ID (Facile)

**Objectif** : Implementer generation UUID pour Session ID

**Difficulte** : ★☆☆☆☆

**Instructions** :
1. Utiliser l'API RPC `UuidCreate()` pour generer UUID
2. Convertir UUID en string avec `UuidToStringA()`
3. Afficher le Session ID genere
4. Tester unicite (generer 100 IDs, verifier pas de duplicates)

**Criteres de validation** :
- [ ] UUID genere correctement
- [ ] Format valide (36 caracteres avec tirets)
- [ ] Pas de duplicates sur 100+ generations

---

## Exercice 2 : Heartbeat Simple (Moyen)

**Objectif** : Implementer heartbeat loop basique

**Difficulte** : ★★☆☆☆

**Instructions** :
1. Creer structure `SessionMetadata` avec Session ID, hostname, timestamp
2. Implementer fonction `SendHeartbeat()` qui envoie POST HTTP
3. Loop infinie : envoyer heartbeat toutes les 60s
4. Ajouter jitter +/- 30%
5. Logger chaque heartbeat (timestamp, status)

**Criteres de validation** :
- [ ] Heartbeat envoye regulierement
- [ ] Jitter applique correctement (timing varie)
- [ ] Logs clairs et informatifs

---

## Exercice 3 : Reconnexion avec Backoff (Moyen)

**Objectif** : Gerer perte connexion C2

**Difficulte** : ★★★☆☆

**Instructions** :
1. Detecter echec heartbeat (timeout, erreur HTTP)
2. Implementer backoff exponentiel : 1s, 2s, 4s, 8s, ... max 60s
3. Retry jusqu'a succes ou max 10 tentatives
4. Preserver Session ID entre reconnexions
5. Logger chaque tentative

**Criteres de reussite** :
- [ ] Backoff exponentiel correct
- [ ] Reconnexion reussie apres C2 revient online
- [ ] Session ID preserve
- [ ] Logs detailles

**Test** : Arreter C2 server, observer retries, redemarrer server, valider reconnexion.

---

## Exercice 4 : Persistence Registry (Difficile)

**Objectif** : Sauvegarder session dans Registry

**Difficulte** : ★★★★☆

**Instructions** :
1. Implementer `SaveSessionToRegistry()` : cle discrete dans `HKCU\Software\...`
2. Sauvegarder Session ID, last_seen timestamp
3. Implementer `LoadSessionFromRegistry()` au demarrage
4. Si session existe, charger et continuer ; sinon creer nouvelle
5. Tester : lancer agent, kill, relancer -> doit recharger session

**Criteres de validation** :
- [ ] Session sauvegardee correctement dans Registry
- [ ] Session rechargee apres redemarrage agent
- [ ] Noms Registry discrets (pas "SessionID", utiliser noms legitimes)

---

## Exercice 5 : Session Complete avec Resilience (Challenge)

**Objectif** : Combiner tous les concepts

**Difficulte** : ★★★★★

**Instructions** :
1. Initial check-in avec metadata complete
2. Heartbeat loop avec jitter
3. Detection echec + reconnexion backoff
4. Persistence Registry
5. Working hours only (9-5, Mon-Fri)
6. Cleanup propre sur exit

**Criteres finaux** :
- [ ] Agent fonctionne end-to-end
- [ ] Survit reboot (persistence)
- [ ] Reconnexion automatique si C2 down
- [ ] Working hours respecte
- [ ] Pas de crash, gestion erreurs robuste

---

## Auto-evaluation

- [ ] Comprendre Session IDs et leur generation
- [ ] Implementer heartbeat fonctionnel
- [ ] Gerer reconnexion avec backoff
- [ ] Persister etat dans Registry
- [ ] Identifier risques OPSEC

---

**RAPPEL** : Lab isole uniquement. Usage malveillant = ILLEGAL.

# Exercices - JSON Parsing

## Objectifs des exercices

Ces exercices vous permettront de pratiquer les concepts vus dans le cours.
Commencez par l'exercice 1 (très facile) et progressez vers les plus difficiles.

---

## Exercice 1 : Parser un JSON simple (Très facile)

**Objectif** : Extraire des valeurs d'un JSON

**Instructions** :
1. Téléchargez cJSON : `git clone https://github.com/DaveGamble/cJSON.git`
2. Copiez cJSON.h et cJSON.c dans votre projet
3. Parsez ce JSON : `{"status":"online","users":42,"version":"1.2.3"}`
4. Affichez chaque valeur

**Résultat attendu** :
```
Status: online
Users: 42
Version: 1.2.3
```

**Indice** : Utilisez `cJSON_GetObjectItem()` et vérifiez le type avec `cJSON_IsString()`, `cJSON_IsNumber()`.

---

## Exercice 2 : Créer un beacon JSON (Facile)

**Objectif** : Construire un payload JSON avec informations système

**Instructions** :
1. Créez un objet JSON avec `cJSON_CreateObject()`
2. Ajoutez : hostname (GetComputerNameA), username (GetUserNameA), PID (GetCurrentProcessId)
3. Convertissez en string avec `cJSON_Print()`
4. Affichez le résultat

**Résultat attendu** :
```json
{
  "hostname": "DESKTOP-ABC",
  "username": "john",
  "pid": 5432
}
```

---

## Exercice 3 : Parser un tableau de commandes (Moyen)

**Objectif** : Gérer des tableaux JSON

**Instructions** :
1. Parsez ce JSON : `{"tasks":["download","upload","screenshot"]}`
2. Extrayez le tableau "tasks"
3. Itérez sur le tableau avec `cJSON_GetArraySize()` et `cJSON_GetArrayItem()`
4. Affichez chaque tâche

**Critères de réussite** :
- [ ] JSON parsé sans erreurs
- [ ] Tableau correctement identifié
- [ ] Toutes les tâches affichées
- [ ] Mémoire libérée avec `cJSON_Delete()`

---

## Exercice 4 : Dispatcher de commandes C2 (Difficile)

**Objectif** : Créer un dispatcher qui exécute des commandes JSON

**Contexte** :
Vous recevez des commandes du serveur C2 au format JSON. Vous devez parser et exécuter chaque commande.

**Format JSON** :
```json
{
  "command": "shell",
  "args": "whoami"
}
```

ou

```json
{
  "command": "sleep",
  "duration": 30
}
```

**Instructions** :
1. Créez une fonction `DispatchCommand(const char* json)`
2. Parsez le JSON pour extraire "command"
3. Selon la commande :
   - "shell" : Exécutez `system(args)`
   - "sleep" : `Sleep(duration * 1000)`
   - "exit" : `ExitProcess(0)`
4. Testez avec plusieurs JSONs

**Bonus** :
- Ajoutez une commande "download" qui lit un fichier et crée un JSON avec le contenu en base64
- Gérez les erreurs de parsing (JSON invalide)

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [ ] Parser un JSON et extraire des valeurs sans erreurs
- [ ] Créer un objet JSON et le convertir en string
- [ ] Gérer des tableaux JSON (itération)
- [ ] Identifier les memory leaks et utiliser correctement cJSON_Delete()
- [ ] Combiner cJSON avec WinAPI pour créer un beacon

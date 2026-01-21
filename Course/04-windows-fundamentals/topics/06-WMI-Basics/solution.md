# Module W07 : WMI Basics - Solutions

## Solution Exercice 1 : Connexion WMI et requête simple

**Objectif** : Se connecter à WMI et lister les processus

```c
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

int main() {
    HRESULT hr;

    printf("[*] === Exercice 1 : Connexion WMI et requete ===\n\n");

    // 1. Initialiser COM
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[-] CoInitializeEx echoue: 0x%X\n", hr);
        return 1;
    }

    printf("[+] COM initialise\n");

    // 2. Initialiser la sécurité COM
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );

    if (FAILED(hr)) {
        printf("[-] CoInitializeSecurity echoue: 0x%X\n", hr);
        CoUninitialize();
        return 1;
    }

    // 3. Créer WbemLocator
    IWbemLocator *pLoc = NULL;
    hr = CoCreateInstance(
        &CLSID_WbemLocator, 0,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator,
        (LPVOID *)&pLoc
    );

    if (FAILED(hr)) {
        printf("[-] CoCreateInstance echoue: 0x%X\n", hr);
        CoUninitialize();
        return 1;
    }

    // 4. Se connecter à WMI
    IWbemServices *pSvc = NULL;
    hr = pLoc->lpVtbl->ConnectServer(
        pLoc,
        L"ROOT\\CIMV2",
        NULL, NULL, NULL, 0, NULL, NULL,
        &pSvc
    );

    if (FAILED(hr)) {
        printf("[-] ConnectServer echoue: 0x%X\n", hr);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return 1;
    }

    printf("[+] Connecte au namespace ROOT\\CIMV2\n\n");

    // 5. Définir les proxies
    hr = CoSetProxyBlanket(
        (IUnknown *)pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE
    );

    // 6. Exécuter une requête WQL
    IEnumWbemClassObject *pEnum = NULL;
    hr = pSvc->lpVtbl->ExecQuery(
        pSvc,
        L"WQL",
        L"SELECT ProcessId, Name FROM Win32_Process",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnum
    );

    if (FAILED(hr)) {
        printf("[-] ExecQuery echoue: 0x%X\n", hr);
    } else {
        printf("[+] Requete executee: SELECT ProcessId, Name FROM Win32_Process\n\n");
        printf("%-8s %s\n", "PID", "Nom");
        printf("----------------------------------------\n");

        // 7. Itérer sur les résultats
        IWbemClassObject *pObj = NULL;
        ULONG uReturn = 0;
        int count = 0;

        while (pEnum && count < 20) {
            hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtPid, vtName;

            pObj->lpVtbl->Get(pObj, L"ProcessId", 0, &vtPid, 0, 0);
            pObj->lpVtbl->Get(pObj, L"Name", 0, &vtName, 0, 0);

            wprintf(L"%-8lu %s\n", vtPid.ulVal, vtName.bstrVal);

            VariantClear(&vtPid);
            VariantClear(&vtName);
            pObj->lpVtbl->Release(pObj);
            count++;
        }

        printf("----------------------------------------\n");
        printf("[+] %d processus affiches (limite a 20)\n", count);

        pEnum->lpVtbl->Release(pEnum);
    }

    // Nettoyage
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();

    return 0;
}
```

**Compilation** :
```bash
cl solution_ex1.c /link ole32.lib oleaut32.lib wbemuuid.lib
```

**Explications** :
- WMI utilise COM, donc initialisation requise avec `CoInitializeEx`
- `ROOT\CIMV2` : namespace principal contenant les classes système
- WQL (WMI Query Language) : similaire à SQL
- `WBEM_FLAG_FORWARD_ONLY` : optimisation pour lectures séquentielles

---

## Solution Exercice 2 : Détection d'antivirus avec WMI

**Objectif** : Énumérer les antivirus installés

```c
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

void DetectAntivirus() {
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

    if (FAILED(hr)) {
        printf("[-] WMI initialisation echouee\n");
        CoUninitialize();
        return;
    }

    // Se connecter au namespace SecurityCenter2
    hr = pLoc->lpVtbl->ConnectServer(
        pLoc,
        L"ROOT\\SecurityCenter2",
        NULL, NULL, NULL, 0, NULL, NULL,
        &pSvc
    );

    if (FAILED(hr)) {
        printf("[-] Connexion a SecurityCenter2 echouee: 0x%X\n", hr);
        printf("[-] Ce namespace peut ne pas exister sur certaines versions de Windows\n");
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return;
    }

    printf("[+] Connecte a ROOT\\SecurityCenter2\n\n");

    CoSetProxyBlanket((IUnknown *)pSvc, RPC_C_AUTHN_WINNT,
                      RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL, EOAC_NONE);

    // Requête pour obtenir les antivirus
    IEnumWbemClassObject *pEnum = NULL;
    hr = pSvc->lpVtbl->ExecQuery(
        pSvc, L"WQL",
        L"SELECT displayName, pathToSignedProductExe, productState FROM AntiVirusProduct",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnum
    );

    if (SUCCEEDED(hr)) {
        printf("[+] Antivirus detectes:\n\n");

        IWbemClassObject *pObj = NULL;
        ULONG uReturn = 0;

        while (pEnum) {
            hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtName, vtPath, vtState;

            pObj->lpVtbl->Get(pObj, L"displayName", 0, &vtName, 0, 0);
            pObj->lpVtbl->Get(pObj, L"pathToSignedProductExe", 0, &vtPath, 0, 0);
            pObj->lpVtbl->Get(pObj, L"productState", 0, &vtState, 0, 0);

            wprintf(L"  Nom: %s\n", vtName.bstrVal);
            if (vtPath.vt != VT_NULL)
                wprintf(L"  Chemin: %s\n", vtPath.bstrVal);
            printf("  Etat: 0x%lX\n\n", vtState.ulVal);

            VariantClear(&vtName);
            VariantClear(&vtPath);
            VariantClear(&vtState);
            pObj->lpVtbl->Release(pObj);
        }

        pEnum->lpVtbl->Release(pEnum);
    } else {
        printf("[-] Aucun antivirus detecte ou erreur: 0x%X\n", hr);
    }

    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();
}

int main() {
    printf("[*] === Exercice 2 : Detection d'antivirus ===\n\n");
    DetectAntivirus();
    return 0;
}
```

**Explications** :
- `ROOT\SecurityCenter2` : namespace contenant les informations de sécurité
- `AntiVirusProduct` : classe WMI listant les AV installés
- `productState` : état de l'AV (activé, désactivé, à jour, etc.)
- Utile en reconnaissance pour adapter les techniques d'évasion

---

## Solution Exercice 3 : Exécution de processus via WMI

**Objectif** : Lancer un processus en utilisant Win32_Process.Create

```c
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

DWORD WMIExecuteProcess(const wchar_t *cmdline) {
    HRESULT hr;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IWbemClassObject *pClass = NULL;
    IWbemClassObject *pInParams = NULL;
    IWbemClassObject *pInParamsInstance = NULL;
    IWbemClassObject *pOutParams = NULL;
    DWORD pid = 0;

    CoInitializeEx(0, COINIT_MULTITHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE, NULL);

    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hr)) goto cleanup;

    hr = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\CIMV2",
                                     NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    if (FAILED(hr)) goto cleanup;

    CoSetProxyBlanket((IUnknown *)pSvc, RPC_C_AUTHN_WINNT,
                      RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL, EOAC_NONE);

    // 1. Obtenir la classe Win32_Process
    hr = pSvc->lpVtbl->GetObject(pSvc, L"Win32_Process", 0, NULL, &pClass, NULL);
    if (FAILED(hr)) {
        printf("[-] GetObject echoue: 0x%X\n", hr);
        goto cleanup;
    }

    // 2. Obtenir la méthode Create
    hr = pClass->lpVtbl->GetMethod(pClass, L"Create", 0, &pInParams, NULL);
    if (FAILED(hr)) {
        printf("[-] GetMethod echoue: 0x%X\n", hr);
        goto cleanup;
    }

    // 3. Créer une instance des paramètres
    hr = pInParams->lpVtbl->SpawnInstance(pInParams, 0, &pInParamsInstance);

    // 4. Définir la commande à exécuter
    VARIANT varCmd;
    VariantInit(&varCmd);
    varCmd.vt = VT_BSTR;
    varCmd.bstrVal = SysAllocString(cmdline);

    hr = pInParamsInstance->lpVtbl->Put(pInParamsInstance,
                                        L"CommandLine", 0, &varCmd, 0);
    VariantClear(&varCmd);

    // 5. Exécuter la méthode
    hr = pSvc->lpVtbl->ExecMethod(pSvc, L"Win32_Process", L"Create", 0,
                                  NULL, pInParamsInstance, &pOutParams, NULL);

    if (FAILED(hr)) {
        printf("[-] ExecMethod echoue: 0x%X\n", hr);
        goto cleanup;
    }

    // 6. Récupérer le PID
    VARIANT varPid, varReturn;
    hr = pOutParams->lpVtbl->Get(pOutParams, L"ProcessId", 0, &varPid, 0, 0);
    pOutParams->lpVtbl->Get(pOutParams, L"ReturnValue", 0, &varReturn, 0, 0);

    if (SUCCEEDED(hr) && varReturn.ulVal == 0) {
        pid = varPid.ulVal;
        printf("[+] Processus cree avec PID: %lu\n", pid);
    } else {
        printf("[-] Echec de creation: code retour %lu\n", varReturn.ulVal);
    }

    VariantClear(&varPid);
    VariantClear(&varReturn);

cleanup:
    if (pOutParams) pOutParams->lpVtbl->Release(pOutParams);
    if (pInParamsInstance) pInParamsInstance->lpVtbl->Release(pInParamsInstance);
    if (pInParams) pInParams->lpVtbl->Release(pInParams);
    if (pClass) pClass->lpVtbl->Release(pClass);
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();

    return pid;
}

int main(int argc, wchar_t *argv[]) {
    printf("[*] === Exercice 3 : Execution via WMI ===\n\n");

    const wchar_t *cmd = (argc > 1) ? argv[1] : L"cmd.exe /c whoami";

    wprintf(L"[*] Commande: %s\n\n", cmd);
    WMIExecuteProcess(cmd);

    return 0;
}
```

**Explications** :
- `Win32_Process.Create` : méthode WMI pour créer un processus
- Alternative à `CreateProcess` et moins surveillée par certains EDR
- Nécessite des privilèges administrateur dans la plupart des cas
- Utile pour l'exécution latérale sur machines distantes via WMI réseau

---

## Solution Exercice 4 : WMI Event Subscription (persistence)

**Objectif** : Créer un mécanisme de persistence via Event Subscription

```c
#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Note : Ce code est simplifié pour la démonstration
// Une implémentation complète nécessiterait plus de gestion d'erreurs

void CreatePersistence() {
    HRESULT hr;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;

    printf("[*] === Exercice 4 : WMI Event Subscription ===\n\n");
    printf("[!] AVERTISSEMENT : Ceci cree une persistence\n");
    printf("[!] A utiliser UNIQUEMENT dans un environnement de test\n\n");

    CoInitializeEx(0, COINIT_MULTITHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE, NULL);

    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hr)) {
        printf("[-] Echec initialisation WMI\n");
        CoUninitialize();
        return;
    }

    // Se connecter au namespace root\subscription
    hr = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\subscription",
                                     NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    if (FAILED(hr)) {
        printf("[-] Connexion echouee: 0x%X\n", hr);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return;
    }

    printf("[+] Connecte au namespace ROOT\\subscription\n");

    CoSetProxyBlanket((IUnknown *)pSvc, RPC_C_AUTHN_WINNT,
                      RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL, EOAC_NONE);

    // Pour créer une persistence complète, il faut :
    // 1. Créer un __EventFilter
    // 2. Créer un CommandLineEventConsumer
    // 3. Créer un __FilterToConsumerBinding

    printf("\n[*] Creation d'une event subscription necessiterait:\n");
    printf("    1. __EventFilter (definir l'evenement a surveiller)\n");
    printf("    2. CommandLineEventConsumer (action a executer)\n");
    printf("    3. __FilterToConsumerBinding (lier filtre et consumer)\n\n");

    printf("[*] Exemple de requete WQL pour le filtre:\n");
    printf("    SELECT * FROM __InstanceModificationEvent WITHIN 60\n");
    printf("    WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\n\n");

    printf("[*] Pour detecter les subscriptions existantes:\n");
    printf("    Get-WMIObject -Namespace root\\Subscription -Class __EventFilter\n");
    printf("    Get-WMIObject -Namespace root\\Subscription -Class CommandLineEventConsumer\n");

    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();
}

int main() {
    CreatePersistence();
    return 0;
}
```

**Explications** :
- Les Event Subscriptions WMI survivent aux redémarrages
- Stockées dans le repository WMI (`C:\Windows\System32\wbem\Repository\`)
- Détectées par Sysmon (Event ID 19, 20, 21)
- Technique utilisée par Cobalt Strike et des APT

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Initialiser COM et se connecter à WMI
- [x] Exécuter des requêtes WQL pour obtenir des informations système
- [x] Détecter les antivirus avec le namespace SecurityCenter2
- [x] Créer des processus via Win32_Process.Create
- [x] Comprendre le concept des Event Subscriptions pour la persistence
- [x] Identifier les considérations OPSEC (logs WMI, artefacts dans le repository)

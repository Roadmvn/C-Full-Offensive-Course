/*
 * LESSON 04: Process Information
 *
 * OBJECTIFS:
 * - Obtenir des informations detaillees sur les processus
 * - Utiliser les fonctions d'interrogation de processus
 * - Recuperer les chemins et modules
 * - Analyser l'environnement d'execution
 *
 * CONCEPTS CLES:
 * - GetCurrentProcessId: PID du processus actuel
 * - GetModuleFileName: Chemin de l'executable
 * - GetSystemInfo: Informations systeme
 * - Variables d'environnement
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")

/*
 * INFORMATIONS BASIQUES DU PROCESSUS ACTUEL
 *
 * Fonctions simples pour obtenir des infos sur le processus courant.
 */
void get_current_process_info() {
    printf("=== INFORMATIONS PROCESSUS ACTUEL ===\n\n");

    // ID du processus
    DWORD pid = GetCurrentProcessId();
    printf("Process ID (PID): %lu\n", pid);

    // ID du thread principal
    DWORD tid = GetCurrentThreadId();
    printf("Thread ID (TID): %lu\n", tid);

    // Handle du processus actuel
    HANDLE hProcess = GetCurrentProcess();
    printf("Handle processus: 0x%p\n", hProcess);
    printf("  Note: Pseudo-handle, pas besoin de CloseHandle\n");

    // Handle du thread actuel
    HANDLE hThread = GetCurrentThread();
    printf("Handle thread: 0x%p\n\n", hThread);
}

/*
 * CHEMIN DE L'EXECUTABLE
 *
 * Obtenir le chemin complet du programme en cours d'execution.
 */
void get_executable_path() {
    printf("=== CHEMIN DE L'EXECUTABLE ===\n\n");

    char exePath[MAX_PATH];

    // Methode 1: GetModuleFileName (NULL = module principal)
    DWORD length = GetModuleFileNameA(NULL, exePath, MAX_PATH);

    if (length > 0) {
        printf("Chemin complet:\n  %s\n\n", exePath);

        // Extraire juste le nom du fichier
        char* fileName = strrchr(exePath, '\\');
        if (fileName) {
            printf("Nom du fichier: %s\n", fileName + 1);
        }

        // Extraire le repertoire
        char directory[MAX_PATH];
        strcpy_s(directory, MAX_PATH, exePath);
        char* lastSlash = strrchr(directory, '\\');
        if (lastSlash) {
            *lastSlash = '\0';
            printf("Repertoire: %s\n\n", directory);
        }
    } else {
        printf("[-] GetModuleFileName echoue: %lu\n\n", GetLastError());
    }
}

/*
 * INFORMATIONS SYSTEME
 *
 * Obtenir des informations sur le systeme d'exploitation.
 */
void get_system_information() {
    printf("=== INFORMATIONS SYSTEME ===\n\n");

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    printf("Architecture:\n");
    printf("  Type processeur: ");
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            printf("x64 (AMD64)\n");
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            printf("x86 (Intel)\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            printf("ARM\n");
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            printf("ARM64\n");
            break;
        default:
            printf("Inconnu (%d)\n", sysInfo.wProcessorArchitecture);
    }

    printf("  Nombre de processeurs: %lu\n", sysInfo.dwNumberOfProcessors);
    printf("  Taille de page: %lu bytes\n", sysInfo.dwPageSize);
    printf("  Granularite allocation: %lu bytes\n", sysInfo.dwAllocationGranularity);

    printf("\nPlage d'adresses memoire:\n");
    printf("  Minimum: 0x%p\n", sysInfo.lpMinimumApplicationAddress);
    printf("  Maximum: 0x%p\n\n", sysInfo.lpMaximumApplicationAddress);
}

/*
 * VERSION DE WINDOWS
 *
 * Obtenir la version du systeme d'exploitation.
 */
void get_windows_version() {
    printf("=== VERSION DE WINDOWS ===\n\n");

    // Methode moderne: RtlGetVersion (via GetVersionEx deprecated)
    typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)
            GetProcAddress(hNtdll, "RtlGetVersion");

        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = {0};
            osvi.dwOSVersionInfoSize = sizeof(osvi);

            if (RtlGetVersion(&osvi) == 0) {
                printf("Version Windows:\n");
                printf("  Major: %lu\n", osvi.dwMajorVersion);
                printf("  Minor: %lu\n", osvi.dwMinorVersion);
                printf("  Build: %lu\n\n", osvi.dwBuildNumber);

                // Interpreter la version
                if (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 22000) {
                    printf("Systeme: Windows 11\n");
                } else if (osvi.dwMajorVersion == 10) {
                    printf("Systeme: Windows 10\n");
                } else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3) {
                    printf("Systeme: Windows 8.1\n");
                } else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2) {
                    printf("Systeme: Windows 8\n");
                } else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) {
                    printf("Systeme: Windows 7\n");
                }
            }
        }
    }

    printf("\n");
}

/*
 * VARIABLES D'ENVIRONNEMENT
 *
 * Acceder aux variables d'environnement du processus.
 */
void get_environment_variables() {
    printf("=== VARIABLES D'ENVIRONNEMENT ===\n\n");

    // Variables communes
    const char* vars[] = {
        "USERNAME",
        "COMPUTERNAME",
        "USERPROFILE",
        "TEMP",
        "PATH"
    };

    char value[MAX_PATH];

    for (int i = 0; i < 5; i++) {
        DWORD result = GetEnvironmentVariableA(vars[i], value, MAX_PATH);

        if (result > 0) {
            printf("%s:\n", vars[i]);

            // PATH est trop long, tronquer l'affichage
            if (strcmp(vars[i], "PATH") == 0 && result > 100) {
                value[100] = '\0';
                printf("  %s...\n", value);
            } else {
                printf("  %s\n", value);
            }
        } else {
            printf("%s: [Non definie]\n", vars[i]);
        }
    }

    printf("\n");
}

/*
 * UTILISATION DE LA MEMOIRE
 *
 * Statistiques sur l'utilisation memoire du processus.
 */
void get_memory_usage() {
    printf("=== UTILISATION MEMOIRE ===\n\n");

    PROCESS_MEMORY_COUNTERS_EX pmc;
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        printf("Working Set (memoire physique):\n");
        printf("  Actuel: %lu KB\n", pmc.WorkingSetSize / 1024);
        printf("  Peak: %lu KB\n\n", pmc.PeakWorkingSetSize / 1024);

        printf("Commit (memoire virtuelle):\n");
        printf("  Actuel: %lu KB\n", pmc.PrivateUsage / 1024);
        printf("  Pagefile: %lu KB\n\n", pmc.PagefileUsage / 1024);

        printf("Fautes de page: %lu\n\n", pmc.PageFaultCount);
    } else {
        printf("[-] GetProcessMemoryInfo echoue: %lu\n\n", GetLastError());
    }
}

/*
 * TEMPS D'EXECUTION
 *
 * Temps CPU utilise par le processus.
 */
void get_process_times() {
    printf("=== TEMPS D'EXECUTION ===\n\n");

    FILETIME createTime, exitTime, kernelTime, userTime;

    if (GetProcessTimes(GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime)) {
        // Convertir createTime en SYSTEMTIME
        SYSTEMTIME st;
        FileTimeToSystemTime(&createTime, &st);

        printf("Heure de creation:\n");
        printf("  %02d/%02d/%04d %02d:%02d:%02d\n\n",
            st.wDay, st.wMonth, st.wYear,
            st.wHour, st.wMinute, st.wSecond);

        // Convertir les temps CPU en millisecondes
        ULARGE_INTEGER kt, ut;
        kt.LowPart = kernelTime.dwLowDateTime;
        kt.HighPart = kernelTime.dwHighDateTime;
        ut.LowPart = userTime.dwLowDateTime;
        ut.HighPart = userTime.dwHighDateTime;

        printf("Temps CPU:\n");
        printf("  Kernel mode: %llu ms\n", kt.QuadPart / 10000);
        printf("  User mode: %llu ms\n", ut.QuadPart / 10000);
        printf("  Total: %llu ms\n\n", (kt.QuadPart + ut.QuadPart) / 10000);
    }
}

/*
 * MODULES CHARGES
 *
 * Liste des DLLs chargees dans le processus actuel.
 */
void get_loaded_modules() {
    printf("=== MODULES CHARGES ===\n\n");

    HMODULE modules[256];
    DWORD bytesNeeded;

    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &bytesNeeded)) {
        DWORD numModules = bytesNeeded / sizeof(HMODULE);

        printf("Nombre de modules: %lu\n\n", numModules);

        char moduleName[MAX_PATH];
        char modulePath[MAX_PATH];

        printf("╔════╦══════════════════════════╦════════════════════════════════════╗\n");
        printf("║ #  ║ NOM                      ║ BASE ADDRESS                       ║\n");
        printf("╠════╬══════════════════════════╬════════════════════════════════════╣\n");

        // Afficher les 15 premiers modules
        for (DWORD i = 0; i < 15 && i < numModules; i++) {
            if (GetModuleBaseNameA(GetCurrentProcess(), modules[i], moduleName, sizeof(moduleName))) {
                printf("║ %2lu ║ %-24s ║ 0x%016p                 ║\n",
                    i, moduleName, modules[i]);
            }
        }

        printf("╚════╩══════════════════════════╩════════════════════════════════════╝\n");

        if (numModules > 15) {
            printf("... et %lu autres modules\n", numModules - 15);
        }
    }

    printf("\n");
}

/*
 * PRIVILEGES DU PROCESSUS
 *
 * Verifier si le processus s'execute avec des privileges eleves.
 */
void check_privileges() {
    printf("=== PRIVILEGES DU PROCESSUS ===\n\n");

    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    // Ouvrir le token du processus
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }

        CloseHandle(hToken);
    }

    printf("Execution en mode eleve (administrateur): %s\n", isElevated ? "OUI" : "NON");

    if (!isElevated) {
        printf("  Note: Certaines operations necessitent des privileges eleves\n");
    }

    printf("\n");
}

/*
 * LIGNE DE COMMANDE
 *
 * Recuperer la ligne de commande complete du processus.
 */
void get_command_line() {
    printf("=== LIGNE DE COMMANDE ===\n\n");

    // Obtenir la ligne de commande
    LPSTR cmdLine = GetCommandLineA();

    printf("Ligne de commande complete:\n");
    printf("  %s\n\n", cmdLine);

    // Parser les arguments (methode simple)
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argv) {
        printf("Arguments (%d):\n", argc);
        for (int i = 0; i < argc; i++) {
            wprintf(L"  [%d] %s\n", i, argv[i]);
        }
        LocalFree(argv);
    }

    printf("\n");
}

/*
 * REPERTOIRE COURANT
 *
 * Obtenir et modifier le repertoire de travail actuel.
 */
void get_current_directory_info() {
    printf("=== REPERTOIRE COURANT ===\n\n");

    char currentDir[MAX_PATH];

    if (GetCurrentDirectoryA(MAX_PATH, currentDir)) {
        printf("Repertoire de travail actuel:\n");
        printf("  %s\n\n", currentDir);
    }

    // Obtenir le repertoire Windows
    char windowsDir[MAX_PATH];
    if (GetWindowsDirectoryA(windowsDir, MAX_PATH)) {
        printf("Repertoire Windows:\n");
        printf("  %s\n\n", windowsDir);
    }

    // Obtenir le repertoire System32
    char systemDir[MAX_PATH];
    if (GetSystemDirectoryA(systemDir, MAX_PATH)) {
        printf("Repertoire System32:\n");
        printf("  %s\n\n", systemDir);
    }
}

/*
 * BONNES PRATIQUES
 */
void show_best_practices() {
    printf("=== BONNES PRATIQUES ===\n\n");

    printf("1. Utiliser GetCurrentProcess() pour le processus actuel\n");
    printf("2. GetModuleFileName(NULL) pour le chemin de l'exe\n");
    printf("3. Verifier la taille des buffers (MAX_PATH)\n");
    printf("4. Toujours verifier les codes de retour\n");
    printf("5. Utiliser PSAPI pour infos detaillees memoire\n");
    printf("6. RtlGetVersion pour version Windows fiable\n\n");
}

int main(void) {
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      LESSON 04: PROCESS INFORMATION - WINDOWS API        ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    get_current_process_info();
    get_executable_path();
    get_system_information();
    get_windows_version();
    get_environment_variables();
    get_memory_usage();
    get_process_times();
    get_loaded_modules();
    check_privileges();
    get_command_line();
    get_current_directory_info();
    show_best_practices();

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║                    FIN DE LA LESSON                       ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}

/*
 * OBJECTIF  : Architecture de dispatch des commandes dans un agent C2
 * PREREQUIS : JSON Parsing, Structures C, function pointers
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Le command dispatcher recoit les commandes du C2, les route vers
 * le handler approprie, et retourne les resultats.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")

/* Buffer de sortie pour les resultats */
typedef struct {
    char data[8192];
    int len;
} OutputBuffer;

void buf_append(OutputBuffer* buf, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    buf->len += vsnprintf(buf->data + buf->len,
                          sizeof(buf->data) - buf->len, fmt, args);
    va_end(args);
}

/* Handlers de commandes */
typedef int (*CommandHandler)(const char* args, OutputBuffer* out);

int cmd_whoami(const char* args, OutputBuffer* out) {
    char user[256] = {0}, host[256] = {0};
    DWORD sz = sizeof(user);
    GetUserNameA(user, &sz);
    sz = sizeof(host);
    GetComputerNameA(host, &sz);
    buf_append(out, "%s\\%s", host, user);
    return 0;
}

int cmd_pwd(const char* args, OutputBuffer* out) {
    char cwd[MAX_PATH] = {0};
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    buf_append(out, "%s", cwd);
    return 0;
}

int cmd_cd(const char* args, OutputBuffer* out) {
    if (!args || !*args) {
        buf_append(out, "Usage: cd <path>");
        return 1;
    }
    if (SetCurrentDirectoryA(args)) {
        char cwd[MAX_PATH] = {0};
        GetCurrentDirectoryA(sizeof(cwd), cwd);
        buf_append(out, "%s", cwd);
        return 0;
    }
    buf_append(out, "Erreur: impossible de changer vers '%s'", args);
    return 1;
}

int cmd_ls(const char* args, OutputBuffer* out) {
    char pattern[MAX_PATH];
    if (args && *args)
        snprintf(pattern, sizeof(pattern), "%s\\*", args);
    else
        snprintf(pattern, sizeof(pattern), "*");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        buf_append(out, "Erreur: impossible de lister '%s'", pattern);
        return 1;
    }
    int count = 0;
    do {
        char type = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : 'f';
        buf_append(out, "[%c] %s\n", type, fd.cFileName);
        count++;
    } while (FindNextFileA(hFind, &fd) && count < 50);
    FindClose(hFind);
    buf_append(out, "(%d entrees)", count);
    return 0;
}

int cmd_ps(const char* args, OutputBuffer* out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        buf_append(out, "Erreur: CreateToolhelp32Snapshot");
        return 1;
    }
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    int count = 0;
    buf_append(out, "%-8s %-8s %s\n", "PID", "PPID", "NAME");
    if (Process32First(snap, &pe)) {
        do {
            buf_append(out, "%-8lu %-8lu %s\n",
                       pe.th32ProcessID, pe.th32ParentProcessID,
                       pe.szExeFile);
            count++;
        } while (Process32Next(snap, &pe) && count < 30);
    }
    CloseHandle(snap);
    buf_append(out, "(%d processus)", count);
    return 0;
}

int cmd_env(const char* args, OutputBuffer* out) {
    const char* vars[] = {
        "USERNAME", "COMPUTERNAME", "USERDOMAIN",
        "OS", "PROCESSOR_ARCHITECTURE", "TEMP", NULL
    };
    int i;
    for (i = 0; vars[i]; i++) {
        char* val = getenv(vars[i]);
        buf_append(out, "%s=%s\n", vars[i], val ? val : "(non defini)");
    }
    return 0;
}

int cmd_sleep(const char* args, OutputBuffer* out) {
    if (!args || !*args) {
        buf_append(out, "Usage: sleep <ms>");
        return 1;
    }
    int ms = atoi(args);
    buf_append(out, "Sleep modifie a %d ms", ms);
    return 0;
}

/* Table de dispatch */
typedef struct {
    const char* name;
    CommandHandler handler;
    const char* help;
} CommandEntry;

CommandEntry dispatch_table[] = {
    {"whoami", cmd_whoami,  "Affiche l'utilisateur courant"},
    {"pwd",    cmd_pwd,     "Affiche le repertoire courant"},
    {"cd",     cmd_cd,      "Change de repertoire"},
    {"ls",     cmd_ls,      "Liste les fichiers"},
    {"ps",     cmd_ps,      "Liste les processus"},
    {"env",    cmd_env,     "Affiche les variables d'environnement"},
    {"sleep",  cmd_sleep,   "Modifie l'intervalle de callback"},
    {NULL,     NULL,        NULL}
};

/* Dispatcher principal */
int dispatch_command(const char* cmd, const char* args, OutputBuffer* out) {
    int i;
    for (i = 0; dispatch_table[i].name; i++) {
        if (strcmp(cmd, dispatch_table[i].name) == 0) {
            return dispatch_table[i].handler(args, out);
        }
    }
    buf_append(out, "Commande inconnue: '%s'", cmd);
    return -1;
}

void demo_dispatch(void) {
    printf("[1] Dispatch des commandes\n\n");

    /* Simuler des commandes recues du C2 */
    struct { const char* cmd; const char* args; } tasks[] = {
        {"whoami", NULL},
        {"pwd",    NULL},
        {"ls",     NULL},
        {"env",    NULL},
        {"sleep",  "10000"},
        {"invalid", NULL},
    };

    int i;
    for (i = 0; i < 6; i++) {
        OutputBuffer out = {0};
        printf("    > %s %s\n", tasks[i].cmd,
               tasks[i].args ? tasks[i].args : "");
        int ret = dispatch_command(tasks[i].cmd, tasks[i].args, &out);
        printf("    [%s] %s\n\n", ret == 0 ? "OK" : "ERR", out.data);
    }
}

void demo_architecture(void) {
    printf("[2] Architecture du dispatcher\n\n");
    printf("    C2 Server -> JSON task -> Agent\n");
    printf("                                |\n");
    printf("                         Parse commande\n");
    printf("                                |\n");
    printf("                     +----------+----------+\n");
    printf("                     |          |          |\n");
    printf("                   whoami      ls         ps\n");
    printf("                     |          |          |\n");
    printf("                  Execute    Execute    Execute\n");
    printf("                     |          |          |\n");
    printf("                     +----------+----------+\n");
    printf("                                |\n");
    printf("                         Output buffer\n");
    printf("                                |\n");
    printf("                     JSON response -> C2\n\n");
    printf("    Avantages de la table de dispatch :\n");
    printf("    - Extensible (ajouter une ligne par commande)\n");
    printf("    - Pas de switch/case geant\n");
    printf("    - Commandes modulaires et testables\n\n");
}

int main(void) {
    printf("[*] Demo : Command Dispatcher C2\n");
    printf("[*] ==========================================\n\n");
    demo_dispatch();
    demo_architecture();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

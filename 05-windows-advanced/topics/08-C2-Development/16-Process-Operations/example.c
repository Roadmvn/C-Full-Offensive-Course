/*
 * OBJECTIF  : Operations sur les processus pour un agent C2
 * PREREQUIS : CreateProcess, Toolhelp, Process API
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Un agent C2 doit pouvoir lister les processus, en creer,
 * en tuer, et identifier les processus de securite.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

/* Liste des processus de securite connus */
typedef struct {
    const char* name;
    const char* product;
} SecurityProcess;

SecurityProcess sec_procs[] = {
    {"MsMpEng.exe",        "Windows Defender"},
    {"csfalconservice.exe","CrowdStrike Falcon"},
    {"SentinelAgent.exe",  "SentinelOne"},
    {"CylanceSvc.exe",     "Cylance"},
    {"cb.exe",             "Carbon Black"},
    {"bdagent.exe",        "Bitdefender"},
    {"avp.exe",            "Kaspersky"},
    {NULL, NULL}
};

void demo_process_list(void) {
    printf("[1] Liste des processus (commande 'ps')\n\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("    [-] Snapshot echoue\n\n");
        return;
    }

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    int count = 0, sec_count = 0;

    printf("    %-8s %-8s %-4s %s\n", "PID", "PPID", "THR", "NAME");
    printf("    %-8s %-8s %-4s %s\n", "---", "----", "---", "----");

    if (Process32First(snap, &pe)) {
        do {
            /* Verifier si c'est un processus de securite */
            int is_sec = 0;
            int i;
            for (i = 0; sec_procs[i].name; i++) {
                if (_stricmp(pe.szExeFile, sec_procs[i].name) == 0) {
                    is_sec = 1;
                    sec_count++;
                    break;
                }
            }

            if (count < 15 || is_sec) {
                printf("    %-8lu %-8lu %-4lu %s%s\n",
                       pe.th32ProcessID, pe.th32ParentProcessID,
                       pe.cntThreads, pe.szExeFile,
                       is_sec ? " [SEC]" : "");
            }
            count++;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    printf("    ... (%d processus total, %d securite)\n\n", count, sec_count);
}

void demo_process_spawn(void) {
    printf("[2] Creation de processus (commande 'spawn')\n\n");

    /* Spawn visible */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    printf("    Spawn classique (notepad.exe) :\n");
    if (CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("    [+] PID: %lu, TID: %lu (SUSPENDED)\n",
               pi.dwProcessId, pi.dwThreadId);
        /* Terminer immediatement (demo seulement) */
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("    [+] Processus termine (demo)\n");
    }

    /* Spawn cache */
    printf("\n    Spawn cache (CREATE_NO_WINDOW) :\n");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    char cmd[] = "cmd.exe /c echo hidden";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("    [+] PID: %lu (cache, pas de fenetre)\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    printf("\n");
}

void demo_process_info(void) {
    printf("[3] Informations sur un processus\n\n");

    DWORD pid = GetCurrentProcessId();
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) {
        printf("    [-] OpenProcess echoue\n\n");
        return;
    }

    printf("    PID: %lu\n", pid);

    /* Chemin de l'executable */
    char path[MAX_PATH] = {0};
    if (GetModuleFileNameExA(hProc, NULL, path, sizeof(path)))
        printf("    Path: %s\n", path);

    /* Memoire utilisee */
    PROCESS_MEMORY_COUNTERS pmc = {0};
    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
        printf("    Working Set: %lu KB\n", (DWORD)(pmc.WorkingSetSize / 1024));
        printf("    Private:     %lu KB\n", (DWORD)(pmc.PagefileUsage / 1024));
    }

    /* Priorite */
    DWORD prio = GetPriorityClass(hProc);
    const char* prio_str = "UNKNOWN";
    if (prio == NORMAL_PRIORITY_CLASS) prio_str = "NORMAL";
    else if (prio == HIGH_PRIORITY_CLASS) prio_str = "HIGH";
    else if (prio == IDLE_PRIORITY_CLASS) prio_str = "IDLE";
    printf("    Priority: %s\n", prio_str);

    /* Integrite */
    HANDLE hToken;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        DWORD il_size = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &il_size);
        if (il_size > 0) {
            TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)malloc(il_size);
            if (tml && GetTokenInformation(hToken, TokenIntegrityLevel,
                                           tml, il_size, &il_size)) {
                DWORD il = *GetSidSubAuthority(tml->Label.Sid,
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
                const char* il_str = "Unknown";
                if (il >= 0x4000) il_str = "System";
                else if (il >= 0x3000) il_str = "High";
                else if (il >= 0x2000) il_str = "Medium";
                else il_str = "Low";
                printf("    Integrity: %s (0x%lX)\n", il_str, il);
            }
            free(tml);
        }
        CloseHandle(hToken);
    }

    CloseHandle(hProc);
    printf("\n");
}

void demo_security_scan(void) {
    printf("[4] Scan des processus de securite\n\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    int found = 0;

    if (Process32First(snap, &pe)) {
        do {
            int i;
            for (i = 0; sec_procs[i].name; i++) {
                if (_stricmp(pe.szExeFile, sec_procs[i].name) == 0) {
                    printf("    [!] %s (PID %lu) = %s\n",
                           pe.szExeFile, pe.th32ProcessID,
                           sec_procs[i].product);
                    found++;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (found == 0)
        printf("    [+] Aucun processus de securite connu detecte\n");
    printf("\n");
}

int main(void) {
    printf("[*] Demo : Process Operations Agent C2\n");
    printf("[*] ==========================================\n\n");
    demo_process_list();
    demo_process_spawn();
    demo_process_info();
    demo_security_scan();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

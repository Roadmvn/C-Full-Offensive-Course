# Command Dispatcher - Architecture de Commandes C2

## Objectifs

- [ ] Comprendre l'architecture dispatcher de commandes
- [ ] Parser et router les commandes du serveur C2
- [ ] Impl\u00e9menter les handlers de commandes
- [ ] G\u00e9rer les erreurs et retourner les r\u00e9sultats

## Introduction

Le dispatcher est le coeur de l'agent C2. Il re\u00e7oit des commandes du serveur (JSON/text), les parse, les route vers le bon handler, ex\u00e9cute, et retourne le r\u00e9sultat.

**Analogie** : Un dispatcher est comme un standard t\u00e9l\u00e9phonique. Il re\u00e7oit un appel (commande), regarde le num\u00e9ro (type), et transfert au bon service (handler).

## Architecture

```
[Serveur C2]
     |
     | JSON: {"cmd":"shell","args":"whoami"}
     v
[Agent - Receive]
     |
     v
[Command Dispatcher]
     |
     +---> [Parse JSON]
     |
     +---> [Route to Handler]
     |         |
     |         +---> shell_handler()
     |         +---> download_handler()
     |         +---> screenshot_handler()
     |         +---> ...
     |
     +---> [Execute & Capture Output]
     |
     +---> [Return Result]
     |
     v
[Send to C2]
```

## Code - Dispatcher Simple

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "cJSON.h"

// Handlers de commandes
void HandleShell(const char* args) {
    printf("[*] Executing shell: %s\n", args);
    system(args);  // Simplifié (voir W58 pour capture output)
}

void HandleSleep(int duration) {
    printf("[*] Sleeping for %d seconds\n", duration);
    Sleep(duration * 1000);
}

void HandleExit() {
    printf("[*] Exiting agent\n");
    ExitProcess(0);
}

void HandleDownload(const char* filepath) {
    printf("[*] Downloading file: %s\n", filepath);
    // Impl\u00e9mentation dans W59
}

// Dispatcher principal
BOOL DispatchCommand(const char* jsonCommand) {
    cJSON* root = cJSON_Parse(jsonCommand);
    if (!root) {
        printf("[-] Invalid JSON\n");
        return FALSE;
    }

    cJSON* cmdObj = cJSON_GetObjectItem(root, "cmd");
    if (!cJSON_IsString(cmdObj)) {
        cJSON_Delete(root);
        return FALSE;
    }

    const char* cmd = cmdObj->valuestring;
    printf("[+] Command received: %s\n", cmd);

    // Router vers le handler appropri\u00e9
    if (strcmp(cmd, "shell") == 0) {
        cJSON* args = cJSON_GetObjectItem(root, "args");
        if (cJSON_IsString(args)) {
            HandleShell(args->valuestring);
        }
    }
    else if (strcmp(cmd, "sleep") == 0) {
        cJSON* duration = cJSON_GetObjectItem(root, "duration");
        if (cJSON_IsNumber(duration)) {
            HandleSleep(duration->valueint);
        }
    }
    else if (strcmp(cmd, "download") == 0) {
        cJSON* filepath = cJSON_GetObjectItem(root, "file");
        if (cJSON_IsString(filepath)) {
            HandleDownload(filepath->valuestring);
        }
    }
    else if (strcmp(cmd, "exit") == 0) {
        cJSON_Delete(root);
        HandleExit();
    }
    else {
        printf("[-] Unknown command: %s\n", cmd);
    }

    cJSON_Delete(root);
    return TRUE;
}

int main() {
    // Simuler r\u00e9ception de commandes
    const char* commands[] = {
        "{\"cmd\":\"shell\",\"args\":\"whoami\"}",
        "{\"cmd\":\"sleep\",\"duration\":5}",
        "{\"cmd\":\"download\",\"file\":\"C:\\\\\\\\file.txt\"}",
        "{\"cmd\":\"exit\"}"
    };

    for (int i = 0; i < 4; i++) {
        printf("\n--- Dispatching command %d ---\n", i+1);
        DispatchCommand(commands[i]);
        Sleep(1000);
    }

    return 0;
}
```

## Dispatcher avec Table de Handlers

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

// D\u00e9finir type de handler
typedef void (*CommandHandler)(const char* args);

// Structure command mapping
typedef struct {
    const char* cmdName;
    CommandHandler handler;
} CommandMapping;

// Handlers
void cmd_shell(const char* args) {
    printf("[Shell] %s\n", args);
    system(args);
}

void cmd_pwd(const char* args) {
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    printf("[PWD] %s\n", cwd);
}

void cmd_whoami(const char* args) {
    char username[256];
    DWORD size = sizeof(username);
    GetUserNameA(username, &size);
    printf("[Whoami] %s\n", username);
}

// Table de dispatch
CommandMapping commandTable[] = {
    {"shell", cmd_shell},
    {"pwd", cmd_pwd},
    {"whoami", cmd_whoami},
    {NULL, NULL}  // Sentinel
};

BOOL DispatchCommandTable(const char* cmdName, const char* args) {
    for (int i = 0; commandTable[i].cmdName != NULL; i++) {
        if (strcmp(cmdName, commandTable[i].cmdName) == 0) {
            commandTable[i].handler(args);
            return TRUE;
        }
    }

    printf("[-] Unknown command: %s\n", cmdName);
    return FALSE;
}

int main() {
    DispatchCommandTable("whoami", NULL);
    DispatchCommandTable("pwd", NULL);
    DispatchCommandTable("shell", "ipconfig");

    return 0;
}
```

## Dispatcher avec R\u00e9sultats

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    BOOL success;
    char result[4096];
} CommandResult;

CommandResult ExecuteCommand(const char* cmd, const char* args) {
    CommandResult res;
    res.success = FALSE;
    memset(res.result, 0, sizeof(res.result));

    if (strcmp(cmd, "hostname") == 0) {
        char hostname[256];
        DWORD size = sizeof(hostname);
        if (GetComputerNameA(hostname, &size)) {
            strcpy(res.result, hostname);
            res.success = TRUE;
        }
    }
    else if (strcmp(cmd, "pid") == 0) {
        sprintf(res.result, "%d", GetCurrentProcessId());
        res.success = TRUE;
    }
    else if (strcmp(cmd, "user") == 0) {
        char username[256];
        DWORD size = sizeof(username);
        if (GetUserNameA(username, &size)) {
            strcpy(res.result, username);
            res.success = TRUE;
        }
    }

    return res;
}

char* CreateResultJSON(const char* cmd, CommandResult* result) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "command", cmd);
    cJSON_AddBoolToObject(root, "success", result->success);
    cJSON_AddStringToObject(root, "output", result->result);

    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return json;  // Caller must cJSON_free()
}

int main() {
    const char* commands[] = {"hostname", "pid", "user"};

    for (int i = 0; i < 3; i++) {
        CommandResult res = ExecuteCommand(commands[i], NULL);
        char* resultJSON = CreateResultJSON(commands[i], &res);

        printf("[Result] %s\n", resultJSON);

        cJSON_free(resultJSON);
    }

    return 0;
}
```

## Gestion d'Erreurs

```c
typedef enum {
    CMD_SUCCESS = 0,
    CMD_ERROR_UNKNOWN = 1,
    CMD_ERROR_PARSE = 2,
    CMD_ERROR_ARGS = 3,
    CMD_ERROR_EXEC = 4
} CommandError;

CommandError SafeDispatch(const char* jsonCmd) {
    cJSON* root = cJSON_Parse(jsonCmd);
    if (!root) return CMD_ERROR_PARSE;

    cJSON* cmd = cJSON_GetObjectItem(root, "cmd");
    if (!cJSON_IsString(cmd)) {
        cJSON_Delete(root);
        return CMD_ERROR_ARGS;
    }

    // Try dispatch
    BOOL found = FALSE;
    for (int i = 0; commandTable[i].cmdName != NULL; i++) {
        if (strcmp(cmd->valuestring, commandTable[i].cmdName) == 0) {
            cJSON* args = cJSON_GetObjectItem(root, "args");
            const char* argsStr = cJSON_IsString(args) ? args->valuestring : NULL;

            __try {
                commandTable[i].handler(argsStr);
                found = TRUE;
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                cJSON_Delete(root);
                return CMD_ERROR_EXEC;
            }
            break;
        }
    }

    cJSON_Delete(root);
    return found ? CMD_SUCCESS : CMD_ERROR_UNKNOWN;
}
```

## OPSEC

```
[Best Practices]
\u2713 Valider toutes les entr\u00e9es (JSON parsing)
\u2713 Timeout sur les commandes longues
\u2713 Capturer exceptions (SEH)
\u2713 Logger les erreurs localement
\u2713 Retourner r\u00e9sultats structur\u00e9s (JSON)

[S\u00e9curit\u00e9]
\u2717 Jamais ex\u00e9cuter commandes sans validation
\u2717 Limiter commandes autoris\u00e9es (whitelist)
\u2717 Éviter buffer overflows (strcpy \u2192 strncpy)
```

## R\u00e9sum\u00e9

- **Dispatcher** : Coeur de l'agent, route commandes vers handlers
- **Architecture** : Parse \u2192 Route \u2192 Execute \u2192 Return
- **Impl\u00e9mentation** : Table de handlers (function pointers)
- **R\u00e9sultats** : JSON structur\u00e9 avec success/output
- **Erreurs** : Validation, exceptions (SEH), error codes
- **OPSEC** : Toujours valider inputs, timeout, logs

## Ressources

- [Command & Control Patterns](https://attack.mitre.org/tactics/TA0011/)
- [Cobalt Strike Beacon Commands](https://www.cobaltstrike.com/help-beacon)

---

**Navigation**
- [Pr\u00e9c\u00e9dent](../W56_staged_vs_stageless/)
- [Suivant](../W58_output_capture/)

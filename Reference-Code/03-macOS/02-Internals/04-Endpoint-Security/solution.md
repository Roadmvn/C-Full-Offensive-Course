# SOLUTION : Endpoint Security Framework

## Exercice 1 : Vérifier la présence du framework

```bash
# Vérifier si Endpoint Security est disponible
ls -l /System/Library/Frameworks/EndpointSecurity.framework/
```

**Sortie attendue** :
```
drwxr-xr-x  EndpointSecurity.framework
```

---

## Exercice 2 : Client ES basique (requires TCC Full Disk Access)

```c
// es_client.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <dispatch/dispatch.h>

void event_handler(es_client_t *client, const es_message_t *message) {
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
        printf("[ES] Process exec: %s\n",
               message->event.exec.target->executable->path.data);
    }
}

int main() {
    es_client_t *client = NULL;

    // Créer client ES
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        event_handler(c, msg);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        printf("[-] Failed to create ES client: %d\n", result);
        printf("[-] Need TCC Full Disk Access permission!\n");
        return 1;
    }

    printf("[+] ES client created successfully\n");

    // Subscribe aux events exec
    es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
    if (es_subscribe(client, events, 1) != ES_RETURN_SUCCESS) {
        printf("[-] Failed to subscribe\n");
        es_delete_client(client);
        return 1;
    }

    printf("[+] Subscribed to EXEC events. Monitoring...\n");

    // Run loop
    dispatch_main();

    return 0;
}
```

**Compilation** :
```bash
# Nécessite entitlements pour ES
clang es_client.c -o es_client \
    -framework EndpointSecurity \
    -framework Foundation \
    --codesign - \
    --entitlements es.entitlements
```

**es.entitlements** :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
</dict>
</plist>
```

**TCC Permission** :
```bash
# Ajouter Full Disk Access dans :
# System Preferences > Security & Privacy > Privacy > Full Disk Access
# Puis ajouter le terminal ou l'app
```

---

## Exercice 3 : Monitor file access

```c
// file_monitor.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <dispatch/dispatch.h>

void handle_event(es_client_t *client, const es_message_t *msg) {
    switch (msg->event_type) {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            printf("[OPEN] %s opened: %s\n",
                   msg->process->executable->path.data,
                   msg->event.open.file->path.data);
            break;

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            printf("[WRITE] %s wrote to: %s\n",
                   msg->process->executable->path.data,
                   msg->event.write.target->path.data);
            break;

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            printf("[DELETE] %s deleted: %s\n",
                   msg->process->executable->path.data,
                   msg->event.unlink.target->path.data);
            break;
    }
}

int main() {
    es_client_t *client = NULL;

    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        handle_event(c, msg);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        printf("[-] Failed to create client\n");
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_UNLINK
    };

    if (es_subscribe(client, events, 3) != ES_RETURN_SUCCESS) {
        printf("[-] Subscribe failed\n");
        es_delete_client(client);
        return 1;
    }

    printf("[+] Monitoring file operations...\n");
    dispatch_main();

    return 0;
}
```

---

## Exercice 4 : Process tree monitoring (RED TEAM)

```c
// process_monitor.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <dispatch/dispatch.h>

typedef struct {
    pid_t pid;
    char name[256];
    char path[1024];
} process_info_t;

void log_process_tree(const es_process_t *proc, int depth) {
    for (int i = 0; i < depth; i++) printf("  ");
    printf("└─ [%d] %s\n",
           audit_token_to_pid(proc->audit_token),
           proc->executable->path.data);

    if (proc->parent) {
        log_process_tree(proc->parent, depth + 1);
    }
}

void handle_exec(es_client_t *client, const es_message_t *msg) {
    const es_event_exec_t *exec = &msg->event.exec;

    printf("\n[EXEC] New process:\n");
    printf("  PID: %d\n", audit_token_to_pid(msg->process->audit_token));
    printf("  Path: %s\n", exec->target->executable->path.data);
    printf("  PPID: %d\n", audit_token_to_pid(msg->process->parent->audit_token));

    // Arguments
    if (exec->args.count > 0) {
        printf("  Args:\n");
        for (uint32_t i = 0; i < exec->args.count; i++) {
            printf("    [%d] %s\n", i, exec->args.data[i].data);
        }
    }

    // Environment (Red Team interest: API keys, tokens, etc.)
    if (exec->env.count > 0) {
        printf("  Env (Red Team relevant):\n");
        for (uint32_t i = 0; i < exec->env.count; i++) {
            const char *env = exec->env.data[i].data;
            // Filter only interesting vars
            if (strstr(env, "KEY") || strstr(env, "TOKEN") ||
                strstr(env, "SECRET") || strstr(env, "PASSWORD")) {
                printf("    %s\n", env);
            }
        }
    }

    // Process tree
    printf("  Process tree:\n");
    log_process_tree(msg->process, 2);
}

int main() {
    es_client_t *client = NULL;

    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        if (msg->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
            handle_exec(c, msg);
        }
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        printf("[-] Failed to create ES client\n");
        return 1;
    }

    es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC };
    es_subscribe(client, events, 1);

    printf("[+] Monitoring process execution (Red Team mode)...\n");
    printf("[+] Looking for credentials in environment variables...\n\n");

    dispatch_main();
    return 0;
}
```

**Compilation** :
```bash
clang process_monitor.c -o process_monitor \
    -framework EndpointSecurity \
    -framework Foundation \
    -framework Security
```

---

## Exercice 5 : AUTH events (block malicious processes)

```c
// auth_client.c
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <string.h>

const char *blacklist[] = {
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/python",
    NULL
};

bool is_blacklisted(const char *path) {
    for (int i = 0; blacklist[i] != NULL; i++) {
        if (strcmp(path, blacklist[i]) == 0) {
            return true;
        }
    }
    return false;
}

void handle_auth_exec(es_client_t *client, const es_message_t *msg) {
    const char *path = msg->event.exec.target->executable->path.data;

    if (is_blacklisted(path)) {
        printf("[-] BLOCKED: %s (PID %d)\n",
               path,
               audit_token_to_pid(msg->process->audit_token));

        // DENY execution
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
    } else {
        // ALLOW
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
    }
}

int main() {
    es_client_t *client = NULL;

    // AUTH events require special entitlements
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        if (msg->action_type == ES_ACTION_TYPE_AUTH) {
            handle_auth_exec(c, msg);
        }
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        printf("[-] Failed. Need system extension!\n");
        return 1;
    }

    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    es_subscribe(client, events, 1);

    printf("[+] AUTH mode: Blocking blacklisted processes\n");
    dispatch_main();

    return 0;
}
```

**Note** : AUTH events nécessitent un System Extension (pas possible avec simple app).

---

## RED TEAM : Detection evasion

**Détecter Endpoint Security clients** :

```c
// detect_es.c
#include <stdio.h>
#include <sys/sysctl.h>
#include <libproc.h>

void detect_es_clients() {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    struct kinfo_proc *procs = NULL;
    size_t size;

    sysctl(mib, 4, NULL, &size, NULL, 0);
    procs = malloc(size);
    sysctl(mib, 4, procs, &size, NULL, 0);

    int count = size / sizeof(struct kinfo_proc);

    printf("[*] Searching for ES clients...\n");

    for (int i = 0; i < count; i++) {
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        proc_pidpath(procs[i].kp_proc.p_pid, pathbuf, sizeof(pathbuf));

        // Check if process has ES entitlements (crude check)
        if (strstr(pathbuf, "SecurityAgent") ||
            strstr(pathbuf, "endpointsecurity") ||
            strstr(pathbuf, "edr")) {
            printf("[!] Potential ES client: %s (PID %d)\n",
                   pathbuf, procs[i].kp_proc.p_pid);
        }
    }

    free(procs);
}

int main() {
    detect_es_clients();
    return 0;
}
```

---

## Resources

- [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [ES Event Reference](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t)
- [EDR Evasion Techniques](https://posts.specterops.io/edr-evasion-techniques-macos-d0e0d3e0b3a0)

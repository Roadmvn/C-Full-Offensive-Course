/*
 * OBJECTIF  : Parsing JSON minimal en C pour protocole C2
 * PREREQUIS : Strings C, HTTP Client
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Les C2 utilisent JSON pour structurer les commandes/reponses.
 * Ce module implemente un parser minimal sans dependance externe.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* Extraire une valeur string par cle */
int json_get_string(const char* json, const char* key, char* out, int out_size) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char* pos = strstr(json, pattern);
    if (!pos) return 0;
    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;
    if (*pos != '"') return 0;
    pos++;
    int i = 0;
    while (*pos && *pos != '"' && i < out_size - 1) {
        if (*pos == '\\' && *(pos+1)) pos++;
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return 1;
}

int json_get_int(const char* json, const char* key, int* out) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char* pos = strstr(json, pattern);
    if (!pos) return 0;
    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;
    *out = atoi(pos);
    return 1;
}

void demo_parse_command(void) {
    printf("[1] Parser une commande C2\n\n");
    const char* json = "{\"id\":42,\"cmd\":\"shell\",\"args\":\"whoami\",\"timeout\":30}";
    printf("    JSON: %s\n\n", json);

    char cmd[64] = {0}, args[256] = {0};
    int id = 0, timeout = 0;
    json_get_string(json, "cmd", cmd, sizeof(cmd));
    json_get_string(json, "args", args, sizeof(args));
    json_get_int(json, "id", &id);
    json_get_int(json, "timeout", &timeout);

    printf("    id=%d cmd=%s args=%s timeout=%d\n\n", id, cmd, args, timeout);
}

void demo_build_checkin(void) {
    printf("[2] Construire un check-in JSON\n\n");
    char host[256] = {0}, user[256] = {0};
    DWORD sz = sizeof(host);
    GetComputerNameA(host, &sz);
    sz = sizeof(user);
    GetUserNameA(user, &sz);

    char json[512];
    snprintf(json, sizeof(json),
             "{\"type\":\"checkin\",\"host\":\"%s\",\"user\":\"%s\",\"pid\":%lu}",
             host, user, GetCurrentProcessId());
    printf("    %s\n\n", json);
}

int main(void) {
    printf("[*] Demo : JSON Parsing pour C2\n");
    printf("[*] ==========================================\n\n");
    demo_parse_command();
    demo_build_checkin();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

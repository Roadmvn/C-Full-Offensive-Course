/*
 * OBJECTIF  : Gestion des sessions agent (heartbeat, reconnexion, etat)
 * PREREQUIS : HTTP Client, Structures C
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Un agent C2 doit gerer sa session : ID unique, heartbeat regulier,
 * reconnexion en cas de perte, et persistance de l'etat entre les check-ins.
 */

#include <windows.h>
#include <stdio.h>
#include <time.h>

/* Structure de session agent */
typedef struct {
    char session_id[64];
    char hostname[256];
    char username[256];
    DWORD pid;
    DWORD ppid;
    time_t first_checkin;
    time_t last_checkin;
    int checkin_count;
    int missed_checkins;
    int max_retries;
    DWORD sleep_ms;
    int alive;
} AgentSession;

/* Generer un ID de session pseudo-unique */
void generate_session_id(char* out, int size) {
    srand((unsigned)(GetTickCount() ^ GetCurrentProcessId()));
    const char hex[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 32 && i < size - 1; i++)
        out[i] = hex[rand() % 16];
    out[i] = '\0';
}

void demo_session_init(AgentSession* session) {
    printf("[1] Initialisation de la session agent\n\n");

    /* Generer l'ID */
    generate_session_id(session->session_id, sizeof(session->session_id));

    /* Collecter les infos systeme */
    DWORD sz = sizeof(session->hostname);
    GetComputerNameA(session->hostname, &sz);
    sz = sizeof(session->username);
    GetUserNameA(session->username, &sz);
    session->pid = GetCurrentProcessId();
    session->first_checkin = time(NULL);
    session->last_checkin = session->first_checkin;
    session->checkin_count = 0;
    session->missed_checkins = 0;
    session->max_retries = 5;
    session->sleep_ms = 5000;
    session->alive = 1;

    /* PPID via NtQueryInformationProcess serait ideal,
       ici on simule */
    session->ppid = 0;

    printf("    [+] Session ID  : %s\n", session->session_id);
    printf("    [+] Hostname    : %s\n", session->hostname);
    printf("    [+] Username    : %s\n", session->username);
    printf("    [+] PID         : %lu\n", session->pid);
    printf("    [+] Sleep       : %lu ms\n", session->sleep_ms);
    printf("    [+] Max retries : %d\n\n", session->max_retries);
}

void demo_heartbeat(AgentSession* session) {
    printf("[2] Simulation de heartbeat\n\n");

    /* Simuler 5 check-ins */
    int i;
    for (i = 0; i < 5; i++) {
        session->checkin_count++;
        session->last_checkin = time(NULL);

        /* Simuler succes/echec */
        int success = (i != 2); /* echec au 3e essai */
        if (success) {
            session->missed_checkins = 0;
            printf("    [+] Check-in #%d OK (total: %d)\n",
                   i + 1, session->checkin_count);
        } else {
            session->missed_checkins++;
            printf("    [-] Check-in #%d ECHOUE (missed: %d/%d)\n",
                   i + 1, session->missed_checkins, session->max_retries);
        }

        /* Verifier si on doit se deconnecter */
        if (session->missed_checkins >= session->max_retries) {
            printf("    [!] Max retries atteint -> kill switch\n");
            session->alive = 0;
            break;
        }
    }
    printf("\n");
}

void demo_reconnection(void) {
    printf("[3] Strategies de reconnexion\n\n");
    printf("    Backoff exponentiel :\n");
    printf("    tentative 1 : sleep 5s\n");
    printf("    tentative 2 : sleep 10s\n");
    printf("    tentative 3 : sleep 20s\n");
    printf("    tentative 4 : sleep 40s\n");
    printf("    tentative 5 : kill switch\n\n");

    /* Demo du calcul backoff */
    DWORD base_sleep = 5000;
    int i;
    for (i = 0; i < 5; i++) {
        DWORD backoff = base_sleep * (1 << i); /* 2^i */
        printf("    Retry %d : %lu ms\n", i + 1, backoff);
    }
    printf("\n");

    printf("    Autres strategies :\n");
    printf("    - Fallback sur DNS C2 si HTTPS echoue\n");
    printf("    - Rotation de domaines C2 (DGA ou liste)\n");
    printf("    - Changement de protocole (HTTP -> SMB -> DNS)\n\n");
}

void demo_session_state(AgentSession* session) {
    printf("[4] Etat de la session\n\n");

    /* Format du check-in JSON */
    char json[1024];
    snprintf(json, sizeof(json),
        "{\n"
        "  \"session_id\": \"%s\",\n"
        "  \"host\": \"%s\",\n"
        "  \"user\": \"%s\",\n"
        "  \"pid\": %lu,\n"
        "  \"checkins\": %d,\n"
        "  \"sleep_ms\": %lu,\n"
        "  \"alive\": %s\n"
        "}",
        session->session_id, session->hostname,
        session->username, session->pid,
        session->checkin_count, session->sleep_ms,
        session->alive ? "true" : "false");

    printf("    %s\n\n", json);

    printf("    Le serveur C2 peut modifier dynamiquement :\n");
    printf("    - sleep_ms  : changer l'intervalle de callback\n");
    printf("    - alive     : kill switch a distance\n");
    printf("    - protocol  : basculer HTTP/DNS/SMB\n");
    printf("    - tasks     : ajouter des commandes a executer\n\n");
}

int main(void) {
    printf("[*] Demo : Session Management C2\n");
    printf("[*] ==========================================\n\n");
    AgentSession session = {0};
    demo_session_init(&session);
    demo_heartbeat(&session);
    demo_reconnection();
    demo_session_state(&session);
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

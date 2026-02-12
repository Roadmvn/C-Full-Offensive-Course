/*
 * OBJECTIF  : Comprendre l'obfuscation pendant le sleep (Ekko, Foliage, chiffrement memoire)
 * PREREQUIS : VirtualProtect, timers Windows, chiffrement XOR
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Quand un implant dort (Sleep), son shellcode reste en memoire en clair.
 * Les scanners memoire EDR peuvent le detecter pendant cette periode.
 *
 * L'obfuscation de sleep consiste a :
 * 1. Chiffrer la memoire du payload avant de dormir
 * 2. Changer la protection en RW (non executable)
 * 3. Dormir
 * 4. Restaurer la protection RX et dechiffrer
 *
 * Techniques : Ekko (timer-based), Foliage (APC-based), custom XOR sleep
 */

#include <windows.h>
#include <stdio.h>

/* Shellcode demo : NOP sled + RET (inoffensif) */
unsigned char demo_payload[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xC3 /* RET */
};

/* Chiffrement/dechiffrement XOR simple */
void xor_memory(BYTE* data, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++)
        data[i] ^= key;
}

/* Chiffrement XOR multi-octets (plus robuste) */
void xor_memory_multi(BYTE* data, SIZE_T size, BYTE* key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < size; i++)
        data[i] ^= key[i % key_len];
}

/* Demo 1 : Sleep obfuscation basique avec XOR */
void demo_basic_sleep_obfuscation(void) {
    printf("[1] Sleep Obfuscation basique (XOR + VirtualProtect)\n\n");

    /* Allouer et copier le payload */
    SIZE_T payload_size = sizeof(demo_payload);
    BYTE* payload = (BYTE*)VirtualAlloc(NULL, payload_size,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (!payload) {
        printf("    [-] VirtualAlloc echoue\n");
        return;
    }
    memcpy(payload, demo_payload, payload_size);

    /* Rendre executable */
    DWORD old;
    VirtualProtect(payload, payload_size, PAGE_EXECUTE_READ, &old);
    printf("    [+] Payload alloue @ %p (RX)\n", payload);

    /* Executer le payload (prouve qu'il fonctionne) */
    printf("    [+] Execution du payload... ");
    ((void(*)(void))payload)();
    printf("OK\n\n");

    /* Afficher l'etat avant chiffrement */
    printf("    [Avant sleep] Bytes: ");
    for (int i = 0; i < 8; i++) printf("%02X ", payload[i]);
    printf("  (en clair, detectable!)\n");

    /* === Phase de sleep === */
    BYTE xor_key = 0x5A;
    printf("\n    [Sleep] Chiffrement et changement de protection...\n");

    /* Etape 1 : Changer en RW pour pouvoir modifier */
    VirtualProtect(payload, payload_size, PAGE_READWRITE, &old);
    printf("    [+] Protection : RX -> RW\n");

    /* Etape 2 : Chiffrer la memoire */
    xor_memory(payload, payload_size, xor_key);
    printf("    [+] Memoire chiffree (XOR 0x%02X)\n", xor_key);

    printf("    [Pendant sleep] Bytes: ");
    for (int i = 0; i < 8; i++) printf("%02X ", payload[i]);
    printf("  (chiffre, invisible aux scans)\n");

    /* Etape 3 : Dormir */
    printf("    [+] Sleep(1000)...\n");
    Sleep(1000);

    /* === Phase de reveil === */
    printf("\n    [Reveil] Dechiffrement et restauration...\n");

    /* Etape 4 : Dechiffrer */
    xor_memory(payload, payload_size, xor_key);
    printf("    [+] Memoire dechiffree\n");

    /* Etape 5 : Restaurer RX */
    VirtualProtect(payload, payload_size, PAGE_EXECUTE_READ, &old);
    printf("    [+] Protection : RW -> RX\n");

    printf("    [Apres sleep] Bytes: ");
    for (int i = 0; i < 8; i++) printf("%02X ", payload[i]);
    printf("  (restaure)\n");

    /* Re-executer pour prouver que tout fonctionne */
    printf("    [+] Re-execution du payload... ");
    ((void(*)(void))payload)();
    printf("OK\n\n");

    VirtualFree(payload, 0, MEM_RELEASE);
}

/* Demo 2 : Simulation du concept Ekko (timer-based) */
void demo_ekko_concept(void) {
    printf("[2] Concept Ekko : Sleep obfuscation via timers\n\n");

    printf("    Principe de Ekko (Cobalt Strike Sleep Mask) :\n\n");

    printf("    1. Creer un Timer Queue avec CreateTimerQueueTimer\n");
    printf("    2. Le timer callback fait :\n");
    printf("       a. RtlCaptureContext() -> sauver le contexte\n");
    printf("       b. NtContinue(ctx_encrypt) -> chiffre la memoire\n");
    printf("       c. NtContinue(ctx_sleep) -> WaitForSingleObject (dort)\n");
    printf("       d. NtContinue(ctx_decrypt) -> dechiffre la memoire\n");
    printf("       e. NtContinue(ctx_restore) -> restaure l'execution\n\n");

    /* Demo simplifiee avec CreateTimerQueueTimer */
    printf("    [Demo simplifiee avec timer]\n");

    HANDLE hTimer = NULL;
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) {
        printf("    [-] CreateTimerQueue echoue\n");
        return;
    }
    printf("    [+] Timer queue creee : %p\n", hTimerQueue);

    /* Allouer un payload demo */
    BYTE* payload = (BYTE*)VirtualAlloc(NULL, 256,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    memset(payload, 0x90, 255);
    payload[255] = 0xC3;

    printf("    [+] Payload @ %p\n", payload);
    printf("    [*] En reel, Ekko utilise NtContinue pour chainer les operations\n");
    printf("    [*] via le contexte du thread (ROP-like, sans nouveau thread)\n\n");

    /* Simuler le cycle encrypt-sleep-decrypt */
    printf("    [Cycle Ekko simule] :\n");
    printf("    -> SystemFunction032(data, key)  [chiffrement RC4]\n");
    printf("    -> VirtualProtect(RW)            [non-executable]\n");
    printf("    -> WaitForSingleObject(event, timeout)  [sleep]\n");
    printf("    -> VirtualProtect(RX)            [re-executable]\n");
    printf("    -> SystemFunction032(data, key)  [dechiffrement RC4]\n\n");

    VirtualFree(payload, 0, MEM_RELEASE);
    DeleteTimerQueue(hTimerQueue);
}

/* Demo 3 : SystemFunction032 (RC4 natif Windows) */
void demo_systemfunction032(void) {
    printf("[3] SystemFunction032 : Chiffrement RC4 natif\n\n");

    /* Structure USTRING utilisee par SystemFunction032 */
    typedef struct {
        DWORD Length;
        DWORD MaximumLength;
        BYTE* Buffer;
    } USTRING;

    typedef NTSTATUS (WINAPI *pSystemFunction032)(USTRING* data, USTRING* key);

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    pSystemFunction032 SystemFunction032 = NULL;
    if (advapi)
        SystemFunction032 = (pSystemFunction032)GetProcAddress(advapi, "SystemFunction032");

    if (!SystemFunction032) {
        printf("    [-] SystemFunction032 non trouvee\n\n");
        return;
    }
    printf("    [+] SystemFunction032 @ %p\n", SystemFunction032);

    /* Donnees a chiffrer */
    BYTE data[] = "Payload secret en memoire!";
    BYTE key[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    DWORD data_len = sizeof(data) - 1;

    USTRING udata = { data_len, data_len, data };
    USTRING ukey  = { sizeof(key), sizeof(key), key };

    printf("    [Avant]  : %s\n", data);

    /* Chiffrer avec RC4 */
    SystemFunction032(&udata, &ukey);
    printf("    [Chiffre]: ");
    for (DWORD i = 0; i < data_len; i++) printf("%02X ", data[i]);
    printf("\n");

    /* Dechiffrer (RC4 est symetrique, re-appliquer = dechiffrer) */
    SystemFunction032(&udata, &ukey);
    printf("    [Dechiffre]: %s\n\n", data);

    printf("    [*] Ekko/Foliage utilisent SystemFunction032 pour le RC4\n");
    printf("    [*] car c'est une fonction Windows native (pas de crypto suspecte)\n\n");

    if (advapi) FreeLibrary(advapi);
}

/* Demo 4 : Concept Foliage (APC-based) */
void demo_foliage_concept(void) {
    printf("[4] Concept Foliage : Sleep obfuscation via APC\n\n");

    printf("    Foliage utilise NtQueueApcThread au lieu de timers :\n\n");
    printf("    1. NtQueueApcThread(NtWaitForSingleObject)  -> sleep\n");
    printf("    2. NtQueueApcThread(VirtualProtect, RW)     -> rend modifiable\n");
    printf("    3. NtQueueApcThread(SystemFunction032, enc) -> chiffre\n");
    printf("    4. NtSignalAndWaitForSingleObject           -> execute la queue\n");
    printf("    5. Au reveil : dechiffre -> VirtualProtect(RX) -> continue\n\n");

    printf("    Avantage vs Ekko :\n");
    printf("    - Pas de Timer Queue (moins de IOCs)\n");
    printf("    - Utilise les APC du thread courant\n");
    printf("    - Tout se passe dans le contexte du thread existant\n\n");

    printf("    [*] Les deux techniques rendent le payload invisible pendant le sleep\n");
    printf("    [*] car la memoire est chiffree ET non-executable\n\n");
}

/* Demo 5 : Detection des techniques de sleep obfuscation */
void demo_detection(void) {
    printf("[5] Detection du sleep obfuscation\n\n");

    printf("    Indicateurs de sleep obfuscation :\n");
    printf("    - VirtualProtect appels repetitifs (RX -> RW -> RX)\n");
    printf("    - Utilisation de CreateTimerQueueTimer avec callback\n");
    printf("    - NtContinue appels depuis usermode\n");
    printf("    - SystemFunction032 appelee en boucle\n");
    printf("    - Regions memoire qui changent frequemment de protection\n\n");

    printf("    Contre-mesures EDR :\n");
    printf("    - Hook sur VirtualProtect pour logger les changements\n");
    printf("    - Scan memoire pendant les phases de transition\n");
    printf("    - ETW pour les timer callbacks\n");
    printf("    - BeaconEye : detecte les patterns Cobalt Strike en memoire\n");
    printf("    - Hunt-Sleeping-Beacons : scan des threads en wait state\n\n");
}

int main(void) {
    printf("[*] Demo : Sleep Obfuscation - Evasion des scans memoire\n");
    printf("[*] ==========================================\n\n");

    demo_basic_sleep_obfuscation();
    demo_ekko_concept();
    demo_systemfunction032();
    demo_foliage_concept();
    demo_detection();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

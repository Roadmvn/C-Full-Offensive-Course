# Process & Threads - Fondations du Malware Multi-Threading

Création et gestion de processus/threads pour architectures C2, backdoors multi-clients et shellcode execution asynchrone. Les techniques de process spawning et thread injection sont fondamentales pour l'exécution de payloads et la persistance.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Thread worker pour beacon C2
void* beacon_thread(void* arg) {
    while(1) {
        send_heartbeat_to_c2();  // Beacon régulier
        check_for_commands();     // Polling des commandes
        sleep(5);                 // Anti-flood
    }
}

// Fork pour process isolation (Linux)
pid_t pid = fork();
if (pid == 0) {
    // Processus enfant isolé pour payload
    execute_shellcode(payload);
    exit(0);
}
```

## Compilation

**Linux/macOS** :
```bash
gcc example.c -o malware -lpthread -D_GNU_SOURCE
```

**Windows (MinGW)** :
```bash
gcc example.c -o malware.exe -lws2_32
```

**Windows (MSVC)** :
```bash
cl example.c /Fe:malware.exe
```

## Concepts clés

- **fork() vs CreateProcess()** : Création de processus pour isolation et parallélisation de payloads
- **pthread vs CreateThread()** : Multi-threading pour beacons C2 simultanés et opérations asynchrones
- **IPC (pipes, shared memory)** : Communication inter-processus pour exfiltration de données et coordination
- **Thread pools** : Gestion efficace de multiples connexions C2 ou backdoor clients
- **Process detachment** : Détachement du processus parent pour persistance après exploitation initiale
- **Signal handling** : Interception de signaux pour cleanup et anti-crash lors de détection
- **Zombie processes** : Éviter les processus zombies qui révèlent l'activité malveillante

## Techniques utilisées par

- **Cobalt Strike** : Thread pools pour gestion de beacons multiples, process injection pour migration
- **Metasploit** : Fork pour isolation de payloads, meterpreter multi-threaded pour sessions simultanées
- **APT29 (Cozy Bear)** : Multi-threading pour beaconing discret et exfiltration parallèle
- **Emotet** : Process spawning pour modules de propagation et credential harvesting
- **TrickBot** : Thread workers pour banking trojan modules et communication C2

## Détection et Mitigation

**Indicateurs de détection** :
- Création anormale de threads/processus sans légitimité business
- Processus enfants non attendus spawned par applications (ex: Word spawning cmd.exe)
- Threads avec stack suspicieuses (RWX memory regions)
- Process hollowing détectable via memory scanning (MemProcFS)

**Mitigations EDR/AV** :
- Monitoring de CreateProcess/CreateThread via ETW
- Analyse comportementale des process trees anormaux
- Memory scanning pour détecter shellcode dans threads
- Sysmon Event ID 1 (Process Creation) et ID 8 (CreateRemoteThread)

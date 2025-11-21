⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.


### EXERCICES - MODULE 27 : NETWORKING & SOCKETS

[ ] 1. REVERSE SHELL TCP ROBUSTE
Implémenter reverse shell avec features avancées :
- Retry logic avec backoff exponentiel (3s, 6s, 12s...)
- Jitter aléatoire pour éviter détection pattern
- Socket keep-alive pour maintenir connexion
- Redirection I/O complète (stdin/stdout/stderr)
- Support Windows (CreateProcess) et Linux (execve)

Référence : Metasploit reverse_tcp payload, Cobalt Strike beacon

[ ] 2. HTTP/HTTPS C2 BEACON
Communication C2 via HTTP avec malleable profile :
- Beacons périodiques avec jitter (+/- 30%)
- User-Agent rotation (Firefox, Chrome, Edge)
- Headers HTTP légitimes (Accept, Accept-Language, etc.)
- URI paths qui ressemblent à API REST (/api/v1/status)
- Parsing commandes depuis response body (JSON)
- Exfiltration data via POST multipart/form-data

Référence : Cobalt Strike HTTP beacon, Empire C2

[ ] 3. DNS TUNNELING EXFILTRATION
Exfiltration de données via DNS queries :
- Encoder data en base32/base64 pour subdomains
- Découpage en chunks de 63 chars (limite label DNS)
- Séquençage pour reconstruction côté serveur
- Utiliser TXT records pour C2 bidirectionnel
- Rate limiting pour éviter détection (pas plus de 10 req/min)

Référence : Iodine, DNSCat2, APT29 DNS tunneling

[ ] 4. ICMP TUNNELING (COVERT CHANNEL)
Communication via ICMP Echo packets :
- Raw socket IPPROTO_ICMP
- Construction manuelle paquet ICMP
- Injection data dans payload (ping normal = vide)
- Calcul checksum ICMP correct
- Nécessite CAP_NET_RAW (Linux) ou admin (Windows)

Référence : ptunnel, ICMP backdoors APT

[ ] 5. PORT KNOCKING C2
Activation C2 via séquence de ports :
- Écouter séquence spécifique (ex: 7000, 8000, 9000)
- Ouvrir port C2 seulement après knock correct
- Fermer port après timeout (30s)
- Support UDP/TCP pour knock
- Logging des tentatives

Référence : Port knocking technique, covert C2

[ ] 6. DOMAIN FRONTING HTTPS
C2 via CDN fronting pour masquer C2 réel :
- Connexion HTTPS vers domaine légitime (cloudflare.com)
- Header Host: contient vrai C2 (evil.attacker.com)
- CDN route vers C2 basé sur Host header
- Bypass firewall/IPS qui whitelist domaine façade

Référence : Cobalt Strike domain fronting, APT29/APT28

[ ] 7. WEBSOCKET C2 BIDIRECTIONNEL
Communication temps réel via WebSocket :
- Handshake HTTP Upgrade to WebSocket
- Full-duplex communication
- Framing protocol WebSocket correct
- Heartbeat/ping-pong pour keep-alive
- Blend in web traffic (wss:// = HTTPS)

Référence : Modern C2 frameworks (Mythic, Havoc)

[ ] 8. SOCKS5 PROXY TUNNELING
Tunnel réseau complet via SOCKS5 :
- Handshake SOCKS5 protocol
- Support authentication (username/password)
- Proxy TCP connections arbitrary
- Support SOCKS5 CONNECT, BIND, UDP ASSOCIATE
- Utiliser pour pivoter dans réseau interne

Référence : Metasploit socks5 module, Cobalt Strike pivot


### NOTES :
- Tous les C2 doivent avoir retry logic robuste
- Beaconing DOIT avoir jitter aléatoire (éviter patterns)
- User-Agents doivent être légitimes (copier Chrome/Firefox)
- Tester détection avec Wireshark, Zeek/Suricata IDS


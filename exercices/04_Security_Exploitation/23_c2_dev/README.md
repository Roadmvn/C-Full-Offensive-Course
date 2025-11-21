# Module 45 - C2 Development

AVERTISSEMENT LEGAL MAXIMAL : Developpement Command & Control infrastructure est ILLEGAL sans autorisation. Usage malveillant = CRIME FEDERAL. Contenu STRICTEMENT educatif pour red team autorise et blue team defense uniquement.

## Concepts

Command and Control (C2) est infrastructure permettant a un attaquant de communiquer avec systemes compromis (implants/beacons) et d'executer commandes a distance.

### Architecture C2

```
C2 Server (Attacker)
    |
    v
[Communication Channel]
    |
    v
Beacon/Implant (Victim)
```

### Composants Principaux

**C2 Server**: Serveur controle attaquant (listener, tasking, logging)
**Beacon/Implant**: Agent deploye sur systeme cible
**Communication Protocol**: HTTP/HTTPS, DNS, SMB, custom
**Tasking**: Commandes envoyees par attaquant
**Callback**: Implant contacte C2 periodiquement

### Communication Patterns

**Beacon Model**: Implant initie connections periodiques (sleep/jitter)
**Reverse Connection**: Implant se connecte vers C2 (bypass firewall)
**Push Model**: C2 push commandes (necessite listener implant)
**P2P**: Implants communiquent entre eux (resiliency)

### Protocols Communs

**HTTP/HTTPS**: Melange dans trafic web legitime
**DNS**: Tunneling via requetes DNS (stealth)
**SMB Named Pipes**: Communication locale/LAN
**TCP/UDP Custom**: Protocoles proprietaires
**Cloud APIs**: Abuse Dropbox, Google Drive, Twitter, etc.

### Beacon Functionality

**Sleep/Jitter**: Intervalles callback randomises
**Task Queue**: Commandes en attente d'execution
**Output Buffering**: Resultat stocke puis upload
**Process Injection**: Execution memory-only (fileless)
**Persistence**: Survival reboot

### Real-World C2 Frameworks

**Cobalt Strike**: Commercial red team tool
**Metasploit**: Open source, Meterpreter payload
**Empire/Covenant**: PowerShell-based C2
**Sliver**: Modern Go-based C2
**Custom C2**: APT groups developpent proprietaires

### C2 Features Avancees

**Multi-Protocol**: Fallback HTTPS -> DNS -> SMB
**Encryption**: TLS, AES, custom crypto
**Obfuscation**: Traffic patterns ressemblent legitime
**Domain Fronting**: Masquer destination reelle
**Malleable Profiles**: Configuration traffic customisable

## Detection & Mitigation

**Beacon Detection**: Traffic periodique suspect (sleep intervals)
**JA3/JA3S Fingerprinting**: TLS handshake signatures
**DNS Analysis**: Anomalies DNS queries (long subdomains, entropy)
**Network Baselines**: Deviation detection trafic normal

## Compilation

```bash
# AVERTISSEMENT : Exemple educatif uniquement
# C2 reel serait illegal sans autorisation

# Beacon simple
gcc beacon.c -o beacon -lssl -lcrypto

# Listener
gcc listener.c -o listener -lpthread
```

## C2 Traffic Indicators

```
HTTP C2 Indicators:
- Requetes regulieres intervalles fixes
- User-Agent suspects/rares
- POST sans GET prealable
- URLs patterns (base64, hex strings)
- Taille payloads uniformes

DNS C2 Indicators:
- Subdomains longs (data exfiltration)
- High entropy domain names
- Volume queries anormal
- TXT records inhabituels
```

## Limitations

- Detection par EDR/NGFW modernes
- TLS inspection expose payload
- Beaconing patterns detectables
- Sandbox detonation analyse comportement

## References

- Framework: Cobalt Strike documentation
- Research: "C2 Matrix" (comparison frameworks)
- Detection: MITRE ATT&CK T1071 (Application Layer Protocol)
- Blue Team: "Threat Hunting C2" (blogs, whitepapers)

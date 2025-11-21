⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.


### EXERCICES - MODULE 28 : CRYPTOGRAPHIE

[ ] 1. SHELLCODE XOR ENCRYPTER
Implémenter crypter XOR pour shellcode :
- Lire shellcode binaire depuis fichier
- Multi-byte XOR key (4-16 bytes aléatoires)
- Générer stub C avec shellcode chiffré
- Stub inclut decrypt loop + execute
- Output : shellcode.enc.c compilable

Référence : MSFvenom encoder shikata_ga_nai (polymorphic XOR)

[ ] 2. AES-256-CBC PAYLOAD ENCRYPTER
Chiffrer payload PE complet :
- Lire PE file (exe/dll)
- Générer AES-256 key + IV aléatoires (CSPRNG)
- Chiffrer avec OpenSSL EVP_aes_256_cbc
- PKCS7 padding automatique
- Output : payload.enc + key.bin + iv.bin
- Créer loader qui decrypt + execute en mémoire

Référence : Cobalt Strike artifact kit, Veil-Evasion

[ ] 3. RC4 STREAM CIPHER C2 TRAFFIC
Chiffrer communication C2 avec RC4 :
- Implémenter RC4 (KSA + PRGA)
- Chiffrer messages C2 bidirectionnels
- Key exchange via Diffie-Hellman ou RSA
- Packet format : [len(2)|encrypted_data|hmac(32)]
- Compatible avec serveur C2

Référence : Emotot C2 encryption, Zeus malware

[ ] 4. STRING OBFUSCATION COMPILE-TIME
Macro C++ constexpr pour strings :
- #define OBFSTR(s) compile_time_xor(s, __LINE__)
- Utiliser __LINE__ comme seed XOR key
- Déchiffrement automatique runtime
- Tester avec 'strings' command (rien visible)
- Support strings Unicode (wchar_t)

Référence : ADVobfuscator library, obfuscate.h

[ ] 5. PE CRYPTER (FULL BINARY ENCRYPTION)
Chiffrer PE entier sauf headers :
- Parser PE headers (DOS, NT, sections)
- Chiffrer sections .text, .data avec AES
- Ajouter nouvelle section .crypt avec decrypt stub
- Modifier entry point vers decrypt stub
- Stub : decrypt sections + jump OEP (Original Entry Point)

Référence : UPX packer (compression), Themida (protection)

[ ] 6. POLYMORPHIC MALWARE GENERATOR
Générer variant unique à chaque build :
- Shellcode chiffré avec clé aléatoire différente
- Stub decrypt avec instructions junk random
- Reorder instructions (équivalent fonctionnel)
- Variable/function names randomisés
- Signature différente chaque build (éviter AV)

Référence : Metasploit shikata_ga_nai encoder

[ ] 7. RANSOMWARE CRYPTO (ÉDUCATIF VM ISOLÉE)
Architecture ransomware complète :
- Générer paire RSA-2048 (clé privée exfiltrée vers C2)
- Pour chaque fichier : AES-256 key aléatoire
- Chiffrer fichier avec AES-256-CTR
- Chiffrer AES key avec RSA public
- Stocker encrypted AES key dans fichier header
- Ransom note avec victim ID
- Decryptor : RSA private key -> AES keys -> fichiers

Référence : WannaCry, Ryuk, REvil architectures

[ ] 8. PBKDF2 KEY DERIVATION
Dériver clé crypto depuis password :
- Implémenter PBKDF2-HMAC-SHA256
- Iterations élevées (100k+) pour ralentir bruteforce
- Salt aléatoire unique (16 bytes)
- Output clé 256-bit pour AES-256
- Utiliser pour chiffrer payloads avec password

Référence : OpenSSL PKCS5_PBKDF2_HMAC, WinCrypt CryptDeriveKey


### NOTES :
- XOR = rapide mais faible (uniquement obfuscation légère)
- AES-256-CBC = standard robuste (attention IV unique!)
- RC4 = déprécié mais rapide (encore utilisé malwares legacy)
- Polymorphic = clé/stub différent chaque build (éviter signatures)
- Toujours utiliser CSPRNG : CryptGenRandom(), /dev/urandom, BCryptGenRandom()
- Tester évasion AV avec : VirusTotal, Antiscan.me, malware sandboxes


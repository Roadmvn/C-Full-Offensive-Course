/*
 * OBJECTIF  : Comprendre la technique Pass-the-Hash (NTLM, utilisation en C)
 * PREREQUIS : NTLM authentication, tokens, Winsock
 * COMPILE   : cl example.c /Fe:example.exe /link advapi32.lib netapi32.lib
 *
 * Pass-the-Hash (PtH) permet de s'authentifier sur un systeme distant
 * en utilisant le hash NTLM d'un mot de passe, sans connaitre le mot de passe.
 *
 * NTLM Challenge-Response :
 * 1. Client -> Server : NEGOTIATE (je veux m'authentifier)
 * 2. Server -> Client : CHALLENGE (voici un nonce aleatoire)
 * 3. Client -> Server : RESPONSE (hash(nonce + NT_hash))
 * Le hash NT suffit pour calculer la reponse.
 *
 * Ce module explique le protocole et demontre la detection.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/* Structure simplifiee d'un message NTLM */
typedef struct {
    char    signature[8];   /* "NTLMSSP\0" */
    DWORD   msg_type;       /* 1=NEGOTIATE, 2=CHALLENGE, 3=AUTHENTICATE */
} NTLM_HEADER;

/* Demo 1 : Expliquer le protocole NTLM */
void demo_ntlm_protocol(void) {
    printf("[1] Protocole NTLM - Comment fonctionne l'authentification\n\n");

    printf("    NTLM Challenge-Response (simplifie) :\n\n");
    printf("    Client                          Server\n");
    printf("    ------                          ------\n");
    printf("    1. NEGOTIATE_MESSAGE     ->     (type 1)\n");
    printf("       Flags: NTLMSSP_NEGOTIATE\n\n");
    printf("                             <-     2. CHALLENGE_MESSAGE (type 2)\n");
    printf("                                    Server envoie un nonce 8 octets\n\n");
    printf("    3. AUTHENTICATE_MESSAGE  ->     (type 3)\n");
    printf("       NtChallengeResponse = \n");
    printf("         HMAC_MD5(NT_Hash, nonce)\n\n");

    printf("    [!] Le serveur ne voit JAMAIS le mot de passe\n");
    printf("    [!] Il compare la reponse avec son propre calcul\n");
    printf("    [!] Donc : si on a le NT_Hash, on peut calculer la reponse\n");
    printf("    [!] = Pass-the-Hash!\n\n");
}

/* Demo 2 : Montrer comment un hash NTLM est calcule */
void demo_ntlm_hash(void) {
    printf("[2] Calcul du hash NTLM (NT Hash)\n\n");

    printf("    Le NT Hash est simplement MD4(UTF16-LE(password)) :\n\n");
    printf("    Exemple : password = \"P@ssw0rd\"\n");
    printf("    1. UTF-16LE : 50 00 40 00 73 00 73 00 77 00 30 00 72 00 64 00\n");
    printf("    2. MD4(...)  : de26cce0356891a4a020e7c4957afc72\n\n");

    printf("    [*] Le hash est stocke dans la SAM (locale) ou NTDS.dit (AD)\n");
    printf("    [*] Format Mimikatz : user:RID:LM_HASH:NT_HASH:::\n\n");

    /* Demo : convertir un mot de passe en UTF-16LE */
    const char* demo_pass = "Demo123";
    printf("    [Demo] Conversion de \"%s\" en UTF-16LE :\n    ", demo_pass);
    for (int i = 0; demo_pass[i]; i++) {
        printf("%02X 00 ", (unsigned char)demo_pass[i]);
    }
    printf("\n\n");

    printf("    [*] En reel, on utiliserait CryptHashData(CALG_MD4) ou BCrypt\n");
    printf("    [*] pour calculer le hash MD4\n\n");
}

/* Demo 3 : Ou trouver les hashes NTLM */
void demo_hash_sources(void) {
    printf("[3] Sources de hashes NTLM\n\n");

    printf("    A) SAM (Security Account Manager) - hashes locaux :\n");
    printf("       - Fichier : C:\\Windows\\System32\\config\\SAM\n");
    printf("       - Registre : HKLM\\SAM\\SAM\\Domains\\Account\\Users\n");
    printf("       - Outils : Mimikatz (lsadump::sam), reg save\n\n");

    printf("    B) LSASS (Local Security Authority) - hashes en memoire :\n");
    printf("       - Process : lsass.exe\n");
    printf("       - Outils : Mimikatz (sekurlsa::logonpasswords)\n");
    printf("       - Contient hashes, tickets Kerberos, mots de passe WDigest\n\n");

    printf("    C) NTDS.dit - hashes Active Directory :\n");
    printf("       - Fichier : C:\\Windows\\NTDS\\ntds.dit\n");
    printf("       - Outils : secretsdump.py, ntdsutil\n");
    printf("       - Contient TOUS les hashes du domaine\n\n");

    printf("    D) DCSync - extraction a distance :\n");
    printf("       - Simule un DC pour demander les hashes\n");
    printf("       - Necessite : DS-Replication-Get-Changes-All\n");
    printf("       - Outils : Mimikatz (lsadump::dcsync)\n\n");

    /* Verifier la protection SAM locale */
    printf("    [Demo] Verification de la protection SAM :\n");
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                       "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                       0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value, size = sizeof(value);
        if (RegQueryValueExA(hKey, "RunAsPPL", NULL, NULL,
                              (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            printf("    [%s] LSASS PPL : %s\n",
                   value ? "!" : "+",
                   value ? "ACTIVE (protection anti-dump)" : "INACTIVE");
        }
        size = sizeof(value);
        if (RegQueryValueExA(hKey, "LsaCfgFlags", NULL, NULL,
                              (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            printf("    [%s] Credential Guard : %s\n",
                   (value & 1) ? "!" : "+",
                   (value & 1) ? "ACTIVE" : "INACTIVE");
        }
        RegCloseKey(hKey);
    }
    printf("\n");
}

/* Demo 4 : Simulation Pass-the-Hash avec pth (concept) */
void demo_pth_concept(void) {
    printf("[4] Pass-the-Hash : Concept d'exploitation\n\n");

    printf("    Scenario : on a obtenu le hash d'un admin local\n");
    printf("    Hash : aad3b435b51404eeaad3b435b51404ee:de26cce0356891a4a020e7c4957afc72\n\n");

    printf("    Methode 1 : Sekurlsa::pth (Mimikatz)\n");
    printf("    -> mimikatz # sekurlsa::pth /user:admin /domain:. /ntlm:de26cce0...\n");
    printf("    -> Lance cmd.exe avec un token utilisant le hash pour le reseau\n\n");

    printf("    Methode 2 : Impacket (Python)\n");
    printf("    -> psexec.py admin@TARGET -hashes :de26cce0356891a4a020e7c4957afc72\n");
    printf("    -> Se connecte via SMB avec le hash, cree un service, execute\n\n");

    printf("    Methode 3 : API Windows (LogonUser + hash injection)\n");
    printf("    -> Modifier le hash dans LSASS pour le token courant\n");
    printf("    -> Les connexions SMB/WMI utiliseront le nouveau hash\n\n");

    printf("    En C, le PtH passe par :\n");
    printf("    1. Injecter le hash dans LSASS (necessite SYSTEM)\n");
    printf("    2. Ou utiliser un protocole NTLM custom (socket SMB)\n");
    printf("    3. Ou LogonUser avec LOGON32_LOGON_NEW_CREDENTIALS\n\n");
}

/* Demo 5 : Detection du Pass-the-Hash */
void demo_detection(void) {
    printf("[5] Detection du Pass-the-Hash\n\n");

    printf("    Indicateurs :\n");
    printf("    - Event ID 4624 Logon Type 3 (Network) avec NTLM\n");
    printf("    - Event ID 4776 (Credential Validation) echecs multiples\n");
    printf("    - Logon depuis une machine inhabituelle\n");
    printf("    - Utilisation du compte local admin sur plusieurs machines\n");
    printf("    - Mimikatz IOCs dans la memoire de LSASS\n\n");

    printf("    Contre-mesures :\n");
    printf("    - Credential Guard (empeche l'extraction des hashes de LSASS)\n");
    printf("    - LAPS (mots de passe admin locaux uniques par machine)\n");
    printf("    - Disable NTLM (forcer Kerberos)\n");
    printf("    - Protected Users group (pas de cache NTLM)\n");
    printf("    - Network segmentation (limiter les lateral movements)\n");
    printf("    - Admin tiering (comptes admin separes par zone)\n\n");
}

int main(void) {
    printf("[*] Demo : Pass-the-Hash - NTLM et utilisation\n");
    printf("[*] ==========================================\n\n");

    demo_ntlm_protocol();
    demo_ntlm_hash();
    demo_hash_sources();
    demo_pth_concept();
    demo_detection();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

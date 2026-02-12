/*
 * OBJECTIF  : Comprendre l'acces au Keychain macOS
 * PREREQUIS : Bases C, securite macOS, TCC, code signing
 * COMPILE   : clang -o example example.c -framework Security
 *
 * Ce programme demontre le fonctionnement du Keychain macOS :
 * architecture, types d'items, API Security framework,
 * extraction de credentials, et protection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Etape 1 : Architecture du Keychain
 */
static void explain_keychain_architecture(void) {
    printf("[*] Etape 1 : Architecture du Keychain\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Application                              │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ SecItemCopyMatching()              │    │\n");
    printf("    │  │ SecItemAdd()                       │    │\n");
    printf("    │  │ SecItemUpdate()                    │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ securityd (daemon)                │    │\n");
    printf("    │  │ - Verifie les ACL                 │    │\n");
    printf("    │  │ - Verifie la signature             │    │\n");
    printf("    │  │ - Demande le mot de passe          │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ Keychain database (SQLite chiffre) │    │\n");
    printf("    │  │ ~/Library/Keychains/              │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Types de Keychains :\n");
    printf("    ───────────────────────────────────\n");
    printf("    login.keychain-db    : Keychain utilisateur\n");
    printf("    System.keychain      : Keychain systeme\n");
    printf("    iCloud Keychain      : Synchronise via iCloud\n\n");
}

/*
 * Etape 2 : Types d'items du Keychain
 */
static void explain_keychain_items(void) {
    printf("[*] Etape 2 : Types d'items du Keychain\n\n");

    printf("    Types d'items stockes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Type                 | kSecClass             | Contenu\n");
    printf("    ─────────────────────|───────────────────────|──────────────\n");
    printf("    Mot de passe web     | kSecClassInternetPwd  | URL + creds\n");
    printf("    Mot de passe generique| kSecClassGenericPwd  | App + creds\n");
    printf("    Certificat           | kSecClassCertificate  | X.509\n");
    printf("    Cle privee           | kSecClassKey          | RSA/EC key\n");
    printf("    Identite             | kSecClassIdentity     | Cert + cle\n\n");

    printf("    Attributs principaux :\n");
    printf("    ───────────────────────────────────\n");
    printf("    kSecAttrService      : nom du service\n");
    printf("    kSecAttrAccount      : nom du compte\n");
    printf("    kSecAttrServer       : serveur (internet pwd)\n");
    printf("    kSecAttrLabel        : label affiche\n");
    printf("    kSecValueData        : le mot de passe/donnee\n");
    printf("    kSecAttrAccessGroup  : groupe d'acces\n\n");
}

/*
 * Etape 3 : API SecItem (code reference)
 */
static void show_secitem_code(void) {
    printf("[*] Etape 3 : API SecItem (reference)\n\n");

    printf("    #include <Security/Security.h>\n\n");

    printf("    Rechercher un mot de passe :\n");
    printf("    ───────────────────────────────────\n");
    printf("    CFMutableDictionaryRef query =\n");
    printf("        CFDictionaryCreateMutable(NULL, 0,\n");
    printf("            &kCFTypeDictionaryKeyCallBacks,\n");
    printf("            &kCFTypeDictionaryValueCallBacks);\n\n");
    printf("    CFDictionarySetValue(query,\n");
    printf("        kSecClass, kSecClassGenericPassword);\n");
    printf("    CFDictionarySetValue(query,\n");
    printf("        kSecAttrService, CFSTR(\"MyService\"));\n");
    printf("    CFDictionarySetValue(query,\n");
    printf("        kSecReturnData, kCFBooleanTrue);\n");
    printf("    CFDictionarySetValue(query,\n");
    printf("        kSecMatchLimit, kSecMatchLimitOne);\n\n");
    printf("    CFDataRef data = NULL;\n");
    printf("    OSStatus status = SecItemCopyMatching(query,\n");
    printf("        (CFTypeRef *)&data);\n\n");
    printf("    if (status == errSecSuccess && data) {\n");
    printf("        // data contient le mot de passe\n");
    printf("        CFIndex len = CFDataGetLength(data);\n");
    printf("        const UInt8 *bytes = CFDataGetBytePtr(data);\n");
    printf("        printf(\"Password: %%.*s\\n\", (int)len, bytes);\n");
    printf("        CFRelease(data);\n");
    printf("    }\n");
    printf("    CFRelease(query);\n\n");

    printf("    Dumper TOUS les items :\n");
    printf("    ───────────────────────────────────\n");
    printf("    CFDictionarySetValue(query,\n");
    printf("        kSecMatchLimit, kSecMatchLimitAll);\n");
    printf("    CFDictionarySetValue(query,\n");
    printf("        kSecReturnAttributes, kCFBooleanTrue);\n");
    printf("    CFDictionarySetValue(query,\n");
    printf("        kSecReturnData, kCFBooleanTrue);\n");
    printf("    // -> Retourne un CFArrayRef de dictionnaires\n\n");
}

/*
 * Etape 4 : Outils en ligne de commande
 */
static void demo_security_command(void) {
    printf("[*] Etape 4 : Commande security (CLI)\n\n");

    printf("    Commandes utiles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Lister les keychains\n");
    printf("    security list-keychains\n\n");
    printf("    # Chercher un mot de passe\n");
    printf("    security find-generic-password -s \"Service\" -w\n\n");
    printf("    # Chercher un mot de passe internet\n");
    printf("    security find-internet-password -s \"server.com\" -w\n\n");
    printf("    # Dumper les mots de passe (demande auth)\n");
    printf("    security dump-keychain -d login.keychain-db\n\n");

    /* Lister les keychains */
    printf("    Keychains configurees :\n");
    FILE *fp = popen("security list-keychains 2>&1", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    /* Verifier les fichiers keychain */
    printf("    Fichiers Keychain :\n");
    const char *home = getenv("HOME");
    if (home) {
        char path[512];
        struct stat st;

        snprintf(path, sizeof(path),
                 "%s/Library/Keychains/login.keychain-db", home);
        if (stat(path, &st) == 0) {
            printf("      login.keychain-db : %lld octets\n", (long long)st.st_size);
        }

        snprintf(path, sizeof(path),
                 "%s/Library/Keychains/login.keychain", home);
        if (stat(path, &st) == 0) {
            printf("      login.keychain    : %lld octets\n", (long long)st.st_size);
        }
    }
    printf("\n");
}

/*
 * Etape 5 : Techniques d'extraction offensive
 */
static void explain_extraction(void) {
    printf("[*] Etape 5 : Techniques d'extraction\n\n");

    printf("    1. Via security CLI (interactif) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    security find-generic-password -ga \"Chrome\" 2>&1\n");
    printf("    # Declenche un popup d'autorisation\n");
    printf("    # L'utilisateur doit cliquer \"Allow\"\n\n");

    printf("    2. Via SecItemCopyMatching (silencieux si ACL ok) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Si l'app est dans la liste d'acces de l'item\n");
    printf("    # Pas de popup ! Extraction silencieuse\n\n");

    printf("    3. Dechiffrement de la DB directement :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Le keychain est chiffre avec le mot de passe\n");
    printf("    # utilisateur. Si connu, on peut dechiffrer.\n");
    printf("    # Outils : chainbreaker, KeychainCracker\n\n");

    printf("    4. Contourner le popup :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Re-signer avec le meme identifiant\n");
    printf("    # Utiliser un binaire Apple qui a deja acces\n");
    printf("    # Modifier l'ACL de l'item (si possible)\n\n");

    printf("    5. Outils connus :\n");
    printf("    - chainbreaker : dechiffre le keychain offline\n");
    printf("    - keychaindump : dump en memoire\n");
    printf("    - security CLI : outil Apple natif\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Protections du Keychain :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - ACL par item (quelle app peut lire)\n");
    printf("    - Popup d'autorisation utilisateur\n");
    printf("    - Chiffrement AES-256 de la base\n");
    printf("    - Verrouillage automatique apres inactivite\n");
    printf("    - Code signing verification de l'appelant\n\n");

    printf("    Detection des acces suspects :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Logs Unified Logging\n");
    printf("    log show --predicate 'subsystem == \"com.apple.securityd\"'\n\n");
    printf("    # Endpoint Security events\n");
    printf("    ES_EVENT_TYPE_NOTIFY_OPEN sur les fichiers keychain\n\n");
    printf("    # Process monitoring\n");
    printf("    Surveiller les appels a SecItemCopyMatching\n\n");

    printf("    Bonnes pratiques :\n");
    printf("    - Verrouiller le keychain automatiquement\n");
    printf("    - Utiliser des ACL restrictives\n");
    printf("    - Refuser les acces non reconnus\n");
    printf("    - Surveiller les tentatives d'acces\n");
    printf("    - Utiliser iCloud Keychain (protection suppl.)\n\n");
}

int main(void) {
    printf("[*] Demo : Keychain Access macOS\n\n");

    explain_keychain_architecture();
    explain_keychain_items();
    show_secitem_code();
    demo_security_command();
    explain_extraction();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}

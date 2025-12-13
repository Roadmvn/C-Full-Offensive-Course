/*
 * ═══════════════════════════════════════════════════════════════════
 * Module 35 : Registry Manipulation - Manipulation du Registre Windows
 * ═══════════════════════════════════════════════════════════════════
 *
 * ⚠️  AVERTISSEMENT LÉGAL ET TECHNIQUE STRICT ⚠️
 *
 * Ce code manipule le registre Windows, base de données système critique.
 * Des modifications incorrectes peuvent CORROMPRE votre système et le
 * rendre INUTILISABLE.
 *
 * PRÉCAUTIONS OBLIGATOIRES :
 * - Créer un backup complet du registre AVANT toute exécution
 * - Utiliser UNIQUEMENT dans une VM de test isolée
 * - Créer un snapshot de la VM avant exécution
 * - NE JAMAIS exécuter sur un système de production
 *
 * UTILISATIONS LÉGALES UNIQUEMENT :
 * - Environnement de test avec backup
 * - Apprentissage sur VM dédiée
 * - Développement d'outils légitimes
 *
 * L'auteur décline toute responsabilité pour corruption système,
 * perte de données ou usage illégal.
 * ═══════════════════════════════════════════════════════════════════
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEPARATEUR "═══════════════════════════════════════════════════════════════════\n"
#define TEST_KEY_PATH "Software\\TestRegistryManipulation"
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

// ═══════════════════════════════════════════════════════════════════
// Prototypes de fonctions
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre);
void afficher_erreur_registre(LONG erreur, const char *operation);
void demonstrer_creation_cle();
void demonstrer_ecriture_valeurs();
void demonstrer_lecture_valeurs();
void demonstrer_enumeration_cles();
void demonstrer_suppression();
void demonstrer_persistence();
BOOL verifier_backup_registre();

// ═══════════════════════════════════════════════════════════════════
// Fonction : Afficher un titre formaté
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre) {
    printf("\n");
    printf(SEPARATEUR);
    printf("  %s\n", titre);
    printf(SEPARATEUR);
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Afficher les erreurs du registre de manière lisible
// ═══════════════════════════════════════════════════════════════════

void afficher_erreur_registre(LONG erreur, const char *operation) {
    char *message;

    switch (erreur) {
        case ERROR_SUCCESS:
            return;  // Pas d'erreur
        case ERROR_FILE_NOT_FOUND:
            message = "Clé ou valeur non trouvée";
            break;
        case ERROR_ACCESS_DENIED:
            message = "Accès refusé (droits insuffisants)";
            break;
        case ERROR_INVALID_HANDLE:
            message = "Handle invalide";
            break;
        case ERROR_MORE_DATA:
            message = "Buffer trop petit";
            break;
        default:
            message = "Erreur inconnue";
            break;
    }

    printf("[-] Erreur lors de %s : %s (code %ld)\n", operation, message, erreur);
}

// ═══════════════════════════════════════════════════════════════════
// Fonction : Vérifier la présence d'un backup du registre
// ═══════════════════════════════════════════════════════════════════

BOOL verifier_backup_registre() {
    printf("\n⚠️  VÉRIFICATION DE SÉCURITÉ ⚠️\n\n");
    printf("AVEZ-VOUS CRÉÉ UN BACKUP DU REGISTRE ?\n\n");
    printf("Pour créer un backup, exécutez dans cmd.exe :\n");
    printf("  reg export HKCU backup_hkcu.reg\n");
    printf("  reg export HKLM backup_hklm.reg\n\n");
    printf("Avez-vous un backup ? (o/n) : ");

    char reponse = getchar();
    while (getchar() != '\n');  // Vider le buffer

    if (reponse != 'o' && reponse != 'O') {
        printf("\n❌ EXÉCUTION ANNULÉE\n");
        printf("Créez d'abord un backup du registre.\n");
        return FALSE;
    }

    printf("\n✅ Backup confirmé - Continuation...\n");
    return TRUE;
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 1 : Création de clés
// ═══════════════════════════════════════════════════════════════════

void demonstrer_creation_cle() {
    afficher_titre("DÉMONSTRATION 1 : Création de clés");

    HKEY hKey;
    DWORD dwDisposition;
    LONG result;

    printf("\n[*] Création d'une clé de test dans HKCU\\%s\n", TEST_KEY_PATH);

    result = RegCreateKeyEx(
        HKEY_CURRENT_USER,          // Clé racine
        TEST_KEY_PATH,               // Chemin de la sous-clé
        0,                           // Réservé
        NULL,                        // Classe
        REG_OPTION_NON_VOLATILE,     // Options (persistant)
        KEY_ALL_ACCESS,              // Droits d'accès
        NULL,                        // Sécurité
        &hKey,                       // Handle résultant
        &dwDisposition               // Disposition
    );

    if (result != ERROR_SUCCESS) {
        afficher_erreur_registre(result, "RegCreateKeyEx");
        return;
    }

    if (dwDisposition == REG_CREATED_NEW_KEY) {
        printf("[+] Nouvelle clé créée avec succès\n");
    } else if (dwDisposition == REG_OPENED_EXISTING_KEY) {
        printf("[+] Clé existante ouverte\n");
    }

    // Créer des sous-clés
    HKEY hSubKey;
    const char *sousClés[] = {"SubKey1", "SubKey2", "SubKey3"};

    for (int i = 0; i < 3; i++) {
        result = RegCreateKeyEx(
            hKey,
            sousClés[i],
            0, NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            NULL,
            &hSubKey,
            &dwDisposition
        );

        if (result == ERROR_SUCCESS) {
            printf("[+] Sous-clé créée : %s\n", sousClés[i]);
            RegCloseKey(hSubKey);
        } else {
            afficher_erreur_registre(result, "création sous-clé");
        }
    }

    RegCloseKey(hKey);

    printf("\n[+] Vous pouvez vérifier avec regedit.exe :\n");
    printf("    HKEY_CURRENT_USER\\%s\n", TEST_KEY_PATH);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 2 : Écriture de valeurs (tous types)
// ═══════════════════════════════════════════════════════════════════

void demonstrer_ecriture_valeurs() {
    afficher_titre("DÉMONSTRATION 2 : Écriture de valeurs");

    HKEY hKey;
    LONG result;

    // Ouvrir la clé de test
    result = RegOpenKeyEx(HKEY_CURRENT_USER, TEST_KEY_PATH, 0, KEY_ALL_ACCESS, &hKey);
    if (result != ERROR_SUCCESS) {
        afficher_erreur_registre(result, "RegOpenKeyEx");
        printf("[-] Exécutez d'abord la démonstration 1\n");
        return;
    }

    printf("\n[*] Écriture de différents types de valeurs...\n\n");

    // 1. REG_SZ (String)
    const char *stringValue = "Ceci est une chaîne de test";
    result = RegSetValueEx(hKey, "TestString", 0, REG_SZ,
                          (const BYTE*)stringValue, strlen(stringValue) + 1);
    if (result == ERROR_SUCCESS) {
        printf("[+] REG_SZ écrit : TestString = \"%s\"\n", stringValue);
    } else {
        afficher_erreur_registre(result, "écriture REG_SZ");
    }

    // 2. REG_DWORD (32-bit integer)
    DWORD dwordValue = 12345;
    result = RegSetValueEx(hKey, "TestDWORD", 0, REG_DWORD,
                          (const BYTE*)&dwordValue, sizeof(DWORD));
    if (result == ERROR_SUCCESS) {
        printf("[+] REG_DWORD écrit : TestDWORD = %lu\n", dwordValue);
    } else {
        afficher_erreur_registre(result, "écriture REG_DWORD");
    }

    // 3. REG_QWORD (64-bit integer)
    ULONGLONG qwordValue = 9876543210ULL;
    result = RegSetValueEx(hKey, "TestQWORD", 0, REG_QWORD,
                          (const BYTE*)&qwordValue, sizeof(ULONGLONG));
    if (result == ERROR_SUCCESS) {
        printf("[+] REG_QWORD écrit : TestQWORD = %llu\n", qwordValue);
    } else {
        afficher_erreur_registre(result, "écriture REG_QWORD");
    }

    // 4. REG_BINARY (binary data)
    BYTE binaryData[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    result = RegSetValueEx(hKey, "TestBinary", 0, REG_BINARY,
                          binaryData, sizeof(binaryData));
    if (result == ERROR_SUCCESS) {
        printf("[+] REG_BINARY écrit : TestBinary = ");
        for (size_t i = 0; i < sizeof(binaryData); i++) {
            printf("%02X ", binaryData[i]);
        }
        printf("\n");
    } else {
        afficher_erreur_registre(result, "écriture REG_BINARY");
    }

    // 5. REG_MULTI_SZ (multiple strings)
    const char multiString[] = "String1\0String2\0String3\0\0";
    result = RegSetValueEx(hKey, "TestMultiString", 0, REG_MULTI_SZ,
                          (const BYTE*)multiString, sizeof(multiString));
    if (result == ERROR_SUCCESS) {
        printf("[+] REG_MULTI_SZ écrit : TestMultiString = [String1, String2, String3]\n");
    } else {
        afficher_erreur_registre(result, "écriture REG_MULTI_SZ");
    }

    RegCloseKey(hKey);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 3 : Lecture de valeurs
// ═══════════════════════════════════════════════════════════════════

void demonstrer_lecture_valeurs() {
    afficher_titre("DÉMONSTRATION 3 : Lecture de valeurs");

    HKEY hKey;
    LONG result;

    result = RegOpenKeyEx(HKEY_CURRENT_USER, TEST_KEY_PATH, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        afficher_erreur_registre(result, "RegOpenKeyEx");
        return;
    }

    printf("\n[*] Lecture des valeurs précédemment écrites...\n\n");

    // Lire REG_SZ
    char stringBuffer[256];
    DWORD bufferSize = sizeof(stringBuffer);
    DWORD type;

    result = RegQueryValueEx(hKey, "TestString", NULL, &type,
                            (LPBYTE)stringBuffer, &bufferSize);
    if (result == ERROR_SUCCESS && type == REG_SZ) {
        printf("[+] TestString (REG_SZ) = \"%s\"\n", stringBuffer);
    } else {
        afficher_erreur_registre(result, "lecture TestString");
    }

    // Lire REG_DWORD
    DWORD dwordValue;
    bufferSize = sizeof(DWORD);

    result = RegQueryValueEx(hKey, "TestDWORD", NULL, &type,
                            (LPBYTE)&dwordValue, &bufferSize);
    if (result == ERROR_SUCCESS && type == REG_DWORD) {
        printf("[+] TestDWORD (REG_DWORD) = %lu\n", dwordValue);
    } else {
        afficher_erreur_registre(result, "lecture TestDWORD");
    }

    // Lire REG_QWORD
    ULONGLONG qwordValue;
    bufferSize = sizeof(ULONGLONG);

    result = RegQueryValueEx(hKey, "TestQWORD", NULL, &type,
                            (LPBYTE)&qwordValue, &bufferSize);
    if (result == ERROR_SUCCESS && type == REG_QWORD) {
        printf("[+] TestQWORD (REG_QWORD) = %llu\n", qwordValue);
    } else {
        afficher_erreur_registre(result, "lecture TestQWORD");
    }

    // Lire REG_BINARY
    BYTE binaryBuffer[256];
    bufferSize = sizeof(binaryBuffer);

    result = RegQueryValueEx(hKey, "TestBinary", NULL, &type,
                            binaryBuffer, &bufferSize);
    if (result == ERROR_SUCCESS && type == REG_BINARY) {
        printf("[+] TestBinary (REG_BINARY) = ");
        for (DWORD i = 0; i < bufferSize; i++) {
            printf("%02X ", binaryBuffer[i]);
        }
        printf("\n");
    } else {
        afficher_erreur_registre(result, "lecture TestBinary");
    }

    RegCloseKey(hKey);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 4 : Énumération de clés et valeurs
// ═══════════════════════════════════════════════════════════════════

void demonstrer_enumeration_cles() {
    afficher_titre("DÉMONSTRATION 4 : Énumération");

    HKEY hKey;
    LONG result;

    result = RegOpenKeyEx(HKEY_CURRENT_USER, TEST_KEY_PATH, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        afficher_erreur_registre(result, "RegOpenKeyEx");
        return;
    }

    // Énumérer les sous-clés
    printf("\n[*] Énumération des sous-clés :\n");

    char subKeyName[MAX_KEY_LENGTH];
    DWORD index = 0;

    while (1) {
        DWORD nameSize = MAX_KEY_LENGTH;
        result = RegEnumKeyEx(hKey, index, subKeyName, &nameSize,
                             NULL, NULL, NULL, NULL);

        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        } else if (result == ERROR_SUCCESS) {
            printf("    [%lu] %s\n", index, subKeyName);
            index++;
        } else {
            afficher_erreur_registre(result, "énumération sous-clés");
            break;
        }
    }

    if (index == 0) {
        printf("    (aucune sous-clé)\n");
    }

    // Énumérer les valeurs
    printf("\n[*] Énumération des valeurs :\n");

    char valueName[MAX_VALUE_NAME];
    index = 0;

    while (1) {
        DWORD nameSize = MAX_VALUE_NAME;
        DWORD type;
        DWORD dataSize;

        result = RegEnumValue(hKey, index, valueName, &nameSize,
                             NULL, &type, NULL, &dataSize);

        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        } else if (result == ERROR_SUCCESS) {
            const char *typeStr;
            switch (type) {
                case REG_SZ: typeStr = "REG_SZ"; break;
                case REG_DWORD: typeStr = "REG_DWORD"; break;
                case REG_QWORD: typeStr = "REG_QWORD"; break;
                case REG_BINARY: typeStr = "REG_BINARY"; break;
                case REG_MULTI_SZ: typeStr = "REG_MULTI_SZ"; break;
                default: typeStr = "UNKNOWN"; break;
            }

            printf("    [%lu] %-20s (%-15s, %lu bytes)\n",
                   index, valueName, typeStr, dataSize);
            index++;
        } else {
            afficher_erreur_registre(result, "énumération valeurs");
            break;
        }
    }

    if (index == 0) {
        printf("    (aucune valeur)\n");
    }

    RegCloseKey(hKey);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 5 : Suppression
// ═══════════════════════════════════════════════════════════════════

void demonstrer_suppression() {
    afficher_titre("DÉMONSTRATION 5 : Suppression");

    HKEY hKey;
    LONG result;

    result = RegOpenKeyEx(HKEY_CURRENT_USER, TEST_KEY_PATH, 0, KEY_ALL_ACCESS, &hKey);
    if (result != ERROR_SUCCESS) {
        afficher_erreur_registre(result, "RegOpenKeyEx");
        return;
    }

    printf("\n[*] Suppression d'une valeur spécifique...\n");

    result = RegDeleteValue(hKey, "TestString");
    if (result == ERROR_SUCCESS) {
        printf("[+] Valeur 'TestString' supprimée\n");
    } else {
        afficher_erreur_registre(result, "suppression valeur");
    }

    RegCloseKey(hKey);

    printf("\n[*] Suppression de la clé de test complète...\n");
    printf("    HKCU\\%s\n", TEST_KEY_PATH);

    // Supprimer récursivement (Windows Vista+)
    result = RegDeleteTree(HKEY_CURRENT_USER, TEST_KEY_PATH);
    if (result == ERROR_SUCCESS) {
        printf("[+] Clé et toutes ses sous-clés supprimées\n");
    } else {
        afficher_erreur_registre(result, "suppression arborescence");
    }

    printf("\n[+] Nettoyage terminé\n");
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 6 : Persistence (INFORMATION UNIQUEMENT)
// ═══════════════════════════════════════════════════════════════════

void demonstrer_persistence() {
    afficher_titre("DÉMONSTRATION 6 : Persistence (Information)");

    printf("\n⚠️  Cette démonstration est INFORMATIVE UNIQUEMENT\n");
    printf("    Elle N'INSTALLE PAS de persistence réelle\n\n");

    printf("EMPLACEMENTS COMMUNS DE PERSISTENCE :\n\n");

    printf("1. Run Keys (démarrage automatique utilisateur) :\n");
    printf("   HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
    printf("   Type : REG_SZ\n");
    printf("   Valeur : Chemin vers l'exécutable\n\n");

    printf("2. Run Keys (démarrage automatique système) :\n");
    printf("   HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
    printf("   Nécessite : Droits administrateur\n\n");

    printf("3. RunOnce Keys (exécution unique) :\n");
    printf("   HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n");
    printf("   Supprimée après exécution\n\n");

    printf("4. Services Windows :\n");
    printf("   HKLM\\SYSTEM\\CurrentControlSet\\Services\n");
    printf("   Nécessite : Droits administrateur\n\n");

    printf("DÉTECTION :\n");
    printf("- Autoruns (Sysinternals)\n");
    printf("- Windows Event Logs (Event ID 4657)\n");
    printf("- EDR / Antivirus\n");
    printf("- Process Monitor\n\n");

    printf("⚠️  L'installation non autorisée de persistence est ILLÉGALE\n");
}

// ═══════════════════════════════════════════════════════════════════
// Fonction principale
// ═══════════════════════════════════════════════════════════════════

int main(void) {
    printf(SEPARATEUR);
    printf("  MODULE 35 : REGISTRY MANIPULATION\n");
    printf("  Manipulation du Registre Windows\n");
    printf(SEPARATEUR);

    printf("\n⚠️  AVERTISSEMENT CRITIQUE ⚠️\n\n");
    printf("Ce programme manipule le registre Windows.\n");
    printf("Des modifications incorrectes peuvent CORROMPRE votre système.\n\n");
    printf("PRÉCAUTIONS OBLIGATOIRES :\n");
    printf("  ✓ Créer un backup complet du registre\n");
    printf("  ✓ Utiliser dans une VM de test isolée\n");
    printf("  ✓ Snapshot de la VM avant exécution\n\n");

    if (!verifier_backup_registre()) {
        return 1;
    }

    // Démonstration 1 : Création de clés
    demonstrer_creation_cle();
    printf("\n\nAppuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 2 : Écriture de valeurs
    demonstrer_ecriture_valeurs();
    printf("\n\nAppuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 3 : Lecture de valeurs
    demonstrer_lecture_valeurs();
    printf("\n\nAppuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 4 : Énumération
    demonstrer_enumeration_cles();
    printf("\n\nAppuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 6 : Persistence (info)
    demonstrer_persistence();
    printf("\n\nAppuyez sur ENTRÉE pour nettoyer et terminer...\n");
    getchar();

    // Démonstration 5 : Suppression (nettoyage final)
    demonstrer_suppression();

    printf("\n");
    afficher_titre("FIN DES DÉMONSTRATIONS");
    printf("\n[+] Toutes les clés de test ont été supprimées\n");
    printf("[+] Consultez exercice.txt pour des défis pratiques\n\n");

    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * Notes techniques importantes
 * ═══════════════════════════════════════════════════════════════════
 *
 * 1. GESTION DES HANDLES :
 *    - Toujours fermer avec RegCloseKey()
 *    - Un handle non fermé = fuite de ressources
 *
 * 2. DROITS D'ACCÈS :
 *    - KEY_READ : Lecture uniquement
 *    - KEY_WRITE : Écriture uniquement
 *    - KEY_ALL_ACCESS : Tous droits
 *    - Principe du moindre privilège
 *
 * 3. ERREURS COURANTES :
 *    - ERROR_ACCESS_DENIED : Droits insuffisants
 *    - ERROR_FILE_NOT_FOUND : Clé inexistante
 *    - ERROR_MORE_DATA : Buffer trop petit
 *
 * 4. PERSISTENCE :
 *    - Les Run Keys sont monitorées par les antivirus
 *    - Détection facile par Autoruns
 *    - Windows Event Logs enregistrent les modifications
 *
 * 5. SÉCURITÉ :
 *    - HKLM nécessite droits administrateur
 *    - HKCU accessible par utilisateur standard
 *    - UAC peut bloquer certaines opérations
 *
 * ═══════════════════════════════════════════════════════════════════
 */

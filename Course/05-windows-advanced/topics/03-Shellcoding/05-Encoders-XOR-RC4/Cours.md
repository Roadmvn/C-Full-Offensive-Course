# Module : Encodeurs XOR et RC4

## Objectifs

- Encoder un shellcode pour éviter la détection
- Implémenter XOR single-byte et multi-byte
- Comprendre RC4 pour l'encodage

---

## 1. XOR Single-Byte

```c
void xor_encode(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
```

---

## 2. XOR Multi-Byte

```c
void xor_multi(unsigned char *data, size_t len, 
               unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}
```

---

## 3. RC4 Encoder

```c
void rc4_crypt(unsigned char *data, size_t len,
               unsigned char *key, size_t key_len) {
    unsigned char S[256];
    int i, j = 0;
    
    // KSA
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    
    // PRGA
    i = j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}
```

---

## 4. Stub de décodage

```nasm
; XOR decoder stub
decoder:
    jmp call_decoder
decode:
    pop rsi                 ; Adresse du shellcode encodé
    xor rcx, rcx
    mov cl, SHELLCODE_LEN
decode_loop:
    xor byte [rsi], KEY
    inc rsi
    loop decode_loop
    jmp shellcode

call_decoder:
    call decode
shellcode:
    ; shellcode encodé ici
```

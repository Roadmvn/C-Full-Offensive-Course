# Solutions Exercice 02 : Lecture Hexadécimale

---

## Partie 1 : Décodage ASCII

| Hex | Décimal | Caractère |
|-----|---------|-----------|
| 0x48 | 72 | H |
| 0x65 | 101 | e |
| 0x6C | 108 | l |
| 0x6F | 111 | o |

1. `48 65 6C 6C 6F` = **Hello**
2. `57 6F 72 6C 64` = **World**
3. `48 61 63 6B 65 72` = **Hacker**
4. `52 6F 6F 74` = **Root**
5. `70 61 73 73 77 6F 72 64` = **password**
6. `2F 62 69 6E 2F 73 68` = **/bin/sh**
7. `41 42 43 44 45 46` = **ABCDEF**
8. `30 31 32 33 34 35 36 37 38 39` = **0123456789**

### Astuce : Table ASCII à mémoriser
```
0x30-0x39 : '0'-'9' (chiffres)
0x41-0x5A : 'A'-'Z' (majuscules)
0x61-0x7A : 'a'-'z' (minuscules)
0x20 : espace
0x2F : /
0x00 : NULL (fin de chaîne)
```

---

## Partie 2 : Encodage ASCII

1. `Linux` = **4C 69 6E 75 78**
2. `Shell` = **53 68 65 6C 6C**
3. `Admin` = **41 64 6D 69 6E**
4. `/etc/passwd` = **2F 65 74 63 2F 70 61 73 73 77 64**
5. `cmd.exe` = **63 6D 64 2E 65 78 65**
6. `GET / HTTP/1.1` = **47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31**

---

## Partie 3 : Identification de Magic Bytes

1. `7F 45 4C 46` = **ELF** (exécutable Linux/Unix)
   - 0x7F suivi de "ELF" en ASCII

2. `4D 5A 90 00` = **PE/MZ** (exécutable Windows)
   - "MZ" = Mark Zbikowski (créateur du format)

3. `89 50 4E 47` = **PNG** (image)
   - 0x89 suivi de "PNG"

4. `25 50 44 46` = **PDF** (document)
   - "%PDF" en ASCII

5. `50 4B 03 04` = **ZIP** (archive, aussi DOCX, XLSX, APK)
   - "PK" = Phil Katz (créateur du format)

6. `FF D8 FF E0` = **JPEG** (image)
   - Start of Image (SOI) marker

7. `CA FE BA BE` = **Java class file** ou **Mach-O fat binary**
   - "Café babe" - humour des développeurs Java

8. `00 00 01 00` = **ICO** (icône Windows)

---

## Partie 4 : Analyse de Dump Mémoire

```
Adresse      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
─────────────────────────────────────────────────────────────
0x00401000: 55 89 E5 83 EC 10 C7 45 FC 00 00 00 00 8B 45 FC
0x00401010: 83 C0 01 89 45 FC 83 7D FC 09 7E F2 B8 00 00 00
0x00401020: 00 C9 C3 00 00 00 00 00 48 65 6C 6C 6F 00 00 00
```

### Réponses :

1. **Adresse 0x00401028 à 0x0040102D** :
   - `48 65 6C 6C 6F 00` = "Hello" + NULL terminator

2. **0x55** = instruction **PUSH EBP**
   - C'est le prologue classique d'une fonction en x86
   - Suivi de `89 E5` = MOV EBP, ESP

3. **`C9 C3`** = **LEAVE + RET**
   - C9 = LEAVE (équivalent à MOV ESP, EBP; POP EBP)
   - C3 = RET (retour de fonction)
   - C'est l'épilogue standard d'une fonction

### Code reconstitué :
```c
void fonction() {
    int i = 0;           // C7 45 FC 00 00 00 00
    while (i <= 9) {     // 83 7D FC 09 7E F2
        i++;             // 83 C0 01
    }
    return;              // C9 C3
}

char message[] = "Hello";  // à l'adresse 0x00401028
```

---

## Partie 5 : Endianness

### Little-Endian vers valeur

1. `78 56 34 12` → **0x12345678**
   - Le byte de poids faible (78) est en premier

2. `EF BE AD DE` → **0xDEADBEEF**
   - Séquence classique utilisée pour le débogage

3. `21 43` → **0x4321**

4. `37 13 00 00` → **0x00001337** = **4919** en décimal
   - "1337" = "LEET" en leet speak

### Valeur vers Little-Endian

1. `0xDEADBEEF` → **EF BE AD DE**
2. `0x12345678` → **78 56 34 12**
3. `0x0041` → **41 00**
4. `0x00401000` → **00 10 40 00**

---

## Partie 6 : Reconstruction de Données

```
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
──────────────────────────────────────────────────────
0x0000: 41 6C 69 63 65 00 00 00 00 00 00 00 00 00 00 00
0x0010: 19 00 00 00 E8 03 00 00 01 00 00 00 00 00 00 00
```

### Réponses :

1. **Nom** (offset 0x00-0x0F) :
   - `41 6C 69 63 65 00` = **"Alice"** (suivi de NULL et padding)

2. **Âge** (offset 0x10-0x13) :
   - `19 00 00 00` en little-endian = 0x00000019 = **25 ans**

3. **Score** (offset 0x14-0x17) :
   - `E8 03 00 00` en little-endian = 0x000003E8 = **1000**

4. **Actif** (offset 0x18-0x1B) :
   - `01 00 00 00` = 1 = **Oui (true)**

---

## Partie 7 : Shellcode Simple

```nasm
31 C0              ; XOR EAX, EAX       - Mettre EAX à 0
50                 ; PUSH EAX           - Empiler 0 (NULL terminator)
68 2F 2F 73 68     ; PUSH 0x68732F2F    - Empiler "//sh"
68 2F 62 69 6E     ; PUSH 0x6E69622F    - Empiler "/bin"
89 E3              ; MOV EBX, ESP       - EBX = pointeur vers "/bin//sh"
50                 ; PUSH EAX           - Empiler NULL (fin argv)
53                 ; PUSH EBX           - Empiler pointeur vers commande
89 E1              ; MOV ECX, ESP       - ECX = argv
B0 0B              ; MOV AL, 0x0B       - Syscall 11 = execve
CD 80              ; INT 0x80           - Appel système
```

### Réponses :

1. `2F 2F 73 68` en ASCII :
   - 2F = '/', 2F = '/', 73 = 's', 68 = 'h'
   - = **"//sh"**
   - Note: "//" équivaut à "/" en chemins Unix

2. `2F 62 69 6E` en ASCII :
   - 2F = '/', 62 = 'b', 69 = 'i', 6E = 'n'
   - = **"/bin"**

3. Ce shellcode **exécute /bin/sh** (lance un shell)
   - Il construit la chaîne "/bin//sh" sur la pile
   - Appelle execve("/bin//sh", argv, NULL)
   - Donne un shell à l'attaquant si exécuté

### Visualisation de la pile après construction :

```
ESP → ┌─────────────────┐
      │ ptr vers "/bin" │  ← argv[0]
      ├─────────────────┤
      │      NULL       │  ← argv[1]
      ├─────────────────┤
EBX → │    "/bin"       │
      │    "//sh"       │
      │     NULL        │
      └─────────────────┘
```

---

## Points Clés à Retenir

1. **Little-endian inverse l'ordre des bytes**
2. **Les magic bytes identifient les formats de fichiers**
3. **Les structures ont du padding pour l'alignement**
4. **Le shellcode utilise des astuces pour être compact**
   - XOR reg, reg pour mettre à zéro (plus court que MOV reg, 0)
   - // au lieu de / pour avoir un multiple de 4 bytes

---

## Navigation

| Retour | Exercice suivant |
|--------|------------------|
| [Exercice 02](../exercices/exercice-02.md) | [Exercice 03](../exercices/exercice-03.md) |

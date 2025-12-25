# Exercice 02 : Lecture Hexadécimale

## Objectif
Apprendre à lire et interpréter des dumps mémoire hexadécimaux.

---

## Partie 1 : Décodage ASCII

Convertissez ces séquences hexadécimales en texte ASCII :

1. `48 65 6C 6C 6F`
2. `57 6F 72 6C 64`
3. `48 61 63 6B 65 72`
4. `52 6F 6F 74`
5. `70 61 73 73 77 6F 72 64`
6. `2F 62 69 6E 2F 73 68`
7. `41 42 43 44 45 46`
8. `30 31 32 33 34 35 36 37 38 39`

---

## Partie 2 : Encodage ASCII

Convertissez ces textes en hexadécimal :

1. `Linux`
2. `Shell`
3. `Admin`
4. `/etc/passwd`
5. `cmd.exe`
6. `GET / HTTP/1.1`

---

## Partie 3 : Identification de Magic Bytes

Identifiez le type de fichier d'après les premiers bytes :

1. `7F 45 4C 46`
2. `4D 5A 90 00`
3. `89 50 4E 47`
4. `25 50 44 46`
5. `50 4B 03 04`
6. `FF D8 FF E0`
7. `CA FE BA BE`
8. `00 00 01 00`

---

## Partie 4 : Analyse de Dump Mémoire

Analysez ce dump mémoire et répondez aux questions :

```
Adresse      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
─────────────────────────────────────────────────────────────
0x00401000: 55 89 E5 83 EC 10 C7 45 FC 00 00 00 00 8B 45 FC
0x00401010: 83 C0 01 89 45 FC 83 7D FC 09 7E F2 B8 00 00 00
0x00401020: 00 C9 C3 00 00 00 00 00 48 65 6C 6C 6F 00 00 00
```

Questions :
1. Que contient l'adresse 0x00401028 à 0x0040102D ?
2. Le premier byte (0x55) correspond à quelle instruction x86 ?
3. Que signifie la séquence `C9 C3` à la fin du code ?

---

## Partie 5 : Endianness

### Little-Endian vers valeur

Si ces bytes sont stockés en little-endian, quelle est la valeur réelle ?

1. `78 56 34 12` (32 bits)
2. `EF BE AD DE` (32 bits)
3. `21 43` (16 bits)
4. `37 13 00 00` (32 bits)

### Valeur vers Little-Endian

Comment ces valeurs seraient-elles stockées en mémoire (little-endian) ?

1. `0xDEADBEEF`
2. `0x12345678`
3. `0x0041` (16 bits)
4. `0x00401000`

---

## Partie 6 : Reconstruction de Données

Ce dump représente une structure en mémoire. Analysez-la :

```
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
──────────────────────────────────────────────────────
0x0000: 41 6C 69 63 65 00 00 00 00 00 00 00 00 00 00 00
0x0010: 19 00 00 00 E8 03 00 00 01 00 00 00 00 00 00 00
```

La structure est définie comme :
```c
struct Personne {
    char nom[16];      // offset 0x00
    int age;           // offset 0x10
    int score;         // offset 0x14
    int actif;         // offset 0x18
};
```

Questions :
1. Quel est le nom de la personne ?
2. Quel est son âge ?
3. Quel est son score ?
4. Est-elle active ?

---

## Partie 7 : Shellcode Simple

Voici un shellcode x86 simple. Identifiez ce qu'il fait :

```
31 C0        ; instruction 1
50           ; instruction 2
68 2F 2F 73 68  ; instruction 3
68 2F 62 69 6E  ; instruction 4
89 E3        ; instruction 5
50           ; instruction 6
53           ; instruction 7
89 E1        ; instruction 8
B0 0B        ; instruction 9
CD 80        ; instruction 10
```

Indices :
- `31 C0` = XOR EAX, EAX
- `50` = PUSH EAX
- `68 XX XX XX XX` = PUSH (valeur 32 bits)
- `89 E3` = MOV EBX, ESP
- `B0 XX` = MOV AL, (valeur 8 bits)
- `CD 80` = INT 0x80 (syscall Linux)
- Syscall 11 (0x0B) = execve

Questions :
1. Que représentent les bytes `2F 2F 73 68` en ASCII ?
2. Que représentent les bytes `2F 62 69 6E` en ASCII ?
3. Que fait ce shellcode ?

---

## Auto-évaluation

Avant de voir les solutions, vérifiez :

- [ ] Vous pouvez convertir rapidement hexa ↔ ASCII pour les lettres courantes
- [ ] Vous reconnaissez les magic bytes des formats courants
- [ ] Vous comprenez le little-endian
- [ ] Vous pouvez lire une structure à partir d'un dump

---

## Solutions

→ Voir [../solutions/solution-02.md](../solutions/solution-02.md)

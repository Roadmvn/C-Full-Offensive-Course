# Cours : API Hooking - Interception d'Appels de Fonctions

## 1. Introduction - Qu'est-ce que le Hooking ?

**Hook** (crochet) = Intercepter un appel de fonction pour modifier son comportement.

**Analogie** : Vous êtes un espion qui intercepte les appels téléphoniques :
- L'appel passe par vous
- Vous écoutez/modifiez le message
- Vous transmettez (ou pas) à la destination originale

```ascii
SANS HOOK :
Programme → Fonction → Exécution

AVEC HOOK :
Programme → HOOK (votre code) → Fonction originale
              ↓
         Intercepter/Modifier
```

## 2. Techniques de Hooking

### 2.1 IAT Hooking (Import Address Table)

La **IAT** contient les adresses des fonctions importées depuis les DLLs.

```ascii
PE HEADER :
┌──────────────────────────┐
│  Import Table            │
│  ├─ kernel32.dll         │
│  │  ├─ CreateFileA → ???│  ← Adresse à résoudre
│  │  └─ ReadFile → ???   │
│  └─ user32.dll           │
└──────────────────────────┘

Au chargement, Windows remplit :
┌──────────────────────────┐
│  IAT (Import Addr Table) │
│  ├─ CreateFileA: 0x76541234  ← Adresse réelle
│  └─ ReadFile: 0x76545678     ← dans kernel32.dll
└──────────────────────────┘

NOTRE HOOK modifie l'IAT :
┌──────────────────────────┐
│  IAT                     │
│  ├─ CreateFileA: 0x00A00000  ← NOTRE fonction !
│  └─ ReadFile: 0x76545678
└──────────────────────────┘
```

**Code** :
```c
// Remplacer adresse dans l'IAT
DWORD oldProtect;
VirtualProtect(iatEntry, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
*iatEntry = (LPVOID)MyHookedFunction;
VirtualProtect(iatEntry, sizeof(LPVOID), oldProtect, &oldProtect);
```

### 2.2 Inline Hooking (Detours)

Modifier le **début de la fonction** pour sauter vers notre code.

```ascii
FONCTION ORIGINALE :

0x76541234:  mov edi, edi        ; Fonction CreateFileA
0x76541236:  push ebp
0x76541237:  mov ebp, esp
0x76541239:  ...

APRÈS INLINE HOOK :

0x76541234:  jmp 0x00A00000      ; Saut vers notre hook !
0x76541239:  (code écrasé)
             ...

Notre Hook :
0x00A00000:  ; Notre code
             ; Log, modification, etc.
             jmp 0x76541239      ; Saute vers code original
```

## Ressources

- [API Hooking Explained](https://www.apriorit.com/dev-blog/160-apihooks)
- [Detours](https://github.com/Microsoft/Detours)


# Cours : Le Concept de Buffer

## 1. Introduction - Qu'est-ce qu'un Buffer ?

### 1.1 Définition Simple

Un **buffer** (tampon) est une **zone de mémoire temporaire** utilisée pour stocker des données en transit.

**Analogie** : Un buffer est comme un **parking de transit** pour camions :
- Les camions (données) s'arrêtent temporairement
- Ils sont déchargés/traités
- Puis ils repartent

```ascii
FLUX DE DONNÉES AVEC BUFFER :

Source        Buffer         Destination
  │            │                │
  ↓            ↓                ↓
[Clavier] → [Buffer] → [Programme] → [Écran]
            └──────┘
            Zone temporaire
```

### 1.2 Pourquoi Utiliser des Buffers ?

**Sans buffer** :
```ascii
read clavier → traiter → read → traiter → read → ...
             ↑ Lent !           ↑ Syscall      ↑
```

**Avec buffer** :
```ascii
read 4KB dans buffer → traiter tout le buffer en une fois
                     ↑ Rapide ! (moins de syscalls)
```

## 2. Types de Buffers

### 2.1 Buffer d'Entrée (stdin)

```ascii
Utilisateur tape : "Bonjour World"

CLAVIER                    BUFFER stdin
┌───┬───┬───┬───┐         ┌──────────────────┐
│ B │ o │ n │...│────────→│'B''o''n''j''o'..│
└───┴───┴───┴───┘         └──────────────────┘
                                 ↓
                          scanf() lit ici
```

### 2.2 Buffer de Sortie (stdout)

```ascii
printf("Hello")

PROGRAMME                  BUFFER stdout          ÉCRAN
   │                       ┌───────────┐            │
   ├── printf("Hello") ───→│'H''e''l'..│────flush──→│
   │                       └───────────┘            │
   │                       Stocké ici               │
   │                       jusqu'au '\n'            │
```

## 3. Buffer Overflow - La Vulnérabilité #1

### 3.1 Le Problème Expliqué Simplement

```ascii
Buffer = Verre d'eau (capacité limitée)

Verre de 100ml :
┌────────────┐  ← Bord
│            │
│            │  Peut contenir 100ml max
│            │
└────────────┘

Verser 200ml :
    ╔══════╗  ← DÉBORDE !
┌───╨──────╨───┐
│   Eau ║   Eau║
│  dans ║ déborde
│ verre ║   ║
└───────╨───╨──┘
    ║   ║
    ↓   ↓
  Inonde la table !

En programmation :
Buffer[64] mais on écrit 200 bytes
→ Déborde et écrase la mémoire adjacente
```

### 3.2 Exemple de Code Vulnérable

```c
char buffer[64];
gets(buffer);  // ❌ DANGEREUX : Pas de limite !
```

```ascii
MÉMOIRE AVANT gets() :

STACK :
0x1000  ┌──────────────┐
        │ buffer[64]   │  64 bytes réservés
        │              │
0x103F  └──────────────┘
0x1040  ┌──────────────┐
        │ return addr  │  8 bytes (adresse de retour)
0x1047  └──────────────┘

UTILISATEUR TAPE : "A" × 100  (100 caractères)

STACK APRÈS gets() :
0x1000  ┌──────────────┐
        │ AAAAAAAA...  │  64 'A' (OK, dans buffer)
0x103F  └──────────────┘
0x1040  ┌──────────────┐
        │ AAAAAAAA...  │  36 'A' en plus (OVERFLOW !)
0x1063  └──────────────┘  
              ↑
        Return address ÉCRASÉE !
        
Programme va sauter à une adresse invalide → CRASH
Ou pire : saute à un shellcode (exploit)
```

## 4. Protections Modernes

### 4.1 Canary (Stack Canary)

```ascii
SANS CANARY :
┌──────────┐
│ buffer   │
├──────────┤
│ ret addr │  ← Facile d'écraser
└──────────┘

AVEC CANARY :
┌──────────┐
│ buffer   │
├──────────┤
│ CANARY   │  ← Valeur secrète (ex: 0xDEADBEEF)
├──────────┤
│ ret addr │
└──────────┘

Si buffer déborde :
1. Canary écrasé
2. Programme vérifie canary avant retour
3. Si différent → CRASH volontaire
```

## Ressources

- [Buffer Overflow](https://en.wikipedia.org/wiki/Buffer_overflow)
- [Stack Canaries](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)


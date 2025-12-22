# Week 07 - DLLs & Dynamic API Resolution

## Objectifs
- Comprendre le chargement dynamique de DLLs
- Maîtriser LoadLibrary et GetProcAddress
- Résoudre des APIs dynamiquement pour éviter l'IAT
- Introduction au PEB walking

## Lessons

### 01-loadlibrary.c
Chargement dynamique de DLLs avec `LoadLibraryA/W`:
- Charger une DLL en mémoire
- Obtenir un HMODULE
- Libérer avec FreeLibrary

### 02-getprocaddress.c
Résolution d'adresses de fonctions:
- Obtenir l'adresse d'une fonction exportée
- Casting vers le bon type de pointeur
- Appeler la fonction via le pointeur

### 03-dynamic-api.c
Appel d'APIs sans import statique:
- Éviter les entrées dans l'IAT
- Charger kernel32.dll dynamiquement
- Résoudre et appeler WinExec, CreateFileA, etc.

### 04-peb-intro.c
Introduction au Process Environment Block:
- Accéder au PEB via le TEB
- Lire la liste des modules chargés
- Trouver une DLL sans LoadLibrary

## Exercises

| Exercice | Description |
|----------|-------------|
| ex01 | Charger user32.dll et appeler MessageBoxA dynamiquement |
| ex02 | Résoudre 3 APIs de kernel32 et les appeler |
| ex03 | Trouver ntdll.dll via le PEB |

## Compilation

```batch
build.bat
```

## Concepts clés pour le maldev

1. **Évitement de l'IAT**: Les imports statiques sont visibles dans le PE. La résolution dynamique les cache.

2. **PEB Walking**: Permet de trouver des DLLs déjà chargées sans appeler LoadLibrary (qui peut être hookée).

3. **Signature réduction**: Moins d'APIs visibles = détection plus difficile.

## Pattern type

```c
typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

HMODULE hUser32 = LoadLibraryA("user32.dll");
pMessageBoxA fnMessageBox = (pMessageBoxA)GetProcAddress(hUser32, "MessageBoxA");
fnMessageBox(NULL, "Hello", "Test", MB_OK);
```

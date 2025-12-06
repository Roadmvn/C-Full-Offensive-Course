# Cours : Reflective DLL Loading - Chargement Sans Disque

## 1. Introduction

**Reflective Loading** = Charger une DLL directement depuis la mémoire, **sans** passer par le disque.

## 2. Le Problème

```ascii
CHARGEMENT NORMAL :

DLL sur disque → LoadLibrary() → Windows loader → DLL en mémoire
                        ↓
                  Détectable (fichier, CreateFile)

REFLECTIVE LOADING :

DLL en mémoire (buffer) → Notre loader custom → DLL en mémoire
                                ↓
                          Furtif (pas de fichier)
```

## 3. Étapes du Chargement Manuel

```ascii
1. Parser PE header de la DLL
2. Allouer mémoire (taille de l'image)
3. Copier sections (.text, .data, .rdata)
4. Traiter les relocations
5. Résoudre les imports (IAT)
6. Modifier les protections mémoire
7. Appeler DllMain(DLL_PROCESS_ATTACH)
```

## Ressources

- [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)


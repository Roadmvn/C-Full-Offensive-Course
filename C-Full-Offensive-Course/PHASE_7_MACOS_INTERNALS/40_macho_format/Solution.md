# SOLUTION : MACH-O PARSER

Voir example.c pour un parser complet.


### COMMANDES UTILES :


```bash
# Analyser header
```
otool -h /bin/ls


```bash
# Load commands détaillés
```
otool -l /bin/ls | grep -A 5 LC_SEGMENT_64


```bash
# Dylibs
```
otool -L /bin/ls


```bash
# Strings
```
strings /bin/ls


```bash
# Code signature
```
codesign -dv /bin/ls


```bash
# Modifier (retirer signature d'abord)
```
codesign --remove-signature binary

```bash
# ... modifications ...
```
codesign -s - binary



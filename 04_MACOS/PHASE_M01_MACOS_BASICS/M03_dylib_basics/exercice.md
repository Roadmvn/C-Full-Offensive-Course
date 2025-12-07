# EXERCICE : DYLIB INJECTION

1. Créer une dylib qui hook printf()

2. Injecter avec DYLD_INSERT_LIBRARIES dans un programme test

3. Créer une dylib qui log toutes les allocations malloc()

4. Modifier un Mach-O pour charger la dylib automatiquement

5. Détecter les dylibs chargées dans un processus


### COMPILATION DYLIB :
clang -dynamiclib -o inject.dylib inject.c


### INJECTION :
DYLD_INSERT_LIBRARIES=./inject.dylib ./target_program

MODIFIER MACH-O :
# Installer insert_dylib d'abord
insert_dylib --inplace ./inject.dylib target_binary
./target_binary

DÉTECTION :
// Code pour lister dylibs
#include <mach-o/dyld.h>
for (uint32_t i = 0; i < _dyld_image_count(); i++) {
    printf("%s\n", _dyld_get_image_name(i));
}



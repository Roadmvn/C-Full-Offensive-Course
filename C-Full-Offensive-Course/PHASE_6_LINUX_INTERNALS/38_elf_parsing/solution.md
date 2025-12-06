# MODULE 38 : ELF PARSING - SOLUTIONS

## Vérifier ELF
```c
Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
    printf("Valid ELF\n");
}
```

## Extract section
```c
Elf64_Shdr *text_shdr = find_section(map, ".text");
FILE *out = fopen("text.bin", "wb");
fwrite((char *)map + text_shdr->sh_offset, 
       text_shdr->sh_size, 1, out);
fclose(out);
```

## Patch entry point
```c
ehdr->e_entry = new_entry;
// Écrire fichier modifié
```

## Outils
```bash
readelf -h binary      # Header
readelf -S binary      # Sections
objdump -d binary      # Désassemble
```

# MODULE 20 : INTEGER OVERFLOW - SOLUTIONS

## Exercice 1
```c
int max = INT_MAX;
printf("%d\n", max + 1);  // -2147483648
unsigned int umax = UINT_MAX;
printf("%u\n", umax + 1);  // 0
```

## Exercice 2
```c
void *vuln_alloc(size_t count, size_t size) {
    size_t total = count * size;
    return malloc(total);
}

// Exploit
size_t count = (SIZE_MAX / 8) + 2;
void *buf = vuln_alloc(count, 8);  // Petit malloc!
```

## Exercice 3
```c
// Vulnérable
if (offset + size < buffer_size) {
    memcpy(buf + offset, data, size);
}

// Exploit: offset = UINT_MAX - 10, size = 20
// offset + size wraparound to 9 < buffer_size!
```

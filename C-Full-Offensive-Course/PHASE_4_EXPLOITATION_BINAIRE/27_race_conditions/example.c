#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

int shared_counter = 0;

void *increment(void *arg) {
    for (int i = 0; i < 100000; i++) {
        shared_counter++;  // Race condition!
    }
    return NULL;
}

void demo_race() {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, increment, NULL);
    pthread_create(&t2, NULL, increment, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    printf("Expected: 200000\n");
    printf("Got: %d (race!)\n", shared_counter);
}

void vulnerable_toctou() {
    if (access("/tmp/testfile", F_OK) == 0) {  // Check
        sleep(1);  // Window for attack!
        FILE *f = fopen("/tmp/testfile", "r");  // Use
        if (f) {
            char buf[100];
            fgets(buf, sizeof(buf), f);
            printf("Content: %s\n", buf);
            fclose(f);
        }
    }
}

int main() {
    demo_race();
    vulnerable_toctou();
    return 0;
}

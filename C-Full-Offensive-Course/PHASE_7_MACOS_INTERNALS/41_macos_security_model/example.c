#include <stdio.h>
#include <sys/sysctl.h>

int main() {
    printf("=== PAC DETECTION ===\n\n");
    
    // Vérifier support PAC
    int has_pac = 0;
    size_t size = sizeof(has_pac);
    
    if (sysctlbyname("hw.optional.arm.FEAT_PAuth", &has_pac, &size, NULL, 0) == 0) {
        printf("PAC Support: %s\n", has_pac ? "YES" : "NO");
    } else {
        printf("Cannot determine PAC support\n");
    }
    
    // Vérifier Apple Silicon
    int is_apple_silicon = 0;
    size = sizeof(is_apple_silicon);
    
    if (sysctlbyname("hw.optional.arm64", &is_apple_silicon, &size, NULL, 0) == 0) {
        printf("Apple Silicon: %s\n", is_apple_silicon ? "YES" : "NO");
    }
    
    return 0;
}


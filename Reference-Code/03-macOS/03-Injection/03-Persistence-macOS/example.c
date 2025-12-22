#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Programme qui sera persisté
int main() {
    // Log pour prouver exécution
    FILE *log = fopen("/tmp/persistence.log", "a");
    if (log) {
        fprintf(log, "Agent executed at %ld\n", time(NULL));
        fclose(log);
    }
    
    // Payload (ici juste un message)
    printf("Persistent agent running...\n");
    
    return 0;
}

/*
 * INSTALLATION PERSISTENCE:
 *
 * 1. Compiler:
 *    clang example.c -o /tmp/agent
 *
 * 2. Créer plist:
 *    cat > ~/Library/LaunchAgents/com.example.agent.plist << 'PLIST'
 *    <?xml version="1.0" encoding="UTF-8"?>
 *    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 *    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 *    <plist version="1.0">
 *    <dict>
 *        <key>Label</key>
 *        <string>com.example.agent</string>
 *        <key>ProgramArguments</key>
 *        <array>
 *            <string>/tmp/agent</string>
 *        </array>
 *        <key>RunAtLoad</key>
 *        <true/>
 *        <key>StartInterval</key>
 *        <integer>300</integer>
 *    </dict>
 *    </plist>
 *    PLIST
 *
 * 3. Charger:
 *    launchctl load ~/Library/LaunchAgents/com.example.agent.plist
 *
 * 4. Vérifier:
 *    launchctl list | grep com.example
 *    tail -f /tmp/persistence.log
 *
 * 5. Désinstaller:
 *    launchctl unload ~/Library/LaunchAgents/com.example.agent.plist
 *    rm ~/Library/LaunchAgents/com.example.agent.plist
 */

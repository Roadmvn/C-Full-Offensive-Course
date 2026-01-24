# Module 44 : macOS Persistence

## Objectifs
- Maîtriser LaunchAgents et LaunchDaemons
- Utiliser Login Items
- Persister sans droits root
- Techniques de persistence avancées

## Théorie

### LaunchAgents (User-level)
```
~/Library/LaunchAgents/          (user)
/Library/LaunchAgents/           (all users, root needed)
```

### LaunchDaemons (System-level)
```
/Library/LaunchDaemons/          (root required)
/System/Library/LaunchDaemons/   (système)
```

### Plist Example
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/binary</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

## Pertinence Red Team

### User persistence
- LaunchAgents sans root
- Login Items via osascript
- Cron jobs

### System persistence
- LaunchDaemons (root)
- Kernel extensions (obsolète)
- Login hooks (deprecated)

### Furtivité
- Noms légitimes (com.apple.*)
- RunAtLoad + KeepAlive
- Pas de notifs

## Ressources
- launchd.plist man page
- macOS Red Team Guide

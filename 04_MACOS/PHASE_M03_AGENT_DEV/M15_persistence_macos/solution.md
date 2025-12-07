# MODULE 44 : macOS PERSISTENCE - SOLUTIONS

## LaunchAgent plist
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.persistence</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/user/agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/agent.err</string>
</dict>
</plist>
```

## Installation
```bash
# Copier binaire
cp agent /Users/$(whoami)/agent

# Créer plist
cat > ~/Library/LaunchAgents/com.example.plist << 'EOF'
[plist content]
EOF

# Charger
launchctl load ~/Library/LaunchAgents/com.example.plist

# Lister
launchctl list | grep example

# Décharger
launchctl unload ~/Library/LaunchAgents/com.example.plist
```

## Login Item (script)
```applescript
osascript << 'APPLESCRIPT'
tell application "System Events"
    make new login item at end with properties {
        path:"/Users/user/agent",
        hidden:false
    }
end tell
APPLESCRIPT
```

## Cron job
```bash
crontab -e
# Ajouter:
@reboot /Users/user/agent
# ou toutes les 5 minutes:
*/5 * * * * /Users/user/agent
```

## Detection
```bash
# Lister LaunchAgents
ls ~/Library/LaunchAgents/
ls /Library/LaunchAgents/

# Lister LaunchDaemons
sudo ls /Library/LaunchDaemons/

# Lister agents chargés
launchctl list

# Lister Login Items
osascript -e 'tell application "System Events" to get the name of every login item'

# Vérifier cron
crontab -l
```

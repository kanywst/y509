Output demo.gif

Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 20
Set TypingSpeed 75ms
Set Theme "Catppuccin Macchiato"

# Generate fresh certificates
Hide
Type "go run scripts/gen_demo_certs.go"
Enter
Sleep 1s
Ctrl+L
Show

# Launch
Type "./y509 testdata/demo/certs.pem"
Sleep 500ms
Enter
Sleep 2s

# 1. Navigation
Type "j"
Sleep 200ms
Type "j"
Sleep 200ms
Type "k"
Sleep 200ms

# 2. Tab Navigation
Right
Sleep 500ms
Tab
Sleep 1s
Tab
Sleep 1s
Tab
Sleep 1s
Left
Sleep 500ms

# 3. Search Popup
Type "/"
Sleep 500ms
Type "expired"
Sleep 500ms
Enter
Sleep 1.5s
# Reset via Esc
Escape
Sleep 500ms

# 4. Validation Popup
Type "v"
Sleep 3s
Escape
Sleep 500ms

# 5. Help
Type "?"
Sleep 2s
Escape

# Quit
Sleep 500ms
Type "q"

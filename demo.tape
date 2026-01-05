Output demo.gif

Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 20
Set TypingSpeed 100ms

# Launch
Type "./y509 testdata/demo/certs.pem"
Sleep 500ms
Enter
Sleep 2s

# 1. Navigation (Basic)
Type "j"
Sleep 500ms
Type "j"
Sleep 500ms
Type "k"
Sleep 500ms

# 2. Detail Pane Switching
Type "k"
Sleep 500ms

# 3. Technical Detail
Type ":"
Sleep 200ms
Type "san"
Sleep 500ms
Enter
Sleep 2.5s
Escape
Sleep 500ms

# 4. Chain Validation (Killer Feature)
Type ":"
Type "validate"
Enter
Sleep 3s
Escape
Sleep 500ms

# 5. Search (Practical Use case)
Type ":"
Type "search Example"
Enter
Sleep 1.5s
# Reset
Type ":"
Type "reset"
Enter
Sleep 1s

# 6. Export (Show utility)
Type ":"
Type "export pem exported.pem"
Enter
Sleep 2s
Escape

# Quit
Type "q"

Output demo.gif

Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 20
Set TypingSpeed 75ms
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set WindowBarSize 40
Set BorderRadius 10

# Generate fresh certificates
Hide
Type "go run scripts/gen_demo_certs.go"
Enter
Sleep 1s
Type "go build -o y509 ./cmd/y509 && export PATH=$PWD:$PATH"
Enter
Sleep 2s
Ctrl+L
Show

# Launch
Type "y509 testdata/demo/certs.pem"
Sleep 500ms
Enter
Sleep 2s

# 1. Navigate certificate list
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "k"
Sleep 400ms

# 2. Switch to details pane and browse tabs
Right
Sleep 500ms
Tab
Sleep 1s
Tab
Sleep 1s
Tab
Sleep 1s
Tab
Sleep 1s
Left
Sleep 500ms

# 3. Search
Type "/"
Sleep 500ms
Type "root"
Sleep 500ms
Enter
Sleep 1.5s
Escape
Sleep 500ms

# 4. Filter
Type "f"
Sleep 500ms
Type "expired"
Sleep 500ms
Enter
Sleep 1.5s
Escape
Sleep 500ms

# 5. Validate
Type "v"
Sleep 2.5s
Enter
Sleep 500ms

# 6. Help
Type "?"
Sleep 2s
Escape
Sleep 500ms

# Quit
Type "q"

Output demo.gif

Set FontSize 14
Set Width 1200
Set Height 800

Type "./y509 testdata/demo/certs.pem"
Enter
Sleep 2s

# Navigate through certificates
Type "j"
Sleep 1s
Type "j"
Sleep 1s

# Switch to right pane
Type "l"
Sleep 1s

# Switch back to left pane
Type "h"
Sleep 1s

# Navigate up
Type "k"
Sleep 1s

# Enter command mode
Type ":"
Sleep 1s

# Show subject command
Type "subject"
Enter
Sleep 3s

# Exit detail view
Escape
Sleep 1s

# Enter command mode again
Type ":"
Sleep 1s

# Show validity command
Type "validity"
Enter
Sleep 3s

# Exit detail view
Escape
Sleep 1s

# Enter command mode for help
Type ":"
Sleep 1s

# Show help
Type "help"
Enter
Sleep 4s

# Exit detail view
Escape
Sleep 1s

# Show final state
Sleep 2s

# Quit
Type "q"
Sleep 1s

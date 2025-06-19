Output demo.gif

Set FontSize 14
Set Width 1200
Set Height 800

# Launch and display certificate list
Type "./y509 testdata/demo/certs.pem"
Enter
Sleep 2s

# Navigate certificate list
Type "j"
Sleep 0.7s
Type "j"
Sleep 0.7s
Type "k"
Sleep 0.7s

# Switch detail pane
Type "l"
Sleep 0.7s
Type "h"
Sleep 0.7s

# Command mode: subject
Type ":"
Sleep 0.5s
Type "subject"
Enter
Sleep 2s
Escape
Sleep 0.7s

# issuer command
Type ":"
Sleep 0.5s
Type "issuer"
Enter
Sleep 2s
Escape
Sleep 0.7s

# validity command
Type ":"
Sleep 0.5s
Type "validity"
Enter
Sleep 2s
Escape
Sleep 0.7s

# Chain validation
Type ":"
Sleep 0.5s
Type "validate"
Enter
Sleep 2s
Escape
Sleep 1s

# Search by organization name
Type ":"
Sleep 0.5s
Type "search Example"
Enter
Sleep 1.5s

# subject command in search results
Type ":"
Sleep 0.5s
Type "subject"
Enter
Sleep 1.5s
Escape
Sleep 0.7s

# Reset to show all entries
Type ":"
Sleep 0.5s
Type "reset"
Enter
Sleep 1s

# help command to show all features
Type ":"
Sleep 0.5s
Type "help"
Enter
Sleep 2.5s
Escape
Sleep 0.7s

# Finally, quit
Type "q"
Sleep 0.7s
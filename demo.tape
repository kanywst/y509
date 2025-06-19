Output demo.gif

Set FontSize 14
Set Width 1200
Set Height 800

# 起動・証明書リスト表示
Type "./y509 testdata/demo/certs.pem"
Enter
Sleep 2s

# 証明書リストのナビゲーション
Type "j"
Sleep 0.7s
Type "j"
Sleep 0.7s
Type "k"
Sleep 0.7s

# 詳細ペイン切り替え
Type "l"
Sleep 0.7s
Type "h"
Sleep 0.7s

# コマンドモードでsubject
Type ":"
Sleep 0.5s
Type "subject"
Enter
Sleep 2s
Escape
Sleep 0.7s

# issuerコマンド
Type ":"
Sleep 0.5s
Type "issuer"
Enter
Sleep 2s
Escape
Sleep 0.7s

# validityコマンド
Type ":"
Sleep 0.5s
Type "validity"
Enter
Sleep 2s
Escape
Sleep 0.7s

# chain validate
Type ":"
Sleep 0.5s
Type "validate"
Enter
Sleep 2s
Escape
Sleep 0.7s

# search: 組織名で検索
Type ":"
Sleep 0.5s
Type "search Example"
Enter
Sleep 1.5s

# 検索結果でsubject
Type ":"
Sleep 0.5s
Type "subject"
Enter
Sleep 1.5s
Escape
Sleep 0.7s

# 存在しない検索
Type ":"
Sleep 0.5s
Type "search NotFound"
Enter
Sleep 1.2s

# resetで全件に戻す
Type ":"
Sleep 0.5s
Type "reset"
Enter
Sleep 1s

# filter: expiring
Type ":"
Sleep 0.5s
Type "filter expiring"
Enter
Sleep 1.5s

# filter: expired
Type ":"
Sleep 0.5s
Type "filter expired"
Enter
Sleep 1.5s

# filter: self-signed
Type ":"
Sleep 0.5s
Type "filter self-signed"
Enter
Sleep 1.5s

# 存在しないフィルタ
Type ":"
Sleep 0.5s
Type "filter unknown"
Enter
Sleep 1.2s

# resetで全件に戻す
Type ":"
Sleep 0.5s
Type "reset"
Enter
Sleep 1s

# exportコマンド（ダミー）
Type ":"
Sleep 0.5s
Type "export pem demo.pem"
Enter
Sleep 1.5s
Escape
Sleep 0.7s

# helpコマンドで全機能を一望
Type ":"
Sleep 0.5s
Type "help"
Enter
Sleep 2.5s
Escape
Sleep 0.7s

# 最後にquit
Type "q"
Sleep 0.7s
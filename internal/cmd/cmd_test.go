package cmd

import (
	"bytes"
	"testing"
)

func TestRootCommandHelp(t *testing.T) {
	// 実際のRootCmdを使用してテスト
	// バッファを作成してコマンドの出力をキャプチャ
	b := new(bytes.Buffer)
	oldOut := RootCmd.OutOrStdout()
	oldErr := RootCmd.ErrOrStderr()
	defer func() {
		RootCmd.SetOut(oldOut)
		RootCmd.SetErr(oldErr)
	}()
	
	RootCmd.SetOut(b)
	RootCmd.SetErr(b)
	
	// ヘルプメッセージを取得
	RootCmd.Help()
	
	// 出力にキーワードが含まれていることを確認（実際の出力内容はテストしない）
	out := b.String()
	if len(out) == 0 {
		t.Error("Expected help output to not be empty")
	}
}

func TestCommandStructure(t *testing.T) {
	// サブコマンドが正しく登録されているか確認
	subcommands := []string{"validate", "export", "version", "completion", "help"}
	
	for _, name := range subcommands {
		found := false
		for _, cmd := range RootCmd.Commands() {
			if cmd.Name() == name {
				found = true
				break
			}
		}
		
		if !found {
			t.Errorf("Expected subcommand '%s' to be registered", name)
		}
	}
}

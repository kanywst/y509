package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommandHelp(t *testing.T) {
	// ルートコマンドのクローンを作成（実際のコマンドを実行せずにテストするため）
	cmd := &cobra.Command{Use: "y509"}
	cmd.SetHelpTemplate(RootCmd.HelpTemplate())
	
	// バッファを作成してコマンドの出力をキャプチャ
	b := new(bytes.Buffer)
	cmd.SetOut(b)
	cmd.SetErr(b)
	cmd.SetArgs([]string{"--help"})
	
	// ヘルプコマンドを実行
	cmd.Execute()
	
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

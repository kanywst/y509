package textwidth

import "testing"

func TestTruncate(t *testing.T) {
	tests := []struct {
		in    string
		width int
		want  string
	}{
		{"abcdef", 3, "abc"},
		{"日本語", 5, "日本"},
		{"日本語", 1, ""},
		{"éé", 1, "é"},
		{"", 4, ""},
	}
	for _, tt := range tests {
		if got := Truncate(tt.in, tt.width); got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
		}
	}
}

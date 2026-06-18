package model

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateText(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		width int
		want  string
	}{
		{name: "Fits", text: "short", width: 10, want: "short"},
		{name: "ASCII truncated", text: "abcdefghij", width: 7, want: "abcd..."},
		{name: "Zero width", text: "abc", width: 0, want: ""},
		{name: "Negative width", text: "abc", width: -5, want: ""},
		{name: "Width equals three", text: "abcdef", width: 3, want: "..."},
		{name: "Tiny width", text: "abcdef", width: 2, want: ".."},
		{name: "Multibyte fits", text: "日本語", width: 5, want: "日本語"},
		{name: "Multibyte truncated", text: "日本語テスト", width: 5, want: "日本..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateText(tt.text, tt.width)
			if got != tt.want {
				t.Errorf("truncateText(%q, %d) = %q, want %q", tt.text, tt.width, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("truncateText(%q, %d) produced invalid UTF-8: %q", tt.text, tt.width, got)
			}
		})
	}
}

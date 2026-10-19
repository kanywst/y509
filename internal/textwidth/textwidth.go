// Package textwidth measures and cuts strings by terminal cells.
package textwidth

import (
	"strings"

	"github.com/rivo/uniseg"
)

// Width is the number of terminal cells s takes.
func Width(s string) int {
	return uniseg.StringWidth(s)
}

// Truncate is the longest prefix of s, in whole grapheme clusters, that is at
// most width terminal cells wide. A CJK character takes two cells, so counting
// runes overflows a column.
func Truncate(s string, width int) string {
	var b strings.Builder
	used := 0
	g := uniseg.NewGraphemes(s)
	for g.Next() && used+g.Width() <= width {
		used += g.Width()
		b.WriteString(g.Str())
	}
	return b.String()
}

package uefi

import (
	"strings"
)

// Indent indents the lines of a string by the given number of spaces,
// with the exception of the first line. If you need everything to be
// indented, use IndentAll.
// If the indentation number is <= 0 the string is returned unmodified.
func Indent(s string, i int) string {
	if i <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for idx, line := range lines {
		if idx == len(lines)-1 {
			break
		}
		lines[idx] = line + "\n"
	}
	return strings.Join(lines, strings.Repeat(" ", i))
}

// IndentAll works like Indent, but it also indents the first line.
func IndentAll(s string, i int) string {
	return strings.Repeat(" ", i) + Indent(s, i)
}

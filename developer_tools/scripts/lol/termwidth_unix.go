//go:build unix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// terminalWidth returns the stdout width in columns, or 0 when stdout is not a terminal.
func terminalWidth() int {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(ws.Col)
}

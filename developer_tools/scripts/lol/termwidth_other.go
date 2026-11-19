//go:build !unix

package main

func terminalWidth() int { return 0 }

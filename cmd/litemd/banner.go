package main

import (
	"fmt"
	"io"
)

// banner is the ASCII wordmark printed at the start of every server launch.
const banner = `  _ _ _       __  __ _____  
 | (_) |     |  \/  |  __ \ 
 | |_| |_ ___| \  / | |  | |
 | | | __/ _ \ |\/| | |  | |
 | | | ||  __/ |  | | |__| |
 |_|_|\__\___|_|  |_|_____/`

// printBanner writes the launch banner to w. The wordmark is ASCII-only, so it
// is safe on any terminal; colour is applied only when the caller asks for it.
func printBanner(w io.Writer, color bool, version string) {
	subtitle := "litemd " + version + " - lightweight file sync server"
	if color {
		fmt.Fprintf(w, "\x1b[36m%s\x1b[0m\n", banner)
		fmt.Fprintf(w, "\x1b[2m%s\x1b[0m\n", subtitle)
		return
	}
	fmt.Fprintln(w, banner)
	fmt.Fprintln(w, subtitle)
}

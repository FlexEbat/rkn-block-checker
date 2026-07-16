// Package logger provides unified colored output for the CLI tool.
// After 1000 lines of code, scattered fmt.Printf calls with hand-rolled
// "[!]" prefixes turn into a mess — this package gives a single
// info/success/warn/error interface instead.
package logger

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

var (
	cyanC   = color.New(color.FgCyan)
	greenC  = color.New(color.FgGreen)
	yellowC = color.New(color.FgYellow)
	redC    = color.New(color.FgRed)
)

// Info prints a neutral informational message ("[*] ...").
func Info(format string, a ...interface{}) {
	cyanC.Printf("[*] ")
	fmt.Printf(format+"\n", a...)
}

// Success prints a success message ("[+] ...").
func Success(format string, a ...interface{}) {
	greenC.Printf("[+] ")
	fmt.Printf(format+"\n", a...)
}

// Warn prints a warning ("[!] ...").
func Warn(format string, a ...interface{}) {
	yellowC.Printf("[!] ")
	fmt.Printf(format+"\n", a...)
}

// Error prints an error message to stderr ("[-] ...").
func Error(format string, a ...interface{}) {
	redC.Fprintf(os.Stderr, "[-] ")
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

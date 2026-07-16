// Package logger предоставляет единый цветной вывод для CLI-инструмента.
// Через 1000 строк кода разрозненные fmt.Printf с ручными префиксами "[!]"
// превращаются в кашу — этот пакет даёт единый интерфейс info/success/warn/error.
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

// Info выводит нейтральное информационное сообщение ("[*] ...").
func Info(format string, a ...interface{}) {
	cyanC.Printf("[*] ")
	fmt.Printf(format+"\n", a...)
}

// Success выводит сообщение об успехе ("[+] ...").
func Success(format string, a ...interface{}) {
	greenC.Printf("[+] ")
	fmt.Printf(format+"\n", a...)
}

// Warn выводит предупреждение ("[!] ...").
func Warn(format string, a ...interface{}) {
	yellowC.Printf("[!] ")
	fmt.Printf(format+"\n", a...)
}

// Error выводит сообщение об ошибке в stderr ("[-] ...").
func Error(format string, a ...interface{}) {
	redC.Fprintf(os.Stderr, "[-] ")
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

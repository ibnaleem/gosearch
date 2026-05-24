package theme

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type Theme struct {
	Reset     string
	Bold      string
	Underline string
	Red       string
	Green     string
	Yellow    string
	Blue      string
	Magenta   string
	Cyan      string
	White     string
	Gray      string
}

var LightTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[31m",
	Green:     "\033[32m",
	Yellow:    "\033[33m",
	Blue:      "\033[34m",
	Magenta:   "\033[35m",
	Cyan:      "\033[36m",
	White:     "\033[37m",
	Gray:      "\033[90m",
}

var DarkTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[91m",
	Green:     "\033[92m",
	Yellow:    "\033[93m",
	Blue:      "\033[94m",
	Magenta:   "\033[95m",
	Cyan:      "\033[96m",
	White:     "\033[97m",
	Gray:      "\033[37m",
}

var CurrentTheme = DarkTheme

func init() {
	CurrentTheme = detectTheme()
}

type Color string

func (c Color) String() string {
	return string(c)
}

func (c Color) Print() {
	fmt.Print(c)
}

func (c Color) Println() {
	fmt.Println(c)
}

func (c Color) Fprint(w io.Writer) {
	fmt.Fprint(w, c)
}

func (c Color) Fprintln(w io.Writer) {
	fmt.Fprintln(w, c)
}

func detectTheme() Theme {
	colorfgbg := os.Getenv("COLORFGBG")
	if strings.Contains(colorfgbg, ";0") {
		return DarkTheme
	} else if strings.Contains(colorfgbg, ";15") {
		return LightTheme
	}
	return DarkTheme
}

func Text(s string, colorCode string) Color {
	return Color(colorCode + s + CurrentTheme.Reset)
}

func Red(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Red)
}

func Green(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Green)
}

func Yellow(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Yellow)
}

func Blue(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Blue)
}

func Cyan(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Cyan)
}

func Magenta(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Magenta)
}

func White(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.White)
}

func Gray(args ...interface{}) Color {
	return Text(fmt.Sprint(args...), CurrentTheme.Gray)
}

func Redf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Red)
}

func Greenf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Green)
}

func Yellowf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Yellow)
}

func Bluef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Blue)
}

func Cyanf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Cyan)
}

func Magentaf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Magenta)
}

func Whitef(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.White)
}

func Grayf(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Gray)
}

func Bold(format string, args ...interface{}) Color {
	return Text(fmt.Sprintf(format, args...), CurrentTheme.Bold)
}

// Config file for theming

package main

import (
	"io"
	"os"
	"fmt"
	"strings"
)

type Theme struct {
	Reset     string // Reset formatting
	Bold      string // Bold text
	Underline string // Underlined text
	Red       string // Red text
	Green     string // Green text
	Yellow    string // Yellow text
	Blue      string // Blue text
	Magenta   string // Magenta text
	Cyan      string // Cyan text
	White     string // White text
	Gray      string // Gray text
}

var LightTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[31m", // Bright red for light background
	Green:     "\033[32m", // Forest green
	Yellow:    "\033[33m", // Dark yellow
	Blue:      "\033[34m", // Navy blue
	Magenta:   "\033[35m", // Dark magenta
	Cyan:      "\033[36m", // Dark cyan
	White:     "\033[37m", // Black for light background
	Gray:      "\033[90m", // Dark gray
}

var DarkTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[91m", // Light red for dark background
	Green:     "\033[92m", // Light green
	Yellow:    "\033[93m", // Bright yellow
	Blue:      "\033[94m", // Light blue
	Magenta:   "\033[95m", // Light magenta
	Cyan:      "\033[96m", // Light cyan
	White:     "\033[97m", // White for dark background
	Gray:      "\033[37m", // Light gray
}

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
		return DarkTheme // Dark background
	} else if strings.Contains(colorfgbg, ";15") {
		return LightTheme // Light background
	}
	return DarkTheme // Default
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
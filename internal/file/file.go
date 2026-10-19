package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// path separators plus characters Windows rejects in file names
var fileNameReplacer = strings.NewReplacer(
	"/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
)

type FileWriter struct {
	outputPath string
	createdAt  time.Time
}

func NewFileWriter(path string) *FileWriter {
	return &FileWriter{
		outputPath: path,
		createdAt:  time.Now(),
	}
}

func (fw *FileWriter) Write(username, content string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if err := os.MkdirAll(fw.outputPath, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// a username like "../x" must not escape the output directory
	fileName := fmt.Sprintf("%s_%s.txt", fileNameReplacer.Replace(username), fw.createdAt.Format("2006-01-02_15-04-05"))
	filePath := filepath.Join(fw.outputPath, fileName)

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}

	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	return nil
}

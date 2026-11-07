package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// path separators plus characters Windows rejects in file names
var fileNameReplacer = strings.NewReplacer(
	"/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
)

const maxUsernameFilenameBytes = 100

type FileWriter struct {
	outputPath string
	createdAt  time.Time

	mu      sync.Mutex
	created map[string]os.FileInfo
}

func NewFileWriter(path string) *FileWriter {
	return &FileWriter{
		outputPath: path,
		createdAt:  time.Now(),
		created:    make(map[string]os.FileInfo),
	}
}

func (fw *FileWriter) Write(username, content string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username cannot be empty")
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	if err := os.MkdirAll(fw.outputPath, 0700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// a username like "../x" must not escape the output directory
	fileName := fmt.Sprintf("%s_%s.txt", safeUsername(username), fw.createdAt.Format("2006-01-02_15-04-05"))
	filePath := filepath.Join(fw.outputPath, fileName)

	file, err := fw.open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	return nil
}

func safeUsername(username string) string {
	sanitized := fileNameReplacer.Replace(username)
	for len(sanitized) > maxUsernameFilenameBytes {
		_, size := utf8.DecodeLastRuneInString(sanitized)
		sanitized = sanitized[:len(sanitized)-size]
	}

	return sanitized
}

// open creates the file exclusively on first use, so a pre-planted file or
// symlink is refused, and later reopens it only if it is still that same file.
func (fw *FileWriter) open(filePath string) (*os.File, error) {
	want, known := fw.created[filePath]

	flags := os.O_WRONLY | os.O_APPEND
	if !known {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}

	file, err := os.OpenFile(filePath, flags, 0600)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat output file: %w", err)
	}

	if !known {
		fw.created[filePath] = info
		return file, nil
	}

	if !os.SameFile(want, info) {
		file.Close()
		return nil, fmt.Errorf("output file %s was replaced", filePath)
	}

	return file, nil
}

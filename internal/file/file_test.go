package file

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentWritesDoNotInterleave(t *testing.T) {
	dir := t.TempDir()
	fw := NewFileWriter(dir)

	const writers = 32
	chunk := func(i int) string {
		return strings.Repeat(string(rune('A'+i%26)), 256*1024) + "\n"
	}

	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			if err := fw.Write("john", chunk(i)); err != nil {
				t.Errorf("Write: %v", err)
			}
		})
	}
	wg.Wait()

	files, _ := filepath.Glob(filepath.Join(dir, "john_*.txt"))
	if len(files) != 1 {
		t.Fatalf("want 1 output file, got %v", files)
	}

	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != writers {
		t.Fatalf("got %d lines, want %d: chunks interleaved", len(lines), writers)
	}
	for i, line := range lines {
		if len(line) != 256*1024 || strings.Trim(line, line[:1]) != "" {
			t.Fatalf("line %d is a mix of chunks", i)
		}
	}
}

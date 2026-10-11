package tests

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/ibnaleem/gosearch/internal/file"
	"github.com/ibnaleem/gosearch/internal/modules"
	"github.com/ibnaleem/gosearch/internal/modules/breachdirectory"
	"github.com/ibnaleem/gosearch/internal/modules/github"
	"github.com/ibnaleem/gosearch/internal/modules/gravatar"
	"github.com/ibnaleem/gosearch/internal/modules/hudsonrock"
	"github.com/ibnaleem/gosearch/internal/modules/keybase"
	"github.com/ibnaleem/gosearch/internal/modules/proxynova"
	"github.com/ibnaleem/gosearch/internal/modules/search"
)

func TestCheckStatus(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"ok", http.StatusOK, false},
		{"not found passes through", http.StatusNotFound, false},
		{"forbidden", http.StatusForbidden, true},
		{"too many requests", http.StatusTooManyRequests, true},
		{"server error", http.StatusInternalServerError, true},
		{"bad request", http.StatusBadRequest, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := modules.CheckStatus("Test", "fn", c.status)
			if (err != nil) != c.wantErr {
				t.Fatalf("CheckStatus(%d) error = %v, wantErr %v", c.status, err, c.wantErr)
			}
		})
	}
}

func TestFileWriterAppendsWithinOneRun(t *testing.T) {
	dir := t.TempDir()

	fw := file.NewFileWriter(dir)
	if err := fw.Write("user", "a\n"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := fw.Write("user", "b\n"); err != nil {
		t.Fatalf("second write: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 file within one run, got %d", len(entries))
	}

	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "a\nb\n" {
		t.Fatalf("want appended content %q, got %q", "a\nb\n", got)
	}
}

func TestFileWriterNamesFilePerRun(t *testing.T) {
	dir := t.TempDir()

	fw := file.NewFileWriter(dir)
	if err := fw.Write("user", "x\n"); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 file, got %d", len(entries))
	}

	pattern := regexp.MustCompile(`^user_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt$`)
	if name := entries[0].Name(); !pattern.MatchString(name) {
		t.Fatalf("file name %q does not match per-run timestamp pattern", name)
	}
}

func TestFileWriterRejectsBlankUsername(t *testing.T) {
	fw := file.NewFileWriter(t.TempDir())
	if err := fw.Write("   ", "x"); err == nil {
		t.Fatal("want error for blank username, got nil")
	}
}

func TestModuleNames(t *testing.T) {
	fw := file.NewFileWriter(t.TempDir())

	cases := []struct {
		module modules.Module
		want   string
	}{
		{gravatar.NewGravatarClient(fw), "Gravatar"},
		{hudsonrock.NewHudsonRockClient(fw), "HudsonRock"},
		{keybase.NewKeyBaseClient(fw), "KeyBase"},
		{proxynova.NewProxyNovaClient(fw), "ProxyNova"},
		{github.NewGithubClient(fw), "Github"},
		{breachdirectory.NewBreachDirectoryClient(fw, ""), "BreachDirectory"},
		{search.NewSearchClient(fw, false), "Search"},
	}

	for _, c := range cases {
		if got := c.module.Name(); got != c.want {
			t.Errorf("Name() = %q, want %q", got, c.want)
		}
	}
}

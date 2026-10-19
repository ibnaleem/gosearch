package tests

import (
	"fmt"
	"net/http"
	"net/url"
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

func TestFileWriterStaysInOutputDir(t *testing.T) {
	for _, username := range []string{"../escaped", "../../etc/passwd", `..\..\x`, "a/b", "c:evil"} {
		t.Run(username, func(t *testing.T) {
			root := t.TempDir()
			out := filepath.Join(root, "out")

			fw := file.NewFileWriter(out)
			if err := fw.Write(username, "x\n"); err != nil {
				t.Fatalf("write: %v", err)
			}

			rootEntries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}

			if len(rootEntries) != 1 || rootEntries[0].Name() != "out" {
				t.Fatalf("file was written outside the output directory: %v", rootEntries)
			}

			outEntries, err := os.ReadDir(out)
			if err != nil {
				t.Fatal(err)
			}

			if len(outEntries) != 1 || outEntries[0].IsDir() {
				t.Fatalf("want 1 file directly inside the output directory, got %v", outEntries)
			}
		})
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
		{github.NewGitHubClient(fw), "Github"},
		{breachdirectory.NewBreachDirectoryClient(fw, ""), "BreachDirectory"},
		{search.NewSearchClient(fw, false), "Search"},
	}

	for _, c := range cases {
		if got := c.module.Name(); got != c.want {
			t.Errorf("Name() = %q, want %q", got, c.want)
		}
	}
}

// The two tests below lock in why the username-in-path modules (e.g. gravatar)
// build their endpoints with url.PathEscape. The username comes from user input
// and is placed into a URL path segment (/{username}.json); without escaping, a
// URL-special character either breaks the request or silently redirects it.
//
// They mirror the exact construction used in buildRequest rather than calling it,
// since buildRequest is unexported and performs a network request.

func TestPathEscapeKeepsUsernameInPathSegment(t *testing.T) {
	cases := []string{"100%", "foo#bar", "foo?bar", "a/b"}

	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			endpoint := fmt.Sprintf("https://gravatar.com/%s.json", url.PathEscape(in))

			req, err := http.NewRequest(http.MethodGet, endpoint, nil)
			if err != nil {
				t.Fatalf("escaped URL failed to build for %q: %v", in, err)
			}

			if req.URL.RawQuery != "" || req.URL.Fragment != "" {
				t.Fatalf("username leaked for %q: query=%q fragment=%q", in, req.URL.RawQuery, req.URL.Fragment)
			}

			if want := "/" + in + ".json"; req.URL.Path != want {
				t.Fatalf("path = %q, want %q", req.URL.Path, want)
			}
		})
	}
}

func TestPlainConcatBreaksOnSpecialChars(t *testing.T) {
	// With a naive fmt.Sprintf (no escaping) each of these is wrong: the request
	// either fails to build or the username leaks out of the path.
	cases := []string{"100%", "foo#bar", "foo?bar"}

	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			endpoint := fmt.Sprintf("https://gravatar.com/%s.json", in)

			req, err := http.NewRequest(http.MethodGet, endpoint, nil)
			if err != nil {
				return // e.g. "100%" fails to parse — exactly the bug PathEscape avoids
			}

			leaked := req.URL.RawQuery != "" ||
				req.URL.Fragment != "" ||
				req.URL.Path != "/"+in+".json"

			if !leaked {
				t.Fatalf("expected naive URL for %q to be malformed, got path=%q query=%q fragment=%q",
					in, req.URL.Path, req.URL.RawQuery, req.URL.Fragment)
			}
		})
	}
}

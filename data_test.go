package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/ibnaleem/gosearch/internal/models"
)

// TestDataJSON guards data.json: it must exist, parse strictly into the
// models.Data schema, and contain no duplicate or malformed site entries.
func TestDataJSON(t *testing.T) {
	raw, err := os.ReadFile("data.json")
	if err != nil {
		t.Fatalf("data.json missing or unreadable: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // catches typo'd keys like "error_type"
	var data models.Data
	if err := dec.Decode(&data); err != nil {
		t.Fatalf("data.json is not valid against models.Data: %v", err)
	}
	// dec.More() misses a stray '}' or ']'; a second Decode must hit EOF.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("data.json has trailing content after the top-level object")
	}
	if len(data.Websites) == 0 {
		t.Fatal("data.json has no websites")
	}

	names := map[string]int{}
	urls := map[string]int{}
	for i, w := range data.Websites {
		if name := strings.ToLower(strings.TrimSpace(w.Name)); name == "" {
			t.Errorf("website #%d has an empty name", i)
		} else if j, dup := names[name]; dup {
			t.Errorf("duplicate name %q at #%d and #%d", w.Name, j, i)
		} else {
			names[name] = i
		}

		if j, dup := urls[w.BaseURL]; dup {
			t.Errorf("%s: duplicate base_url %q (also #%d)", w.Name, w.BaseURL, j)
		}
		urls[w.BaseURL] = i

		checkURL(t, w.Name, "base_url", w.BaseURL)
		if w.URLProbe != "" {
			checkURL(t, w.Name, "url_probe", w.URLProbe)
		}

		switch w.ErrorType {
		case "status_code", "unknown": // errorCode is optional: any status >= 400 counts as not found
		case "errorMsg", "profilePresence":
			if w.ErrorMsg == "" {
				t.Errorf("%s: errorType %s needs errorMsg", w.Name, w.ErrorType)
			}
		case "response_url":
			if w.ResponseURL == "" {
				t.Errorf("%s: errorType response_url needs response_url", w.Name)
			}
		default:
			t.Errorf("%s: invalid errorType %q", w.Name, w.ErrorType)
		}
	}
}

func checkURL(t *testing.T, site, field, raw string) {
	t.Helper()
	if !strings.Contains(raw, "{}") {
		t.Errorf("%s: %s %q has no {} username placeholder", site, field, raw)
	}
	u, err := url.Parse(strings.ReplaceAll(raw, "{}", "x"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		t.Errorf("%s: %s %q is not a valid http(s) URL", site, field, raw)
	}
}

package darkeye

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is kept", "Acme Corp", "Acme Corp"},
		{"escape sequences lose their escape", "\x1b[31mACME\x1b[0m", "[31mACME[0m"},
		{"bell and backspace are dropped", "a\x07b\x08c", "abc"},
		{"C1 controls are dropped", "a\u009bb", "ab"},
		{"bidi overrides are dropped", "a‮b⁦c", "abc"},
		{"newlines and tabs become one space", "a\r\n\tb\n\nc", "a b c"},
		{"invalid utf-8 is dropped", "a\xffb", "ab"},
		{"surrounding space is trimmed", "  a  ", "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clean(tt.in); got != tt.want {
				t.Errorf("clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCleanCapsLength(t *testing.T) {
	got := clean(strings.Repeat("é", maxTextRunes+50))
	if want := strings.Repeat("é", maxTextRunes); got != want {
		t.Errorf("clean kept %d runes (%q), want %d whole runes", len([]rune(got)), got, maxTextRunes)
	}
}

func TestTextUnmarshal(t *testing.T) {
	var got struct {
		A text `json:"a"`
		B text `json:"b"`
		C text `json:"c"`
		D text `json:"d"`
		E text `json:"e"`
	}

	if err := json.Unmarshal([]byte(`{"a":"x","b":42,"c":null,"d":true,"e":{"k":1}}`), &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.A != "x" || got.B != "42" || got.C != "" || got.D != "" || got.E != "" {
		t.Errorf("got %+v, want a=x b=42 and the rest empty", got)
	}
}

func TestTextUnmarshalKeepsNumbersAsWritten(t *testing.T) {
	var got struct {
		A text `json:"a"`
		B text `json:"b"`
		C text `json:"c"`
		D text `json:"d"`
	}

	body := `{"a":1e1000,"b":{"value":1e1000},"c":[1e1000],"d":-12.50}`
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.A != "1e1000" || got.B != "" || got.C != "" || got.D != "-12.50" {
		t.Errorf("got %+v, want a=1e1000 d=-12.50 and the rest empty", got)
	}
}

func TestNewRecordKeepsListingMetadataOnly(t *testing.T) {
	var item listing
	body := `{"id_source":"s-1","post_title":"Acme","website":"acme.example","group_name":"grp",
		"country":"US","discovered":"2025-01-02T03:04:05Z","password":"hunter2","hash":"abc"}`
	if err := json.Unmarshal([]byte(body), &item); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := newRecord("P", "breach", item)
	want := record{Product: "P", Category: "breach", ID: "s-1", Title: "Acme", Website: "acme.example", Group: "grp", Country: "US", Date: "2025-01-02"}
	if got != want {
		t.Errorf("newRecord = %+v, want %+v", got, want)
	}
}

func TestNewRecordFallsBackToAlternativeFields(t *testing.T) {
	var item listing
	if err := json.Unmarshal([]byte(`{"victim_id":7,"name":"Fallback"}`), &item); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := newRecord("P", "leak", item)
	if got.ID != "7" || got.Title != "Fallback" {
		t.Errorf("newRecord = %+v, want id 7 and title Fallback", got)
	}
}

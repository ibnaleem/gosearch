package breachdirectory

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSearchPrintsToGivenWriter(t *testing.T) {
	var out bytes.Buffer
	bdc := NewBreachDirectoryClient(&out, nil, nil, "")

	if _, err := bdc.Search(context.Background(), "john"); err != nil {
		t.Fatalf("Search: %v", err)
	}

	if !strings.Contains(out.String(), "Skipping Breach Directory") {
		t.Fatalf("output = %q, want the skip notice", out.String())
	}
}

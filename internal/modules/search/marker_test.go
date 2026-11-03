package search

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ibnaleem/gosearch/internal/config"
)

func TestSearchSiteCountsOversizedMarkerBodyAsUnchecked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer server.Close()

	defer func(old int64) { maxMarkerBytes = old }(maxMarkerBytes)
	maxMarkerBytes = 50

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}
	sites := []website{{Name: "big", BaseURL: server.URL + "/{}", ErrorType: "errorMsg", ErrorMsg: "not found"}}

	found, _, err := sc.searchSite(context.Background(), "john", sites)
	if err != nil {
		t.Fatalf("searchSite error: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("found = %v, want none: a truncated body could fake a missing marker", found)
	}
	if !strings.Contains(out.String(), "1 site(s) could not be checked") {
		t.Fatalf("output = %q, want the oversized site counted as unchecked", out.String())
	}
}

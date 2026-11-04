package search

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSearchSiteMissingResponseURLIsUnverified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var out bytes.Buffer
	sc := &searchClient{
		out:             &out,
		httpClient:      server.Client(),
		noFalsePositive: false,
	}

	found, uncertain, err := sc.searchSite(context.Background(), "john", []website{{
		Name:        "missing metadata",
		BaseURL:     server.URL + "/user/{}",
		ErrorType:   "response_url",
		ResponseURL: "",
	}})
	if err != nil {
		t.Fatalf("searchSite error: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("found = %v, want none", found)
	}
	if len(uncertain) != 1 || uncertain[0] != server.URL+"/user/john" {
		t.Fatalf("uncertain = %v, want the site URL", uncertain)
	}
}

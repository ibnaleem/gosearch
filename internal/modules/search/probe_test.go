package search

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
)

func TestSearchSiteGivesUpOnHangingSite(t *testing.T) {
	release := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hanging.Close()
	defer close(release)

	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer live.Close()

	defer func(old time.Duration) { probeTimeout = old }(probeTimeout)
	probeTimeout = 200 * time.Millisecond

	sc := &searchClient{httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}
	sites := []website{
		{Name: "hang", BaseURL: hanging.URL + "/{}", ErrorType: "status_code"},
		{Name: "live", BaseURL: live.URL + "/{}", ErrorType: "status_code"},
	}

	start := time.Now()
	found, _, err := sc.searchSite(context.Background(), "john", sites)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("searchSite error: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("searchSite took %v; a hanging site must give up after probeTimeout", elapsed)
	}
	if len(found) != 1 || found[0] != live.URL+"/john" {
		t.Fatalf("found = %v, want only the live site", found)
	}
}

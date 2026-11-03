package search

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ibnaleem/gosearch/internal/config"
)

func TestSearchSitePropagatesCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer hanging.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}
	sites := []website{{Name: "hang", BaseURL: hanging.URL + "/{}", ErrorType: "status_code"}}

	_, _, err := sc.searchSite(ctx, "john", sites)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("searchSite error = %v, want context.Canceled", err)
	}
	if strings.Contains(out.String(), "No sites found") {
		t.Fatalf("output = %q, a cancelled sweep must not report a clean no-results", out.String())
	}
}

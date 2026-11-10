package search

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
)

func TestSearchSiteKeepsPartialResultsOnCancel(t *testing.T) {
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
	if err != nil {
		t.Fatalf("searchSite error = %v, want nil (partial results on cancel)", err)
	}
	if !strings.Contains(out.String(), "interrupted") {
		t.Fatalf("output = %q, want an interrupted notice", out.String())
	}
	if strings.Contains(out.String(), "No sites found") {
		t.Fatalf("output = %q, a cancelled sweep must not report a clean no-results", out.String())
	}
}

func TestSearchSiteKeepsPartialResultsOnTimeout(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer fast.Close()

	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hanging.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}
	sites := []website{
		{Name: "fast", BaseURL: fast.URL + "/{}", ErrorType: "status_code", ErrorCode: http.StatusNotFound},
		{Name: "hang", BaseURL: hanging.URL + "/{}", ErrorType: "status_code", ErrorCode: http.StatusNotFound},
	}

	found, _, err := sc.searchSite(ctx, "john", sites)
	if err != nil {
		t.Fatalf("searchSite error = %v, want nil (partial results on timeout)", err)
	}

	want := fast.URL + "/john"
	if len(found) != 1 || found[0] != want {
		t.Fatalf("found = %v, want only %s", found, want)
	}
	if !strings.Contains(out.String(), "timed out") {
		t.Fatalf("output = %q, want a timed out notice", out.String())
	}
	if !strings.Contains(out.String(), want) {
		t.Fatalf("output = %q, want the partial result %s listed", out.String(), want)
	}
}

// a deadline used up by the domain search must not turn into a buildResources
// error, or Search would drop the domains it already found
func TestBuildResourcesReturnsNoSitesWhenContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}

	resources, err := sc.buildResources(ctx)
	if err != nil {
		t.Fatalf("buildResources error = %v, want nil", err)
	}
	if resources == nil || len(resources.Websites) != 0 {
		t.Fatalf("resources = %+v, want no sites", resources)
	}
	if strings.Contains(out.String(), "local copy") {
		t.Fatalf("output = %q, a done context must not fall back to the local data.json", out.String())
	}
}

func TestSearchSiteSkipsEmptySiteList(t *testing.T) {
	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}

	found, uncertain, err := sc.searchSite(context.Background(), "john", nil)
	if err != nil || found != nil || uncertain != nil {
		t.Fatalf("searchSite = (%v, %v, %v), want (nil, nil, nil)", found, uncertain, err)
	}
	if out.Len() != 0 {
		t.Fatalf("output = %q, want nothing printed for an empty site list", out.String())
	}
}

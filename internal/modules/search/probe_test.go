package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
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

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}
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
	if !strings.Contains(out.String(), "Searching 2 site(s)") {
		t.Fatalf("output = %q, want the progress line in the given writer", out.String())
	}
}

func TestSearchSiteBoundsConcurrentProbes(t *testing.T) {
	var (
		mu             sync.Mutex
		inFlight, peak int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		mu.Unlock()

		time.Sleep(20 * time.Millisecond)

		mu.Lock()
		inFlight--
		mu.Unlock()
	}))
	defer server.Close()

	defer func(old int) { maxProbes = old }(maxProbes)
	maxProbes = 4

	var sites []website
	for i := range 5 * maxProbes {
		sites = append(sites, website{Name: fmt.Sprint(i), BaseURL: fmt.Sprintf("%s/%d/{}", server.URL, i), ErrorType: "status_code"})
	}

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}

	found, _, err := sc.searchSite(context.Background(), "john", sites)
	if err != nil {
		t.Fatalf("searchSite error: %v", err)
	}
	if len(found) != len(sites) {
		t.Fatalf("found %d sites, want all %d probed", len(found), len(sites))
	}
	if peak > maxProbes {
		t.Fatalf("peak concurrent probes = %d, want at most %d", peak, maxProbes)
	}
}

func TestSearchSiteReportsBodyReadTimeoutAsFailedProbe(t *testing.T) {
	release := make(chan struct{})
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer stalled.Close()
	defer close(release)

	defer func(old time.Duration) { probeTimeout = old }(probeTimeout)
	probeTimeout = 200 * time.Millisecond

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: config.NewHTTPClient()}
	sites := []website{{Name: "stalled", BaseURL: stalled.URL + "/{}", ErrorType: "errorMsg", ErrorMsg: "not found"}}

	if _, _, err := sc.searchSite(context.Background(), "john", sites); err != nil {
		t.Fatalf("searchSite error: %v", err)
	}
	if !strings.Contains(out.String(), "1 site(s) could not be checked") {
		t.Fatalf("output = %q, want the stalled site counted as unchecked", out.String())
	}
}

func TestSearchSiteFollowsRedirectsUnlessDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/john") {
			http.Redirect(w, r, "/missing", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	noRedirect := config.NewHTTPClient()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	for _, tc := range []struct {
		entry     string
		wantFound bool
	}{
		{`{"name": "default", "base_url": "` + server.URL + `/default/{}", "errorType": "status_code", "errorCode": 302}`, true},
		{`{"name": "disabled", "base_url": "` + server.URL + `/disabled/{}", "errorType": "status_code", "errorCode": 302, "follow_redirects": false}`, false},
		{`{"name": "enabled", "base_url": "` + server.URL + `/enabled/{}", "errorType": "status_code", "errorCode": 302, "follow_redirects": true}`, true},
	} {
		var site website
		if err := json.Unmarshal([]byte(tc.entry), &site); err != nil {
			t.Fatalf("decode %s: %v", tc.entry, err)
		}

		var out bytes.Buffer
		sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: noRedirect}

		found, _, err := sc.searchSite(context.Background(), "john", []website{site})
		if err != nil {
			t.Fatalf("%s: searchSite error: %v", site.Name, err)
		}
		if got := len(found) == 1; got != tc.wantFound {
			t.Fatalf("%s: found = %v, want found=%v", site.Name, found, tc.wantFound)
		}
	}
}

func TestSearchSiteCountsUnexpectedRedirectAsUnchecked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/challenge/john"):
			http.Redirect(w, r, "/bot-check", http.StatusTemporaryRedirect)
		case strings.HasSuffix(r.URL.Path, "/missing/john"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer server.Close()

	noRedirect := config.NewHTTPClient()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	no := false
	site := func(name string) website {
		return website{Name: name, BaseURL: server.URL + "/" + name + "/{}", ErrorType: "status_code", ErrorCode: 200, FollowRedirects: &no}
	}

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: config.NewHTTPClient(), noRedirectHTTPClient: noRedirect}

	found, _, err := sc.searchSite(context.Background(), "john", []website{site("challenge"), site("missing"), site("present")})
	if err != nil {
		t.Fatalf("searchSite error: %v", err)
	}
	if want := []string{server.URL + "/present/john"}; !slices.Equal(found, want) {
		t.Fatalf("found = %v, want %v", found, want)
	}
	if !strings.Contains(out.String(), "1 site(s) could not be checked (rate limited, redirected") {
		t.Fatalf("output = %q, want the redirected site counted as unchecked", out.String())
	}
}

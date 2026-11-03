package search

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"
)

type blockingTransport struct{}

func (blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestSearchDomainGivesUpOnHangingDomain(t *testing.T) {
	defer func(old time.Duration) { probeTimeout = old }(probeTimeout)
	probeTimeout = 50 * time.Millisecond

	var out bytes.Buffer
	sc := &searchClient{out: &out, httpClient: &http.Client{Transport: blockingTransport{}}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	found, err := sc.searchDomain(ctx, "abc")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("searchDomain error: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("found = %v, want none", found)
	}
	if elapsed > time.Second {
		t.Fatalf("searchDomain took %v; a hanging domain must give up after probeTimeout", elapsed)
	}
}

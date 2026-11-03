package search

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

type blockingTransport struct {
	mu        sync.Mutex
	deadlines map[string][]time.Time
	schemes   map[string][]string
}

func (b *blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	deadline, _ := r.Context().Deadline()

	b.mu.Lock()
	if b.deadlines == nil {
		b.deadlines = map[string][]time.Time{}
		b.schemes = map[string][]string{}
	}
	b.deadlines[r.URL.Host] = append(b.deadlines[r.URL.Host], deadline)
	b.schemes[r.URL.Host] = append(b.schemes[r.URL.Host], r.URL.Scheme)
	b.mu.Unlock()

	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestSearchDomainGivesUpOnHangingDomain(t *testing.T) {
	defer func(old time.Duration) { probeTimeout = old }(probeTimeout)
	probeTimeout = 50 * time.Millisecond

	var out bytes.Buffer
	transport := &blockingTransport{}
	sc := &searchClient{out: &out, httpClient: &http.Client{Transport: transport}}

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

	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.deadlines) == 0 {
		t.Fatal("no requests were made")
	}
	for host, deadlines := range transport.deadlines {
		schemes := transport.schemes[host]
		if len(deadlines) != 2 || schemes[0] != "https" || schemes[1] != "http" {
			t.Fatalf("%s: schemes = %v, want [https http]", host, schemes)
		}
		if !deadlines[0].Equal(deadlines[1]) {
			t.Fatalf("%s: https and http attempts have different deadlines (%v vs %v); they must share one probeTimeout", host, deadlines[0], deadlines[1])
		}
	}
}

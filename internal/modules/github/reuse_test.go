package github

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestMutualFollowerChecksReuseOneConnection(t *testing.T) {
	var connections atomic.Int32

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	var dialer net.Dialer
	ghc := &gitHubClient{httpClient: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
	}}}

	followers := []gitHubFollowersResponse{{Login: "a"}, {Login: "b"}, {Login: "c"}}

	if _, err := ghc.buildMutualFollowersRequest(context.Background(), "someone", followers); err != nil {
		t.Fatal(err)
	}

	if got := connections.Load(); got != 1 {
		t.Fatalf("opened %d connections for 3 checks, want 1", got)
	}
}

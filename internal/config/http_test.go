package config

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRefusePrivateAddress(t *testing.T) {
	for _, tc := range []struct {
		address string
		wantErr bool
	}{
		{"127.0.0.1:80", true},
		{"[::1]:80", true},
		{"[::ffff:127.0.0.1]:80", true},
		{"10.0.0.1:80", true},
		{"192.168.1.1:80", true},
		{"169.254.169.254:80", true},
		{"[fe80::1]:80", true},
		{"[fd00::1]:80", true},
		{"0.0.0.0:80", true},
		{"224.0.0.1:80", true},
		{"8.8.8.8:443", false},
		{"[2606:4700::1111]:443", false},
	} {
		err := refusePrivateAddress("tcp", tc.address, nil)
		if (err != nil) != tc.wantErr {
			t.Errorf("refusePrivateAddress(%s) error = %v, wantErr %v", tc.address, err, tc.wantErr)
		}
	}
}

func TestNewPublicHTTPClientRefusesLoopback(t *testing.T) {
	if proxy, _ := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}); proxy != nil {
		t.Skip("a proxy is set in the environment, so the dial guard is off")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	response, err := NewHTTPClient().Get(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPClient().Get: %v", err)
	}
	response.Body.Close()

	if response, err := NewPublicHTTPClient().Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("NewPublicHTTPClient().Get a loopback server succeeded, want a refused dial")
	}
}

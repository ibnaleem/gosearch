package weakpass

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func crackerReturning(status int, body string) *HashCracker {
	return &HashCracker{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}}
}

func TestCrackHashForbiddenReturnsError(t *testing.T) {
	got, err := crackerReturning(http.StatusForbidden, "").CrackHash(context.Background(), "abc")
	if err == nil {
		t.Fatal("err = nil, want an error on HTTP 403")
	}
	if got != "" {
		t.Fatalf("got %q, want empty password", got)
	}
}

func TestCrackHashNotFoundIsUncracked(t *testing.T) {
	got, err := crackerReturning(http.StatusNotFound, "").CrackHash(context.Background(), "abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty password", got)
	}
}

func TestCrackHashReturnsPassword(t *testing.T) {
	got, err := crackerReturning(http.StatusOK, `{"pass":"x"}`).CrackHash(context.Background(), "abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "x" {
		t.Fatalf("got %q, want x", got)
	}
}

package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMutualFollowersKeepsMatchesFoundBeforeCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ghc := &gitHubClient{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}}

	followers := []gitHubFollowersResponse{{Login: "alice"}, {Login: "bob"}}

	got, err := ghc.buildMutualFollowersRequest(ctx, "someone", followers)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("mutual followers = %v, want [alice]", got)
	}
}

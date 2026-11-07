package modules

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fetchPayload struct {
	Name string `json:"name"`
}

func serve(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestFetchJSONNotFoundReturnsErrNotFound(t *testing.T) {
	server := serve(t, http.StatusNotFound, `{"message":"Not Found"}`)

	got, err := FetchJSON[fetchPayload](context.Background(), server.Client(), server.URL, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if got != nil {
		t.Fatalf("got %+v, want nil result on 404", got)
	}
}

func TestFetchJSONDecodesSuccess(t *testing.T) {
	server := serve(t, http.StatusOK, `{"name":"zero"}`)

	got, err := FetchJSON[fetchPayload](context.Background(), server.Client(), server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "zero" {
		t.Fatalf("Name = %q, want zero", got.Name)
	}
}

func TestFetchJSONServerErrorFails(t *testing.T) {
	server := serve(t, http.StatusInternalServerError, `{"name":"zero"}`)

	got, err := FetchJSON[fetchPayload](context.Background(), server.Client(), server.URL, nil)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want a non-ErrNotFound error", err)
	}
	if got != nil {
		t.Fatalf("got %+v, want nil result on 500", got)
	}
}

func TestReadBodyEnforcesLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"under limit", 9, false},
		{"at limit", 10, false},
		{"one over limit", 11, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := ReadBody(strings.NewReader(strings.Repeat("x", tc.size)), 10)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && len(body) != tc.size {
				t.Fatalf("read %d bytes, want %d", len(body), tc.size)
			}
		})
	}
}

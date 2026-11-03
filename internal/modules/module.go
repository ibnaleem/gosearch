package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ibnaleem/gosearch/internal/config"
)

// ErrNotFound is returned by FetchJSON on HTTP 404. Callers decide whether a
// 404 means a missing record or a real failure for their endpoint.
var ErrNotFound = errors.New("not found (HTTP 404)")

// MaxBodyBytes caps an API response read into memory
const MaxBodyBytes = 10 << 20

// ReadBody reads all of r and errors if it holds more than limit bytes, so a
// hostile or broken server can't make the process buffer an unbounded body.
func ReadBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(body)) > limit {
		return nil, fmt.Errorf("body exceeds %d bytes", limit)
	}

	return body, nil
}

type Module interface {
	Name() string
	Search(ctx context.Context, query string) (*Result, error)
}

type Result struct {
	Module  string
	Summary string
}

// FetchJSON sends a GET request to endpoint and decodes the JSON body into T.
// headers are applied after the defaults, so they can override Accept.
// Errors are returned unlabelled; the caller wraps them with its module name.
func FetchJSON[T any](ctx context.Context, httpClient *http.Client, endpoint string, headers map[string]string) (*T, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/json")

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer response.Body.Close()

	switch status := response.StatusCode; {
	case status == http.StatusNotFound:
		return nil, ErrNotFound

	case status == http.StatusTooManyRequests || status == http.StatusForbidden:
		return nil, fmt.Errorf("rate limit exceeded or access denied (HTTP %d)", status)

	case status >= 400:
		return nil, fmt.Errorf("unexpected status %d", status)
	}

	body, err := ReadBody(response.Body, MaxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

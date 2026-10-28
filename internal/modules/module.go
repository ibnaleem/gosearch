package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ibnaleem/gosearch/internal/config"
)

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
	case status == http.StatusTooManyRequests || status == http.StatusForbidden:
		return nil, fmt.Errorf("rate limit exceeded or access denied (HTTP %d)", status)

	case status >= 400 && status != http.StatusNotFound:
		return nil, fmt.Errorf("unexpected status %d", status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

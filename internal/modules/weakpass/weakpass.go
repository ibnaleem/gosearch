package weakpass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/modules"
)

// HashCracker resolves password hashes to plaintext through weakpass.com. It is
// not a module: main.go creates one and passes it to every module that gets
// password hashes, so they all share one client and connection pool.
type HashCracker struct {
	httpClient *http.Client
}

type weakpassResponse struct {
	Type     string `json:"type"`
	Hash     string `json:"hash"`
	Password string `json:"pass"`
}

func NewHashCracker() *HashCracker {
	httpClient := config.NewHTTPClient()

	return &HashCracker{
		httpClient: httpClient,
	}
}

// CrackHash looks up a SHA-1 hash on weakpass.com and returns its plaintext.
// It returns "" with no error when the hash is empty or unknown to Weakpass
// (404). A rate-limited or denied lookup (403) and any other failure are
// errors, so callers can tell "not cracked" from "not checked".
func (hc *HashCracker) CrackHash(ctx context.Context, hash string) (string, error) {
	if hash == "" {
		return "", nil
	}

	endpoint := fmt.Sprintf("https://weakpass.com/api/v1/search/%s.json", url.PathEscape(hash))

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("weakpass: build request: %w", err)
	}

	request.Header.Set("User-Agent", config.DefaultUserAgent)
	request.Header.Set("Accept", "application/json")

	response, err := hc.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("weakpass: send request: %w", err)
	}

	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusNotFound:
		return "", nil

	case response.StatusCode == http.StatusForbidden:
		return "", errors.New("weakpass: rate limited or access denied (HTTP 403)")

	case response.StatusCode < 200 || response.StatusCode >= 300:
		return "", fmt.Errorf("weakpass: unexpected status %d", response.StatusCode)
	}

	body, err := modules.ReadBody(response.Body, modules.MaxBodyBytes)
	if err != nil {
		return "", fmt.Errorf("weakpass: read response: %w", err)
	}

	var weakpassResponse weakpassResponse
	if err := json.Unmarshal(body, &weakpassResponse); err != nil {
		return "", fmt.Errorf("weakpass: decode response: %w", err)
	}

	return weakpassResponse.Password, nil
}

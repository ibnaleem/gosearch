package weakpass

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ibnaleem/gosearch/internal/config"
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
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: config.TLSConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	return &HashCracker{
		httpClient: httpClient,
	}
}

// CrackHash looks up a SHA-1 hash on weakpass.com and returns its plaintext.
// It returns "" with no error when the hash is empty, unknown to Weakpass
// (404) or the lookup is rate-limited (403); any other failure is an error.
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
	case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound:
		// 403 (rate limited) and 404 (hash not in Weakpass) just mean "not cracked".
		return "", nil

	case response.StatusCode < 200 || response.StatusCode >= 300:
		return "", fmt.Errorf("weakpass: unexpected status %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("weakpass: read response: %w", err)
	}

	var weakpassResponse weakpassResponse
	if err := json.Unmarshal(body, &weakpassResponse); err != nil {
		return "", fmt.Errorf("weakpass: decode response: %w", err)
	}

	return weakpassResponse.Password, nil
}

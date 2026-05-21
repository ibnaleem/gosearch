package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ibnaleem/gosearch/internal/config"
)

type GitHubSSHKey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

func FetchSSHKeys(username string) ([]GitHubSSHKey, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s/users/%s/keys", githubAPIBase, username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	setAuthHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching SSH keys: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d — unauthenticated requests are limited to 60 req/hour; set GITHUB_TOKEN for 5,000 req/hour", resp.StatusCode)
	}

	var keys []GitHubSSHKey
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("error parsing SSH keys: %w", err)
	}

	return keys, nil
}

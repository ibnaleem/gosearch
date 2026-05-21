package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
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

func DisplaySSHKeys(username string) {
	theme.Yellow("[*] Fetching SSH keys for ", username, "...").Println()

	keys, err := FetchSSHKeys(username)
	if err != nil {
		theme.Redf("[-] Error fetching SSH keys: %v", err).Println()
		return
	}

	if len(keys) == 0 {
		theme.Yellow("[!] No public SSH keys found").Println()
		utils.WriteToFile(username, "[!] No public SSH keys found\n")
		return
	}

	theme.Greenf("[+] Found %d SSH key(s):", len(keys)).Println()
	utils.WriteToFile(username, fmt.Sprintf("[+] Found %d SSH key(s):\n", len(keys)))

	for _, key := range keys {
		keyType := strings.SplitN(key.Key, " ", 2)[0]
		theme.Greenf("[+] ↳ %s (id: %d)", keyType, key.ID).Println()
		utils.WriteToFile(username, fmt.Sprintf("[+] ↳ %s (id: %d)\n", keyType, key.ID))
	}
}

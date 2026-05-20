package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ibnaleem/gosearch/internal/config"
	"github.com/ibnaleem/gosearch/internal/theme"
	"github.com/ibnaleem/gosearch/internal/utils"
)

type GitHubGPGKey struct {
	Name      string           `json:"name"`
	KeyID     string           `json:"key_id"`
	Emails    []GitHubGPGEmail `json:"emails"`
	CreatedAt string           `json:"created_at"`
	ExpiresAt *string          `json:"expires_at"`
	Revoked   bool             `json:"revoked"`
}

type GitHubGPGEmail struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

func FetchGPGKeys(username string) ([]GitHubGPGKey, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s/users/%s/gpg_keys", githubAPIBase, username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	setAuthHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching GPG keys: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d — unauthenticated requests are limited to 60 req/hour; set GITHUB_TOKEN for 5,000 req/hour", resp.StatusCode)
	}

	var keys []GitHubGPGKey
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("error parsing GPG keys: %w", err)
	}

	return keys, nil
}

func DisplayGPGKeys(username string) {
	theme.Yellow("[*] Fetching GPG keys for ", username, "...").Println()

	keys, err := FetchGPGKeys(username)
	if err != nil {
		theme.Redf("[-] Error fetching GPG keys: %v", err).Println()
		return
	}

	if len(keys) == 0 {
		theme.Yellow("[!] No public GPG keys found").Println()
		utils.WriteToFile(username, "[!] No public GPG keys found\n")
		return
	}

	theme.Greenf("[+] Found %d GPG key(s):", len(keys)).Println()
	utils.WriteToFile(username, fmt.Sprintf("[+] Found %d GPG key(s):\n", len(keys)))

	for _, key := range keys {
		if key.Name != "" {
			theme.Greenf("[+] ↳ %s (fingerprint: %s)", key.Name, key.KeyID).Println()
			utils.WriteToFile(username, fmt.Sprintf("[+] ↳ %s (fingerprint: %s)\n", key.Name, key.KeyID))
		} else {
			theme.Greenf("[+] ↳ fingerprint: %s", key.KeyID).Println()
			utils.WriteToFile(username, fmt.Sprintf("[+] ↳ fingerprint: %s\n", key.KeyID))
		}

		for _, email := range key.Emails {
			verified := ""
			if email.Verified {
				verified = " (verified)"
			}
			theme.Greenf("[+]   ↳ email: %s%s", email.Email, verified).Println()
			utils.WriteToFile(username, fmt.Sprintf("[+]   ↳ email: %s%s\n", email.Email, verified))
		}

		if key.Revoked {
			theme.Yellowf("[!]   ↳ key is revoked").Println()
			utils.WriteToFile(username, "[!]   ↳ key is revoked\n")
		}
	}
}

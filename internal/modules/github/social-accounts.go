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

type GitHubSocialAccount struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

func FetchSocialAccounts(username string) ([]GitHubSocialAccount, error) {
	client := &http.Client{}
	url := fmt.Sprintf("%s/users/%s/social_accounts", githubAPIBase, username)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("User-Agent", config.DefaultUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	setAuthHeader(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching social accounts: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d — unauthenticated requests are limited to 60 req/hour; set GITHUB_TOKEN for 5,000 req/hour", resp.StatusCode)
	}

	var accounts []GitHubSocialAccount
	if err := json.Unmarshal(body, &accounts); err != nil {
		return nil, fmt.Errorf("error parsing social accounts: %w", err)
	}

	return accounts, nil
}

func DisplaySocialAccounts(username string) {
	theme.Yellow("[*] Fetching social accounts for ", username, "...").Println()

	accounts, err := FetchSocialAccounts(username)
	if err != nil {
		theme.Redf("[-] Error fetching social accounts: %v", err).Println()
		return
	}

	if len(accounts) == 0 {
		theme.Yellow("[!] No social accounts found").Println()
		utils.WriteToFile(username, "[!] No social accounts found\n")
		return
	}

	theme.Greenf("[+] Found %d social account(s):", len(accounts)).Println()
	utils.WriteToFile(username, fmt.Sprintf("[+] Found %d social account(s):\n", len(accounts)))

	for _, account := range accounts {
		theme.Greenf("[+] ↳ %s: %s", account.Provider, account.URL).Println()
		utils.WriteToFile(username, fmt.Sprintf("[+] ↳ %s: %s\n", account.Provider, account.URL))
	}
}
